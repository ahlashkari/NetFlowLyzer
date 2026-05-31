#!/usr/bin/env python3

import dpkt
import multiprocessing
import threading
import warnings
from multiprocessing import Process, Manager, Pool

from .network_flow_capturer.udp_network_flow_capturer import UDPNetworkFlowCapturer
from .udp_feature_extractor import UDPFeatureExtractor
from .writers import Writer, CSVWriter
from .config_loader import ConfigLoader


class _SyncFlag:
    def __init__(self, initial=False):
        self._value = initial

    def get(self):
        return self._value

    def set(self, value):
        self._value = bool(value)


class _SyncInt:
    def __init__(self, initial=0):
        self._value = initial

    def get(self):
        return self._value

    def set(self, value):
        self._value = value


class UDPNetworkFlowAnalyzer(object):
    """Analyze UDP flows in an offline PCAP file."""

    def __init__(self, config: ConfigLoader, continues_batch_mode: bool = False):
        self.__config = config
        self.__continues_batch_mode = continues_batch_mode
        warnings.filterwarnings("ignore")

    def _build_capturer(self) -> UDPNetworkFlowCapturer:
        return UDPNetworkFlowCapturer(
            max_flow_duration=getattr(self.__config, "udp_max_flow_duration", 300),
            activity_timeout=getattr(self.__config, "udp_activity_timeout", 60),
            check_flows_ending_min_flows=getattr(
                self.__config, "udp_check_flows_ending_min_flows", 2500
            ),
            capturer_updating_flows_min_value=getattr(
                self.__config, "udp_capturer_updating_flows_min_value", 2500
            ),
            read_packets_count_value_log_info=self.__config.read_packets_count_value_log_info,
            vxlan_ip=getattr(self.__config, "vxlan_ip", ""),
            continues_batch_address=self.__config.continues_batch_address,
            continues_pcap_prefix=self.__config.continues_pcap_prefix,
            number_of_continues_files=self.__config.number_of_continues_files,
            continues_batch_mode=self.__continues_batch_mode,
            base_number_continues_files=getattr(
                self.__config, "base_number_continues_files", 1
            ),
        )

    def run(self):
        """Capture UDP flows, extract features and write them to CSV."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            print(">> Analyzing the", self.__config.pcap_file_address, "...")
            with open(self.__config.pcap_file_address, "rb") as f:
                pcap = dpkt.pcap.Reader(f)
                packets_temp = [1 for _ in pcap]
            print(f">> The input PCAP file contains {len(packets_temp)} packets.")

            if getattr(self.__config, "single_process", False):
                self._run_single_process()
                print(">> Results are ready!")
                return

            with Manager() as manager:
                self.__flows = manager.list()
                self.__data = manager.list()

                number_of_writer_threads = 1
                number_of_required_threads = 3
                number_of_extractor_threads = (
                    self.__config.number_of_threads - number_of_writer_threads
                )
                if self.__config.number_of_threads < number_of_required_threads:
                    print(
                        ">> At least 3 threads are required. "
                        "There should be one for the capturer, one for the writer, "
                        "and one or more for the feature extractor."
                        "\nWe set the number of threads based on your CPU cores."
                    )
                    number_of_extractor_threads = (
                        multiprocessing.cpu_count() - number_of_writer_threads
                    )
                    if multiprocessing.cpu_count() < number_of_required_threads:
                        number_of_extractor_threads = (
                            number_of_required_threads - number_of_writer_threads
                        )

                self.__capturer_thread_finish = manager.Value("i", False)
                self.__extractor_thread_finish = manager.Value("i", False)
                self.__written_rows = manager.Value("i", 0)
                self.__output_file_index = manager.Value("i", 1)

                self.__data_lock = manager.Lock()
                self.__flows_lock = manager.Lock()
                self.__feature_extractor_watchdog_lock = manager.Lock()
                self.__written_rows_lock = manager.Lock()
                self.__output_file_index_lock = manager.Lock()

                capturer = self._build_capturer()

                writer_thread = Process(target=self.writer)
                writer_thread.start()

                with Pool(processes=number_of_extractor_threads) as pool:
                    pool.starmap_async(
                        capturer.capture,
                        [
                            (
                                self.__config.pcap_file_address,
                                self.__flows,
                                self.__flows_lock,
                                self.__capturer_thread_finish,
                            )
                        ],
                    )
                    self.feature_extractor(pool)
                    pool.close()
                    pool.join()
                    with self.__feature_extractor_watchdog_lock:
                        self.__extractor_thread_finish.set(True)

                writer_thread.join()
            print(">> Results are ready!")

    def _run_single_process(self):
        print(">> Single-process mode (no extra Python workers; fewer firewall prompts).")
        self.__flows = []
        self.__data = []
        self.__capturer_thread_finish = _SyncFlag()
        self.__extractor_thread_finish = _SyncFlag()
        self.__written_rows = _SyncInt(0)
        self.__output_file_index = _SyncInt(1)
        self.__data_lock = threading.Lock()
        self.__flows_lock = threading.Lock()
        self.__feature_extractor_watchdog_lock = threading.Lock()
        self.__written_rows_lock = threading.Lock()
        self.__output_file_index_lock = threading.Lock()

        capturer = self._build_capturer()
        feature_extractor = UDPFeatureExtractor(self.__config.floating_point_unit)

        writer_thread = threading.Thread(target=self.writer, daemon=True)
        writer_thread.start()

        capture_thread = threading.Thread(
            target=capturer.capture,
            args=(
                self.__config.pcap_file_address,
                self.__flows,
                self.__flows_lock,
                self.__capturer_thread_finish,
            ),
            daemon=True,
        )
        capture_thread.start()
        self._feature_extractor_single(feature_extractor)
        capture_thread.join()
        with self.__feature_extractor_watchdog_lock:
            self.__extractor_thread_finish.set(True)
        writer_thread.join()

    def _feature_extractor_single(self, feature_extractor: UDPFeatureExtractor):
        min_flows = getattr(self.__config, "udp_feature_extractor_min_flows", 10)
        ignore_list = getattr(self.__config, "udp_features_ignore_list", [])
        while True:
            if len(self.__flows) >= min_flows:
                temp_flows = []
                with self.__flows_lock:
                    temp_flows.extend(self.__flows)
                    self.__flows[:] = []
                print(f">> Extracting features of {len(temp_flows)} number of UDP flows...")
                feature_extractor.execute(
                    self.__data,
                    self.__data_lock,
                    temp_flows,
                    ignore_list,
                    self.__config.label,
                )
            if self.__capturer_thread_finish.get():
                if len(self.__flows) == 0:
                    return
                temp_flows = []
                with self.__flows_lock:
                    temp_flows.extend(self.__flows)
                    self.__flows[:] = []
                print(
                    f">> Extracting features of the last {len(temp_flows)} number of UDP flows..."
                )
                feature_extractor.execute(
                    self.__data,
                    self.__data_lock,
                    temp_flows,
                    ignore_list,
                    self.__config.label,
                )
                return

    def feature_extractor(self, pool: Pool):
        """Extract features from captured UDP flows using a multiprocessing pool."""
        feature_extractor = UDPFeatureExtractor(self.__config.floating_point_unit)
        while True:
            if len(self.__flows) >= getattr(
                self.__config, "udp_feature_extractor_min_flows", 10
            ):
                temp_flows = []
                with self.__flows_lock:
                    temp_flows.extend(self.__flows)
                    self.__flows[:] = []
                print(f">> Extracting features of {len(temp_flows)} number of UDP flows...")
                pool.starmap_async(
                    feature_extractor.execute,
                    [
                        (
                            self.__data,
                            self.__data_lock,
                            temp_flows,
                            getattr(self.__config, "udp_features_ignore_list", []),
                            self.__config.label,
                        )
                    ],
                )
                del temp_flows
            if self.__capturer_thread_finish.get():
                if len(self.__flows) == 0:
                    return
                temp_flows = []
                with self.__flows_lock:
                    temp_flows.extend(self.__flows)
                    self.__flows[:] = []
                print(
                    f">> Extracting features of the last {len(temp_flows)} number of UDP flows..."
                )
                pool.starmap_async(
                    feature_extractor.execute,
                    [
                        (
                            self.__data,
                            self.__data_lock,
                            temp_flows,
                            getattr(self.__config, "udp_features_ignore_list", []),
                            self.__config.label,
                        )
                    ],
                )
                del temp_flows

    def writer(self):
        """Write extracted UDP flow features to CSV."""
        writer = Writer(CSVWriter())
        header_writing_mode = "w"
        data_writing_mode = "a+"
        file_address = getattr(
            self.__config, "udp_output_file_address", "./udp_flows_output.csv"
        )
        write_headers = True
        while True:
            if len(self.__data) >= getattr(
                self.__config, "udp_writer_min_rows", 5
            ):
                with self.__written_rows_lock, self.__output_file_index_lock:
                    if self.__written_rows.get() > self.__config.max_rows_number:
                        new_file_address = file_address + str(self.__output_file_index.get())
                        print(f">> {file_address} has reached its maximum number of rows.")
                        print(
                            f">> The {file_address} file will be closed and other rows"
                            f" will be written in the {new_file_address}."
                        )
                        file_address = new_file_address
                        self.__output_file_index.set(self.__output_file_index.get() + 1)
                        write_headers = True
                        self.__written_rows.set(0)
                if write_headers:
                    writer.write(file_address, self.__data, header_writing_mode, only_headers=True)
                    write_headers = False
                temp_data = []
                with self.__data_lock:
                    temp_data.extend(self.__data)
                    self.__data[:] = []
                    print(f">> Writing {len(temp_data)} UDP flows with extracted features...")
                writer.write(file_address, temp_data, data_writing_mode)
                with self.__written_rows_lock:
                    self.__written_rows.set(self.__written_rows.get() + len(temp_data))
                del temp_data
            with self.__feature_extractor_watchdog_lock:
                if self.__extractor_thread_finish.get():
                    print(">> Extracting finished, lets go for final writing...")
                    temp_data = []
                    with self.__data_lock:
                        temp_data.extend(self.__data)
                        self.__data[:] = []
                    print(
                        f">> Writing the last {len(temp_data)} UDP flows with extracted features..."
                    )

                    if write_headers:
                        writer.write(
                            file_address, temp_data, header_writing_mode, only_headers=True
                        )
                        write_headers = False

                    if len(temp_data) > 0:
                        writer.write(file_address, temp_data, data_writing_mode)
                    if len(self.__data) == 0:
                        print(">> Writing finished, lets wrapp up!")
                        return 0
