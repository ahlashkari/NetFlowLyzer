#!/usr/bin/env python3

import json
import multiprocessing

class ConfigLoader:
    def __init__(self, config_file_address: str):
        self.config_file_address = config_file_address
        self.pcap_file_address: str = None
        self.output_file_address: str = "./"
        self.interface_name: str = "eth0"
        self.max_flow_duration: int = 120000
        self.activity_timeout: int = 5000
        self.protocols: list = []
        self.floating_point_unit: str = ".4f"
        self.features_ignore_list: list = []
        self.number_of_threads: int = multiprocessing.cpu_count()
        self.single_process: bool = False
        self.label = ""
        self.feature_extractor_min_flows = 4000
        self.writer_min_rows = 6000
        self.read_packets_count_value_log_info = 10000
        self.check_flows_ending_min_flows = 2000
        self.capturer_updating_flows_min_value = 2000
        self.max_rows_number = 900000
        self.batch_address = ""
        self.vxlan_ip = ""
        self.continues_batch_address = ""
        self.continues_pcap_prefix = ""
        self.batch_address_output = ""
        self.number_of_continues_files = 0
        self.base_number_continues_files = 1
        self.analyze_udp_flows = False
        self.udp_feature_extractor_min_flows = 10
        self.udp_writer_min_rows = 5
        self.udp_output_file_address = "udp_flows_output.csv"
        self.udp_max_flow_duration = 300
        self.udp_activity_timeout = 60
        self.udp_check_flows_ending_min_flows = 2500
        self.udp_capturer_updating_flows_min_value = 2500
        self.udp_features_ignore_list = []
        self.read_config_file()

    def read_config_file(self):
        try:
            with open(self.config_file_address) as config_file:
                for key, value in json.loads(config_file.read()).items():
                    setattr(self, key, value)
                if not self.pcap_file_address and not self.batch_address and not self.continues_batch_address:
                    raise Exception("Please specify the 'pcap_file_address' or 'batch_address' or 'continues_batch_address' in the config file.")
        except Exception as error:
            print(f">> Error was detected while reading {self.config_file_address}: {str(error)}. "\
                    "Default values will be applied.")
            exit(-1)
