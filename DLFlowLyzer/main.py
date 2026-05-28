from IO.pcapExt import pcap_reader
from IO.csvSave import pkt_csv, flow_csv
import argparse
import os
import tempfile
import warnings
import yaml
from featureExt.flowPred import flow_pred

PCAP_PATH = None
FINAL_FILE_PATH = None
FINAL_FILE_NAME = None
CAP_UDP = False
JUSTTCP = False
EXTRA = False
FEATURES = []

warnings.filterwarnings("ignore")
parser = argparse.ArgumentParser(
    prog="ETH_FLOW",
    description="DataLink Layer Feature Extractor",
)


def _load_yaml_settings():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base_dir, "setting.yaml"), encoding="utf-8") as file:
        return yaml.safe_load(file)


def configure_globals(
    pcap_path,
    final_file_path,
    final_file_name="packets.csv",
    cap_udp=False,
    just_tcp=False,
    extra=False,
    features=None,
):
    global PCAP_PATH, FINAL_FILE_PATH, FINAL_FILE_NAME, CAP_UDP, JUSTTCP, EXTRA, FEATURES
    PCAP_PATH = pcap_path
    FINAL_FILE_PATH = final_file_path
    FINAL_FILE_NAME = final_file_name
    CAP_UDP = cap_udp
    JUSTTCP = just_tcp
    EXTRA = extra
    FEATURES = features if features is not None else []


def extract_save(flow_output_path=None):
    eth, extra, llc, stp, arp, loop, dtp, isl, cdp, dhcp, flow = pcap_reader(
        PCAP_PATH, CAP_UDP, JUSTTCP, EXTRA, FEATURES
    )
    pkt_csv(
        eth, extra, llc, stp, arp, loop, dtp, isl, cdp, dhcp, flow,
        FINAL_FILE_PATH, FINAL_FILE_NAME,
    )
    list_dict = flow_pred(
        f"{FINAL_FILE_PATH}/pkts_all_{FINAL_FILE_NAME}", EXTRA, FEATURES, CAP_UDP
    )
    flow_csv(list_dict, FINAL_FILE_PATH, FINAL_FILE_NAME, flow_output_path=flow_output_path)


def run_dl_analysis(pcap_path: str, flow_output_path: str, work_dir: str | None = None):
    """Entry point for NetFlowLyzer: write flow features directly to flow_output_path."""
    setting = _load_yaml_settings()
    capture = setting[1]["Capture"]
    if work_dir is None:
        work_dir = tempfile.mkdtemp(prefix="netflowlyzer-dl-")
    configure_globals(
        pcap_path=os.path.normpath(pcap_path),
        final_file_path=work_dir,
        final_file_name="packets.csv",
        cap_udp=capture["CAP_UDP"],
        just_tcp=capture["JUSTTCP"],
        extra=capture["extra"],
        features=capture["features"],
    )
    print(
        f"DLFlowLyzer: PCAP={PCAP_PATH}\n"
        f"  work_dir={FINAL_FILE_PATH}\n"
        f"  output={os.path.normpath(flow_output_path)}"
    )
    extract_save(flow_output_path=os.path.abspath(flow_output_path))


if __name__ == "__main__":
    parser.add_argument("-R", "--result", action="store", help="base file name for results (without .csv)")
    parser.add_argument("-S", "--save", action="store", help="save folder to store the results")
    parser.add_argument("-P", "--pcap", action="store", help="path to pcap file")
    parser.add_argument("-U", "--UDP", action="store_true", help="capture udp")
    parser.add_argument("-J", "--justTCP", action="store_true", help="Extract features just in TCP connections")
    parser.add_argument(
        "-E",
        "--extra",
        action="store_true",
        help="extract all extra features from pcap(llc,stp,arp,loop,dtp,isl,cdp,dhcp)",
    )
    parser.add_argument(
        "-F",
        "--features",
        action="store",
        help="select which extra features to save (l,s,a,t,d,i,c,h)",
    )
    args = parser.parse_args()
    setting = _load_yaml_settings()

    final_file_name = (args.result + ".csv") if args.result else setting[0]["Files"]["FINAL_FILE_NAME"]
    final_file_path = args.save if args.save else setting[0]["Files"]["FINAL_FILE_PATH"]
    pcap_path = args.pcap if args.pcap else setting[0]["Files"]["PCAP_PATH"]
    cap_udp = args.UDP if args.UDP else setting[1]["Capture"]["CAP_UDP"]
    just_tcp = args.justTCP if args.justTCP else setting[1]["Capture"]["JUSTTCP"]
    extra = args.extra if args.extra else setting[1]["Capture"]["extra"]
    features = [char for char in args.features] if args.features else setting[1]["Capture"]["features"]

    configure_globals(
        pcap_path=pcap_path,
        final_file_path=final_file_path,
        final_file_name=final_file_name,
        cap_udp=cap_udp,
        just_tcp=just_tcp,
        extra=extra,
        features=features,
    )
    print(
        f"SETTINGS:\nPCAP_PATH:{PCAP_PATH}\nFINAL_FILE_PATH:{FINAL_FILE_PATH}\n"
        f"FINAL_FILE_NAME:{FINAL_FILE_NAME}\nCAP_UDP:{CAP_UDP}\nJUSTTCP:{JUSTTCP}\n"
        f"EXTRA:{EXTRA}\nFEATURES:{FEATURES}"
    )
    extract_save()
