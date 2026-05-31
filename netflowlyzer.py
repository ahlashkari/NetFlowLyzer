#!/usr/bin/env python3

import argparse
import glob
import importlib.util
import json
import os
import sys
import tempfile
from contextlib import contextmanager

from ALFlowLyzer.application_flow_analyzer import ALFlowLyzer
from NTLFlowLyzer.__main__ import main as ntl_main
from UDPFlowLyzer.__main__ import main as udp_main

DEFAULT_INPUT_DIR = os.path.join("..", "input")
DEFAULT_OUTPUT_DIR = os.path.join("..", "output")
DL_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "DLFlowLyzer")
QUIC_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "QUICFlowLyzer")
LAYER_SUFFIX = {"AL": "AL", "NTL": "NTL", "DL": "DL", "Q": "Q", "U": "U"}
PCAP_EXTENSIONS = (".pcap", ".pcapng")
LAYER_FLOW_LABELS = {
    "AL": "application",
    "NTL": "TCP transport",
    "DL": "link",
    "Q": "QUIC",
    "U": "UDP",
}

_dl_module = None

WHOIS_FEATURES = [
    "dns_whois_domain_name",
    "dns_domain_email",
    "dns_domain_registrar",
    "dns_domain_creation_date",
    "dns_domain_expiration_date",
    "dns_domain_age",
    "dns_domain_country",
    "dns_domain_dnssec",
    "dns_domain_address",
    "dns_domain_city",
    "dns_domain_state",
    "dns_domain_zipcode",
    "dns_domain_name_servers",
    "dns_domain_updated_date",
]

DNS_FEATURES = [
    "dns_domain_name",
    "dns_top_level_domain",
    "dns_second_level_domain",
    "dns_domain_name_length",
    "dns_subdomain_name_length",
    "uni_gram_domain_name",
    "bi_gram_domain_name",
    "tri_gram_domain_name",
    "numerical_percentage",
    "character_distribution",
    "character_entropy",
    "max_continuous_numeric_len",
    "max_continuous_alphabet_len",
    "max_continuous_consonants_len",
    "max_continuous_same_alphabet_len",
    "vowels_consonant_ratio",
    "conv_freq_vowels_consonants",
    "distinct_ttl_values",
    "ttl_values_min",
    "ttl_values_max",
    "ttl_values_mean",
    "ttl_values_mode",
    "ttl_values_variance",
    "ttl_values_standard_deviation",
    "ttl_values_median",
    "ttl_values_skewness",
    "ttl_values_coefficient_of_variation",
    "distinct_A_records",
    "distinct_NS_records",
    "average_authority_resource_records",
    "average_additional_resource_records",
    "average_answer_resource_records",
    "query_resource_record_type",
    "ans_resource_record_type",
    "query_resource_record_class",
    "ans_resource_record_class",
    *WHOIS_FEATURES,
]


@contextmanager
def temporary_argv(new_argv):
    old_argv = sys.argv[:]
    sys.argv = new_argv
    try:
        yield
    finally:
        sys.argv = old_argv


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netflowlyzer",
        description=(
            "Unified traffic analyzer. -i can be a folder (.pcap / .pcapng files) or one capture path. "
            "Each selected layer writes output/<basename>-<LAYER>.csv "
            "(e.g. 2.pcap becomes 2-DL.csv)."
        ),
    )
    parser.add_argument("-AL", action="store_true", help="Run ALFlowLyzer")
    parser.add_argument("-NTL", action="store_true", help="Run NTLFlowLyzer (TCP/IP transport, TCP-focused)")
    parser.add_argument("-Q", action="store_true", help="Run QUICFlowLyzer (QUIC transport features)")
    parser.add_argument("-U", action="store_true", help="Run UDPFlowLyzer (UDP transport features)")
    parser.add_argument("-DL", action="store_true", help="Run DLFlowLyzer")
    parser.add_argument(
        "-i",
        "--input-dir",
        "--input",
        dest="input_path",
        default=DEFAULT_INPUT_DIR,
        metavar="PATH",
        help=(
            "Input folder (.pcap / .pcapng) or path to one capture file "
            f"(default: {DEFAULT_INPUT_DIR})."
        ),
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output folder for CSV files (default: {DEFAULT_OUTPUT_DIR}).",
    )
    parser.add_argument(
        "-c",
        "--config-file",
        dest="ntl_config_file",
        help="Optional NTL base config JSON (paths are overridden per run).",
    )
    parser.add_argument(
        "--al-config",
        dest="al_config_file",
        help="Optional AL base config JSON (paths are overridden per run).",
    )
    parser.add_argument(
        "--udp-config",
        dest="udp_config_file",
        help="Optional UDP base config JSON (paths are overridden per run).",
    )
    al_whois_group = parser.add_mutually_exclusive_group()
    al_whois_group.add_argument(
        "--al-no-whois",
        action="store_true",
        help="Disable WHOIS DNS features in AL (default when -AL is used).",
    )
    al_whois_group.add_argument(
        "--al-whois",
        action="store_true",
        help="Enable WHOIS DNS lookups in AL (slow; requires network; may error).",
    )
    parser.add_argument(
        "--al-no-dns",
        action="store_true",
        help="Disable all DNS/domain features in AL (general AL stats only).",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help=(
            "Use multiple Python worker processes for AL/NTL/UDP (faster, but many "
            "Windows Firewall prompts). Default is single-process."
        ),
    )
    parser.add_argument(
        "--q-vxlan-ip",
        default=None,
        metavar="IP",
        help="QUIC (-Q): restrict VXLAN decapsulation to this outer IP (cloud captures).",
    )
    parser.add_argument(
        "--q-vxlan-port",
        type=int,
        default=4789,
        help="QUIC (-Q): VXLAN UDP port (default: 4789).",
    )
    parser.add_argument(
        "--q-allow-mirrored-sport",
        action="store_true",
        help="QUIC (-Q): allow mirrored VXLAN where source port equals the VXLAN port.",
    )
    parser.add_argument(
        "--q-inner-cidr",
        action="append",
        default=None,
        metavar="CIDR",
        help="QUIC (-Q): allowed inner CIDR after VXLAN decap (repeatable).",
    )
    parser.add_argument(
        "--q-idle-gap-sec",
        type=float,
        default=1.0,
        help="QUIC (-Q): idle gap in seconds for active/idle episode stats (default: 1.0).",
    )
    parser.add_argument(
        "--q-verbose",
        action="store_true",
        help="QUIC (-Q): print per-packet QUIC parsing details (default: quiet).",
    )
    return parser


def is_pcap_file(path: str) -> bool:
    return path.lower().endswith(PCAP_EXTENSIONS)


def list_pcaps_in_dir(directory: str) -> list[str]:
    pcaps: list[str] = []
    for ext in PCAP_EXTENSIONS:
        pcaps.extend(glob.glob(os.path.join(directory, f"*{ext}")))
    return sorted(set(pcaps))


def count_csv_data_rows(csv_path: str) -> int | None:
    """Return data row count (excluding header), or None if the file is missing/unreadable."""
    if not os.path.isfile(csv_path):
        return None
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as csv_file:
            line_count = sum(1 for _ in csv_file)
    except OSError:
        return None
    if line_count == 0:
        return 0
    return max(0, line_count - 1)


def report_layer_result(layer: str, csv_path: str, flow_count: int | None = None) -> None:
    """Print a unified completion message for every analyzer layer."""
    flow_label = LAYER_FLOW_LABELS.get(layer, layer.lower())
    if flow_count is None:
        flow_count = count_csv_data_rows(csv_path)

    if flow_count is None:
        print(f"[{layer}] Warning: expected output missing: {csv_path}")
        return

    if flow_count == 0:
        if os.path.isfile(csv_path):
            print(
                f"[{layer}] Warning: no {flow_label} flows found; "
                f"{csv_path} contains headers only."
            )
        else:
            print(f"[{layer}] Warning: expected output missing: {csv_path}")
        return

    print(f"[{layer}] {flow_count} {flow_label} flow(s) written to {csv_path}")


def remove_path_safe(path: str | None) -> None:
    if not path:
        return
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def no_pcaps_error(path: str, *, is_file: bool = False) -> FileNotFoundError:
    resolved = os.path.abspath(path)
    if is_file:
        return FileNotFoundError(f"PCAP file not found: {resolved}")
    return FileNotFoundError(
        f"No .pcap or .pcapng files found in folder: {resolved}\n"
        "Use -i with a folder containing capture files, or -i path\\to\\one.pcap"
    )


def capture_entry(pcap_path: str) -> tuple[str, str]:
    pcap_path = os.path.normpath(os.path.abspath(pcap_path))
    base = os.path.splitext(os.path.basename(pcap_path))[0]
    return base, pcap_path


def list_captures(input_path: str) -> list[tuple[str, str]]:
    """Return (basename, pcap_path) for a folder of PCAPs or a single .pcap file."""
    input_path = os.path.normpath(input_path)

    if os.path.isfile(input_path):
        if is_pcap_file(input_path):
            return [capture_entry(input_path)]
        raise FileNotFoundError(
            f"Not a capture file (expected .pcap or .pcapng): {os.path.abspath(input_path)}"
        )

    if os.path.isdir(input_path):
        pcaps = list_pcaps_in_dir(input_path)
        if not pcaps:
            raise no_pcaps_error(input_path)
        return [capture_entry(path) for path in pcaps]

    if input_path.lower().endswith(PCAP_EXTENSIONS):
        raise no_pcaps_error(input_path, is_file=True)

    raise FileNotFoundError(
        f"Input path does not exist: {os.path.abspath(input_path)}\n"
        "Use -i with an existing folder or .pcap file path."
    )


def output_csv_path(output_dir: str, base: str, layer: str) -> str:
    return os.path.abspath(os.path.join(output_dir, f"{base}-{LAYER_SUFFIX[layer]}.csv"))


def apply_parallel_defaults(config: dict, parallel: bool) -> None:
    if not parallel:
        config["single_process"] = True
        config["number_of_threads"] = 3
    else:
        config["single_process"] = False


def disable_al_whois_features(config: dict) -> None:
    ignore = list(config.get("features_ignore_list", []))
    for name in WHOIS_FEATURES:
        if name not in ignore:
            ignore.append(name)
    config["features_ignore_list"] = ignore


def enable_al_whois_features(config: dict) -> None:
    ignore = list(config.get("features_ignore_list", []))
    config["features_ignore_list"] = [name for name in ignore if name not in WHOIS_FEATURES]


def disable_all_al_dns_features(config: dict) -> None:
    ignore = list(config.get("features_ignore_list", []))
    for name in DNS_FEATURES:
        if name not in ignore:
            ignore.append(name)
    config["features_ignore_list"] = ignore


def build_runtime_config(
    pcap_path: str,
    csv_path: str,
    config_file: str | None,
    default_config_path: str,
    temp_prefix: str,
    parallel: bool,
) -> str:
    base_config_path = config_file or default_config_path
    with open(base_config_path, "r", encoding="utf-8") as config_file_handle:
        config = json.load(config_file_handle)

    config["pcap_file_address"] = os.path.abspath(pcap_path)
    config["output_file_address"] = os.path.abspath(csv_path)
    apply_parallel_defaults(config, parallel)

    tmp_file = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        prefix=temp_prefix,
        delete=False,
        encoding="utf-8",
    )
    with tmp_file:
        json.dump(config, tmp_file, indent=4)

    return tmp_file.name


def build_ntl_runtime_config(pcap_path: str, csv_path: str, config_file: str | None, parallel: bool) -> str:
    return build_runtime_config(
        pcap_path,
        csv_path,
        config_file,
        os.path.join("NTLFlowLyzer", "config.json"),
        "netflowlyzer-ntl-",
        parallel,
    )


def build_udp_runtime_config(
    pcap_path: str, csv_path: str, config_file: str | None, parallel: bool
) -> str:
    base_config_path = config_file or os.path.join("UDPFlowLyzer", "config.json")
    with open(base_config_path, "r", encoding="utf-8") as config_file_handle:
        config = json.load(config_file_handle)

    config["pcap_file_address"] = os.path.abspath(pcap_path)
    config["udp_output_file_address"] = os.path.abspath(csv_path)
    config["label"] = ""
    apply_parallel_defaults(config, parallel)

    tmp_file = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        prefix="netflowlyzer-u-",
        delete=False,
        encoding="utf-8",
    )
    with tmp_file:
        json.dump(config, tmp_file, indent=4)

    return tmp_file.name


def build_al_runtime_config(
    pcap_path: str,
    csv_path: str,
    config_file: str | None,
    parallel: bool,
    enable_whois: bool,
    disable_dns: bool,
) -> str:
    base_config_path = config_file or os.path.join("ALFlowLyzer", "config.json")
    with open(base_config_path, "r", encoding="utf-8") as config_file_handle:
        config = json.load(config_file_handle)

    config["pcap_file_address"] = os.path.abspath(pcap_path)
    config["output_file_address"] = os.path.abspath(csv_path)
    apply_parallel_defaults(config, parallel)
    if disable_dns:
        disable_all_al_dns_features(config)
    elif enable_whois:
        enable_al_whois_features(config)
    else:
        disable_al_whois_features(config)

    tmp_file = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        prefix="netflowlyzer-al-",
        delete=False,
        encoding="utf-8",
    )
    with tmp_file:
        json.dump(config, tmp_file, indent=4)

    return tmp_file.name


def al_online_mode(extra_args: list) -> bool:
    # Do not treat -o as online mode; netflowlyzer uses -o for the output folder.
    return "--online-capturing" in extra_args


def run_al(
    pcap_path: str,
    csv_path: str,
    config_file: str | None,
    parallel: bool,
    extra_args: list,
    enable_whois: bool,
    disable_dns: bool,
):
    runtime_config_path = build_al_runtime_config(
        pcap_path, csv_path, config_file, parallel, enable_whois, disable_dns
    )
    try:
        alflowlyzer = ALFlowLyzer(runtime_config_path, al_online_mode(extra_args))
        alflowlyzer.run()
    finally:
        remove_path_safe(runtime_config_path)


def run_ntl(pcap_path: str, csv_path: str, config_file: str | None, parallel: bool, extra_args: list):
    runtime_config_path = build_ntl_runtime_config(pcap_path, csv_path, config_file, parallel)
    ntl_args = list(extra_args) + ["-c", runtime_config_path]

    try:
        with temporary_argv(["ntlflowlyzer", *ntl_args]):
            ntl_main()
    finally:
        remove_path_safe(runtime_config_path)


def run_udp(
    pcap_path: str,
    csv_path: str,
    config_file: str | None,
    parallel: bool,
    extra_args: list,
):
    runtime_config_path = build_udp_runtime_config(pcap_path, csv_path, config_file, parallel)
    udp_args = list(extra_args) + ["-c", runtime_config_path]

    try:
        with temporary_argv(["udpflowlyzer", *udp_args]):
            udp_main()
    finally:
        remove_path_safe(runtime_config_path)


def ensure_quic_import_path() -> None:
    quic_root = os.path.abspath(QUIC_ROOT)
    if quic_root not in sys.path:
        sys.path.insert(0, quic_root)


def run_quic(pcap_path: str, csv_path: str, args) -> int:
    quic_cap = os.path.join(QUIC_ROOT, "quic_cap")
    if not os.path.isdir(quic_cap):
        raise FileNotFoundError(f"QUICFlowLyzer not found at {QUIC_ROOT}")

    pcap_path = os.path.abspath(pcap_path)
    csv_path = os.path.abspath(csv_path)
    out_dir = os.path.dirname(csv_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    ensure_quic_import_path()
    from quic_cap.features.feat_cli import run_extraction

    return run_extraction(
        pcap_path=pcap_path,
        features_out=csv_path,
        vxlan_ip=args.q_vxlan_ip,
        vxlan_port=args.q_vxlan_port,
        allow_mirrored_sport=args.q_allow_mirrored_sport,
        inner_cidr=args.q_inner_cidr,
        idle_gap_sec=args.q_idle_gap_sec,
        verbose=args.q_verbose,
    )


def ensure_tshark_on_path() -> None:
    wireshark = r"C:\Program Files\Wireshark"
    if os.name == "nt" and os.path.isdir(wireshark):
        path = os.environ.get("PATH", "")
        if wireshark.lower() not in path.lower():
            os.environ["PATH"] = wireshark + os.pathsep + path


def load_dl_module():
    global _dl_module
    if _dl_module is not None:
        return _dl_module

    dl_main = os.path.join(DL_ROOT, "main.py")
    if not os.path.isfile(dl_main):
        raise FileNotFoundError(f"DLFlowLyzer not found at {DL_ROOT}")

    old_cwd = os.getcwd()
    if DL_ROOT not in sys.path:
        sys.path.insert(0, DL_ROOT)
    try:
        os.chdir(DL_ROOT)
        spec = importlib.util.spec_from_file_location("dlflowlyzer_main", dl_main)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _dl_module = module
        return module
    finally:
        os.chdir(old_cwd)


def run_dl(pcap_path: str, csv_path: str):
    ensure_tshark_on_path()
    pcap_path = os.path.abspath(pcap_path)
    csv_path = os.path.abspath(csv_path)
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    module = load_dl_module()
    old_cwd = os.getcwd()
    try:
        os.chdir(DL_ROOT)
        module.run_dl_analysis(pcap_path, csv_path)
    finally:
        os.chdir(old_cwd)


def run_layer(layer: str, pcap_path: str, csv_path: str, args, parallel: bool, extra_args: list):
    print(f"[{layer}] input:  {pcap_path}")
    print(f"[{layer}] output: {csv_path}")

    if layer == "AL":
        if args.al_no_dns:
            mode_note = "general features only (--al-no-dns)"
        elif args.al_whois:
            mode_note = "with WHOIS DNS features"
        else:
            mode_note = "with DNS features, without WHOIS"
        print(f"Starting ALFlowLyzer ({mode_note})...")
        run_al(
            pcap_path,
            csv_path,
            args.al_config_file,
            parallel,
            extra_args,
            enable_whois=args.al_whois,
            disable_dns=args.al_no_dns,
        )
        report_layer_result("AL", csv_path)
        return

    if layer == "NTL":
        print("Starting NTLFlowLyzer (TCP-focused transport)...")
        run_ntl(pcap_path, csv_path, args.ntl_config_file, parallel, extra_args)
        report_layer_result("NTL", csv_path)
        return

    if layer == "Q":
        print("Starting QUICFlowLyzer (header-level QUIC; no decryption)...")
        flow_count = run_quic(pcap_path, csv_path, args)
        report_layer_result("Q", csv_path, flow_count=flow_count)
        return

    if layer == "U":
        print("Starting UDPFlowLyzer (UDP transport)...")
        run_udp(pcap_path, csv_path, args.udp_config_file, parallel, extra_args)
        report_layer_result("U", csv_path)
        return

    if layer == "DL":
        print("Starting DLFlowLyzer... (pyshark/tshark; slow on large PCAPs)")
        run_dl(pcap_path, csv_path)
        report_layer_result("DL", csv_path)
        return


def main():
    parser = create_parser()
    args, extra_args = parser.parse_known_args()

    selected = []
    if args.AL:
        selected.append("AL")
    if args.NTL:
        selected.append("NTL")
    if args.Q:
        selected.append("Q")
    if args.U:
        selected.append("U")
    if args.DL:
        selected.append("DL")

    if not selected:
        selected = ["AL", "NTL", "DL"]

    if args.parallel:
        print("Parallel mode: AL/NTL/UDP may spawn many Python workers (extra firewall prompts).")
    else:
        print(
            "Single-process mode (default): one Python process per analyzer — "
            "allow Python through Windows Firewall once if prompted."
        )

    if "U" in selected and args.parallel:
        print("U: parallel mode enabled (--parallel); extra Python workers for UDP.")

    if "AL" in selected:
        if args.al_no_dns:
            print("AL: all DNS/domain features disabled (--al-no-dns).")
        elif args.al_whois:
            print("AL: DNS features on; WHOIS enabled (--al-whois).")
        else:
            print("AL: DNS features on; WHOIS disabled (default).")

    if "Q" in selected:
        if args.q_verbose:
            print("Q: verbose per-packet logging enabled (--q-verbose).")
        else:
            print("Q: quiet mode (progress every 10k packets; use --q-verbose for details).")
        if args.q_vxlan_ip:
            print(f"Q: VXLAN outer IP filter: {args.q_vxlan_ip} (port {args.q_vxlan_port}).")

    input_path = os.path.normpath(args.input_path)
    output_dir = os.path.abspath(os.path.normpath(args.output_dir))
    os.makedirs(output_dir, exist_ok=True)

    captures = list_captures(input_path)
    if len(captures) == 1:
        print(f"Processing 1 PCAP: {captures[0][1]}")
    else:
        print(f"Found {len(captures)} PCAP file(s) in {os.path.abspath(input_path)}")

    for base, pcap_path in captures:
        print(f"\n=== Capture: {base} ({pcap_path}) ===")
        for layer in selected:
            csv_path = output_csv_path(output_dir, base, layer)
            run_layer(layer, pcap_path, csv_path, args, args.parallel, extra_args)


if __name__ == "__main__":
    main()
