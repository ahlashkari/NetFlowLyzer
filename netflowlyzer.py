#!/usr/bin/env python3

import argparse
import glob
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from contextlib import contextmanager

from ALFlowLyzer.application_flow_analyzer import ALFlowLyzer
from NTLFlowLyzer.__main__ import main as ntl_main

DEFAULT_INPUT_DIR = os.path.join("..", "input")
DEFAULT_OUTPUT_DIR = os.path.join("..", "output")
DL_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "DLFlowLyzer")
QUIC_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "QUICFlowLyzer")
LAYER_SUFFIX = {"AL": "AL", "NTL": "NTL", "DL": "DL", "Q": "Q"}

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
            "Unified traffic analyzer. -i can be a folder (all .pcap files) or one .pcap path. "
            "Each selected layer writes output/<basename>-<LAYER>.csv "
            "(e.g. 2.pcap becomes 2-DL.csv)."
        ),
    )
    parser.add_argument("-AL", action="store_true", help="Run ALFlowLyzer")
    parser.add_argument("-NTL", action="store_true", help="Run NTLFlowLyzer (TCP/IP transport, TCP-focused)")
    parser.add_argument("-Q", action="store_true", help="Run QUICFlowLyzer (QUIC transport features)")
    parser.add_argument("-DL", action="store_true", help="Run DLFlowLyzer")
    parser.add_argument(
        "-i",
        "--input-dir",
        "--input",
        dest="input_path",
        default=DEFAULT_INPUT_DIR,
        metavar="PATH",
        help=(
            "Input folder (all .pcap files) or path to one .pcap file "
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
        "--parallel",
        action="store_true",
        help=(
            "Use multiple Python worker processes for AL/NTL (faster, but many "
            "Windows Firewall prompts). Default is single-process."
        ),
    )
    return parser


def list_pcaps_in_dir(directory: str) -> list[str]:
    pattern = os.path.join(directory, "*.pcap")
    return sorted(glob.glob(pattern))


def no_pcaps_error(path: str, *, is_file: bool = False) -> FileNotFoundError:
    resolved = os.path.abspath(path)
    if is_file:
        return FileNotFoundError(f"PCAP file not found: {resolved}")
    return FileNotFoundError(
        f"No .pcap files found in folder: {resolved}\n"
        "Use -i with a folder containing .pcap files, or -i path\\to\\one.pcap"
    )


def capture_entry(pcap_path: str) -> tuple[str, str]:
    pcap_path = os.path.normpath(os.path.abspath(pcap_path))
    base = os.path.splitext(os.path.basename(pcap_path))[0]
    return base, pcap_path


def list_captures(input_path: str) -> list[tuple[str, str]]:
    """Return (basename, pcap_path) for a folder of PCAPs or a single .pcap file."""
    input_path = os.path.normpath(input_path)

    if os.path.isfile(input_path):
        if input_path.lower().endswith(".pcap"):
            return [capture_entry(input_path)]
        raise FileNotFoundError(
            f"Not a PCAP file (expected .pcap extension): {os.path.abspath(input_path)}"
        )

    if os.path.isdir(input_path):
        pcaps = list_pcaps_in_dir(input_path)
        if not pcaps:
            raise no_pcaps_error(input_path)
        return [capture_entry(path) for path in pcaps]

    if input_path.lower().endswith(".pcap"):
        raise no_pcaps_error(input_path, is_file=True)

    raise FileNotFoundError(
        f"Input path does not exist: {os.path.abspath(input_path)}\n"
        "Use -i with an existing folder or .pcap file path."
    )


def output_csv_path(output_dir: str, base: str, layer: str) -> str:
    return os.path.abspath(os.path.join(output_dir, f"{base}-{LAYER_SUFFIX[layer]}.csv"))


def apply_unified_defaults(config: dict, parallel: bool) -> None:
    if not parallel:
        config["single_process"] = True
        config["number_of_threads"] = 3
    else:
        config["single_process"] = False
    ignore = list(config.get("features_ignore_list", []))
    for name in WHOIS_FEATURES:
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
    apply_unified_defaults(config, parallel)

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


def build_al_runtime_config(pcap_path: str, csv_path: str, config_file: str | None, parallel: bool) -> str:
    return build_runtime_config(
        pcap_path,
        csv_path,
        config_file,
        os.path.join("ALFlowLyzer", "config.json"),
        "netflowlyzer-al-",
        parallel,
    )


def al_online_mode(extra_args: list) -> bool:
    # Do not treat -o as online mode; netflowlyzer uses -o for the output folder.
    return "--online-capturing" in extra_args


def run_al(pcap_path: str, csv_path: str, config_file: str | None, parallel: bool, extra_args: list):
    runtime_config_path = build_al_runtime_config(pcap_path, csv_path, config_file, parallel)
    alflowlyzer = ALFlowLyzer(runtime_config_path, al_online_mode(extra_args))
    alflowlyzer.run()


def run_ntl(pcap_path: str, csv_path: str, config_file: str | None, parallel: bool, extra_args: list):
    runtime_config_path = build_ntl_runtime_config(pcap_path, csv_path, config_file, parallel)
    ntl_args = list(extra_args) + ["-c", runtime_config_path]

    with temporary_argv(["ntlflowlyzer", *ntl_args]):
        ntl_main()


def run_quic(pcap_path: str, csv_path: str):
    quic_cap = os.path.join(QUIC_ROOT, "quic_cap")
    if not os.path.isdir(quic_cap):
        raise FileNotFoundError(f"QUICFlowLyzer not found at {QUIC_ROOT}")

    pcap_path = os.path.abspath(pcap_path)
    csv_path = os.path.abspath(csv_path)
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)

    env = os.environ.copy()
    quic_root = os.path.abspath(QUIC_ROOT)
    env["PYTHONPATH"] = quic_root + os.pathsep + env.get("PYTHONPATH", "")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "quic_cap.features.feat_cli",
            "--pcap",
            pcap_path,
            "--features-out",
            csv_path,
        ],
        cwd=quic_root,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"QUICFlowLyzer failed with exit code {result.returncode}")


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
        print("Starting ALFlowLyzer...")
        run_al(pcap_path, csv_path, args.al_config_file, parallel, extra_args)
        return

    if layer == "NTL":
        print("Starting NTLFlowLyzer (TCP-focused transport)...")
        run_ntl(pcap_path, csv_path, args.ntl_config_file, parallel, extra_args)
        return

    if layer == "Q":
        print("Starting QUICFlowLyzer...")
        run_quic(pcap_path, csv_path)
        if os.path.isfile(csv_path) and os.path.getsize(csv_path) > 0:
            print(f"[Q] CSV created: {csv_path}")
        else:
            print(f"[Q] Warning: expected output missing or empty: {csv_path}")
        return

    if layer == "DL":
        print("Starting DLFlowLyzer... (pyshark/tshark; slow on large PCAPs)")
        run_dl(pcap_path, csv_path)
        if os.path.isfile(csv_path) and os.path.getsize(csv_path) > 0:
            print(f"[DL] CSV created: {csv_path}")
        else:
            print(f"[DL] Warning: expected output missing or empty: {csv_path}")
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
    if args.DL:
        selected.append("DL")

    if not selected:
        selected = ["AL", "NTL", "DL"]

    if args.parallel:
        print("Parallel mode: AL/NTL may spawn many Python workers (extra firewall prompts).")
    else:
        print(
            "Single-process mode (default): one Python process per analyzer, "
            "no WHOIS lookups — allow Python through Windows Firewall once if prompted."
        )

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
