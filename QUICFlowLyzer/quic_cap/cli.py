from __future__ import annotations

import argparse
import logging

from .capture import run_capture


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Lightweight QUIC flow capturer (header-only)")
    p.add_argument("--pcap", required=False, help="Input PCAP file")
    p.add_argument("--pcaps", nargs="+", default=None, help="List of pcap/pcapng files (processed in natural order)")
    p.add_argument("--pcap-glob", default=None, help='Glob for inputs (e.g. "trace.pcap*")')
    p.add_argument("--flows-out", required=True, help="Output flows CSV path")
    p.add_argument("--vxlan-ip", default=None, help="Restrict VXLAN outer IP (optional)")
    p.add_argument("--vxlan-port", type=int, default=4789, help="VXLAN UDP port")
    p.add_argument("--allow-mirrored-sport", action="store_true", help="Allow sport==VXLAN port (AWS mirroring)")
    p.add_argument("--inner-cidr", action="append", default=None, help="Allowed inner CIDRs (repeatable)")
    p.add_argument("--idle-timeout", type=int, default=15, help="Idle timeout (s)")
    p.add_argument("--log-level", default="INFO", help="Logging level")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    use_batch = bool(args.pcaps or args.pcap_glob)
    if use_batch:
        from .batch import run_capture_batch
        run_capture_batch(
            pcaps=args.pcaps,
            pcap_glob=args.pcap_glob,
            flows_csv=args.flows_out,
            vxlan_ip=args.vxlan_ip,
            vxlan_port=args.vxlan_port,
            allow_mirrored_sport=args.allow_mirrored_sport,
            allowed_inner_cidrs=args.inner_cidr,
            idle_timeout_sec=args.idle_timeout,
        )
        return
    # else fallback to single-file
    if not args.pcap:
        raise SystemExit("--pcap is required when not using --pcaps/--pcap-glob")
    run_capture(
        pcap_path=args.pcap,
        flows_csv=args.flows_out,
        vxlan_ip=args.vxlan_ip,
        vxlan_port=args.vxlan_port,
        allow_mirrored_sport=args.allow_mirrored_sport,
        allowed_inner_cidrs=args.inner_cidr,
        idle_timeout_sec=args.idle_timeout,
    )


if __name__ == "__main__":
    main()


