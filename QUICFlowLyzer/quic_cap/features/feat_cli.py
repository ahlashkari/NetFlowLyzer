from __future__ import annotations

import argparse
import glob
import logging
import os
from typing import Iterable, Iterator, List, Optional

import dpkt

from ..utils import ethernet_to_ip_udp
from ..writers import open_csv as open_pkt_csv  # not used, but ensures parity
from ..quic_parser import iter_quic_packets  # import to ensure availability
from .. import capture as _unused_capture  # ensure dpkt reading consistency
from .. import batch as _unused_batch
from vxlan import try_decap_vxlan  # used by extractor

from .extractor import FeatureExtractor, write_features_csv
from . import schema as feature_schema


def _gather_inputs(pcap: Optional[str], pcaps: Optional[List[str]], pcap_glob: Optional[str]) -> List[str]:
    files: List[str] = []
    if pcaps:
        files.extend(pcaps)
    if pcap_glob:
        files.extend(sorted(glob.glob(pcap_glob)))
    if pcap and not files:
        files.append(pcap)
    # Deduplicate while preserving order
    seen = set()
    out = []
    for f in files:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extract NTLFlowLyzer-style QUIC flow features")
    p.add_argument("--pcap", required=False, help="Input PCAP file")
    p.add_argument("--pcaps", nargs="+", default=None, help="List of pcap/pcapng files (processed in natural order)")
    p.add_argument("--pcap-glob", default=None, help='Glob for inputs (e.g. "trace.pcap*")')
    p.add_argument("--features-out", required=True, help="Output features CSV path")
    p.add_argument("--vxlan-ip", default=None, help="Restrict VXLAN outer IP (optional)")
    p.add_argument("--vxlan-port", type=int, default=4789, help="VXLAN UDP port")
    p.add_argument("--allow-mirrored-sport", action="store_true", help="Allow sport==VXLAN port (AWS mirroring)")
    p.add_argument("--inner-cidr", action="append", default=None, help="Allowed inner CIDRs (repeatable)")
    p.add_argument("--idle-gap-sec", type=float, default=1.0, help="Idle gap threshold for episode segmentation")
    p.add_argument("--log-level", default="INFO", help="Logging level")
    return p.parse_args()


def _iter_pcap_packets(path: str) -> Iterator[tuple[float, dpkt.ethernet.Ethernet]]:
    # Simple reader mirroring capture module's approach; keep streaming and robust
    with open(path, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue
                yield float(ts), eth
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            f.seek(0)
            try:
                pcapng = dpkt.pcapng.Reader(f)
                for ts, buf in pcapng:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                    except Exception:
                        continue
                    yield float(ts), eth
            except Exception:
                return


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    inputs = _gather_inputs(args.pcap, args.pcaps, args.pcap_glob)
    if not inputs:
        raise SystemExit("At least one of --pcap, --pcaps, or --pcap-glob is required")

    print("[feat] Starting QUIC feature extraction")
    print(f"[feat] Inputs: {len(inputs)} file(s)")
    for p in inputs:
        print(f"[feat]  - {p}")
    print(f"[feat] VXLAN: ip={args.vxlan_ip or ''} port={args.vxlan_port} allow_mirrored_sport={bool(args.allow_mirrored_sport)}")
    print(f"[feat] Inner CIDRs: {args.inner_cidr if args.inner_cidr else 'None'}")
    print(f"[feat] Idle gap (s): {args.idle_gap_sec}")

    extractor = FeatureExtractor(idle_gap_sec=args.idle_gap_sec)

    for path in inputs:
        print(f"[feat] Processing: {path}")
        pkt_count = 0
        for ts, eth in _iter_pcap_packets(path):
            try:
                extractor.observe_packet(
                    ts,
                    eth,
                    vxlan_port=args.vxlan_port,
                    allow_mirrored_sport=args.allow_mirrored_sport,
                    allowed_inner_cidrs=args.inner_cidr,
                    allowed_outer_ips=set([args.vxlan_ip]) if args.vxlan_ip else None,
                )
                pkt_count += 1
                if pkt_count % 10000 == 0:
                    print(f"[feat]  .. {pkt_count} packets processed (flows so far: {len(extractor.flows)})")
            except Exception:
                # Be robust to malformed packets/frames; continue streaming
                continue
        print(f"[feat] Completed: {path} (packets={pkt_count}, flows={len(extractor.flows)})")

    print("[feat] Finalizing flows and computing statistics ...")
    rows = extractor.finalize()
    print(f"[feat] Finalized {len(rows)} flow feature rows")
    write_features_csv(rows, args.features_out)
    print(f"[feat] Features written to: {args.features_out}")


if __name__ == "__main__":
    main()


