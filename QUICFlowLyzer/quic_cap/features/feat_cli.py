from __future__ import annotations

import argparse
import glob
import logging
from typing import Iterator, List, Optional

import dpkt

from ..quic_parser import iter_quic_packets  # import to ensure availability
from .. import capture as _unused_capture  # ensure dpkt reading consistency
from .. import batch as _unused_batch
from vxlan import try_decap_vxlan  # used by extractor

from .extractor import FeatureExtractor, write_features_csv


def _gather_inputs(pcap: Optional[str], pcaps: Optional[List[str]], pcap_glob: Optional[str]) -> List[str]:
    files: List[str] = []
    if pcaps:
        files.extend(pcaps)
    if pcap_glob:
        files.extend(sorted(glob.glob(pcap_glob)))
    if pcap and not files:
        files.append(pcap)
    seen = set()
    out = []
    for f in files:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def _iter_pcap_packets(path: str) -> Iterator[tuple[float, dpkt.ethernet.Ethernet]]:
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


def run_extraction(
    *,
    pcap_path: str | None = None,
    pcaps: list[str] | None = None,
    pcap_glob: str | None = None,
    features_out: str,
    vxlan_ip: str | None = None,
    vxlan_port: int = 4789,
    allow_mirrored_sport: bool = False,
    inner_cidr: list[str] | None = None,
    idle_gap_sec: float = 1.0,
    verbose: bool = False,
) -> int:
    """Extract QUIC flow features. Returns the number of flow rows written."""
    inputs = _gather_inputs(pcap_path, pcaps, pcap_glob)
    if not inputs:
        raise ValueError("At least one input PCAP path is required")

    print("[Q] Starting QUIC feature extraction", flush=True)
    print(f"[Q] Inputs: {len(inputs)} file(s)", flush=True)
    for path in inputs:
        print(f"[Q]  - {path}", flush=True)
    print(
        f"[Q] VXLAN: ip={vxlan_ip or ''} port={vxlan_port} "
        f"allow_mirrored_sport={allow_mirrored_sport}",
        flush=True,
    )
    print(f"[Q] Inner CIDRs: {inner_cidr if inner_cidr else 'None'}", flush=True)
    print(f"[Q] Idle gap (s): {idle_gap_sec}", flush=True)
    if verbose:
        print("[Q] Verbose per-packet QUIC logging enabled", flush=True)

    extractor = FeatureExtractor(idle_gap_sec=idle_gap_sec, verbose=verbose)
    allowed_outer_ips = {vxlan_ip} if vxlan_ip else None

    for path in inputs:
        print(f"[Q] Processing: {path}", flush=True)
        pkt_count = 0
        for ts, eth in _iter_pcap_packets(path):
            try:
                extractor.observe_packet(
                    ts,
                    eth,
                    vxlan_port=vxlan_port,
                    allow_mirrored_sport=allow_mirrored_sport,
                    allowed_inner_cidrs=inner_cidr,
                    allowed_outer_ips=allowed_outer_ips,
                )
                pkt_count += 1
                if pkt_count % 10000 == 0:
                    print(
                        f"[Q]  .. {pkt_count} packets processed "
                        f"(QUIC flows so far: {len(extractor.flows)})",
                        flush=True,
                    )
            except Exception:
                continue
        print(
            f"[Q] Completed: {path} (packets={pkt_count}, flows={len(extractor.flows)})",
            flush=True,
        )

    print("[Q] Finalizing flows and computing statistics ...", flush=True)
    rows = extractor.finalize()
    print(f"[Q] Finalized {len(rows)} QUIC flow feature rows", flush=True)
    write_features_csv(rows, features_out)
    print(f"[Q] Features written to: {features_out}", flush=True)
    return len(rows)


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
    p.add_argument("--verbose", action="store_true", help="Print per-packet QUIC parsing details")
    p.add_argument("--log-level", default="INFO", help="Logging level")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    run_extraction(
        pcap_path=args.pcap,
        pcaps=args.pcaps,
        pcap_glob=args.pcap_glob,
        features_out=args.features_out,
        vxlan_ip=args.vxlan_ip,
        vxlan_port=args.vxlan_port,
        allow_mirrored_sport=args.allow_mirrored_sport,
        inner_cidr=args.inner_cidr,
        idle_gap_sec=args.idle_gap_sec,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
