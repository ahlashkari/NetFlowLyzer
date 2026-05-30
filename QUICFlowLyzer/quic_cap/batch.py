from __future__ import annotations

import glob
import os
import re
import logging
from typing import Iterable, List, Optional, Tuple

import dpkt

from vxlan import try_decap_vxlan
from .utils import ethernet_to_ip_udp, ip_pair_str
from .quic_parser import iter_quic_packets
from .writers import open_flows_csv
from .capture import ShortCidLenCache
from .quic_tracker import QuicTracker


logger = logging.getLogger(__name__)


_NUM_RE = re.compile(r"(\d+)")


def _natural_key(s: str) -> Tuple:
    # Split on runs of digits to sort 1,2,10 naturally
    parts = _NUM_RE.split(os.path.basename(s))
    return tuple(int(p) if p.isdigit() else p for p in parts)


def _gather_inputs(pcaps: Optional[List[str]], pcap_glob: Optional[str]) -> List[str]:
    files: List[str] = []
    if pcap_glob:
        files.extend(glob.glob(pcap_glob))
    if pcaps:
        files.extend(pcaps)
    # unique, existing, sorted
    uniq = sorted({os.path.abspath(p) for p in files if os.path.isfile(p)}, key=_natural_key)
    return uniq


def _open_reader(fp) -> object:
    # Detect pcapng magic: 0x0A0D0D0A
    head = fp.read(4)
    fp.seek(0)
    if head == b"\x0a\x0d\x0d\x0a":
        return dpkt.pcapng.Reader(fp)
    return dpkt.pcap.Reader(fp)


def run_capture_batch(
    pcaps: Optional[List[str]],
    pcap_glob: Optional[str],
    flows_csv: str,
    vxlan_ip: Optional[str] = None,
    vxlan_port: int = 4789,
    allow_mirrored_sport: bool = False,
    allowed_inner_cidrs: Optional[List[str]] = None,
    idle_timeout_sec: int = 15,
) -> None:
    inputs = _gather_inputs(pcaps, pcap_glob)
    if not inputs:
        logger.warning("No input pcap files resolved.")
        # still create empty CSV with header for consistency
        f, w = open_flows_csv(flows_csv)
        try:
            f.close()
        except Exception:
            pass
        return

    cache = ShortCidLenCache(idle_timeout_sec=idle_timeout_sec)
    tracker = QuicTracker(idle_timeout_sec=idle_timeout_sec)

    f, writer = open_flows_csv(flows_csv)
    try:
        for i, path in enumerate(inputs, 1):
            try:
                logger.info("Processing [%d/%d]: %s", i, len(inputs), path)
                with open(path, "rb") as fp:
                    reader = _open_reader(fp)
                    for ts, buf in reader:
                        # Ethernet parse
                        try:
                            eth = dpkt.ethernet.Ethernet(buf)
                        except Exception:
                            continue

                        # VXLAN decap first
                        vx = try_decap_vxlan(
                            eth,
                            vxlan_port=vxlan_port,
                            allow_mirrored_sport=allow_mirrored_sport,
                            allowed_outer_ips={vxlan_ip} if vxlan_ip else None,
                            allowed_inner_cidrs=allowed_inner_cidrs,
                        )
                        decapped_eth = vx.eth

                        ip_udp = ethernet_to_ip_udp(decapped_eth)
                        if ip_udp is None:
                            continue
                        ip, udp = ip_udp

                        udp_payload = bytes(udp.data)
                        if not udp_payload:
                            continue

                        src, dst = ip_pair_str(ip)
                        sport = int(getattr(udp, "sport", 0))
                        dport = int(getattr(udp, "dport", 0))

                        # Learn short DCID length for receiver (dst,dport)
                        known_len_key = (dst, dport, src, sport)
                        known_short_len = cache.get(known_len_key)

                        quic_packets = iter_quic_packets(udp_payload, known_short_dcid_len=known_short_len)

                        # Learn from long headers we just parsed
                        for pkt in quic_packets:
                            if pkt.get("is_long") and isinstance(pkt.get("dcid_len"), int):
                                cache.learn(known_len_key, int(pkt["dcid_len"]))

                        # Feed tracker (skip Version Negotiation)
                        for pkt in quic_packets:
                            if pkt.get("qtype") == "vn":
                                continue
                            tracker.observe(
                                ts=float(ts),
                                src_ip=src,
                                src_port=sport,
                                dst_ip=dst,
                                dst_port=dport,
                                udp_len=len(udp_payload),
                                pkt=pkt,
                            )
                logger.info("Completed [%d/%d]: %s", i, len(inputs), path)
            except Exception as e:
                logger.exception("Error processing %s: %s", path, e)

        # Finished all files: dump all flows once
        for row in tracker.iter_rows():
            writer.writerow(row)

    finally:
        try:
            f.close()
        except Exception:
            pass


