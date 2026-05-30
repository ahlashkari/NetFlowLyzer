from __future__ import annotations

import logging
import time
from typing import Dict, Tuple, Optional

import dpkt

from vxlan import try_decap_vxlan
from .utils import ethernet_to_ip_udp, ip_pair_str
from .quic_parser import iter_quic_packets
from .writers import open_flows_csv
from .quic_tracker import QuicTracker


logger = logging.getLogger(__name__)


class ShortCidLenCache:
    """Tiny cache mapping 4-tuple to learned short DCID length.

    Not flow logic; stores minimal state with idle eviction.
    """

    def __init__(self, idle_timeout_sec: int = 15) -> None:
        self._store: Dict[Tuple[str, int, str, int], Tuple[int, float]] = {}
        self._idle = idle_timeout_sec

    def get(self, key: Tuple[str, int, str, int]) -> Optional[int]:
        val = self._store.get(key)
        if not val:
            return None
        length, ts = val
        if time.time() - ts > self._idle:
            self._store.pop(key, None)
            return None
        return length

    def learn(self, key: Tuple[str, int, str, int], dcid_len: int) -> None:
        if dcid_len <= 0:
            return
        self._store[key] = (dcid_len, time.time())


def run_capture(
    pcap_path: str,
    flows_csv: str,
    vxlan_ip: Optional[str] = None,
    vxlan_port: int = 4789,
    allow_mirrored_sport: bool = False,
    allowed_inner_cidrs: Optional[list[str]] = None,
    idle_timeout_sec: int = 15,
) -> None:
    cache = ShortCidLenCache(idle_timeout_sec=idle_timeout_sec)
    tracker = QuicTracker(idle_timeout_sec=idle_timeout_sec)

    f, writer = open_flows_csv(flows_csv)
    try:
        with open(pcap_path, "rb") as fp:
            pcap = dpkt.pcap.Reader(fp)
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except Exception:
                    continue

                # VXLAN first
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

                # Learn DCID length from long headers (receiver DCID length)
                known_len_key = (dst, dport, src, sport)  # who will receive shorts next
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

        # Write all finalized connections
        for row in tracker.iter_rows():
            writer.writerow(row)

    finally:
        try:
            f.close()
        except Exception:
            pass


