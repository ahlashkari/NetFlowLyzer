from __future__ import annotations

from typing import Optional, Tuple

import dpkt
from dpkt.utils import inet_to_str


def ethernet_to_ip_udp(
    eth: dpkt.ethernet.Ethernet,
) -> Optional[Tuple[dpkt.ip.IP | dpkt.ip6.IP6, dpkt.udp.UDP]]:
    if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return None
    ip = eth.data
    if not isinstance(ip.data, dpkt.udp.UDP):
        return None
    return ip, ip.data


def ip_pair_str(ip: dpkt.ip.IP | dpkt.ip6.IP6) -> Tuple[str, str]:
    return inet_to_str(ip.src), inet_to_str(ip.dst)


def safe_slice(buf: bytes, start: int, length: int) -> Optional[bytes]:
    end = start + length
    if start < 0 or length < 0 or end > len(buf):
        return None
    return buf[start:end]


