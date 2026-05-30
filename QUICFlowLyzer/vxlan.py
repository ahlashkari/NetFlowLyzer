"""
Robust VXLAN decapsulation helpers compatible with dpkt and NTLFlowLyzer.

This module exposes a single primary API `try_decap_vxlan` that accepts a
parsed `dpkt.ethernet.Ethernet` frame and, when the outer encapsulation is a
valid VXLAN packet, returns the inner Ethernet frame along with metadata.

Design goals:
- Strict validation with fast guards (type, port, length)
- IPv4 and IPv6 support
- Optional policy filters (allowed outer IPs, allowed inner CIDRs)
- Nested VXLAN support with configurable maximum depth
- Fail-closed behavior: on any error or policy block, return the original frame
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple, Literal, List, Set
import ipaddress
import logging

import dpkt
from dpkt.utils import inet_to_str


# Module-level logger. No noisy prints; use debug/info sparingly.
logger = logging.getLogger(__name__)


# Constants
VXLAN_HEADER_LEN: int = 8
VXLAN_DEFAULT_PORT: int = 4789


@dataclass
class VxlanDecapResult:
    """Result of a VXLAN decapsulation attempt.

    - `eth`: Returned Ethernet frame (inner or original)
    - `was_vxlan`: True if VXLAN was detected at least once
    - `decapsulated`: True if the returned frame is an inner Ethernet (one or more layers stripped)
    - `vni`: Last parsed VNI if any successful layer was parsed
    - `outer_5tuple`: (src_ip, dst_ip, sport, dport, "udp") for the first decapsulated outer layer
    - `layers_stripped`: Number of VXLAN layers successfully removed
    """

    eth: dpkt.ethernet.Ethernet
    was_vxlan: bool
    decapsulated: bool
    vni: Optional[int]
    outer_5tuple: Optional[Tuple[str, str, int, int, Literal["udp"]]]
    layers_stripped: int


def _ip_and_udp_if_present(
    eth: dpkt.ethernet.Ethernet,
) -> Optional[Tuple[dpkt.ip.IP | dpkt.ip6.IP6, dpkt.udp.UDP]]:
    """Return (ip, udp) if Ethernet carries IP{v4,v6}/UDP; otherwise None.

    This function performs tight isinstance checks to avoid brittle `.data` chains.
    """
    try:
        if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return None
        ip = eth.data
        if not isinstance(ip.data, dpkt.udp.UDP):
            return None
        return ip, ip.data
    except Exception:
        return None


def _ports_match_vxlan(
    udp: dpkt.udp.UDP,
    vxlan_port: int,
    allow_mirrored_sport: bool,
) -> bool:
    """Return True if UDP ports match VXLAN policy.

    - Default: require dport == vxlan_port
    - If `allow_mirrored_sport` is True, also allow sport == vxlan_port
    """
    if udp.dport == vxlan_port:
        return True
    if allow_mirrored_sport and udp.sport == vxlan_port:
        return True
    return False


def _parse_vxlan_inner_and_vni(
    udp_payload: bytes,
    require_instance_flag: bool,
) -> Optional[Tuple[bytes, int]]:
    """Validate VXLAN header and return (inner_bytes, vni) if valid.

    - Header must be at least 8 bytes
    - When `require_instance_flag` is True, the I-flag (bit 3 of first byte) must be set
    - VNI is a 24-bit integer at bytes 4..6
    """
    if len(udp_payload) < VXLAN_HEADER_LEN:
        logger.debug("VXLAN header too short: %d < %d", len(udp_payload), VXLAN_HEADER_LEN)
        return None

    flags = udp_payload[0]
    i_flag_set = (flags & 0x08) != 0
    if require_instance_flag and not i_flag_set:
        logger.debug("VXLAN I-flag required but not set")
        return None

    vni = (udp_payload[4] << 16) | (udp_payload[5] << 8) | udp_payload[6]
    inner = udp_payload[VXLAN_HEADER_LEN:]
    if len(inner) < 14:  # minimum Ethernet header
        logger.debug("Inner Ethernet too short: %d < 14", len(inner))
        return None

    return inner, vni


def _outer_ip_allowed(
    ip: dpkt.ip.IP | dpkt.ip6.IP6,
    allowed_outer_ips: Optional[Set[str]],
) -> bool:
    if not allowed_outer_ips:
        return True
    try:
        src = inet_to_str(ip.src)
        dst = inet_to_str(ip.dst)
        return (src in allowed_outer_ips) or (dst in allowed_outer_ips)
    except Exception:
        return False


def _parse_networks(cidrs: Optional[List[str]]) -> List[ipaddress._BaseNetwork]:
    networks: List[ipaddress._BaseNetwork] = []
    if not cidrs:
        return networks
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            logger.debug("Ignoring invalid CIDR: %s", cidr)
    return networks


def _inner_ip_in_networks(inner_eth: dpkt.ethernet.Ethernet, networks: List[ipaddress._BaseNetwork]) -> bool:
    if not networks:
        return True
    try:
        inner_l3 = inner_eth.data
        if isinstance(inner_l3, dpkt.ip.IP):
            src = ipaddress.ip_address(inet_to_str(inner_l3.src))
            dst = ipaddress.ip_address(inet_to_str(inner_l3.dst))
        elif isinstance(inner_l3, dpkt.ip6.IP6):
            src = ipaddress.ip_address(inet_to_str(inner_l3.src))
            dst = ipaddress.ip_address(inet_to_str(inner_l3.dst))
        else:
            # If there is no inner IP, we cannot evaluate CIDR policy; fail closed.
            return False

        for net in networks:
            if src in net or dst in net:
                return True
        return False
    except Exception:
        return False


def try_decap_vxlan(
    eth: dpkt.ethernet.Ethernet,
    vxlan_port: int = VXLAN_DEFAULT_PORT,
    allow_mirrored_sport: bool = False,
    allowed_outer_ips: Optional[Set[str]] = None,
    allowed_inner_cidrs: Optional[List[str]] = None,
    require_instance_flag: bool = True,
    max_layers: int = 2,
) -> VxlanDecapResult:
    """Attempt to decapsulate VXLAN, possibly stripping multiple nested layers.

    Returns a `VxlanDecapResult` with the inner Ethernet (if decapsulated), the
    last parsed VNI, the first outer 5-tuple (src, dst, sport, dport, "udp"),
    and accounting for how many layers were removed.

    Behavior on policy or parse failure is fail-closed: return the original
    Ethernet frame with `decapsulated=False`. `was_vxlan` is True if a VXLAN
    header was identified at least once, even if a policy prevented decapsulation.
    """
    layers_stripped: int = 0
    was_vxlan_detected: bool = False
    last_vni: Optional[int] = None
    first_outer_5tuple: Optional[Tuple[str, str, int, int, Literal["udp"]]] = None

    current_eth = eth
    networks = _parse_networks(allowed_inner_cidrs)

    for _ in range(max_layers):
        parsed = _ip_and_udp_if_present(current_eth)
        if parsed is None:
            break
        ip, udp = parsed

        if not _ports_match_vxlan(udp, vxlan_port, allow_mirrored_sport):
            break

        # If ports indicate VXLAN, we consider it a detection
        was_vxlan_detected = True

        # Outer IP policy gate
        if not _outer_ip_allowed(ip, allowed_outer_ips):
            try:
                src = inet_to_str(ip.src)
                dst = inet_to_str(ip.dst)
                logger.info("VXLAN outer IP blocked by policy: %s -> %s", src, dst)
            except Exception:
                logger.info("VXLAN outer IP blocked by policy (unable to stringify IPs)")
            # Policy drop, do not decap
            break

        # Parse and validate VXLAN header
        result = _parse_vxlan_inner_and_vni(udp.data, require_instance_flag)
        if result is None:
            # Malformed VXLAN header or inner too short
            break

        inner_bytes, vni = result
        try:
            inner_eth = dpkt.ethernet.Ethernet(inner_bytes)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            logger.debug("dpkt failed to unpack inner Ethernet")
            break
        except Exception:
            break

        # Inner CIDR policy gate (if configured)
        if not _inner_ip_in_networks(inner_eth, networks):
            logger.info("VXLAN inner IP blocked by CIDR policy")
            # Policy drop, do not decap
            break

        # Successful decapsulation of one layer
        if first_outer_5tuple is None:
            try:
                src_ip = inet_to_str(ip.src)
                dst_ip = inet_to_str(ip.dst)
                first_outer_5tuple = (src_ip, dst_ip, int(udp.sport), int(udp.dport), "udp")
            except Exception:
                # Keep None if we cannot stringify for any reason
                first_outer_5tuple = None

        last_vni = vni
        layers_stripped += 1
        current_eth = inner_eth

        # Continue loop to handle nested VXLAN if present

    decapsulated = layers_stripped > 0

    return VxlanDecapResult(
        eth=current_eth if decapsulated else eth,
        was_vxlan=was_vxlan_detected,
        decapsulated=decapsulated,
        vni=last_vni,
        outer_5tuple=first_outer_5tuple,
        layers_stripped=layers_stripped,
    )


