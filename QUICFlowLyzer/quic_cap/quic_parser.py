from __future__ import annotations

from typing import List, Dict, Optional


def _consume(buf: bytes, n: int) -> Optional[tuple[bytes, bytes]]:
    if n < 0 or n > len(buf):
        return None
    return buf[:n], buf[n:]


def iter_quic_packets(
    udp_payload: bytes,
    known_short_dcid_len: int | None = None,
) -> list[dict]:
    packets: List[Dict] = []
    remaining = udp_payload

    while len(remaining) > 0:
        if len(remaining) < 1:
            break
        b0 = remaining[0]
        # Fixed bit must be set
        if (b0 & 0x40) != 0x40:
            break

        is_long = (b0 & 0x80) != 0
        if is_long:
            # Long header format (RFC 9000)
            if len(remaining) < 1 + 4 + 1 + 1:
                break
            # type nibble
            type_nibble = (b0 >> 4) & 0x03
            qtype_map = {0: "initial", 1: "0rtt", 2: "handshake", 3: "retry"}

            version = int.from_bytes(remaining[1:5], "big")
            idx = 5

            if idx >= len(remaining):
                break
            dcid_len = remaining[idx]
            idx += 1
            if idx + dcid_len > len(remaining):
                break
            dcid = remaining[idx: idx + dcid_len]
            idx += dcid_len

            if idx >= len(remaining):
                break
            scid_len = remaining[idx]
            idx += 1
            if idx + scid_len > len(remaining):
                break
            scid = remaining[idx: idx + scid_len]
            idx += scid_len

            token_len = 0
            payload_len = 0
            raw_len = 0

            if qtype_map.get(type_nibble) == "retry":
                # Retry carries token and integrity tag; conservatively consume the entire remainder
                raw_len = len(remaining)
            else:
                # For Initial and Handshake/0-RTT: token length (varint) for Initial, payload length (varint)
                # Implement minimal varint reader per RFC 9000
                def read_varint(buf: bytes, start: int) -> Optional[tuple[int, int]]:
                    if start >= len(buf):
                        return None
                    first = buf[start]
                    prefix = (first >> 6) & 0x03
                    length = 1 << prefix  # 1,2,4,8
                    if start + length > len(buf):
                        return None
                    val = 0
                    for i in range(length):
                        if i == 0:
                            val = buf[start] & 0x3F
                        else:
                            val = (val << 8) | buf[start + i]
                    return val, start + length

                if qtype_map.get(type_nibble) == "initial":
                    token_res = read_varint(remaining, idx)
                    if token_res is None:
                        break
                    token_len, idx = token_res
                    # Skip token
                    if idx + token_len > len(remaining):
                        break
                    idx += token_len
                # payload length varint
                pay_res = read_varint(remaining, idx)
                if pay_res is None:
                    break
                payload_len, idx = pay_res
                raw_len = idx + payload_len
                if raw_len > len(remaining):
                    break

                # For Initial, require minimum UDP datagram length 1200
                if qtype_map.get(type_nibble) == "initial" and len(udp_payload) < 1200:
                    break

            qtype = qtype_map.get(type_nibble, "unknown")
            pkt = {
                "is_long": True,
                "version": version,
                "qtype": "vn" if version == 0 else qtype,
                "dcid": dcid,
                "scid": scid,
                "dcid_len": dcid_len,
                "scid_len": scid_len,
                "token_len": token_len,
                "payload_len": payload_len,
                "raw_len": raw_len if raw_len else len(remaining),
            }
            packets.append(pkt)
            # Advance by raw_len or all remaining if retry/unknown sizes
            step = pkt["raw_len"]
            if step <= 0 or step > len(remaining):
                break
            remaining = remaining[step:]
        else:
            # Short header: only emit when we have a known short DCID length
            if known_short_dcid_len is None:
                # Do not emit short header packets without known DCID length
                break
            # Short header DCID is first bytes after header; minimal 1 byte header
            if len(remaining) < 1 + known_short_dcid_len:
                break
            dcid = remaining[1:1 + known_short_dcid_len]
            # We cannot determine payload length without keys; consume entire remainder as raw_len
            pkt = {
                "is_long": False,
                "version": None,
                "qtype": "short",
                "dcid": dcid,
                "scid": None,
                "dcid_len": known_short_dcid_len,
                "scid_len": None,
                "token_len": 0,
                "payload_len": max(0, len(remaining) - (1 + known_short_dcid_len)),
                "raw_len": len(remaining),
            }
            packets.append(pkt)
            remaining = b""

    return packets


