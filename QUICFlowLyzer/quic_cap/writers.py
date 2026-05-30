from __future__ import annotations

import csv
import os
from typing import Optional, Tuple


CSV_COLUMNS = [
    "ts",
    "outer_vxlan",
    "outer_vni",
    "outer_5tuple",
    "l3_saddr",
    "l3_daddr",
    "l4_sport",
    "l4_dport",
    "udp_len",
    "quic_is_long",
    "quic_type",
    "quic_version",
    "dcid_hex",
    "dcid_len",
    "scid_hex",
    "scid_len",
    "token_len",
    "payload_len",
    "raw_len",
    "short_dcid_len_source",
]


def open_csv(path: str):
    f = open(path, "w", newline="", encoding="utf-8")
    w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
    w.writeheader()
    return f, w


def fmt_outer_tuple(outer_5: Optional[Tuple[str, str, int, int, str]]) -> str:
    if not outer_5:
        return ""
    src, dst, sport, dport, proto = outer_5
    return f"{src}:{sport}>{dst}:{dport}/{proto}"


def bhex(b: Optional[bytes]) -> str:
    return b.hex() if isinstance(b, (bytes, bytearray)) else ""



# --- flows CSV schema ---
FLOW_COLUMNS = [
    "conn_id",
    "client_ip","client_port","server_ip","server_port","version",
    "start_ts","end_ts","duration_s",
    "pkts_total","bytes_total",
    "migration_count","paths_count",
    "dcid_rotations_client","dcid_rotations_server",
    "dcids_client_hex","dcids_server_hex",
]


def open_flows_csv(path: str):
    directory = os.path.dirname(path)
    if directory:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception:
            pass
    f = open(path, "w", newline="", encoding="utf-8")
    w = csv.DictWriter(f, fieldnames=FLOW_COLUMNS)
    w.writeheader()
    return f, w