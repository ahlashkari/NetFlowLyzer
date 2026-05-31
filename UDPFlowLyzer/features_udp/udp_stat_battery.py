"""Per-series statistics over packet, payload, header, IAT and length-delta values."""
from __future__ import annotations

import numpy as np

from .base import Feature


def _is_forward(packet, flow) -> bool:
    if (hasattr(packet, "src_ip") and hasattr(packet, "dst_ip")
            and hasattr(packet, "src_port") and hasattr(packet, "dst_port")):
        if (packet.src_ip == flow.src_ip and packet.dst_ip == flow.dst_ip
                and packet.src_port == flow.src_port
                and packet.dst_port == flow.dst_port):
            return True
        if (packet.src_ip == flow.dst_ip and packet.dst_ip == flow.src_ip
                and packet.src_port == flow.dst_port
                and packet.dst_port == flow.src_port):
            return False
    if hasattr(packet, "is_forward"):
        return packet.is_forward()
    return True


def _select(packets, flow, direction):
    if direction == "overall":
        return packets
    if direction == "fwd":
        return [p for p in packets if _is_forward(p, flow)]
    return [p for p in packets if not _is_forward(p, flow)]


def _pkt_len(p):
    return float(p.get_length())


def _payload_len(p):
    return float(p.get_payloadbytes())


def _header_len(p):
    return float(p.get_header_size())


def _timestamp(p):
    return float(p.get_timestamp())


def _series_array(flow, direction, value_fn, kind) -> np.ndarray:
    packets = _select(flow.get_packets(), flow, direction)
    if kind == "value":
        return np.array([value_fn(p) for p in packets], dtype=float)
    if kind == "iat":
        ts = np.array([value_fn(p) for p in packets], dtype=float)
        return np.diff(ts) if ts.size >= 2 else np.array([], dtype=float)
    vals = np.array([value_fn(p) for p in packets], dtype=float)
    return np.abs(np.diff(vals)) if vals.size >= 2 else np.array([], dtype=float)


def _mean(a):
    return float(a.mean()) if a.size else 0.0


def _std(a):
    return float(a.std()) if a.size else 0.0


def _var(a):
    return float(a.var()) if a.size else 0.0


def _cov(a):
    if a.size == 0:
        return 0.0
    m = a.mean()
    return float(a.std() / m) if m != 0 else 0.0


def _max(a):
    return float(a.max()) if a.size else 0.0


def _min(a):
    return float(a.min()) if a.size else 0.0


def _sum(a):
    return float(a.sum()) if a.size else 0.0


def _median(a):
    return float(np.median(a)) if a.size else 0.0


def _mode(a):
    if a.size == 0:
        return 0.0
    vals, counts = np.unique(a, return_counts=True)
    return float(vals[counts.argmax()])


def _skew(a):
    if a.size < 3:
        return 0.0
    m, s = a.mean(), a.std()
    if s == 0:
        return 0.0
    return float(np.mean(((a - m) / s) ** 3))


def _kurt(a):
    if a.size < 4:
        return 0.0
    m, s = a.mean(), a.std()
    if s == 0:
        return 0.0
    return float(np.mean(((a - m) / s) ** 4))


def _percentile(q):
    def _fn(a):
        return float(np.percentile(a, q)) if a.size else 0.0
    return _fn


STATS = {
    "mean": _mean,
    "std": _std,
    "var": _var,
    "cov": _cov,
    "max": _max,
    "min": _min,
    "sum": _sum,
    "median": _median,
    "mode": _mode,
    "skew": _skew,
    "kurt": _kurt,
    "p10": _percentile(10),
    "p25": _percentile(25),
    "p50": _percentile(50),
    "p75": _percentile(75),
    "p90": _percentile(90),
    "p95": _percentile(95),
}

# series token -> (value getter, kind, category)
SERIES = {
    "pkt_size": (_pkt_len, "value", "size"),
    "payload_size": (_payload_len, "value", "payload"),
    "header_size": (_header_len, "value", "header_size_stats"),
    "iat": (_timestamp, "iat", "iat"),
    "delta_pkt_size": (_pkt_len, "delta", "delta_pkt"),
    "delta_payload_size": (_payload_len, "delta", "delta_payload"),
    "delta_header_size": (_header_len, "delta", "delta_header"),
}

DIRECTIONS = ("overall", "fwd", "bwd")


def _make_extract(value_fn, kind, direction, stat_fn):
    def extract(self, flow):
        return stat_fn(_series_array(flow, direction, value_fn, kind))
    return extract


def _generate():
    created = {}
    for series_tok, (value_fn, kind, category) in SERIES.items():
        for direction in DIRECTIONS:
            for stat_tok, stat_fn in STATS.items():
                fname = f"{series_tok}_{direction}_{stat_tok}"
                cls_name = "".join(p.capitalize() for p in fname.split("_")) + "Feature"
                created[cls_name] = type(
                    cls_name,
                    (Feature,),
                    {
                        # Feature is an ABC; set module so it is not reported as abc
                        "__module__": __name__,
                        "__qualname__": cls_name,
                        "name": fname,
                        "category": category,
                        "extract": _make_extract(value_fn, kind, direction, stat_fn),
                    },
                )
    return created


globals().update(_generate())
