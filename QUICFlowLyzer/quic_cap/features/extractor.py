from __future__ import annotations

import csv
import math
import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple, Set

import dpkt

from ..quic_parser import iter_quic_packets
from ..utils import ethernet_to_ip_udp, ip_pair_str
from ..quic_tracker import make_conn_id
from vxlan import try_decap_vxlan

from .stats import OnlineStats, SeriesStats, percentile, safe_div
from . import schema as feature_schema


@dataclass
class DirSeries:
    lengths: List[float] = field(default_factory=list)
    times: List[float] = field(default_factory=list)
    deltas_time: List[float] = field(default_factory=list)
    deltas_len: List[float] = field(default_factory=list)
    header_proxy: List[float] = field(default_factory=list)


@dataclass
class FlowAgg:
    # Keys
    flow_id: str = ""
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = "QUIC"
    timestamp: float = float("nan")
    duration: float = float("nan")
    version: Optional[int] = None
    initial_dcid: Optional[bytes] = None
    initial_scid: Optional[bytes] = None

    # Counters
    pkts_total: int = 0
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    bytes_total: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    paths: set = field(default_factory=set)
    migration_count: int = 0

    # Type distribution
    n_initial: int = 0
    n_handshake: int = 0
    n_0rtt: int = 0
    n_retry: int = 0
    n_short: int = 0
    n_long: int = 0
    used_0rtt: int = 0
    had_retry: int = 0
    had_token: int = 0

    # DCIDs by receiver
    dcids_client: set = field(default_factory=set)
    dcids_server: set = field(default_factory=set)
    rotations_client: int = 0
    rotations_server: int = 0

    # Time markers
    first_initial_ts: float = float("nan")
    first_short_ts: float = float("nan")

    # Inferred short DCID lengths
    inferred_short_dcid_len_server: int = -1
    inferred_short_dcid_len_client: int = -1

    # Series
    overall: DirSeries = field(default_factory=DirSeries)
    fwd: DirSeries = field(default_factory=DirSeries)
    bwd: DirSeries = field(default_factory=DirSeries)

    # Long payload and tokens
    long_payloads: List[float] = field(default_factory=list)
    token_lengths: List[float] = field(default_factory=list)

    # Active/Idle episode measurement
    active_episodes: List[float] = field(default_factory=list)
    idle_episodes: List[float] = field(default_factory=list)

    start_ts: float = float("nan")
    end_ts: float = float("nan")


def _update_deltas(series: DirSeries) -> None:
    ts = series.times
    ln = series.lengths
    if len(ts) >= 2:
        for i in range(1, len(ts)):
            dt = ts[i] - ts[i - 1]
            if dt >= 0:
                series.deltas_time.append(dt)
    if len(ln) >= 2:
        for i in range(1, len(ln)):
            series.deltas_len.append(ln[i] - ln[i - 1])


def _series_stats(vals: List[float], prefix: str, include_percentiles: bool = True) -> Dict[str, float]:
    return SeriesStats.from_list(vals, prefix, include_percentiles=include_percentiles)


def _episodes_from_timestamps(times_sorted: List[float], idle_gap: float) -> Tuple[List[float], List[float]]:
    if not times_sorted:
        return [], []
    active: List[float] = []
    idle: List[float] = []
    start = times_sorted[0]
    last = times_sorted[0]
    for t in times_sorted[1:]:
        gap = t - last
        if gap > idle_gap:
            active.append(max(0.0, last - start))
            idle.append(gap)
            start = t
        last = t
    active.append(max(0.0, last - start))
    return active, idle


def _dict_nan_fill(keys: Iterable[str]) -> Dict[str, float]:
    return {k: float("nan") for k in keys}


class FeatureExtractor:
    def __init__(self, idle_gap_sec: float = 1.0, verbose: bool = False) -> None:
        self.idle_gap_sec = float(idle_gap_sec)
        self.verbose = verbose
        self.flows: Dict[str, FlowAgg] = {}

    def _log(self, message: str) -> None:
        if self.verbose:
            print(message, flush=True)

    def _get_or_create_flow(self, server_ip: str, server_port: int, pkt: dict, ts: float,
                             src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> FlowAgg:
        version = pkt.get("version")
        dcid = pkt.get("dcid")
        scid = pkt.get("scid")
        conn_id = make_conn_id(server_ip, int(server_port), dcid, scid, version)
        f = self.flows.get(conn_id)
        if f is None:
            f = FlowAgg()
            f.flow_id = conn_id
            f.src_ip = src_ip
            f.src_port = int(src_port)
            f.dst_ip = dst_ip
            f.dst_port = int(dst_port)
            f.version = version if isinstance(version, int) else None
            f.timestamp = float(ts)
            f.start_ts = float(ts)
            f.initial_dcid = dcid if isinstance(dcid, (bytes, bytearray)) else None
            f.initial_scid = scid if isinstance(scid, (bytes, bytearray)) else None
            self.flows[conn_id] = f
            self._log(
                f"[feat] New flow: {conn_id} {src_ip}:{src_port}>{dst_ip}:{dst_port} "
                f"v={f.version if f.version is not None else ''}"
            )
        return f

    def observe_packet(self, ts: float, eth: dpkt.ethernet.Ethernet,
                        vxlan_port: int, allow_mirrored_sport: bool,
                        allowed_inner_cidrs: Optional[List[str]],
                        allowed_outer_ips: Optional[Set[str]] = None) -> None:
        # Optional VXLAN decap
        decap = try_decap_vxlan(
            eth,
            vxlan_port=vxlan_port,
            allow_mirrored_sport=allow_mirrored_sport,
            allowed_inner_cidrs=allowed_inner_cidrs,
            allowed_outer_ips=allowed_outer_ips,
        )
        inner_eth = decap.eth if decap.decapsulated else eth
        if decap.was_vxlan:
            if decap.decapsulated:
                self._log(f"[feat] VXLAN decapsulated (layers={decap.layers_stripped}, vni={decap.vni})")
            else:
                self._log("[feat] VXLAN detected but not decapsulated (policy or parse)")

        parsed = ethernet_to_ip_udp(inner_eth)
        if parsed is None:
            return
        ip, udp = parsed

        udp_len = int(len(udp.data))
        src_ip, dst_ip = ip_pair_str(ip)
        src_port = int(udp.sport)
        dst_port = int(udp.dport)

        # Parse QUIC
        # For short headers, infer DCID len when first seen per receiver
        # Use currently known inference if any
        known_short_dcid_len: Optional[int] = None
        # We will attempt parsing twice if needed: first with None to capture long headers,
        # then with inferred len if we have per-receiver knowledge
        packets = iter_quic_packets(udp.data, known_short_dcid_len=known_short_dcid_len)
        if not packets:
            return

        # Determine server_ip once we see an Initial in this UDP datagram, else use dst as candidate
        candidate_server_ip = dst_ip

        for pkt in packets:
            is_long = bool(pkt.get("is_long"))
            qtype = str(pkt.get("qtype"))
            version = pkt.get("version")
            dcid: Optional[bytes] = pkt.get("dcid")
            scid: Optional[bytes] = pkt.get("scid")
            if is_long:
                self._log(
                    f"[feat] QUIC long {qtype} v={version} dcid_len={pkt.get('dcid_len')} "
                    f"scid_len={pkt.get('scid_len')} token_len={pkt.get('token_len')} "
                    f"payload_len={pkt.get('payload_len')} raw_len={pkt.get('raw_len')}"
                )
            else:
                self._log(f"[feat] QUIC short dcid_len={pkt.get('dcid_len')} raw_len={pkt.get('raw_len')}")

            # Identify server ip/port from Initial (uplink)
            if is_long and qtype == "initial" and isinstance(version, int) and version != 0:
                candidate_server_ip = dst_ip
                self._log(f"[feat] Initial detected: server={candidate_server_ip}:{dst_port}")

            # Direction: Fwd if to server, else Bwd
            direction_fwd = (dst_ip == candidate_server_ip)

            flow = self._get_or_create_flow(candidate_server_ip, dst_port, pkt, ts, src_ip, src_port, dst_ip, dst_port)

            flow.end_ts = float(ts)
            flow.pkts_total += 1
            flow.bytes_total += max(0, udp_len)
            if direction_fwd:
                flow.fwd_pkts += 1
                flow.fwd_bytes += max(0, udp_len)
            else:
                flow.bwd_pkts += 1
                flow.bwd_bytes += max(0, udp_len)

            # Path/migration
            path = (src_ip, src_port, dst_ip, dst_port)
            if path not in flow.paths:
                if len(flow.paths) > 0:
                    flow.migration_count += 1
                flow.paths.add(path)

            # Record series
            flow.overall.lengths.append(float(udp_len))
            flow.overall.times.append(float(ts))
            (flow.fwd if direction_fwd else flow.bwd).lengths.append(float(udp_len))
            (flow.fwd if direction_fwd else flow.bwd).times.append(float(ts))

            # Type distribution and long header specifics
            if is_long:
                flow.n_long += 1
                if qtype == "initial":
                    flow.n_initial += 1
                    if math.isnan(flow.first_initial_ts):
                        flow.first_initial_ts = float(ts)
                        self._log(f"[feat] FirstInitialTs set: {flow.first_initial_ts}")
                    flow.version = version if isinstance(version, int) else flow.version
                    flow.initial_dcid = dcid if isinstance(dcid, (bytes, bytearray)) else flow.initial_dcid
                    flow.initial_scid = scid if isinstance(scid, (bytes, bytearray)) else flow.initial_scid
                elif qtype == "handshake":
                    flow.n_handshake += 1
                elif qtype == "0rtt":
                    flow.n_0rtt += 1
                    flow.used_0rtt = 1
                elif qtype == "retry":
                    flow.n_retry += 1
                    flow.had_retry = 1

                token_len = int(pkt.get("token_len") or 0)
                if token_len > 0:
                    flow.had_token = 1
                    flow.token_lengths.append(float(token_len))

                payload_len = int(pkt.get("payload_len") or 0)
                raw_len = int(pkt.get("raw_len") or udp_len)
                header_proxy = max(0, raw_len - payload_len)
                flow.overall.header_proxy.append(float(header_proxy))
                (flow.fwd if direction_fwd else flow.bwd).header_proxy.append(float(header_proxy))
                if payload_len > 0:
                    flow.long_payloads.append(float(payload_len))
            else:
                flow.n_short += 1
                if math.isnan(flow.first_short_ts):
                    flow.first_short_ts = float(ts)
                    self._log(f"[feat] FirstShortTs set: {flow.first_short_ts}")
                # Infer short DCID length from first short header seen per receiver
                if dcid is not None and isinstance(dcid, (bytes, bytearray)):
                    if direction_fwd:
                        if flow.inferred_short_dcid_len_server < 0:
                            flow.inferred_short_dcid_len_server = len(dcid)
                            self._log(f"[feat] Inferred short DCID len (server): {flow.inferred_short_dcid_len_server}")
                    else:
                        if flow.inferred_short_dcid_len_client < 0:
                            flow.inferred_short_dcid_len_client = len(dcid)
                            self._log(f"[feat] Inferred short DCID len (client): {flow.inferred_short_dcid_len_client}")

            # DCID rotation/accounting per receiver side
            if dcid is not None:
                if direction_fwd:
                    # receiver is server
                    if len(flow.dcids_server) > 0 and dcid not in flow.dcids_server:
                        flow.rotations_server += 1
                        self._log("[feat] DCID rotation (server) +1")
                    flow.dcids_server.add(dcid)
                else:
                    if len(flow.dcids_client) > 0 and dcid not in flow.dcids_client:
                        flow.rotations_client += 1
                        self._log("[feat] DCID rotation (client) +1")
                    flow.dcids_client.add(dcid)

    def finalize(self) -> List[Dict[str, object]]:
        rows: List[Dict[str, object]] = []
        columns = feature_schema.get_columns()
        for f in self.flows.values():
            f.duration = max(0.0, float(f.end_ts - f.start_ts)) if not math.isnan(f.end_ts) and not math.isnan(f.start_ts) else float("nan")
            # Update deltas now that all times are collected
            for s in (f.overall, f.fwd, f.bwd):
                _update_deltas(s)

            # Active/Idle episodes from overall times (sorted)
            t_sorted = sorted(f.overall.times)
            act, idle = _episodes_from_timestamps(t_sorted, self.idle_gap_sec)
            f.active_episodes = act
            f.idle_episodes = idle

            # Build row dict
            row: Dict[str, object] = {}

            # 1) Keys
            row.update({
                "flow_id": f.flow_id,
                "src_ip": f.src_ip,
                "src_port": f.src_port,
                "dst_ip": f.dst_ip,
                "dst_port": f.dst_port,
                "protocol": f.protocol,
                "timestamp": f.start_ts,
                "Duration": f.duration,
                "version": f.version if f.version is not None else "",
                "initial_dcid_hex": (f.initial_dcid or b"").hex(),
                "initial_dcid_len": len(f.initial_dcid or b""),
                "initial_scid_hex": (f.initial_scid or b"").hex(),
                "initial_scid_len": len(f.initial_scid or b""),
            })

            # 2) Counters & rates
            row.update({
                "PacketsCount": f.pkts_total,
                "FwdPacketsCount": f.fwd_pkts,
                "BwdPacketsCount": f.bwd_pkts,
                "TotalPayloadBytes": f.bytes_total,
                "FwdTotalPayloadBytes": f.fwd_bytes,
                "BwdTotalPayloadBytes": f.bwd_bytes,
                "BytesRate": safe_div(float(f.bytes_total), f.duration),
                "FwdBytesRate": safe_div(float(f.fwd_bytes), f.duration),
                "BwdBytesRate": safe_div(float(f.bwd_bytes), f.duration),
                "PacketsRate": safe_div(float(f.pkts_total), f.duration),
                "FwdPacketsRate": safe_div(float(f.fwd_pkts), f.duration),
                "BwdPacketsRate": safe_div(float(f.bwd_pkts), f.duration),
                "DownUpRate": safe_div(float(f.bwd_bytes), float(f.fwd_bytes)),
                "DirAsymBytes": safe_div(abs(float(f.fwd_bytes - f.bwd_bytes)), float(max(1, f.bytes_total))),
                "PathsCount": len(f.paths),
                "MigrationCount": f.migration_count,
                "ServerPortIs443": 1 if int(f.dst_port) == 443 else 0,
            })

            # 3) Packet type distribution & handshake flags
            total_type_bytes = float(f.bytes_total) if f.bytes_total > 0 else float("nan")
            # We do not track bytes per type; we can approximate shares via counts over total pkts
            row.update({
                "n_initial": f.n_initial,
                "n_handshake": f.n_handshake,
                "n_0rtt": f.n_0rtt,
                "n_retry": f.n_retry,
                "n_short": f.n_short,
                "n_long": f.n_long,
                "Used0RTT": f.used_0rtt,
                "HadRetry": f.had_retry,
                "HadToken": f.had_token,
                "DistinctDCIDsClient": len(f.dcids_client),
                "DistinctDCIDsServer": len(f.dcids_server),
                "DCIDRotationsClient": f.rotations_client,
                "DCIDRotationsServer": f.rotations_server,
                "InitialBytesShare": safe_div(float(f.n_initial), float(max(1, f.pkts_total))),
                "ShortBytesShare": safe_div(float(f.n_short), float(max(1, f.pkts_total))),
                "LongBytesShare": safe_div(float(f.n_long), float(max(1, f.pkts_total))),
            })

            # 4) Time milestones & IAT
            row.update({
                "FirstInitialTs": f.first_initial_ts,
                "FirstShortTs": f.first_short_ts,
                "HandshakeDuration": (f.first_short_ts - f.first_initial_ts) if (not math.isnan(f.first_initial_ts) and not math.isnan(f.first_short_ts)) else float("nan"),
            })

            # IAT stats: overall, fwd, bwd
            iat_overall = _series_stats(_iat_from_times(f.overall.times), "PacketsIAT", include_percentiles=True)
            iat_fwd = _series_stats(_iat_from_times(f.fwd.times), "FwdPacketsIAT", include_percentiles=False)
            iat_bwd = _series_stats(_iat_from_times(f.bwd.times), "BwdPacketsIAT", include_percentiles=False)
            row.update(iat_overall); row.update(iat_fwd); row.update(iat_bwd)

            # 5) UDP length stats overall/fwd/bwd + synonyms PayloadBytes*
            seg_all = _series_stats(f.overall.lengths, "SegmentSize", include_percentiles=True)
            seg_fwd = _series_stats(f.fwd.lengths, "FwdSegmentSize", include_percentiles=True)
            seg_bwd = _series_stats(f.bwd.lengths, "BwdSegmentSize", include_percentiles=True)
            row.update(seg_all); row.update(seg_fwd); row.update(seg_bwd)
            pay_all = _series_stats(f.overall.lengths, "PayloadBytes", include_percentiles=True)
            pay_fwd = _series_stats(f.fwd.lengths, "FwdPayloadBytes", include_percentiles=True)
            pay_bwd = _series_stats(f.bwd.lengths, "BwdPayloadBytes", include_percentiles=True)
            row.update(pay_all); row.update(pay_fwd); row.update(pay_bwd)

            # 6) Header proxy stats (only from long headers)
            row["TotalHeaderBytes"] = sum(x for x in f.overall.header_proxy) if f.overall.header_proxy else 0.0
            row["FwdTotalHeaderBytes"] = sum(x for x in f.fwd.header_proxy) if f.fwd.header_proxy else 0.0
            row["BwdTotalHeaderBytes"] = sum(x for x in f.bwd.header_proxy) if f.bwd.header_proxy else 0.0
            row.update(_series_stats(f.overall.header_proxy, "HeaderBytes", include_percentiles=True))
            row.update(_series_stats(f.fwd.header_proxy, "FwdHeaderBytes", include_percentiles=True))
            row.update(_series_stats(f.bwd.header_proxy, "BwdHeaderBytes", include_percentiles=True))

            # 7) Long payload & token stats
            row.update({
                "LongPayloadCount": len(f.long_payloads),
                "LongPayloadMean": (sum(f.long_payloads) / len(f.long_payloads)) if f.long_payloads else float("nan"),
                "LongPayloadMax": max(f.long_payloads) if f.long_payloads else float("nan"),
                "LongPayloadStd": _std_from_list(f.long_payloads),
                "LongPayloadMedian": percentile(f.long_payloads, 50.0) if f.long_payloads else float("nan"),
                "LongPayloadP90": percentile(f.long_payloads, 90.0) if f.long_payloads else float("nan"),
                "TokenLenSum": sum(f.token_lengths) if f.token_lengths else 0.0,
                "TokenLenMean": (sum(f.token_lengths) / len(f.token_lengths)) if f.token_lengths else float("nan"),
                "TokenLenMax": max(f.token_lengths) if f.token_lengths else float("nan"),
            })

            # 8) Delta stats
            row.update(_series_stats(f.overall.deltas_time, "DeltaTime", include_percentiles=True))
            row.update(_series_stats(f.fwd.deltas_time, "FwdDeltaTime", include_percentiles=False))
            row.update(_series_stats(f.bwd.deltas_time, "BwdDeltaTime", include_percentiles=False))
            row.update(_series_stats(f.overall.deltas_len, "DeltaLen", include_percentiles=True))
            row.update(_series_stats(f.fwd.deltas_len, "FwdDeltaLen", include_percentiles=False))
            row.update(_series_stats(f.bwd.deltas_len, "BwdDeltaLen", include_percentiles=False))

            # 9) Active/Idle episodes
            row.update(_series_stats(f.active_episodes, "ActiveEpisode", include_percentiles=False))
            row["ActiveEpisodeCount"] = len(f.active_episodes)
            row.update(_series_stats(f.idle_episodes, "IdleEpisode", include_percentiles=False))
            row["IdleEpisodeCount"] = len(f.idle_episodes)

            # 10) Inferred short DCID lens
            row.update({
                "InferredShortDCIDLenServer": f.inferred_short_dcid_len_server,
                "InferredShortDCIDLenClient": f.inferred_short_dcid_len_client,
            })

            # Ensure all expected columns are present
            for k in columns:
                if k not in row:
                    row[k] = float("nan")
            row["label"] = ""
            rows.append(row)
        return rows


def _iat_from_times(times: List[float]) -> List[float]:
    if len(times) < 2:
        return []
    out: List[float] = []
    prev = times[0]
    for t in times[1:]:
        dt = t - prev
        if dt >= 0:
            out.append(dt)
        prev = t
    return out


def _std_from_list(vals: List[float]) -> float:
    if len(vals) < 2:
        return float("nan")
    m = sum(vals) / len(vals)
    s2 = sum((x - m) ** 2 for x in vals) / (len(vals) - 1)
    return math.sqrt(s2)


def write_features_csv(rows: List[Dict[str, object]], path: str) -> None:
    cols = feature_schema.get_columns()
    directory = os.path.dirname(path)
    if directory:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception:
            pass
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, float("nan")) for k in cols})


