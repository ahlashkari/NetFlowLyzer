from __future__ import annotations

from typing import List


def get_columns() -> List[str]:
    # Keys (13)
    cols: List[str] = [
        "flow_id",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "timestamp",
        "Duration",
        "version",
        "initial_dcid_hex",
        "initial_dcid_len",
        "initial_scid_hex",
        "initial_scid_len",
    ]

    # 2) Packet/byte counters & directions
    counters = [
        "PacketsCount",
        "FwdPacketsCount",
        "BwdPacketsCount",
        "TotalPayloadBytes",
        "FwdTotalPayloadBytes",
        "BwdTotalPayloadBytes",
        "BytesRate",
        "FwdBytesRate",
        "BwdBytesRate",
        "PacketsRate",
        "FwdPacketsRate",
        "BwdPacketsRate",
        "DownUpRate",
        "DirAsymBytes",
        "PathsCount",
        "MigrationCount",
        "ServerPortIs443",
    ]
    cols += counters

    # 3) Packet type distribution & handshake
    typedist = [
        "n_initial",
        "n_handshake",
        "n_0rtt",
        "n_retry",
        "n_short",
        "n_long",
        "Used0RTT",
        "HadRetry",
        "HadToken",
        "DistinctDCIDsClient",
        "DistinctDCIDsServer",
        "DCIDRotationsClient",
        "DCIDRotationsServer",
        "InitialBytesShare",
        "ShortBytesShare",
        "LongBytesShare",
    ]
    cols += typedist

    # 4) Time milestones & IATs
    time_milestones = [
        "FirstInitialTs",
        "FirstShortTs",
        "HandshakeDuration",
    ]
    cols += time_milestones

    def add_series(prefix: str, include_percentiles: bool = True) -> List[str]:
        base = [
            f"{prefix}Mean",
            f"{prefix}Std",
            f"{prefix}Max",
            f"{prefix}Min",
            f"{prefix}Sum",
            f"{prefix}Median",
            f"{prefix}Skewness",
            f"{prefix}CoV",
            f"{prefix}Variance",
            f"{prefix}Mode",
        ]
        if include_percentiles:
            base += [
                f"{prefix}P10",
                f"{prefix}P25",
                f"{prefix}P50",
                f"{prefix}P75",
                f"{prefix}P90",
                f"{prefix}P95",
            ]
        return base

    # IAT overall + Fwd/Bwd (overall includes percentiles, dirs can omit P10/P25/P75/P95 to save columns if needed)
    cols += add_series("PacketsIAT", include_percentiles=True)
    cols += add_series("FwdPacketsIAT", include_percentiles=False)
    cols += add_series("BwdPacketsIAT", include_percentiles=False)

    # 5) UDP length (“SegmentSize”) stats overall/fwd/bwd + PayloadBytes* synonyms
    for pr in ("SegmentSize", "PayloadBytes"):
        cols += add_series(pr, include_percentiles=True)
        cols += add_series(f"Fwd{pr}", include_percentiles=True)
        cols += add_series(f"Bwd{pr}", include_percentiles=True)

    # 6) Header proxy stats (overall/fwd/bwd)
    header_totals = [
        "TotalHeaderBytes",
        "FwdTotalHeaderBytes",
        "BwdTotalHeaderBytes",
    ]
    cols += header_totals
    cols += add_series("HeaderBytes", include_percentiles=True)
    cols += add_series("FwdHeaderBytes", include_percentiles=True)
    cols += add_series("BwdHeaderBytes", include_percentiles=True)

    # 7) Long payload & token stats
    cols += [
        "LongPayloadCount",
        "LongPayloadMean",
        "LongPayloadMax",
        "LongPayloadStd",
        "LongPayloadMedian",
        "LongPayloadP90",
        "TokenLenSum",
        "TokenLenMean",
        "TokenLenMax",
    ]

    # 8) Delta stats (time & len) overall/fwd/bwd
    for pr in ("DeltaTime", "DeltaLen"):
        cols += add_series(pr, include_percentiles=True)
        cols += add_series(f"Fwd{pr}", include_percentiles=False)
        cols += add_series(f"Bwd{pr}", include_percentiles=False)

    # 9) Active/Idle episodes
    for pr in ("ActiveEpisode", "IdleEpisode"):
        cols += add_series(pr, include_percentiles=False)
        cols.append(f"{pr}Count")

    # 10) Inferred short DCID lens
    cols += [
        "InferredShortDCIDLenServer",
        "InferredShortDCIDLenClient",
    ]

    cols.append("label")
    return cols


