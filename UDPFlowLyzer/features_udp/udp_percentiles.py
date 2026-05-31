"""Range, IQR and MAD spread statistics for packet sizes and timing."""
from .base import Feature
import numpy as np


class PacketSizeRangeFeature(Feature):
    """Range of packet sizes (max - min)."""
    name = "pkt_size_range"
    category = "stat"
    min_samples = 2

    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0

        sizes = np.array([pkt.get_length() for pkt in packets])
        return float(np.max(sizes) - np.min(sizes))


class IATRangeFeature(Feature):
    """Range of inter-arrival times (max - min)."""
    name = "iat_range"
    category = "timing"
    min_samples = 3
    requires_timestamps = True

    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0

        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)

        if len(iats) < 2:
            return 0.0

        return float(np.max(iats) - np.min(iats))


class PacketSizeIQRFeature(Feature):
    """Interquartile range of packet sizes (75th - 25th percentile)."""
    name = "pkt_size_iqr"
    category = "stat"
    min_samples = 4

    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0

        sizes = np.array([pkt.get_length() for pkt in packets])
        q75 = np.percentile(sizes, 75)
        q25 = np.percentile(sizes, 25)
        return float(q75 - q25)


class IATIQRFeature(Feature):
    """Interquartile range of inter-arrival times."""
    name = "iat_iqr"
    category = "timing"
    min_samples = 5
    requires_timestamps = True

    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0

        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)

        if len(iats) < 4:
            return 0.0

        q75 = np.percentile(iats, 75)
        q25 = np.percentile(iats, 25)
        return float(q75 - q25)


class PacketSizeMADFeature(Feature):
    """Median Absolute Deviation of packet sizes - robust measure."""
    name = "pkt_size_mad"
    category = "stat"
    min_samples = 2

    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0

        sizes = np.array([pkt.get_length() for pkt in packets])
        median_size = np.median(sizes)
        mad = np.median(np.abs(sizes - median_size))
        return float(mad)
