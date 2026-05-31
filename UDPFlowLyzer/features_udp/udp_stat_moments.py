"""Correlation between packet size and arrival time."""
from .base import Feature
import numpy as np


class SizeTimeCorrelationFeature(Feature):
    """Correlation between packet size and arrival time."""
    name = "size_time_correlation"
    category = "stat"
    min_samples = 5
    requires_timestamps = True

    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0

        # Extract sizes and timestamps
        sizes = np.array([pkt.get_length() for pkt in packets])
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])

        if len(sizes) != len(timestamps) or len(sizes) < self.min_samples:
            return 0.0

        # Calculate correlation coefficient
        try:
            correlation = np.corrcoef(sizes, timestamps)[0, 1]
            return float(correlation) if not np.isnan(correlation) else 0.0
        except Exception:
            return 0.0
