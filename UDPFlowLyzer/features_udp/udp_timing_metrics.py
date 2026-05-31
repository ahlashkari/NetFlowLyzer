"""Timing-related flow features including jitter and burst analysis."""
from .base import Feature
import numpy as np

class JitterFirstOrderFeature(Feature):
    """First-order jitter - standard deviation of inter-arrival times."""
    name = "jitter_first_order"
    category = "timing"
    min_samples = 3
    requires_timestamps = True
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)
        
        return float(np.std(iats)) if len(iats) > 0 else 0.0

class JitterSecondOrderFeature(Feature):
    """Second-order jitter - standard deviation of IAT differences."""
    name = "jitter_second_order"
    category = "timing"
    min_samples = 4
    requires_timestamps = True
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)
        
        if len(iats) < 2:
            return 0.0
        
        iat_diffs = np.diff(iats)
        return float(np.std(iat_diffs))

class PeriodicFlowFlagFeature(Feature):
    """Flag indicating periodic flow - 1 if periodic, 0 otherwise."""
    name = "periodic_flow_flag"
    category = "timing"
    min_samples = 5
    requires_timestamps = True
    periodic_cv_threshold = 0.3  # More realistic CV threshold (was 0.05 which is too strict)
    
    def extract(self, flow) -> int:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)
        
        if len(iats) < 3:
            return 0
        
        # Check if variation is low - periodic flows have consistent IATs
        mean_iat = np.mean(iats)
        if mean_iat <= 0:
            return 0
            
        cov = np.std(iats) / mean_iat
        # Flag as periodic if CV is BELOW threshold (low variation = periodic)
        # Increased threshold from 0.05 to 0.3 to detect more realistic periodic patterns
        return 1 if cov < self.periodic_cv_threshold else 0

class IATEntropyFeature(Feature):
    """Entropy of inter-arrival times using 3-bin classification."""
    name = "iat_entropy"
    category = "timing"
    min_samples = 3
    requires_timestamps = True
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)
        
        if len(iats) == 0:
            return 0.0
        
        # Classify IATs into bins: <1ms, 1-10ms, >10ms
        bins = np.array([0, 0.001, 0.01, float('inf')])
        hist, _ = np.histogram(iats, bins=bins)
        
        # Calculate entropy
        probs = hist / np.sum(hist)
        probs = probs[probs > 0]  # Remove zero probabilities
        
        if len(probs) <= 1:
            return 0.0
        
        entropy = -np.sum(probs * np.log2(probs))
        return float(entropy)

class RollingPktCountCV100msFeature(Feature):
    """Coefficient of variation of packet counts in 100ms rolling windows."""
    name = "rolling_pkt_count_cv_100ms"
    category = "timing"
    min_samples = 5
    requires_timestamps = True
    window_size = 0.1  # 100ms windows
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        
        if len(timestamps) == 0:
            return 0.0
        
        # Create 100ms windows
        start_time = timestamps[0]
        end_time = timestamps[-1]
        duration = end_time - start_time
        
        if duration < self.window_size:
            return 0.0
        
        window_counts = []
        current_time = start_time
        
        while current_time + self.window_size <= end_time:
            window_end = current_time + self.window_size
            count = np.sum((timestamps >= current_time) & (timestamps < window_end))
            window_counts.append(count)
            current_time += self.window_size
        
        if len(window_counts) < 2:
            return 0.0
        
        window_counts = np.array(window_counts)
        mean_count = np.mean(window_counts)
        
        if mean_count == 0:
            return 0.0
        
        return float(np.std(window_counts) / mean_count)

class Windowed95PctRateFeature(Feature):
    """95th percentile of packet rates in 1-second windows."""
    name = "windowed_95pct_rate"
    category = "timing"
    min_samples = 5
    requires_timestamps = True
    bulk_window = 1.0  # 1-second windows
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        
        if len(timestamps) == 0:
            return 0.0
        
        # Create 1-second windows
        start_time = timestamps[0]
        end_time = timestamps[-1]
        duration = end_time - start_time
        
        if duration < self.bulk_window:
            # Single window
            return float(len(packets) / duration) if duration > 0 else 0.0
        
        window_rates = []
        current_time = start_time
        
        while current_time + self.bulk_window <= end_time:
            window_end = current_time + self.bulk_window
            count = np.sum((timestamps >= current_time) & (timestamps < window_end))
            rate = count / self.bulk_window
            window_rates.append(rate)
            current_time += self.bulk_window
        
        if len(window_rates) == 0:
            return 0.0
        
        return float(np.percentile(window_rates, 95))

class PeakPktRate1sFeature(Feature):
    """Peak packet rate in any 1-second window."""
    name = "peak_pkt_rate_1s"
    category = "timing"
    min_samples = 2
    requires_timestamps = True
    bulk_window = 1.0
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        
        if len(timestamps) == 0:
            return 0.0
        
        # Sliding window to find peak rate
        max_rate = 0.0
        
        for i, start_time in enumerate(timestamps):
            end_time = start_time + self.bulk_window
            count = np.sum((timestamps >= start_time) & (timestamps < end_time))
            rate = count / self.bulk_window
            max_rate = max(max_rate, rate)
        
        return float(max_rate) 

class IATBurstRatioFeature(Feature):
    """Fraction of inter-arrival times ≤ threshold (burst detection)."""
    name = "iat_burst_ratio"
    category = "timing"
    min_samples = 2
    requires_timestamps = True
    burst_threshold = 0.05  # 50ms
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)
        
        if len(iats) == 0:
            return 0.0
        
        burst_count = np.sum(iats <= self.burst_threshold)
        return float(burst_count / len(iats))

class IATMADFeature(Feature):
    """Median Absolute Deviation of inter-arrival times - robust timing measure."""
    name = "iat_mad"
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
        
        # Calculate median absolute deviation
        median_iat = np.median(iats)
        mad = np.median(np.abs(iats - median_iat))
        return float(mad)

class FlowRegularityIndexFeature(Feature):
    """Flow regularity index - IAT standard deviation / IAT mean."""
    name = "flow_regularity_index"
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
        
        mean_iat = np.mean(iats)
        std_iat = np.std(iats)
        
        if mean_iat == 0:
            return 0.0
        
        return float(std_iat / mean_iat)

class SilenceRatioFeature(Feature):
    """Silence ratio - ratio of time with no packets to total flow time."""
    name = "silence_ratio"
    category = "timing"
    min_samples = 2
    requires_timestamps = True
    silence_threshold = 1.0  # 1 second gap considered silence
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        total_duration = timestamps[-1] - timestamps[0]
        
        if total_duration <= 0:
            return 0.0
        
        # Calculate time in silence (gaps > threshold)
        iats = np.diff(timestamps)
        silence_time = np.sum(iats[iats > self.silence_threshold])
        
        return float(silence_time / total_duration)

class PeakToMeanIATRatioFeature(Feature):
    """Peak IAT to mean IAT ratio - timing variability measure."""
    name = "peak_to_mean_iat_ratio"
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
        
        peak_iat = np.max(iats)
        mean_iat = np.mean(iats)
        
        if mean_iat == 0:
            return 0.0
        
        return float(peak_iat / mean_iat)

