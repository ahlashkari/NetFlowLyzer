"""Metrics describing burstiness and idle periods in UDP flows - L2-L4 only."""
from .base import Feature
import numpy as np

class BurstCountFeature(Feature):
    """Number of burst periods (consecutive packets with IAT ≤ 100ms)."""
    name = "burst_count"
    category = "burst"
    min_samples = 3
    requires_timestamps = True
    burst_threshold = 0.1
    
    def extract(self, flow) -> int:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)
        
        burst_threshold = self.burst_threshold
        in_burst = False
        burst_count = 0
        
        for iat in iats:
            if iat <= burst_threshold:
                if not in_burst:
                    burst_count += 1
                    in_burst = True
            else:
                in_burst = False
        
        return burst_count

class MeanBurstLengthFeature(Feature):
    """Mean length of burst periods (in packets)."""
    name = "mean_burst_length"
    category = "burst"
    min_samples = 3
    requires_timestamps = True
    burst_threshold = 0.1
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)
        
        burst_threshold = self.burst_threshold
        burst_lengths = []
        current_burst_length = 0
        in_burst = False
        
        for iat in iats:
            if iat <= burst_threshold:
                if not in_burst:
                    current_burst_length = 2  # Start with 2 packets
                    in_burst = True
                else:
                    current_burst_length += 1
            else:
                if in_burst:
                    burst_lengths.append(current_burst_length)
                    in_burst = False
                    current_burst_length = 0
        
        # Handle final burst if flow ends in a burst
        if in_burst:
            burst_lengths.append(current_burst_length)
        
        return float(np.mean(burst_lengths)) if burst_lengths else 0.0

class MaxIdleGapFeature(Feature):
    """Maximum idle gap duration in seconds."""
    name = "max_idle_gap"
    category = "burst"
    min_samples = 2
    requires_timestamps = True
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)
        
        # Find gaps that are considered "idle" (larger than burst threshold)
        idle_threshold = 0.1  # 100ms
        idle_gaps = iats[iats > idle_threshold]
        
        return float(np.max(idle_gaps)) if len(idle_gaps) > 0 else 0.0

class BurstIntensityFeature(Feature):
    """Burst intensity - packets per second during burst periods."""
    name = "burst_intensity"
    category = "burst"
    min_samples = 5
    requires_timestamps = True
    burst_threshold = 0.1
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)
        
        burst_threshold = self.burst_threshold
        burst_periods = []
        current_burst_start = None
        current_burst_packets = 0
        
        for i, iat in enumerate(iats):
            if iat <= burst_threshold:
                if current_burst_start is None:
                    current_burst_start = timestamps[i]
                    current_burst_packets = 2  # Include both packets
                else:
                    current_burst_packets += 1
            else:
                if current_burst_start is not None:
                    burst_duration = timestamps[i] - current_burst_start
                    if burst_duration > 0:
                        intensity = current_burst_packets / burst_duration
                        burst_periods.append(intensity)
                    current_burst_start = None
                    current_burst_packets = 0
        
        # Handle final burst if flow ends in a burst
        if current_burst_start is not None:
            burst_duration = timestamps[-1] - current_burst_start
            if burst_duration > 0:
                intensity = current_burst_packets / burst_duration
                burst_periods.append(intensity)
        
        return float(np.mean(burst_periods)) if burst_periods else 0.0

class BurstRegularityFeature(Feature):
    """Burst regularity - standard deviation of burst lengths."""
    name = "burst_regularity"
    category = "burst"
    min_samples = 5
    requires_timestamps = True
    burst_threshold = 0.1
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)
        
        burst_threshold = self.burst_threshold
        burst_lengths = []
        current_burst_length = 0
        in_burst = False
        
        for iat in iats:
            if iat <= burst_threshold:
                if not in_burst:
                    current_burst_length = 1
                    in_burst = True
                else:
                    current_burst_length += 1
            else:
                if in_burst:
                    burst_lengths.append(current_burst_length)
                    in_burst = False
                    current_burst_length = 0
        
        # Handle final burst if flow ends in a burst
        if in_burst:
            burst_lengths.append(current_burst_length)
        
        return float(np.std(burst_lengths)) if len(burst_lengths) > 1 else 0.0

class BurstFrequencyFeature(Feature):
    """Burst frequency - number of bursts per second of flow duration."""
    name = "burst_frequency"
    category = "burst"
    min_samples = 3
    requires_timestamps = True
    burst_threshold = 0.1
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        total_duration = timestamps[-1] - timestamps[0]
        
        if total_duration <= 0:
            return 0.0
        
        iats = np.diff(timestamps)
        burst_threshold = self.burst_threshold
        burst_count = 0
        in_burst = False
        
        for iat in iats:
            if iat <= burst_threshold:
                if not in_burst:
                    burst_count += 1
                    in_burst = True
            else:
                in_burst = False
        
        return float(burst_count / total_duration)

class ActivePeriodMeanFeature(Feature):
    """Mean duration of active periods."""
    name = "active_period_mean"
    category = "burst"
    min_samples = 3
    requires_timestamps = True
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        # Get active periods from flow object if available
        if hasattr(flow, 'flow_active') and flow.flow_active:
            active_periods = [abs(period) for period in flow.flow_active]
            return float(np.mean(active_periods)) / 1000000.0  # Convert to seconds
        
        # Fallback: use inter-arrival time analysis
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        total_duration = timestamps[-1] - timestamps[0]
        
        # Simple approximation: assume flow is mostly active
        return float(total_duration)

class IdlePeriodMeanFeature(Feature):
    """Mean duration of idle periods."""
    name = "idle_period_mean"
    category = "burst"
    min_samples = 3
    requires_timestamps = True
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        # Get idle periods from flow object if available
        if hasattr(flow, 'flow_idle') and flow.flow_idle:
            idle_periods = [abs(period) for period in flow.flow_idle]
            return float(np.mean(idle_periods)) / 1000000.0  # Convert to seconds
        
        # Fallback: use large inter-arrival times as idle periods
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)
        idle_threshold = 1.0  # 1 second
        idle_periods = iats[iats > idle_threshold]
        
        return float(np.mean(idle_periods)) if len(idle_periods) > 0 else 0.0

class IdlePeriodMaxFeature(Feature):
    """Maximum duration of idle periods."""
    name = "idle_period_max"
    category = "burst"
    min_samples = 3
    requires_timestamps = True
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        # Get idle periods from flow object if available
        if hasattr(flow, 'flow_idle') and flow.flow_idle:
            idle_periods = [abs(period) for period in flow.flow_idle]
            return float(np.max(idle_periods)) / 1000000.0  # Convert to seconds
        
        # Fallback: use largest inter-arrival time as max idle
        timestamps = np.array([pkt.get_timestamp() for pkt in packets])
        iats = np.diff(timestamps)
        
        return float(np.max(iats)) 