"""Entropy-based metrics for packet size distributions - L2-L4 analysis only."""
from .base import Feature
import numpy as np
from collections import Counter

class PacketSizeEntropyFeature(Feature):
    """Shannon entropy of packet size distribution - L2-L4 network analysis."""
    name = "pkt_size_entropy"
    category = "entropy"
    min_samples = 2
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        # Extract packet sizes (total length including headers)
        sizes = [pkt.get_length() for pkt in packets]
        
        if len(sizes) < 2:
            return 0.0
        
        # Calculate Shannon entropy
        counter = Counter(sizes)
        total = len(sizes)
        entropy = 0.0
        
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        
        return float(entropy)

class ForwardPacketSizeEntropyFeature(Feature):
    """Entropy of forward packet sizes - L2-L4 header analysis."""
    name = "fwd_packet_size_entropy"
    category = "entropy"
    min_samples = 2
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        # Extract forward packet sizes
        sizes = [p.get_length() for p in packets if p.is_forward()]
        if len(sizes) < 2:
            return 0.0
        
        counter = Counter(sizes)
        total = len(sizes)
        entropy = 0.0
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        return float(entropy)

class ReversePacketSizeEntropyFeature(Feature):
    """Entropy of reverse packet sizes - L2-L4 header analysis."""
    name = "rev_packet_size_entropy"
    category = "entropy"
    min_samples = 2
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        # Extract reverse packet sizes
        sizes = [p.get_length() for p in flow.get_packets() if not p.is_forward()]
        if len(sizes) < 2:
            return 0.0
        counter = Counter(sizes)
        total = len(sizes)
        entropy = 0.0
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        return float(entropy)

class TimeWindowEntropyMeanFeature(Feature):
    """Mean entropy of packet sizes across 1-second time windows."""
    name = "time_window_entropy_mean"
    category = "entropy"
    min_samples = 5
    requires_timestamps = True
    window_size = 1.0  # seconds
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        # Group packets by time windows
        start_time = packets[0].get_timestamp()
        end_time = packets[-1].get_timestamp()
        
        if end_time - start_time < self.window_size:
            # Single window case
            sizes = [pkt.get_length() for pkt in packets]
            if len(set(sizes)) < 2:
                return 0.0
            counter = Counter(sizes)
            total = len(sizes)
            entropy = 0.0
            for count in counter.values():
                p = count / total
                if p > 0:
                    entropy -= p * np.log2(p)
            return float(entropy)
        
        # Multiple windows
        entropies = []
        current = start_time
        
        while current < end_time:
            window_end = current + self.window_size
            window_packets = [pkt for pkt in packets 
                            if current <= pkt.get_timestamp() < window_end]
            
            if len(window_packets) >= 2:
                sizes = [pkt.get_length() for pkt in window_packets]
                if len(set(sizes)) >= 2:
                    counter = Counter(sizes)
                    total = len(sizes)
                    entropy = 0.0
                    for count in counter.values():
                        p = count / total
                        if p > 0:
                            entropy -= p * np.log2(p)
                    entropies.append(entropy)
            
            current += self.window_size
        
        return float(np.mean(entropies)) if len(entropies) > 0 else 0.0

class TimeWindowEntropyStdFeature(Feature):
    """Standard deviation of packet size entropy across 1-second time windows."""
    name = "time_window_entropy_std"
    category = "entropy"
    min_samples = 5
    requires_timestamps = True
    window_size = 1.0  # seconds
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        # Group packets by time windows
        start_time = packets[0].get_timestamp()
        end_time = packets[-1].get_timestamp()
        
        if end_time - start_time < self.window_size:
            return 0.0  # Need multiple windows for std
        
        entropies = []
        current = start_time
        
        while current < end_time:
            window_end = current + self.window_size
            window_packets = [pkt for pkt in packets 
                            if current <= pkt.get_timestamp() < window_end]
            
            if len(window_packets) >= 2:
                sizes = [pkt.get_length() for pkt in window_packets]
                if len(set(sizes)) >= 2:
                    counter = Counter(sizes)
                    total = len(sizes)
                    entropy = 0.0
                    for count in counter.values():
                        p = count / total
                        if p > 0:
                            entropy -= p * np.log2(p)
                    entropies.append(entropy)
            
            current += self.window_size
        
        return float(np.std(entropies)) if len(entropies) > 1 else 0.0
