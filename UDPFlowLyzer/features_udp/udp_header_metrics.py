"""Advanced header-based metrics derived from available packet fields - L2-L4 only."""
from .base import Feature
import numpy as np
from collections import Counter

# Note: Basic features like fragmentation and multicast are in header_features.py

class FragmentSizeEntropyFeature(Feature):
    """Entropy of fragment sizes (for fragmented packets only)."""
    name = "fragment_size_entropy"
    category = "header"
    min_samples = 1
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        # Get sizes of fragmented packets only
        frag_sizes = []
        for pkt in packets:
            if hasattr(pkt, 'is_fragment') and pkt.is_fragment:
                frag_sizes.append(pkt.get_length())
        
        if len(frag_sizes) < 2:
            return 0.0
        
        # Calculate Shannon entropy of fragment sizes
        counter = Counter(frag_sizes)
        total = len(frag_sizes)
        entropy = 0.0
        
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        
        return float(entropy)

class HeaderSizeConsistencyFeature(Feature):
    """Header size consistency flag - 1 if all header sizes are identical."""
    name = "header_size_consistency"
    category = "header"
    
    def extract(self, flow) -> int:
        packets = flow.get_packets()
        if len(packets) <= 1:
            return 1  # Single packet is consistent
        
        header_sizes = [pkt.get_header_size() for pkt in packets]
        return 1 if len(set(header_sizes)) == 1 else 0 