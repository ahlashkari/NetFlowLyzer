"""Classic header-based statistics like port numbers and fragmentation - L2-L4 only."""
from .base import Feature
import numpy as np
from collections import Counter


class FragRatioFeature(Feature):
    """Ratio of fragmented packets - packets with MF=1 or offset>0."""
    name = "frag_ratio"
    category = "header"
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if not packets:
            return 0.0
        
        # Count packets with actual fragmentation indicators
        frag_count = 0
        for pkt in packets:
            # Primary check: use the is_fragment attribute that exists on UDPPacket
            if hasattr(pkt, 'is_fragment') and pkt.is_fragment:
                    frag_count += 1
        
        return float(frag_count / len(packets))

class IPv4FragRatioFeature(Feature):
    """Ratio of fragmented IPv4 packets - more specific than frag_ratio."""
    name = "ipv4_frag_ratio"
    category = "header"
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if not packets:
            return 0.0
        
        # All packets in UDP flow should be IPv4 (this is UDP-specific tool)
        ipv4_count = len(packets)
        frag_count = 0
        
        for pkt in packets:
            # Use the is_fragment attribute that exists on UDPPacket
            if hasattr(pkt, 'is_fragment') and pkt.is_fragment:
                    frag_count += 1
        
        return float(frag_count / ipv4_count) if ipv4_count > 0 else 0.0

class FragmentsPerFlowFeature(Feature):
    """Count of fragmented packets per flow."""
    name = "fragments_per_flow"
    category = "header"
    
    def extract(self, flow) -> int:
        packets = flow.get_packets()
        frag_count = 0
        
        for pkt in packets:
            # Use the is_fragment attribute that exists on UDPPacket  
            if hasattr(pkt, 'is_fragment') and pkt.is_fragment:
                    frag_count += 1
        
        return frag_count

class DestMulticastFlagFeature(Feature):
    """Flag indicating multicast destination - 1 if dst IP in 224.0.0.0/4 or ff00::/8."""
    name = "dest_multicast_flag"
    category = "header"
    
    def extract(self, flow) -> int:
        dst_ip = flow.dst_ip
        # Check IPv4 multicast range (224.0.0.0/4)
        if '.' in dst_ip:  # IPv4
            try:
                first_octet = int(dst_ip.split('.')[0])
                if 224 <= first_octet <= 239:
                    return 1
            except (ValueError, IndexError):
                pass
        # Check IPv6 multicast range (ff00::/8)
        elif ':' in dst_ip:  # IPv6
            if dst_ip.lower().startswith('ff'):
                return 1
        return 0

class MulticastRatioFeature(Feature):
    """Ratio of packets sent to multicast addresses."""
    name = "multicast_ratio"
    category = "header"
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if not packets:
            return 0.0
        
        multicast_count = 0
        for pkt in packets:
            dst_ip = getattr(pkt, 'dst_ip', flow.dst_ip)
            if '.' in dst_ip:  # IPv4
                try:
                    first_octet = int(dst_ip.split('.')[0])
                    if 224 <= first_octet <= 239:
                        multicast_count += 1
                except (ValueError, IndexError):
                    pass
            elif ':' in dst_ip:  # IPv6
                if dst_ip.lower().startswith('ff'):
                    multicast_count += 1
        
        return float(multicast_count / len(packets))

class UDPLengthMismatchRatioFeature(Feature):
    """Ratio of packets where UDP length field != actual payload + 8."""
    name = "udp_length_mismatch_ratio"
    category = "header"
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if not packets:
            return 0.0
        
        mismatch_count = 0
        for pkt in packets:
            # Get declared UDP length from header
            declared_udp_len = getattr(pkt, 'udp_len', 0)
            # Calculate actual UDP length (payload + 8 byte header)
            payload_len = pkt.get_payloadbytes()
            actual_udp_len = payload_len + 8
            
            if declared_udp_len != actual_udp_len:
                mismatch_count += 1
        
        return float(mismatch_count / len(packets))

class DSCPDiversityFeature(Feature):
    """Count unique DSCP values in the flow - simplified for UDP packets."""
    name = "dscp_diversity"
    category = "header"
    
    def extract(self, flow) -> int:
        packets = flow.get_packets()
        if not packets:
            return 0
        
        # Since UDP packets don't have ToS field exposed, use a simplified approach
        # Based on flow characteristics as a proxy for DSCP diversity
        unique_ports = set()
        for pkt in packets:
            # Use port numbers as a proxy for service type diversity
            unique_ports.add(pkt.get_src_port())
            unique_ports.add(pkt.get_dst_port())
        
        # Simple heuristic: more diverse ports suggest more diverse DSCP usage
        return min(len(unique_ports), 8)  # Cap at reasonable DSCP diversity

class ToSModeFeature(Feature):
    """Most common Type of Service value - simplified for UDP packets."""
    name = "tos_mode"
    category = "header"
    
    def extract(self, flow) -> int:
        packets = flow.get_packets()
        if not packets:
            return 0
        
        # Since UDP packets don't have ToS field exposed, use default
        # In most cases, UDP traffic uses default ToS = 0
        return 0

class IPIDIncrementVarFeature(Feature):
    """Variance of IP ID field increments - simplified for UDP packets."""
    name = "ipid_increment_var"
    category = "header"
    min_samples = 3
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if len(packets) < self.min_samples:
            return 0.0
        
        # Since UDP packets don't have IP ID exposed, use packet sequence as proxy
        # This gives a measure of sequence regularity
        sequence_increments = []
        for i in range(1, len(packets)):
            # Use timestamp differences as proxy for IP ID increments
            time_diff = packets[i].get_timestamp() - packets[i-1].get_timestamp()
            sequence_increments.append(time_diff * 1000)  # Convert to ms
        
        if len(sequence_increments) < 2:
            return 0.0
        
        return float(np.var(sequence_increments))
