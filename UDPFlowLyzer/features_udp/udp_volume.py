"""Volume-based flow features such as packet and byte counts."""
from .base import Feature

def _get_packet_direction(packet, flow):
    """Determine packet direction relative to flow."""
    # Check if packet attributes match flow src->dst (forward)
    if (hasattr(packet, 'src_ip') and hasattr(packet, 'dst_ip') and 
        hasattr(packet, 'src_port') and hasattr(packet, 'dst_port')):
        if (packet.src_ip == flow.src_ip and packet.dst_ip == flow.dst_ip and
            packet.src_port == flow.src_port and packet.dst_port == flow.dst_port):
            return True  # Forward
        elif (packet.src_ip == flow.dst_ip and packet.dst_ip == flow.src_ip and
              packet.src_port == flow.dst_port and packet.dst_port == flow.src_port):
            return False  # Backward
    
    # Fallback: use packet's is_forward() method if available
    if hasattr(packet, 'is_forward'):
        return packet.is_forward()
    
    # Default fallback: assume forward
    return True

class PktCountForwardFeature(Feature):
    """Forward packet count - packets sent from first observed source."""
    name = "pkt_count_fwd"
    category = "volume"
    
    def extract(self, flow) -> int:
        count = 0
        for pkt in flow.get_packets():
            if _get_packet_direction(pkt, flow):
                count += 1
        return count

class PktCountBackwardFeature(Feature):
    """Backward packet count - packets sent to first observed source."""
    name = "pkt_count_bwd"
    category = "volume"
    
    def extract(self, flow) -> int:
        count = 0
        for pkt in flow.get_packets():
            if not _get_packet_direction(pkt, flow):
                count += 1
        return count

class ByteCountForwardFeature(Feature):
    """Forward byte count - total bytes sent from first observed source."""
    name = "byte_count_fwd"
    category = "volume"
    
    def extract(self, flow) -> int:
        count = 0
        for pkt in flow.get_packets():
            if _get_packet_direction(pkt, flow):
                count += pkt.get_length()
        return count

class ByteCountBackwardFeature(Feature):
    """Backward byte count - total bytes sent to first observed source."""
    name = "byte_count_bwd"
    category = "volume"
    
    def extract(self, flow) -> int:
        count = 0
        for pkt in flow.get_packets():
            if not _get_packet_direction(pkt, flow):
                count += pkt.get_length()
        return count

class PayloadBytesForwardFeature(Feature):
    """Forward payload bytes - payload only, excluding headers."""
    name = "payload_bytes_fwd"
    category = "volume"
    
    def extract(self, flow) -> int:
        count = 0
        for pkt in flow.get_packets():
            if _get_packet_direction(pkt, flow):
                count += pkt.get_payloadbytes()
        return count

class PayloadBytesBackwardFeature(Feature):
    """Backward payload bytes - payload only, excluding headers."""
    name = "payload_bytes_bwd"
    category = "volume"
    
    def extract(self, flow) -> int:
        count = 0
        for pkt in flow.get_packets():
            if not _get_packet_direction(pkt, flow):
                count += pkt.get_payloadbytes()
        return count

class FwdBwdPktRatioFeature(Feature):
    """Forward to backward packet ratio - Fwd/(Bwd+1)."""
    name = "fwd_bwd_pkt_ratio"
    category = "volume"
    
    def extract(self, flow) -> float:
        fwd_count = 0
        bwd_count = 0
        
        for pkt in flow.get_packets():
            if _get_packet_direction(pkt, flow):
                fwd_count += 1
            else:
                bwd_count += 1
        
        return float(fwd_count) / (bwd_count + 1)

class FwdBwdByteRatioFeature(Feature):
    """Forward to backward byte ratio - Fwd/(Bwd+1)."""
    name = "fwd_bwd_byte_ratio"
    category = "volume"
    
    def extract(self, flow) -> float:
        fwd_bytes = 0
        bwd_bytes = 0
        
        for pkt in flow.get_packets():
            if _get_packet_direction(pkt, flow):
                fwd_bytes += pkt.get_length()
            else:
                bwd_bytes += pkt.get_length()
        
        return float(fwd_bytes) / (bwd_bytes + 1) 

class PayloadEfficiencyFeature(Feature):
    """Payload efficiency - total payload bytes / total packet bytes."""
    name = "payload_efficiency"
    category = "volume"
    min_samples = 1
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if not packets:
            return 0.0
        
        total_payload = sum(pkt.get_payloadbytes() for pkt in packets)
        total_packet = sum(pkt.get_length() for pkt in packets)
        
        if total_packet == 0:
            return 0.0
        
        return float(total_payload / total_packet)

class HeaderOverheadRatioFeature(Feature):
    """Header overhead ratio - total header bytes / total packet bytes."""
    name = "header_overhead_ratio"
    category = "volume"
    min_samples = 1
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if not packets:
            return 0.0
        
        total_header = sum(pkt.get_header_size() for pkt in packets)
        total_packet = sum(pkt.get_length() for pkt in packets)
        
        if total_packet == 0:
            return 0.0
        
        return float(total_header / total_packet)

class DirectionalAsymmetryFeature(Feature):
    """Directional asymmetry - |forward_bytes - backward_bytes| / total_bytes."""
    name = "directional_asymmetry"
    category = "volume"
    min_samples = 1
    
    def extract(self, flow) -> float:
        packets = flow.get_packets()
        if not packets:
            return 0.0
        
        forward_bytes = 0
        backward_bytes = 0
        
        for pkt in packets:
            if _get_packet_direction(pkt, flow):
                forward_bytes += pkt.get_length()
            else:
                backward_bytes += pkt.get_length()
        
        total_bytes = forward_bytes + backward_bytes
        if total_bytes == 0:
            return 0.0
        
        asymmetry = abs(forward_bytes - backward_bytes) / total_bytes
        return float(asymmetry) 