"""Common direction filtering utilities for forward/backward packet analysis."""

from typing import List, Iterator, Any

class DirectionFilters:
    """Utilities for filtering packets by direction (forward/backward)."""
    
    @staticmethod
    def get_forward_packets(flow) -> List[Any]:
        """Get all forward packets from a flow."""
        return [pkt for pkt in flow.get_packets() if pkt.is_forward()]
    
    @staticmethod
    def get_backward_packets(flow) -> List[Any]:
        """Get all backward packets from a flow."""
        return [pkt for pkt in flow.get_packets() if not pkt.is_forward()]
    
    @staticmethod
    def filter_forward(packets: List[Any]) -> Iterator[Any]:
        """Filter packets to only forward direction."""
        return (pkt for pkt in packets if pkt.is_forward())
    
    @staticmethod
    def filter_backward(packets: List[Any]) -> Iterator[Any]:
        """Filter packets to only backward direction."""
        return (pkt for pkt in packets if not pkt.is_forward())
    
    @staticmethod
    def count_by_direction(flow) -> tuple[int, int]:
        """Get counts of forward and backward packets.
        
        Returns:
            tuple: (forward_count, backward_count)
        """
        packets = flow.get_packets()
        fwd_count = sum(1 for pkt in packets if pkt.is_forward())
        bwd_count = len(packets) - fwd_count
        return fwd_count, bwd_count
    
    @staticmethod
    def sum_by_direction(flow, attribute_getter) -> tuple[int, int]:
        """Sum an attribute by direction.
        
        Args:
            flow: The flow object
            attribute_getter: Function to extract attribute from packet
            
        Returns:
            tuple: (forward_sum, backward_sum)
        """
        packets = flow.get_packets()
        fwd_sum = sum(attribute_getter(pkt) for pkt in packets if pkt.is_forward())
        bwd_sum = sum(attribute_getter(pkt) for pkt in packets if not pkt.is_forward())
        return fwd_sum, bwd_sum 