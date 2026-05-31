"""Common array extraction utilities for packet data analysis."""

import numpy as np
from typing import List, Any, Optional

class ArrayExtractors:
    """Utilities for extracting arrays of packet attributes."""
    
    @staticmethod
    def extract_timestamps(flow) -> np.ndarray:
        """Extract timestamps from all packets in flow."""
        timestamps = [pkt.get_timestamp() for pkt in flow.get_packets()]
        return np.array(timestamps, dtype=float)
    
    @staticmethod
    def extract_packet_sizes(flow) -> np.ndarray:
        """Extract packet sizes from all packets in flow."""
        sizes = [pkt.get_length() for pkt in flow.get_packets()]
        return np.array(sizes, dtype=int)
    
    @staticmethod
    def extract_payload_sizes(flow) -> np.ndarray:
        """Extract payload sizes from all packets in flow."""
        sizes = [pkt.get_payloadbytes() for pkt in flow.get_packets()]
        return np.array(sizes, dtype=int)
    
    @staticmethod
    def extract_header_sizes(flow) -> np.ndarray:
        """Extract header sizes from all packets in flow."""
        sizes = [pkt.get_header_size() for pkt in flow.get_packets()]
        return np.array(sizes, dtype=int)
    
    @staticmethod
    def extract_inter_arrival_times(flow) -> np.ndarray:
        """Extract inter-arrival times between consecutive packets."""
        timestamps = ArrayExtractors.extract_timestamps(flow)
        if len(timestamps) < 2:
            return np.array([])
        return np.diff(timestamps)
    
    @staticmethod
    def extract_by_direction(flow, extractor_func, forward_only: bool = True) -> np.ndarray:
        """Extract array filtered by packet direction.
        
        Args:
            flow: The flow object
            extractor_func: Function to extract value from packet
            forward_only: If True, extract only forward packets; if False, only backward
            
        Returns:
            numpy array of extracted values
        """
        packets = flow.get_packets()
        if forward_only:
            values = [extractor_func(pkt) for pkt in packets if pkt.is_forward()]
        else:
            values = [extractor_func(pkt) for pkt in packets if not pkt.is_forward()]
        return np.array(values)
    
    @staticmethod
    def extract_deltas(flow, extractor_func) -> np.ndarray:
        """Extract delta (difference) values between consecutive packets.
        
        Args:
            flow: The flow object
            extractor_func: Function to extract value from packet
            
        Returns:
            numpy array of delta values (absolute differences)
        """
        values = [extractor_func(pkt) for pkt in flow.get_packets()]
        if len(values) < 2:
            return np.array([])
        deltas = [abs(values[i] - values[i-1]) for i in range(1, len(values))]
        return np.array(deltas)
    
    @staticmethod
    def safe_extract_array(flow, array_getter, default_value=0.0) -> np.ndarray:
        """Safely extract array from flow with fallback to default.
        
        Args:
            flow: The flow object
            array_getter: Function to get array from flow (e.g., flow.get_ttl_array)
            default_value: Value to return if array is empty
            
        Returns:
            numpy array or single-element array with default value
        """
        try:
            array = array_getter()
            if len(array) > 0:
                return np.array(array)
            else:
                return np.array([default_value])
        except (AttributeError, TypeError):
            return np.array([default_value]) 