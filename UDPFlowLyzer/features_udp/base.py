from abc import ABC, abstractmethod
from typing import Union, Optional, List
import numpy as np
import logging

logger = logging.getLogger(__name__)

class Feature(ABC):
    """Abstract base for all feature extractors."""

    name: str = "base_feature"
    category: str = "unknown"
    floating_point_unit: str = ".4f"
    window_size: Optional[float] = None    # seconds
    packet_window: Optional[int] = None    # e.g. 50
    requires_timestamps: bool = False
    min_samples: int = 1
    paper_reference: str = ""
    
    @abstractmethod
    def extract(self, flow) -> Union[float, int, str]:
        """Extract the feature value from a flow.
        
        Parameters
        ----------
        flow
            UDPFlow object containing packets and metadata.
            
        Returns
        -------
        Union[float, int, str]
            The extracted feature value.
        """
        pass
    
    def fmt(self, value: Union[float, int, str]) -> Union[float, int, str]:
        """Format floating-point values according to ``floating_point_unit``."""

        if isinstance(value, float):
            try:
                return format(value, self.floating_point_unit)
            except Exception:
                # Fallback to default string conversion if formatting fails
                return f"{value}"
        return value

    def apply_windowing(self, series: np.ndarray) -> List[np.ndarray]:
        """Return list of sub-arrays sliced per window_size / packet_window.
        
        Parameters
        ----------
        series : np.ndarray
            Time series data to window.
            
        Returns
        -------
        List[np.ndarray]
            List of windowed sub-arrays.
        """
        if self.window_size is not None and self.requires_timestamps:
            # Time-based windowing - would need timestamps
            # For now, return entire series as single window
            return [series] if len(series) > 0 else []
        elif self.packet_window is not None:
            # Packet-based windowing
            windows = []
            for i in range(0, len(series), self.packet_window):
                window = series[i:i + self.packet_window]
                if len(window) >= self.min_samples:
                    windows.append(window)
            return windows
        else:
            # No windowing
            return [series] if len(series) >= self.min_samples else []

    def validate_flow_compatibility(self, flow) -> None:
        """Raise ValueError or log warning if flow too small or wrong builder.
        
        Parameters
        ----------
        flow
            UDPFlow object to validate.
            
        Raises
        ------
        ValueError
            If flow is incompatible with this feature.
        """
        if len(flow.get_packets()) < self.min_samples:
            logger.warning("Feature %s requires min %d samples, got %d", 
                         self.name, self.min_samples, len(flow.get_packets())) 