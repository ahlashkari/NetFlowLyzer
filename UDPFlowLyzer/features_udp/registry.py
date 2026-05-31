"""Registry of available feature extractors and helpers."""
from typing import List
import logging
from .base import Feature

logger = logging.getLogger(__name__)

# Import all feature modules to ensure classes are registered
logger.debug("🔍 Loading feature modules...")
try:
    from . import stat_features
    from . import header_features
    # Import new feature modules (renamed for consistency)
    from . import udp_volume
    from . import udp_stat_moments
    from . import udp_timing_metrics
    from . import udp_burst_metrics
    from . import udp_entropy_metrics
    from . import udp_header_metrics
    from . import udp_percentiles
    from . import udp_stat_battery
    logger.debug("✅ Successfully imported UDP feature modules")
except ImportError as e:
    logger.warning(f"⚠️ Could not import some UDP feature modules: {e}")
    # Create a simple fallback feature for testing
    class SimpleUDPFeature(Feature):
        name = "simple_udp_feature"
        category = "basic"
        
        def extract(self, flow):
            return len(flow.get_packets()) if hasattr(flow, 'get_packets') else 0

# Auto-discover all Feature subclasses
logger.debug("🔍 Auto-discovering Feature subclasses...")
_ALL = {cls.name: cls() for cls in Feature.__subclasses__()}
logger.debug("✅ Discovered %d feature classes", len(_ALL))

# Log feature discovery summary
if logger.isEnabledFor(logging.DEBUG):
    logger.debug("📊 Feature Discovery Summary:")
    categories = {}
    for feature in _ALL.values():
        cat = feature.category
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(feature.name)
    
    for category, features in sorted(categories.items()):
        logger.debug("   • %s: %d features", category.upper(), len(features))
        for feature_name in sorted(features):
            logger.debug("     - %s", feature_name)

def get_features(
    categories: List[str],
    heavy_allowed: bool = False,
    burst_threshold: float | None = None,
    idle_threshold: float | None = None,
    min_delta_samples: int | None = None,
    bulk_window: float | None = None,
    bulk_pkt_threshold: int | None = None,
    subflow_threshold: float | None = None,
    periodic_cv_threshold: float | None = None,
    min_moment_samples: int | None = None,
) -> List[Feature]:
    """Get feature instances by category.
    
    Parameters
    ----------
    categories : List[str]
        List of feature categories to include (e.g., ['stat', 'header']).
        Special value 'all' returns all available features.
    heavy_allowed : bool, default False
        Whether to include computationally heavy features.
    burst_threshold : float, optional
        Threshold in seconds to consider packets part of a burst.
    idle_threshold : float, optional
        Inter-arrival time considered an idle gap (legacy parameter).
    min_delta_samples : int, optional
        Minimum packets required to compute Δsize statistics.
    bulk_window : float, optional
        Time window in seconds for bulk-burst detection.
    bulk_pkt_threshold : int, optional
        Minimum packets per window to consider bulk state.
    subflow_threshold : float, optional
        Time gap in seconds to split subflows.
    periodic_cv_threshold : float, optional
        Maximum CV(IAT) to flag flow as periodic.
    min_moment_samples : int, optional
        Minimum packets to compute skewness/kurtosis.
        
    Returns
    -------
    List[Feature]
        List of feature instances matching the requested categories.
    """
    logger.debug("🎯 Selecting features for categories: %s", categories)
    
    if 'all' in categories:
        features = list(_ALL.values())
        logger.debug("   Selected ALL features: %d total", len(features))
    else:
        features = [f for f in _ALL.values() if f.category in categories]
        logger.debug("   Selected features by category: %d total", len(features))
        
        # Log selection by category
        for category in categories:
            category_features = [f for f in features if f.category == category]
            logger.debug("     • %s: %d features", category.upper(), len(category_features))
    
    # Filter heavy features if not allowed
    pre_heavy_count = len(features)
    if not heavy_allowed:
        features = [f for f in features if not getattr(f, 'is_heavy', False)]
        heavy_filtered = pre_heavy_count - len(features)
        if heavy_filtered > 0:
            logger.debug("   Filtered %d heavy features (heavy_allowed=False)", heavy_filtered)
    
    logger.debug("🔧 Configuring feature parameters...")
    
    # Track parameter configuration statistics
    config_stats = {
        'burst_threshold': 0,
        'idle_threshold': 0,
        'min_delta_samples': 0,
        'bulk_window': 0,
        'bulk_pkt_threshold': 0,
        'subflow_threshold': 0,
        'periodic_cv_threshold': 0,
        'min_moment_samples': 0,
    }
    
    # Set configuration parameters on all features
    for feature in features:
        feature.heavy_allowed = heavy_allowed
        
        # Legacy parameters for backward compatibility
        if burst_threshold is not None and hasattr(feature, "burst_threshold"):
            feature.burst_threshold = burst_threshold
            config_stats['burst_threshold'] += 1
        if idle_threshold is not None and hasattr(feature, "idle_threshold"):
            feature.idle_threshold = idle_threshold
            config_stats['idle_threshold'] += 1
            
        # New refactored parameters
        if min_delta_samples is not None and hasattr(feature, "min_delta_samples"):
            feature.min_delta_samples = min_delta_samples
            config_stats['min_delta_samples'] += 1
        if bulk_window is not None and hasattr(feature, "bulk_window"):
            feature.bulk_window = bulk_window
            config_stats['bulk_window'] += 1
        if bulk_pkt_threshold is not None and hasattr(feature, "bulk_pkt_threshold"):
            feature.bulk_pkt_threshold = bulk_pkt_threshold
            config_stats['bulk_pkt_threshold'] += 1
        if subflow_threshold is not None and hasattr(feature, "subflow_threshold"):
            feature.subflow_threshold = subflow_threshold
            config_stats['subflow_threshold'] += 1
        if periodic_cv_threshold is not None and hasattr(feature, "periodic_cv_threshold"):
            feature.periodic_cv_threshold = periodic_cv_threshold
            config_stats['periodic_cv_threshold'] += 1
        if min_moment_samples is not None and hasattr(feature, "min_moment_samples"):
            feature.min_moment_samples = min_moment_samples
            config_stats['min_moment_samples'] += 1
    
    # Log parameter configuration summary
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("📊 Parameter Configuration Summary:")
        for param, count in config_stats.items():
            if count > 0:
                param_value = locals().get(param.replace('_', '_'), 'N/A')
                logger.debug("   • %s: applied to %d features (value: %s)", param, count, param_value)
    
    # Validate feature configurations
    validation_warnings = []
    validation_errors = []
    
    for feature in features:
        # Check for required parameter mismatches
        if hasattr(feature, 'min_delta_samples') and hasattr(feature, 'min_samples'):
            if getattr(feature, 'min_delta_samples', 10) != getattr(feature, 'min_samples', 10):
                validation_warnings.append(f"{feature.name}: min_delta_samples and min_samples mismatch")
        
        # Check for reasonable parameter values
        if hasattr(feature, 'min_moment_samples'):
            if getattr(feature, 'min_moment_samples', 50) < 10:
                validation_warnings.append(f"{feature.name}: min_moment_samples < 10 may be unreliable")
        
        if hasattr(feature, 'bulk_window'):
            if getattr(feature, 'bulk_window', 1.0) <= 0:
                validation_errors.append(f"{feature.name}: bulk_window must be positive")
    
    # Log validation results
    if validation_warnings:
        logger.warning("⚠️ Feature Configuration Warnings:")
        for warning in validation_warnings[:5]:  # Limit to first 5
            logger.warning("   • %s", warning)
        if len(validation_warnings) > 5:
            logger.warning("   • ... and %d more warnings", len(validation_warnings) - 5)
    
    if validation_errors:
        logger.error("❌ Feature Configuration Errors:")
        for error in validation_errors:
            logger.error("   • %s", error)
    
    logger.debug("✅ Feature selection and configuration completed: %d features ready", len(features))
    return features

def get_all_features(heavy_allowed: bool = False) -> List[Feature]:
    """Get all available feature instances.
    
    Parameters
    ----------
    heavy_allowed : bool, default False
        Whether to include computationally heavy features.
    
    Returns
    -------
    List[Feature]
        List of all available feature instances.
    """
    logger.debug("🔍 Getting all features (heavy_allowed=%s)", heavy_allowed)
    features = list(_ALL.values())
    
    if not heavy_allowed:
        pre_count = len(features)
        features = [f for f in features if not getattr(f, 'is_heavy', False)]
        heavy_filtered = pre_count - len(features)
        if heavy_filtered > 0:
            logger.debug("   Filtered %d heavy features", heavy_filtered)
    
    for feature in features:
        feature.heavy_allowed = heavy_allowed
        
    logger.debug("✅ Returning %d features", len(features))
    return features

def get_feature_names(categories: List[str]) -> List[str]:
    """Get feature names by category.
    
    Parameters
    ----------
    categories : List[str]
        List of feature categories to include.
        
    Returns
    -------
    List[str]
        List of feature names matching the requested categories.
    """
    logger.debug("🏷️ Getting feature names for categories: %s", categories)
    names = [f.name for f in get_features(categories)]
    logger.debug("   Found %d feature names", len(names))
    return names

def get_available_categories() -> List[str]:
    """Get list of all available feature categories.
    
    Returns
    -------
    List[str]
        List of unique category names.
    """
    logger.debug("📂 Getting available feature categories")
    categories = set()
    for feature in _ALL.values():
        categories.add(feature.category)
    
    sorted_categories = sorted(list(categories))
    logger.debug("   Found categories: %s", sorted_categories)
    return sorted_categories

def get_feature_count_by_category() -> dict:
    """Get count of features by category.
    
    Returns
    -------
    dict
        Dictionary mapping category names to feature counts.
    """
    logger.debug("📊 Counting features by category")
    counts = {}
    for feature in _ALL.values():
        category = feature.category
        counts[category] = counts.get(category, 0) + 1
    
    logger.debug("   Category counts: %s", counts)
    return counts

def get_feature_registry_summary() -> dict:
    """Get comprehensive summary of the feature registry.
    
    Returns
    -------
    dict
        Dictionary with registry statistics and feature information.
    """
    logger.debug("📋 Generating feature registry summary")
    
    summary = {
        'total_features': len(_ALL),
        'categories': get_feature_count_by_category(),
        'available_categories': get_available_categories(),
        'heavy_features': [],
        'research_features': [],
    }
    
    # Identify special feature types
    for feature in _ALL.values():
        if getattr(feature, 'is_heavy', False):
            summary['heavy_features'].append(feature.name)
        
        # Features using new research parameters
        research_params = ['min_delta_samples', 'bulk_window', 'bulk_pkt_threshold', 
                          'subflow_threshold', 'periodic_cv_threshold', 'min_moment_samples']
        if any(hasattr(feature, param) for param in research_params):
            summary['research_features'].append(feature.name)
    
    logger.debug("✅ Registry summary generated: %d total features across %d categories", 
                 summary['total_features'], len(summary['categories']))
    
    return summary 