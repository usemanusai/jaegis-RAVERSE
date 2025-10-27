"""
Prometheus Metrics Module for RAVERSE
Date: October 25, 2025

This module provides Prometheus metrics collection for monitoring
the RAVERSE binary patching system.
"""

from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY
from prometheus_client import CollectorRegistry, multiprocess, generate_latest
from typing import Optional
import time
from functools import wraps


# Create metrics registry
registry = REGISTRY

# Counter metrics
patches_total = Counter(
    'raverse_patches_total',
    'Total number of patches attempted',
    ['status', 'binary_type'],
    registry=registry
)

patches_success_total = Counter(
    'raverse_patches_success_total',
    'Total number of successful patches',
    ['binary_type'],
    registry=registry
)

patches_failed_total = Counter(
    'raverse_patches_failed_total',
    'Total number of failed patches',
    ['binary_type', 'error_type'],
    registry=registry
)

api_calls_total = Counter(
    'raverse_api_calls_total',
    'Total number of API calls',
    ['provider', 'model', 'status'],
    registry=registry
)

cache_hits_total = Counter(
    'raverse_cache_hits_total',
    'Total number of cache hits',
    ['cache_type'],
    registry=registry
)

cache_misses_total = Counter(
    'raverse_cache_misses_total',
    'Total number of cache misses',
    ['cache_type'],
    registry=registry
)

embeddings_generated_total = Counter(
    'raverse_embeddings_generated_total',
    'Total number of embeddings generated',
    ['model'],
    registry=registry
)

# Histogram metrics
patch_duration_seconds = Histogram(
    'raverse_patch_duration_seconds',
    'Time spent patching binaries',
    ['binary_type'],
    buckets=[0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0],
    registry=registry
)

api_call_duration_seconds = Histogram(
    'raverse_api_call_duration_seconds',
    'Time spent on API calls',
    ['provider', 'model'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
    registry=registry
)

embedding_generation_duration_seconds = Histogram(
    'raverse_embedding_generation_duration_seconds',
    'Time spent generating embeddings',
    ['model'],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0],
    registry=registry
)

database_query_duration_seconds = Histogram(
    'raverse_database_query_duration_seconds',
    'Time spent on database queries',
    ['operation'],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0],
    registry=registry
)

# Gauge metrics
active_patches = Gauge(
    'raverse_active_patches',
    'Number of patches currently being processed',
    registry=registry
)

database_connections = Gauge(
    'raverse_database_connections',
    'Number of active database connections',
    registry=registry
)

cache_size_bytes = Gauge(
    'raverse_cache_size_bytes',
    'Size of cache in bytes',
    ['cache_type'],
    registry=registry
)


class MetricsCollector:
    """Metrics collector for RAVERSE operations."""
    
    @staticmethod
    def record_patch_attempt(binary_type: str, status: str):
        """Record a patch attempt."""
        patches_total.labels(status=status, binary_type=binary_type).inc()
        if status == 'success':
            patches_success_total.labels(binary_type=binary_type).inc()
        elif status == 'failed':
            patches_failed_total.labels(binary_type=binary_type, error_type='unknown').inc()
    
    @staticmethod
    def record_patch_failure(binary_type: str, error_type: str):
        """Record a patch failure."""
        patches_failed_total.labels(binary_type=binary_type, error_type=error_type).inc()
    
    @staticmethod
    def record_api_call(provider: str, model: str, status: str, duration: float):
        """Record an API call."""
        api_calls_total.labels(provider=provider, model=model, status=status).inc()
        api_call_duration_seconds.labels(provider=provider, model=model).observe(duration)
    
    @staticmethod
    def record_cache_hit(cache_type: str):
        """Record a cache hit."""
        cache_hits_total.labels(cache_type=cache_type).inc()
    
    @staticmethod
    def record_cache_miss(cache_type: str):
        """Record a cache miss."""
        cache_misses_total.labels(cache_type=cache_type).inc()
    
    @staticmethod
    def record_embedding_generation(model: str, duration: float):
        """Record embedding generation."""
        embeddings_generated_total.labels(model=model).inc()
        embedding_generation_duration_seconds.labels(model=model).observe(duration)
    
    @staticmethod
    def record_database_query(operation: str, duration: float):
        """Record a database query."""
        database_query_duration_seconds.labels(operation=operation).observe(duration)
    
    @staticmethod
    def set_active_patches(count: int):
        """Set the number of active patches."""
        active_patches.set(count)
    
    @staticmethod
    def set_database_connections(count: int):
        """Set the number of database connections."""
        database_connections.set(count)
    
    @staticmethod
    def set_cache_size(cache_type: str, size_bytes: int):
        """Set the cache size."""
        cache_size_bytes.labels(cache_type=cache_type).set(size_bytes)

    @staticmethod
    def record_operation_duration(operation: str, duration: float):
        """
        Record duration of a generic operation.

        Args:
            operation: Name of the operation
            duration: Duration in seconds
        """
        # Use database_query_duration_seconds as a generic operation timer
        database_query_duration_seconds.labels(operation=operation).observe(duration)

    @staticmethod
    def increment_counter(counter_name: str, **labels):
        """
        Increment a generic counter by looking up the counter by name.

        This is a convenience method for incrementing counters dynamically.
        For better performance, use the specific counter methods instead.

        Args:
            counter_name: Name of the counter (e.g., 'validation_chmod_failures', 'cache_l2_clear_failures')
            **labels: Labels for the counter
        """
        # Map counter names to actual counter objects
        counter_map = {
            'validation_chmod_failures': patches_failed_total,
            'cache_l2_clear_failures': cache_misses_total,
            'cache_l3_clear_failures': cache_misses_total,
        }

        counter = counter_map.get(counter_name)
        if counter:
            # Increment the counter with appropriate labels
            if labels:
                counter.labels(**labels).inc()
            else:
                # Use default labels if none provided
                if counter_name == 'validation_chmod_failures':
                    counter.labels(binary_type='unknown', error_type='chmod_failed').inc()
                elif counter_name in ['cache_l2_clear_failures', 'cache_l3_clear_failures']:
                    counter.labels(cache_type='l2' if 'l2' in counter_name else 'l3').inc()
                else:
                    # Generic increment without labels (may fail for counters requiring labels)
                    try:
                        counter.inc()
                    except Exception:
                        # Counter requires labels, skip
                        pass
        else:
            # Counter not found, log warning
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Unknown counter name: {counter_name}")


def track_time(metric: Histogram, **labels):
    """Decorator to track execution time."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                duration = time.time() - start_time
                if labels:
                    metric.labels(**labels).observe(duration)
                else:
                    metric.observe(duration)
        return wrapper
    return decorator


def get_metrics() -> bytes:
    """Get current metrics in Prometheus format."""
    return generate_latest(registry)


# Example usage decorators
def track_patch_duration(binary_type: str):
    """Decorator to track patch duration."""
    return track_time(patch_duration_seconds, binary_type=binary_type)


def track_api_call_duration(provider: str, model: str):
    """Decorator to track API call duration."""
    return track_time(api_call_duration_seconds, provider=provider, model=model)


def track_database_query_duration(operation: str):
    """Decorator to track database query duration."""
    return track_time(database_query_duration_seconds, operation=operation)


# Initialize metrics collector
metrics_collector = MetricsCollector()

