import pytest
import time
from prometheus_client import REGISTRY, Histogram, CollectorRegistry

# We patch REGISTRY to avoid duplicate errors when running all tests
import prometheus_client.registry
# Just catch the exception on duplicate
original_register = prometheus_client.registry.CollectorRegistry.register
def patched_register(self, collector):
    try:
        original_register(self, collector)
    except ValueError:
        pass
prometheus_client.registry.CollectorRegistry.register = patched_register

from src.utils.metrics import track_time

def test_track_time_decorator_with_labels():
    # Use a custom registry or just rely on the global one with unique names
    h = Histogram('test_track_with_labels_seconds', 'Test', ['label'])

    @track_time(h, label='test1')
    def my_func():
        time.sleep(0.01)
        return "success"

    result = my_func()
    assert result == "success"

    count = REGISTRY.get_sample_value('test_track_with_labels_seconds_count', {'label': 'test1'})
    assert count == 1.0

def test_track_time_decorator_without_labels():
    h = Histogram('test_track_without_labels_seconds', 'Test')

    @track_time(h)
    def my_func():
        time.sleep(0.01)
        return "success"

    result = my_func()
    assert result == "success"

    count = REGISTRY.get_sample_value('test_track_without_labels_seconds_count')
    assert count == 1.0

def test_track_time_with_exception():
    h = Histogram('test_track_exception_seconds', 'Test', ['label'])

    @track_time(h, label='test2')
    def fail_func():
        time.sleep(0.01)
        raise ValueError("Intentional failure")

    with pytest.raises(ValueError):
        fail_func()

    # The metric should still be recorded even if an exception occurs
    count = REGISTRY.get_sample_value('test_track_exception_seconds_count', {'label': 'test2'})
    assert count == 1.0
