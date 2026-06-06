import pytest
from unittest.mock import patch

from src.config.quality_gate_settings import validate_config

def test_validate_config_valid_default():
    """Test that default configuration passes validation."""
    assert validate_config() is True

def test_validate_config_invalid_threshold():
    """Test validation failure for out-of-bounds threshold."""
    with patch("src.config.quality_gate_settings.ACCURACY_THRESHOLD", 1.5):
        with pytest.raises(ValueError, match="ACCURACY_THRESHOLD must be between 0 and 1"):
            validate_config()

    with patch("src.config.quality_gate_settings.INTEGRITY_THRESHOLD", -0.5):
        with pytest.raises(ValueError, match="INTEGRITY_THRESHOLD must be between 0 and 1"):
            validate_config()

def test_validate_config_invalid_execution_time():
    """Test validation failure for invalid max execution time."""
    with patch("src.config.quality_gate_settings.EFFICIENCY_MAX_EXECUTION_TIME", 0):
        with pytest.raises(ValueError, match="EFFICIENCY_MAX_EXECUTION_TIME must be positive"):
            validate_config()

    with patch("src.config.quality_gate_settings.EFFICIENCY_MAX_EXECUTION_TIME", -10):
        with pytest.raises(ValueError, match="EFFICIENCY_MAX_EXECUTION_TIME must be positive"):
            validate_config()

def test_validate_config_invalid_memory():
    """Test validation failure for invalid max memory."""
    with patch("src.config.quality_gate_settings.EFFICIENCY_MAX_MEMORY", 0):
        with pytest.raises(ValueError, match="EFFICIENCY_MAX_MEMORY must be positive"):
            validate_config()

def test_validate_config_invalid_cpu():
    """Test validation failure for invalid max cpu."""
    with patch("src.config.quality_gate_settings.EFFICIENCY_MAX_CPU", -1.0):
        with pytest.raises(ValueError, match="EFFICIENCY_MAX_CPU must be between 0 and 100"):
            validate_config()

    with patch("src.config.quality_gate_settings.EFFICIENCY_MAX_CPU", 101.0):
        with pytest.raises(ValueError, match="EFFICIENCY_MAX_CPU must be between 0 and 100"):
            validate_config()

def test_validate_config_multiple_errors():
    """Test validation failure for multiple invalid settings simultaneously."""
    with patch("src.config.quality_gate_settings.ACCURACY_THRESHOLD", 2.0), \
         patch("src.config.quality_gate_settings.EFFICIENCY_MAX_EXECUTION_TIME", 0):
        with pytest.raises(ValueError) as excinfo:
            validate_config()

        error_msg = str(excinfo.value)
        assert "ACCURACY_THRESHOLD must be between 0 and 1" in error_msg
        assert "EFFICIENCY_MAX_EXECUTION_TIME must be positive" in error_msg
