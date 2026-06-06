import pytest
from unittest.mock import patch

from src.config.agent_memory_config import (
    get_agent_memory_config,
    MEMORY_PRESETS,
    AGENT_MEMORY_CONFIG
)


def test_get_agent_memory_config_valid_preset():
    """Test getting a valid preset configuration."""
    config = get_agent_memory_config("any_agent", strategy_override="light")
    assert config["strategy"] == "sliding_window"
    assert config["preset"] == "light"
    assert config["config"]["window_size"] == 2


def test_get_agent_memory_config_agent_specific():
    """Test getting an agent-specific configuration when preset is none."""
    config = get_agent_memory_config("version_manager")
    assert config["strategy"] == "hierarchical"
    assert config["preset"] == "medium"
    assert config["config"]["window_size"] == 3


def test_get_agent_memory_config_default_fallback():
    """Test fallback to default when preset is none and agent is unknown."""
    config = get_agent_memory_config("unknown_agent")
    assert config["strategy"] is None
    assert config["preset"] == "none"
    assert config["config"] == {}


def test_get_agent_memory_config_invalid_preset_uses_agent_specific():
    """Test that an invalid preset falls back to agent specific config."""
    config = get_agent_memory_config("version_manager", strategy_override="invalid_preset")
    assert config["strategy"] == "hierarchical"


def test_get_agent_memory_config_invalid_preset_unknown_agent():
    """Test that an invalid preset with unknown agent falls back to default."""
    config = get_agent_memory_config("unknown_agent", strategy_override="invalid_preset")
    assert config["strategy"] is None
    assert config["preset"] == "none"


@patch.dict("src.config.agent_memory_config.MEMORY_PRESETS", {}, clear=True)
def test_get_agent_memory_config_empty_presets():
    """Test behavior when MEMORY_PRESETS is empty."""
    # Should fall back to agent specific
    config = get_agent_memory_config("version_manager", strategy_override="light")
    assert config["strategy"] == "hierarchical"


@patch.dict("src.config.agent_memory_config.AGENT_MEMORY_CONFIG", {}, clear=True)
def test_get_agent_memory_config_empty_agent_configs():
    """Test behavior when AGENT_MEMORY_CONFIG is empty."""
    # Should fall back to default
    config = get_agent_memory_config("version_manager")
    assert config["strategy"] is None
    assert config["preset"] == "none"


@patch.dict("src.config.agent_memory_config.MEMORY_PRESETS", {"light": {}}, clear=True)
def test_get_agent_memory_config_invalid_preset_dict():
    """Test behavior when preset dictionary is invalid (missing keys)."""
    with pytest.raises(KeyError):
        get_agent_memory_config("any_agent", strategy_override="light")


@patch.dict("src.config.agent_memory_config.AGENT_MEMORY_CONFIG", {"version_manager": {}}, clear=True)
def test_get_agent_memory_config_invalid_agent_dict():
    """Test behavior when agent dictionary is invalid (missing keys is fine here since it just returns the dict)."""
    # Unlike presets, it directly returns the dict from AGENT_MEMORY_CONFIG
    config = get_agent_memory_config("version_manager")
    assert config == {}
