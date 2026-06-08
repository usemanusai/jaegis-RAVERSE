import pytest
from unittest.mock import patch

from src.config.agent_memory_config import (
    list_agent_configs,
    get_agent_memory_config,
    get_memory_hardware_requirements,
    list_available_presets,
    MEMORY_PRESETS,
    AGENT_MEMORY_CONFIG
)

def test_list_agent_configs():
    """Test that list_agent_configs returns the correct configuration dictionary."""
    configs = list_agent_configs()

    # Check that it returns a dictionary
    assert isinstance(configs, dict)

    # Check that it returns the actual AGENT_MEMORY_CONFIG dictionary
    assert configs is AGENT_MEMORY_CONFIG

    # Check that it has expected keys
    assert "version_manager" in configs
    assert "knowledge_base" in configs

    # Check structure of returned items
    for agent_type, config in configs.items():
        assert isinstance(agent_type, str)
        assert isinstance(config, dict)
        assert "strategy" in config
        assert "config" in config
        assert "preset" in config
        assert "reason" in config

def test_get_agent_memory_config():
    """Test getting memory config for agents."""
    # Test preset override
    config = get_agent_memory_config("version_manager", strategy_override="heavy")
    assert config["preset"] == "heavy"
    assert config["strategy"] == MEMORY_PRESETS["heavy"]["strategy"]

    # Test default agent config (no preset provided, so preset="none")
    config = get_agent_memory_config("version_manager")
    # For 'version_manager', AGENT_MEMORY_CONFIG has strategy="hierarchical", preset="medium"
    assert config == AGENT_MEMORY_CONFIG["version_manager"]
    assert config["preset"] == "medium"

    # Test unknown agent with no preset
    config_unknown = get_agent_memory_config("unknown_agent")
    assert config_unknown["strategy"] is None
    assert config_unknown["preset"] == "none"

def test_get_memory_hardware_requirements():
    """Test getting hardware requirements."""
    # Test known strategy
    reqs = get_memory_hardware_requirements("sliding_window")
    assert "ram_mb" in reqs
    assert "cpu_percent" in reqs
    assert reqs["ram_mb"] == 5

    # Test unknown strategy
    reqs = get_memory_hardware_requirements("unknown")
    assert reqs["ram_mb"] == 0
    assert reqs["cpu_percent"] == 0

def test_list_available_presets():
    """Test listing presets."""
    presets = list_available_presets()
    assert presets is MEMORY_PRESETS
    assert "none" in presets
    assert "heavy" in presets


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
