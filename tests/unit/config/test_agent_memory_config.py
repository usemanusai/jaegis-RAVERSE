import pytest
from src.config.agent_memory_config import (
    list_agent_configs,
    AGENT_MEMORY_CONFIG,
    get_agent_memory_config,
    get_memory_hardware_requirements,
    list_available_presets,
    MEMORY_PRESETS
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
    config = get_agent_memory_config("version_manager", preset="heavy")
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
