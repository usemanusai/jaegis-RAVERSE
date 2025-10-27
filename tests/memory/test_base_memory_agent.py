"""
Test suite for BaseMemoryAgent - Core memory functionality tests.
"""

import pytest
import json
from typing import Dict, Any
from agents.base_memory_agent import BaseMemoryAgent
from config.agent_memory_config import MEMORY_PRESETS


class MockOrchestrator:
    """Mock orchestrator for testing."""
    pass


class TestBaseMemoryAgentInitialization:
    """Test BaseMemoryAgent initialization."""
    
    def test_init_without_memory(self):
        """Test initialization without memory support."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST",
            orchestrator=None,
            memory_strategy=None
        )
        assert agent.name == "Test Agent"
        assert agent.agent_type == "TEST"
        assert not agent.has_memory_enabled()
        assert agent.memory is None
    
    def test_init_with_sliding_window_memory(self):
        """Test initialization with sliding window memory."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST",
            orchestrator=None,
            memory_strategy="sliding_window",
            memory_config={"window_size": 3}
        )
        assert agent.has_memory_enabled()
        assert agent.memory is not None
        assert agent.memory_strategy_name == "sliding_window"
    
    def test_init_with_hierarchical_memory(self):
        """Test initialization with hierarchical memory."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST",
            orchestrator=None,
            memory_strategy="hierarchical",
            memory_config={"window_size": 3, "k": 2}
        )
        assert agent.has_memory_enabled()
        assert agent.memory_strategy_name == "hierarchical"


class TestMemoryOperations:
    """Test memory add and retrieval operations."""
    
    def test_add_to_memory_when_disabled(self):
        """Test adding to memory when disabled (should be no-op)."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST",
            orchestrator=None,
            memory_strategy=None
        )
        # Should not raise error
        agent.add_to_memory("input", "output")
    
    def test_add_to_memory_when_enabled(self):
        """Test adding to memory when enabled."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST",
            orchestrator=None,
            memory_strategy="sliding_window",
            memory_config={"window_size": 3}
        )
        agent.add_to_memory("test input", "test output")
        # Should not raise error
    
    def test_get_memory_context_when_disabled(self):
        """Test retrieving memory context when disabled."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST",
            orchestrator=None,
            memory_strategy=None
        )
        context = agent.get_memory_context("query")
        assert context == ""
    
    def test_get_memory_context_when_enabled(self):
        """Test retrieving memory context when enabled."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST",
            orchestrator=None,
            memory_strategy="sliding_window",
            memory_config={"window_size": 3}
        )
        agent.add_to_memory("input1", "output1")
        agent.add_to_memory("input2", "output2")
        context = agent.get_memory_context("query")
        assert isinstance(context, str)


class TestMemoryPresets:
    """Test memory presets."""
    
    def test_none_preset(self):
        """Test 'none' preset (no memory)."""
        preset = MEMORY_PRESETS["none"]
        assert preset["strategy"] is None
        assert preset["ram_mb"] == 0
        assert preset["cpu_percent"] == 0
    
    def test_light_preset(self):
        """Test 'light' preset."""
        preset = MEMORY_PRESETS["light"]
        assert preset["strategy"] == "sliding_window"
        assert preset["ram_mb"] == 5
        assert preset["cpu_percent"] == 1
    
    def test_medium_preset(self):
        """Test 'medium' preset."""
        preset = MEMORY_PRESETS["medium"]
        assert preset["strategy"] == "hierarchical"
        assert preset["ram_mb"] == 20
        assert preset["cpu_percent"] == 3
    
    def test_heavy_preset(self):
        """Test 'heavy' preset."""
        preset = MEMORY_PRESETS["heavy"]
        assert preset["strategy"] == "retrieval"
        assert preset["ram_mb"] == 100
        assert preset["cpu_percent"] == 5


class TestBackwardCompatibility:
    """Test backward compatibility."""
    
    def test_agent_works_without_memory_parameters(self):
        """Test that agents work without memory parameters."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST",
            orchestrator=None
        )
        assert agent.name == "Test Agent"
        assert not agent.has_memory_enabled()
    
    def test_memory_disabled_by_default(self):
        """Test that memory is disabled by default."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST"
        )
        assert not agent.has_memory_enabled()
        assert agent.memory is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

