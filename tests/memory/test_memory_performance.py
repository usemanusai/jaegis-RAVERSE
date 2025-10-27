"""
Performance tests for memory functionality.
"""

import pytest
import time
import json
from agents.base_memory_agent import BaseMemoryAgent
from config.agent_memory_config import MEMORY_PRESETS


class TestMemoryPerformance:
    """Test performance characteristics of memory strategies."""
    
    def test_no_memory_overhead(self):
        """Test that disabled memory has zero overhead."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST",
            orchestrator=None,
            memory_strategy=None
        )
        
        start = time.time()
        for _ in range(1000):
            agent.add_to_memory("input", "output")
        elapsed_no_memory = time.time() - start
        
        # Should be very fast (< 10ms for 1000 operations)
        assert elapsed_no_memory < 0.01
    
    def test_sliding_window_performance(self):
        """Test sliding window memory performance."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST",
            orchestrator=None,
            memory_strategy="sliding_window",
            memory_config={"window_size": 5}
        )
        
        start = time.time()
        for i in range(100):
            agent.add_to_memory(f"input{i}", f"output{i}")
        elapsed = time.time() - start
        
        # Should complete in reasonable time
        assert elapsed < 1.0
    
    def test_memory_context_retrieval_performance(self):
        """Test memory context retrieval performance."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST",
            orchestrator=None,
            memory_strategy="sliding_window",
            memory_config={"window_size": 5}
        )
        
        # Add some data
        for i in range(10):
            agent.add_to_memory(f"input{i}", f"output{i}")
        
        # Test retrieval performance
        start = time.time()
        for _ in range(100):
            context = agent.get_memory_context("query")
        elapsed = time.time() - start
        
        # Should be fast
        assert elapsed < 1.0
    
    def test_memory_preset_overhead(self):
        """Test overhead of different memory presets."""
        presets = ["none", "light", "medium", "heavy"]
        times = {}
        
        for preset_name in presets:
            preset = MEMORY_PRESETS[preset_name]
            agent = BaseMemoryAgent(
                name="Test Agent",
                agent_type="TEST",
                orchestrator=None,
                memory_strategy=preset["strategy"],
                memory_config=preset["config"]
            )
            
            start = time.time()
            for i in range(50):
                agent.add_to_memory(f"input{i}", f"output{i}")
            times[preset_name] = time.time() - start
        
        # None should be fastest
        assert times["none"] <= times["light"]
        # All should complete in reasonable time
        for preset_name, elapsed in times.items():
            assert elapsed < 2.0, f"{preset_name} took too long: {elapsed}s"


class TestMemoryScalability:
    """Test memory scalability with large datasets."""
    
    def test_sliding_window_with_many_entries(self):
        """Test sliding window with many entries."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST",
            orchestrator=None,
            memory_strategy="sliding_window",
            memory_config={"window_size": 10}
        )
        
        # Add many entries
        for i in range(1000):
            agent.add_to_memory(f"input{i}", f"output{i}")
        
        # Should still work
        context = agent.get_memory_context("query")
        assert isinstance(context, str)
    
    def test_memory_augmented_with_many_entries(self):
        """Test memory-augmented strategy with many entries."""
        agent = BaseMemoryAgent(
            name="Test Agent",
            agent_type="TEST",
            orchestrator=None,
            memory_strategy="memory_augmented",
            memory_config={"window_size": 5}
        )
        
        # Add many entries
        for i in range(500):
            agent.add_to_memory(f"input{i}", f"output{i}")
        
        # Should still work
        context = agent.get_memory_context("query")
        assert isinstance(context, str)


class TestMemoryResourceUsage:
    """Test memory resource usage."""
    
    def test_preset_resource_estimates(self):
        """Test that presets have reasonable resource estimates."""
        for preset_name, preset in MEMORY_PRESETS.items():
            ram_mb = preset["ram_mb"]
            cpu_percent = preset["cpu_percent"]
            
            # All should be reasonable
            assert ram_mb >= 0
            assert cpu_percent >= 0
            assert ram_mb <= 200  # Max 200MB
            assert cpu_percent <= 10  # Max 10% CPU
    
    def test_none_preset_zero_resources(self):
        """Test that 'none' preset uses zero resources."""
        preset = MEMORY_PRESETS["none"]
        assert preset["ram_mb"] == 0
        assert preset["cpu_percent"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

