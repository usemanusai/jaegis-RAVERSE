"""
Tests for individual memory strategies.
"""

import pytest
from config.memory_strategies import (
    SequentialMemory,
    SlidingWindowMemory,
    SummarizationMemory,
    MemoryAugmentedMemory,
    HierarchicalMemory,
    CompressionMemory,
    OSLikeMemory
)


class TestSequentialMemory:
    """Test sequential memory strategy."""
    
    def test_sequential_memory_creation(self):
        """Test creating sequential memory."""
        memory = SequentialMemory()
        assert memory is not None
    
    def test_sequential_memory_add_message(self):
        """Test adding messages to sequential memory."""
        memory = SequentialMemory()
        memory.add_message("user input", "ai response")
        # Should not raise error
    
    def test_sequential_memory_get_context(self):
        """Test getting context from sequential memory."""
        memory = SequentialMemory()
        memory.add_message("input1", "output1")
        memory.add_message("input2", "output2")
        context = memory.get_context("query")
        assert isinstance(context, str)


class TestSlidingWindowMemory:
    """Test sliding window memory strategy."""
    
    def test_sliding_window_creation(self):
        """Test creating sliding window memory."""
        memory = SlidingWindowMemory(window_size=3)
        assert memory is not None
    
    def test_sliding_window_add_message(self):
        """Test adding messages to sliding window."""
        memory = SlidingWindowMemory(window_size=2)
        memory.add_message("input1", "output1")
        memory.add_message("input2", "output2")
        memory.add_message("input3", "output3")
        # Should keep only last 2
    
    def test_sliding_window_get_context(self):
        """Test getting context from sliding window."""
        memory = SlidingWindowMemory(window_size=2)
        memory.add_message("input1", "output1")
        memory.add_message("input2", "output2")
        context = memory.get_context("query")
        assert isinstance(context, str)


class TestSummarizationMemory:
    """Test summarization memory strategy."""
    
    def test_summarization_memory_creation(self):
        """Test creating summarization memory."""
        memory = SummarizationMemory(summary_interval=5)
        assert memory is not None
    
    def test_summarization_memory_add_message(self):
        """Test adding messages to summarization memory."""
        memory = SummarizationMemory(summary_interval=2)
        memory.add_message("input1", "output1")
        memory.add_message("input2", "output2")
        # Should trigger summarization
    
    def test_summarization_memory_get_context(self):
        """Test getting context from summarization memory."""
        memory = SummarizationMemory(summary_interval=5)
        memory.add_message("input1", "output1")
        context = memory.get_context("query")
        assert isinstance(context, str)


class TestMemoryAugmentedMemory:
    """Test memory-augmented strategy."""
    
    def test_memory_augmented_creation(self):
        """Test creating memory-augmented memory."""
        memory = MemoryAugmentedMemory(window_size=3)
        assert memory is not None
    
    def test_memory_augmented_add_message(self):
        """Test adding messages to memory-augmented."""
        memory = MemoryAugmentedMemory(window_size=2)
        memory.add_message("input1", "output1")
        memory.add_message("input2", "output2")
    
    def test_memory_augmented_get_context(self):
        """Test getting context from memory-augmented."""
        memory = MemoryAugmentedMemory(window_size=2)
        memory.add_message("input1", "output1")
        context = memory.get_context("query")
        assert isinstance(context, str)


class TestHierarchicalMemory:
    """Test hierarchical memory strategy."""
    
    def test_hierarchical_creation(self):
        """Test creating hierarchical memory."""
        memory = HierarchicalMemory(window_size=3, k=2)
        assert memory is not None
    
    def test_hierarchical_add_message(self):
        """Test adding messages to hierarchical memory."""
        memory = HierarchicalMemory(window_size=2, k=1)
        memory.add_message("input1", "output1")
        memory.add_message("input2", "output2")
    
    def test_hierarchical_get_context(self):
        """Test getting context from hierarchical memory."""
        memory = HierarchicalMemory(window_size=2, k=1)
        memory.add_message("input1", "output1")
        context = memory.get_context("query")
        assert isinstance(context, str)


class TestCompressionMemory:
    """Test compression memory strategy."""
    
    def test_compression_creation(self):
        """Test creating compression memory."""
        memory = CompressionMemory(compression_ratio=0.5)
        assert memory is not None
    
    def test_compression_add_message(self):
        """Test adding messages to compression memory."""
        memory = CompressionMemory(compression_ratio=0.5)
        memory.add_message("input1", "output1")
        memory.add_message("input2", "output2")
    
    def test_compression_get_context(self):
        """Test getting context from compression memory."""
        memory = CompressionMemory(compression_ratio=0.5)
        memory.add_message("input1", "output1")
        context = memory.get_context("query")
        assert isinstance(context, str)


class TestOSLikeMemory:
    """Test OS-like memory strategy."""
    
    def test_oslike_creation(self):
        """Test creating OS-like memory."""
        memory = OSLikeMemory(ram_size_mb=50, disk_size_mb=500)
        assert memory is not None
    
    def test_oslike_add_message(self):
        """Test adding messages to OS-like memory."""
        memory = OSLikeMemory(ram_size_mb=50, disk_size_mb=500)
        memory.add_message("input1", "output1")
        memory.add_message("input2", "output2")
    
    def test_oslike_get_context(self):
        """Test getting context from OS-like memory."""
        memory = OSLikeMemory(ram_size_mb=50, disk_size_mb=500)
        memory.add_message("input1", "output1")
        context = memory.get_context("query")
        assert isinstance(context, str)


class TestMemoryStrategyInteroperability:
    """Test that all strategies have compatible interfaces."""
    
    def test_all_strategies_have_add_message(self):
        """Test that all strategies implement add_message."""
        strategies = [
            SequentialMemory(),
            SlidingWindowMemory(window_size=3),
            SummarizationMemory(summary_interval=5),
            MemoryAugmentedMemory(window_size=3),
            HierarchicalMemory(window_size=3, k=2),
            CompressionMemory(compression_ratio=0.5),
            OSLikeMemory(ram_size_mb=50, disk_size_mb=500)
        ]
        
        for strategy in strategies:
            assert hasattr(strategy, 'add_message')
            assert callable(strategy.add_message)
    
    def test_all_strategies_have_get_context(self):
        """Test that all strategies implement get_context."""
        strategies = [
            SequentialMemory(),
            SlidingWindowMemory(window_size=3),
            SummarizationMemory(summary_interval=5),
            MemoryAugmentedMemory(window_size=3),
            HierarchicalMemory(window_size=3, k=2),
            CompressionMemory(compression_ratio=0.5),
            OSLikeMemory(ram_size_mb=50, disk_size_mb=500)
        ]
        
        for strategy in strategies:
            assert hasattr(strategy, 'get_context')
            assert callable(strategy.get_context)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

