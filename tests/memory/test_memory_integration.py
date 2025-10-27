"""
Integration tests for memory functionality across agents.
"""

import pytest
import json
from typing import Dict, Any
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from agents.online_version_manager_agent import VersionManagerAgent
from agents.online_knowledge_base_agent import KnowledgeBaseAgent
from agents.online_quality_gate_agent import QualityGateAgent
from agents.online_governance_agent import GovernanceAgent
from config.agent_memory_config import AGENT_MEMORY_CONFIG


class TestAgentMemoryIntegration:
    """Test memory integration with actual agents."""
    
    def test_version_manager_with_memory(self):
        """Test VersionManagerAgent with memory enabled."""
        agent = VersionManagerAgent(
            orchestrator=None,
            memory_strategy="sliding_window",
            memory_config={"window_size": 2}
        )
        assert agent.has_memory_enabled()
        assert agent.memory_strategy_name == "sliding_window"
    
    def test_version_manager_without_memory(self):
        """Test VersionManagerAgent without memory (default)."""
        agent = VersionManagerAgent(orchestrator=None)
        assert not agent.has_memory_enabled()
    
    def test_knowledge_base_with_memory(self):
        """Test KnowledgeBaseAgent with memory enabled."""
        agent = KnowledgeBaseAgent(
            orchestrator=None,
            memory_strategy="retrieval",
            memory_config={"k": 5, "embedding_dim": 384}
        )
        assert agent.has_memory_enabled()
        assert agent.memory_strategy_name == "retrieval"
    
    def test_quality_gate_with_memory(self):
        """Test QualityGateAgent with memory enabled."""
        agent = QualityGateAgent(
            orchestrator=None,
            memory_strategy="memory_augmented",
            memory_config={"window_size": 2}
        )
        assert agent.has_memory_enabled()
    
    def test_governance_with_memory(self):
        """Test GovernanceAgent with memory enabled."""
        agent = GovernanceAgent(
            orchestrator=None,
            memory_strategy="hierarchical",
            memory_config={"window_size": 3, "k": 2}
        )
        assert agent.has_memory_enabled()


class TestMemoryContextFlow:
    """Test memory context retrieval and storage flow."""
    
    def test_memory_context_retrieval_disabled(self):
        """Test memory context retrieval when disabled."""
        agent = VersionManagerAgent(orchestrator=None)
        context = agent.get_memory_context("test_query")
        assert context == ""
    
    def test_memory_context_retrieval_enabled(self):
        """Test memory context retrieval when enabled."""
        agent = VersionManagerAgent(
            orchestrator=None,
            memory_strategy="sliding_window",
            memory_config={"window_size": 2}
        )
        agent.add_to_memory("query1", "result1")
        context = agent.get_memory_context("query1")
        assert isinstance(context, str)
    
    def test_memory_storage_multiple_entries(self):
        """Test storing multiple entries in memory."""
        agent = VersionManagerAgent(
            orchestrator=None,
            memory_strategy="sliding_window",
            memory_config={"window_size": 5}
        )
        for i in range(3):
            agent.add_to_memory(f"query{i}", f"result{i}")
        # Should not raise error


class TestAgentMemoryConfig:
    """Test agent memory configurations."""
    
    def test_version_manager_config(self):
        """Test VersionManagerAgent memory config."""
        config = AGENT_MEMORY_CONFIG.get("version_manager")
        assert config is not None
        assert config["strategy"] == "hierarchical"
        assert config["preset"] == "medium"
    
    def test_knowledge_base_config(self):
        """Test KnowledgeBaseAgent memory config."""
        config = AGENT_MEMORY_CONFIG.get("knowledge_base")
        assert config is not None
        assert config["strategy"] == "retrieval"
        assert config["preset"] == "heavy"
    
    def test_quality_gate_config(self):
        """Test QualityGateAgent memory config."""
        config = AGENT_MEMORY_CONFIG.get("quality_gate")
        assert config is not None
        assert config["strategy"] == "memory_augmented"
        assert config["preset"] == "medium"
    
    def test_all_agents_have_config(self):
        """Test that all agents have memory configuration."""
        expected_agents = [
            "version_manager", "knowledge_base", "quality_gate",
            "governance", "document_generator", "rag_orchestrator",
            "daa", "lima", "reconnaissance", "api_reverse_engineering",
            "javascript_analysis", "wasm_analysis", "security_analysis",
            "traffic_interception", "validation", "reporting",
            "web_researcher", "content_analyzer", "topic_enhancer"
        ]
        for agent_name in expected_agents:
            assert agent_name in AGENT_MEMORY_CONFIG, f"Missing config for {agent_name}"


class TestMemoryErrorHandling:
    """Test error handling in memory operations."""
    
    def test_memory_add_error_handling(self):
        """Test error handling when adding to memory."""
        agent = VersionManagerAgent(
            orchestrator=None,
            memory_strategy="sliding_window",
            memory_config={"window_size": 2}
        )
        # Should not raise error even with unusual input
        agent.add_to_memory(None, None)
        agent.add_to_memory("", "")
        agent.add_to_memory({"complex": "object"}, {"complex": "result"})
    
    def test_memory_retrieval_error_handling(self):
        """Test error handling when retrieving from memory."""
        agent = VersionManagerAgent(
            orchestrator=None,
            memory_strategy="sliding_window",
            memory_config={"window_size": 2}
        )
        # Should not raise error
        context = agent.get_memory_context(None)
        assert context == ""
        context = agent.get_memory_context("")
        assert isinstance(context, str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

