"""
Tests for RAVERSE 2.0 Complete Architecture
Tests all layers: Version Management, Knowledge Base, Quality Gate, Governance, Document Generation
"""

import pytest
import json
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from agents.online_version_manager_agent import VersionManagerAgent
from agents.online_knowledge_base_agent import KnowledgeBaseAgent
from agents.online_quality_gate_agent import QualityGateAgent
from agents.online_governance_agent import GovernanceAgent
from agents.online_document_generator_agent import DocumentGeneratorAgent


class TestVersionManagerAgent:
    """Tests for Version Manager Agent (Layer 0)."""

    @pytest.fixture
    def agent(self):
        """Create agent instance."""
        return VersionManagerAgent()

    def test_agent_initialization(self, agent):
        """Test agent initialization."""
        assert agent.agent_type == "VERSION_MANAGER"
        assert agent.name == "Version Manager"

    def test_check_compatibility(self, agent):
        """Test compatibility checking."""
        result = agent._execute_impl({
            "action": "check_compatibility",
            "components": {
                "postgresql": "17.0",
                "redis": "8.0",
                "python": "3.13"
            }
        })
        
        assert result["status"] == "success"
        assert "compatible" in result
        assert "compatibility_matrix" in result

    def test_register_version(self, agent):
        """Test version registration."""
        result = agent._execute_impl({
            "action": "register_version",
            "component_name": "test_component",
            "version": "1.0.0",
            "metadata": {"test": True}
        })
        
        assert result["status"] == "success"
        assert "version_id" in result

    def test_validate_onboarding(self, agent):
        """Test onboarding validation."""
        result = agent._execute_impl({
            "action": "validate_onboarding"
        })
        
        assert result["status"] == "success"
        assert "onboarding_valid" in result
        assert "validation_results" in result


class TestKnowledgeBaseAgent:
    """Tests for Knowledge Base Agent (Layer 1)."""

    @pytest.fixture
    def agent(self):
        """Create agent instance."""
        return KnowledgeBaseAgent()

    def test_agent_initialization(self, agent):
        """Test agent initialization."""
        assert agent.agent_type == "KNOWLEDGE_BASE"
        assert agent.name == "Knowledge Base Manager"

    def test_store_knowledge(self, agent):
        """Test knowledge storage."""
        result = agent._execute_impl({
            "action": "store_knowledge",
            "content": "Test knowledge content",
            "source": "test_source",
            "metadata": {"test": True}
        })
        
        assert result["status"] == "success"
        assert "knowledge_id" in result
        assert result["source"] == "test_source"

    def test_search_knowledge(self, agent):
        """Test knowledge search."""
        result = agent._execute_impl({
            "action": "search_knowledge",
            "query": "test query",
            "limit": 5
        })
        
        assert result["status"] == "success"
        assert "results" in result
        assert "count" in result

    def test_retrieve_for_rag(self, agent):
        """Test RAG retrieval."""
        result = agent._execute_impl({
            "action": "retrieve_for_rag",
            "query": "test query",
            "limit": 3
        })
        
        assert result["status"] == "success"
        assert "session_id" in result
        assert "retrieved_knowledge" in result

    def test_generate_with_rag(self, agent):
        """Test RAG generation."""
        result = agent._execute_impl({
            "action": "generate_with_rag",
            "query": "test query"
        })
        
        assert result["status"] == "success"
        assert "response" in result
        assert "confidence" in result


class TestQualityGateAgent:
    """Tests for Quality Gate Agent (Layer 2)."""

    @pytest.fixture
    def agent(self):
        """Create agent instance."""
        return QualityGateAgent()

    def test_agent_initialization(self, agent):
        """Test agent initialization."""
        assert agent.agent_type == "QUALITY_GATE"
        assert agent.name == "Quality Gate (A.I.E.F.N.M.W. Sentry)"

    def test_validate_phase(self, agent):
        """Test phase validation."""
        result = agent._execute_impl({
            "action": "validate_phase",
            "phase_name": "test_phase",
            "phase_data": {
                "required_fields": ["field1"],
                "field1": "value1"
            }
        })
        
        assert result["status"] == "success"
        assert "passed" in result
        assert "results" in result

    def test_check_accuracy(self, agent):
        """Test accuracy check."""
        result = agent._execute_impl({
            "action": "check_accuracy",
            "data": {
                "required_fields": ["field1", "field2"],
                "field1": "value1",
                "field2": "value2"
            }
        })
        
        assert result["status"] == "success"
        assert "passed" in result
        assert "score" in result

    def test_check_integrity(self, agent):
        """Test integrity check."""
        result = agent._execute_impl({
            "action": "check_integrity",
            "data": {"field1": "value1"}
        })
        
        assert result["status"] == "success"
        assert "passed" in result

    def test_check_efficiency(self, agent):
        """Test efficiency check."""
        result = agent._execute_impl({
            "action": "check_efficiency",
            "data": {
                "execution_time": 10,
                "memory_usage": 100,
                "cpu_usage": 50,
                "throughput": 100
            }
        })
        
        assert result["status"] == "success"
        assert "passed" in result
        assert "metrics" in result


class TestGovernanceAgent:
    """Tests for Governance Agent (Layer 3)."""

    @pytest.fixture
    def agent(self):
        """Create agent instance."""
        return GovernanceAgent()

    def test_agent_initialization(self, agent):
        """Test agent initialization."""
        assert agent.agent_type == "GOVERNANCE"
        assert agent.name == "Governance Manager"

    def test_create_approval_request(self, agent):
        """Test approval request creation."""
        result = agent._execute_impl({
            "action": "create_approval_request",
            "request_type": "test_request",
            "description": "Test description",
            "requester": "test_user",
            "approvers": ["admin"],
            "priority": "high"
        })
        
        assert result["status"] == "success"
        assert "request_id" in result
        assert "workflow_id" in result

    def test_create_policy(self, agent):
        """Test policy creation."""
        result = agent._execute_impl({
            "action": "create_policy",
            "policy_name": "test_policy",
            "rules": {"rule1": "value1"},
            "enforcement_level": "strict"
        })
        
        assert result["status"] == "success"
        assert "policy_id" in result

    def test_list_policies(self, agent):
        """Test policy listing."""
        result = agent._execute_impl({
            "action": "list_policies"
        })
        
        assert result["status"] == "success"
        assert "policies" in result
        assert "total" in result


class TestDocumentGeneratorAgent:
    """Tests for Document Generator Agent (Layer 5)."""

    @pytest.fixture
    def agent(self):
        """Create agent instance."""
        return DocumentGeneratorAgent()

    def test_agent_initialization(self, agent):
        """Test agent initialization."""
        assert agent.agent_type == "DOCUMENT_GENERATOR"
        assert agent.name == "Document Generator"

    def test_generate_manifest(self, agent):
        """Test manifest generation."""
        result = agent._execute_impl({
            "action": "generate_manifest",
            "research_topic": "Test Topic",
            "research_findings": {"finding1": "value1"},
            "metadata": {"test": True}
        })
        
        assert result["status"] == "success"
        assert "manifest_id" in result
        assert result["document_type"] == "manifest"
        assert "content" in result

    def test_generate_white_paper(self, agent):
        """Test white paper generation."""
        result = agent._execute_impl({
            "action": "generate_white_paper",
            "topic": "Test Topic",
            "research_data": {"data1": "value1"},
            "analysis": {"analysis1": "value1"}
        })
        
        assert result["status"] == "success"
        assert "paper_id" in result
        assert result["document_type"] == "white_paper"
        assert "content" in result

    def test_generate_topic_documentation(self, agent):
        """Test topic documentation generation."""
        result = agent._execute_impl({
            "action": "generate_topic_documentation",
            "topic": "Test Topic",
            "content": "Test content",
            "examples": ["example1", "example2"]
        })
        
        assert result["status"] == "success"
        assert "doc_id" in result
        assert result["document_type"] == "topic_documentation"
        assert "content" in result

    def test_generate_report(self, agent):
        """Test report generation."""
        result = agent._execute_impl({
            "action": "generate_report",
            "report_type": "analysis",
            "data": {"data1": "value1"}
        })
        
        assert result["status"] == "success"
        assert "report_id" in result
        assert "content" in result


class TestCompleteArchitectureIntegration:
    """Integration tests for complete architecture."""

    def test_all_agents_importable(self):
        """Test all agents can be imported."""
        from agents import (
            VersionManagerAgent,
            KnowledgeBaseAgent,
            QualityGateAgent,
            GovernanceAgent,
            DocumentGeneratorAgent
        )
        
        assert VersionManagerAgent is not None
        assert KnowledgeBaseAgent is not None
        assert QualityGateAgent is not None
        assert GovernanceAgent is not None
        assert DocumentGeneratorAgent is not None

    def test_orchestrator_has_all_agents(self):
        """Test orchestrator has all new agents."""
        from agents.online_orchestrator import OnlineOrchestrationAgent
        
        orchestrator = OnlineOrchestrationAgent()
        
        assert 'VERSION_MANAGER' in orchestrator.agents
        assert 'KNOWLEDGE_BASE' in orchestrator.agents
        assert 'QUALITY_GATE' in orchestrator.agents
        assert 'GOVERNANCE' in orchestrator.agents
        assert 'DOCUMENT_GENERATOR' in orchestrator.agents

    def test_orchestrator_has_complete_agent_count(self):
        """Test orchestrator has all agents (16 total)."""
        from agents.online_orchestrator import OnlineOrchestrationAgent
        
        orchestrator = OnlineOrchestrationAgent()
        
        # 5 new architecture agents + 11 original agents + 3 deep research = 19 total
        assert len(orchestrator.agents) >= 19

