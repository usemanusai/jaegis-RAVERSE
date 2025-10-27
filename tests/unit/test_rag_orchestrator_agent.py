"""
Unit tests for RAGOrchestratorAgent
Tests iterative research, query refinement, and knowledge synthesis
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import psycopg2

from agents.online_rag_orchestrator_agent import RAGOrchestratorAgent


@pytest.fixture
def rag_orchestrator_agent():
    """Create a RAGOrchestratorAgent instance for testing."""
    with patch('agents.online_rag_orchestrator_agent.DatabaseManager'):
        agent = RAGOrchestratorAgent()
        agent.db_manager = Mock()
        agent.api_key = "test-key"
        return agent


class TestRAGOrchestratorAgent:
    """Test suite for RAGOrchestratorAgent."""
    
    def test_initialization(self, rag_orchestrator_agent):
        """Test agent initialization."""
        assert rag_orchestrator_agent.agent_type == "RAGOrchestrator"
        assert rag_orchestrator_agent.max_retries == 3
        assert rag_orchestrator_agent.convergence_threshold == 0.85
    
    def test_iterative_research_success(self, rag_orchestrator_agent):
        """Test successful iterative research."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            {"knowledge_id": "1", "content": "result", "similarity": 0.95}
        ]
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        rag_orchestrator_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(rag_orchestrator_agent, '_call_llm', return_value="refined query"):
            result = rag_orchestrator_agent._iterative_research({
                "initial_query": "test query",
                "max_iterations": 3
            })
        
        assert result["status"] == "success"
        assert "research_results" in result
        mock_cursor.execute.assert_called()
    
    def test_refine_query_success(self, rag_orchestrator_agent):
        """Test successful query refinement."""
        with patch.object(rag_orchestrator_agent, '_call_llm', return_value="refined query"):
            result = rag_orchestrator_agent._refine_query({
                "current_query": "test query",
                "findings": ["finding1", "finding2"]
            })
        
        assert result["status"] == "success"
        assert "refined_query" in result
    
    def test_synthesize_knowledge_success(self, rag_orchestrator_agent):
        """Test successful knowledge synthesis."""
        with patch.object(rag_orchestrator_agent, '_call_llm', return_value="synthesized knowledge"):
            result = rag_orchestrator_agent._synthesize_knowledge({
                "research_data": [
                    {"content": "data1", "similarity": 0.95},
                    {"content": "data2", "similarity": 0.87}
                ]
            })
        
        assert result["status"] == "success"
        assert "synthesis" in result
    
    def test_call_llm_success(self, rag_orchestrator_agent):
        """Test successful LLM call."""
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "LLM response"}}]
            }
            mock_post.return_value = mock_response
            
            result = rag_orchestrator_agent._call_llm("test prompt")
            
            assert result == "LLM response"
            mock_post.assert_called_once()
    
    def test_convergence_threshold(self, rag_orchestrator_agent):
        """Test convergence threshold."""
        assert rag_orchestrator_agent.convergence_threshold == 0.85
    
    def test_max_iterations(self, rag_orchestrator_agent):
        """Test max iterations."""
        assert rag_orchestrator_agent.max_iterations == 3
    
    def test_database_error_handling(self, rag_orchestrator_agent):
        """Test database error handling."""
        rag_orchestrator_agent.db_manager.get_connection.side_effect = psycopg2.OperationalError("Connection failed")
        
        with pytest.raises(psycopg2.OperationalError):
            rag_orchestrator_agent._iterative_research({
                "initial_query": "test query"
            })
    
    def test_execute_success(self, rag_orchestrator_agent):
        """Test successful agent execution."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        rag_orchestrator_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(rag_orchestrator_agent, '_call_llm', return_value="response"):
            result = rag_orchestrator_agent.execute({
                "action": "iterative_research",
                "initial_query": "test query"
            })
        
        assert result["status"] == "success"
        assert result["agent_type"] == "RAGOrchestrator"


class TestIterativeResearch:
    """Test iterative research functionality."""
    
    def test_research_cycle_one(self, rag_orchestrator_agent):
        """Test first research cycle."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            {"knowledge_id": "1", "content": "result", "similarity": 0.95}
        ]
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        rag_orchestrator_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(rag_orchestrator_agent, '_call_llm', return_value="refined"):
            result = rag_orchestrator_agent._iterative_research({
                "initial_query": "test",
                "max_iterations": 3
            })
        
        assert result["status"] == "success"
    
    def test_research_convergence(self, rag_orchestrator_agent):
        """Test research convergence."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            {"knowledge_id": "1", "content": "result", "similarity": 0.95}
        ]
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        rag_orchestrator_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(rag_orchestrator_agent, '_call_llm', return_value="refined"):
            result = rag_orchestrator_agent._iterative_research({
                "initial_query": "test",
                "max_iterations": 3
            })
        
        assert result["status"] == "success"


class TestQueryRefinement:
    """Test query refinement functionality."""
    
    def test_query_refinement_with_findings(self, rag_orchestrator_agent):
        """Test query refinement with findings."""
        with patch.object(rag_orchestrator_agent, '_call_llm', return_value="refined query"):
            result = rag_orchestrator_agent._refine_query({
                "current_query": "test query",
                "findings": ["finding1", "finding2"]
            })
        
        assert result["status"] == "success"
        assert "refined_query" in result
    
    def test_query_refinement_empty_findings(self, rag_orchestrator_agent):
        """Test query refinement with empty findings."""
        with patch.object(rag_orchestrator_agent, '_call_llm', return_value="refined query"):
            result = rag_orchestrator_agent._refine_query({
                "current_query": "test query",
                "findings": []
            })
        
        assert result["status"] == "success"


class TestKnowledgeSynthesis:
    """Test knowledge synthesis functionality."""
    
    def test_synthesis_with_multiple_sources(self, rag_orchestrator_agent):
        """Test synthesis with multiple sources."""
        with patch.object(rag_orchestrator_agent, '_call_llm', return_value="synthesized"):
            result = rag_orchestrator_agent._synthesize_knowledge({
                "research_data": [
                    {"content": "data1", "similarity": 0.95},
                    {"content": "data2", "similarity": 0.87},
                    {"content": "data3", "similarity": 0.78}
                ]
            })
        
        assert result["status"] == "success"
        assert "synthesis" in result
    
    def test_synthesis_with_single_source(self, rag_orchestrator_agent):
        """Test synthesis with single source."""
        with patch.object(rag_orchestrator_agent, '_call_llm', return_value="synthesized"):
            result = rag_orchestrator_agent._synthesize_knowledge({
                "research_data": [
                    {"content": "data1", "similarity": 0.95}
                ]
            })
        
        assert result["status"] == "success"


class TestRAGOrchestratorLLMIntegration:
    """Test LLM integration in RAGOrchestratorAgent."""
    
    def test_llm_call_with_retry(self, rag_orchestrator_agent):
        """Test LLM call with retry logic."""
        with patch('requests.post') as mock_post:
            mock_response_429 = Mock()
            mock_response_429.status_code = 429
            
            mock_response_200 = Mock()
            mock_response_200.status_code = 200
            mock_response_200.json.return_value = {
                "choices": [{"message": {"content": "response"}}]
            }
            
            mock_post.side_effect = [mock_response_429, mock_response_200]
            
            with patch('time.sleep'):
                result = rag_orchestrator_agent._call_llm("test")
            
            assert result == "response"
    
    def test_llm_timeout_handling(self, rag_orchestrator_agent):
        """Test LLM timeout handling."""
        with patch('requests.post') as mock_post:
            import requests
            mock_post.side_effect = requests.exceptions.Timeout("Timeout")
            
            result = rag_orchestrator_agent._call_llm("test")
            
            assert result == ""


class TestRAGOrchestratorDatabaseOperations:
    """Test database operations in RAGOrchestratorAgent."""
    
    def test_research_persistence(self, rag_orchestrator_agent):
        """Test research persistence."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        rag_orchestrator_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(rag_orchestrator_agent, '_call_llm', return_value="response"):
            rag_orchestrator_agent._iterative_research({
                "initial_query": "test"
            })
        
        # Verify database operation
        mock_cursor.execute.assert_called()


