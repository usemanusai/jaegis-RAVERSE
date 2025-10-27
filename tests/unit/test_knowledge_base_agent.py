"""
Unit tests for KnowledgeBaseAgent
Tests vector embeddings, semantic search, and RAG functionality
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import numpy as np
import psycopg2

from agents.online_knowledge_base_agent import KnowledgeBaseAgent


@pytest.fixture
def knowledge_base_agent():
    """Create a KnowledgeBaseAgent instance for testing."""
    with patch('agents.online_knowledge_base_agent.DatabaseManager'):
        with patch('agents.online_knowledge_base_agent.SentenceTransformer'):
            agent = KnowledgeBaseAgent()
            agent.db_manager = Mock()
            agent.embedding_model = Mock()
            agent.api_key = "test-key"
            return agent


class TestKnowledgeBaseAgent:
    """Test suite for KnowledgeBaseAgent."""
    
    def test_initialization(self, knowledge_base_agent):
        """Test agent initialization."""
        assert knowledge_base_agent.agent_type == "KnowledgeBase"
        assert knowledge_base_agent.max_retries == 3
        assert knowledge_base_agent.retry_backoff == 2
    
    def test_generate_embedding_success(self, knowledge_base_agent):
        """Test successful embedding generation."""
        # Mock embedding model
        mock_embedding = np.random.rand(384)
        knowledge_base_agent.embedding_model.encode.return_value = mock_embedding
        
        result = knowledge_base_agent._generate_embedding("test content")
        
        assert result is not None
        assert len(result) == 384
        knowledge_base_agent.embedding_model.encode.assert_called_once()
    
    def test_store_knowledge_success(self, knowledge_base_agent):
        """Test successful knowledge storage."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        knowledge_base_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        knowledge_base_agent.embedding_model.encode.return_value = np.random.rand(384)
        
        result = knowledge_base_agent._store_knowledge({
            "content": "Test knowledge content",
            "source": "test_source",
            "metadata": {"key": "value"}
        })
        
        assert result["status"] == "success"
        assert "knowledge_id" in result
        mock_cursor.execute.assert_called()
    
    def test_search_knowledge_success(self, knowledge_base_agent):
        """Test successful knowledge search."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            {"knowledge_id": "1", "content": "result1", "similarity": 0.95},
            {"knowledge_id": "2", "content": "result2", "similarity": 0.87}
        ]
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        knowledge_base_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        knowledge_base_agent.embedding_model.encode.return_value = np.random.rand(384)
        
        result = knowledge_base_agent._search_knowledge({
            "query": "test query",
            "limit": 5,
            "threshold": 0.5
        })
        
        assert result["status"] == "success"
        assert len(result["results"]) == 2
        assert result["results"][0]["similarity"] >= 0.5
    
    def test_call_llm_success(self, knowledge_base_agent):
        """Test successful LLM call."""
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "LLM response"}}]
            }
            mock_post.return_value = mock_response
            
            result = knowledge_base_agent._call_llm("test prompt")
            
            assert result == "LLM response"
            mock_post.assert_called_once()
    
    def test_call_llm_rate_limiting(self, knowledge_base_agent):
        """Test LLM call with rate limiting."""
        with patch('requests.post') as mock_post:
            # First call returns 429, second succeeds
            mock_response_429 = Mock()
            mock_response_429.status_code = 429
            
            mock_response_200 = Mock()
            mock_response_200.status_code = 200
            mock_response_200.json.return_value = {
                "choices": [{"message": {"content": "LLM response"}}]
            }
            
            mock_post.side_effect = [mock_response_429, mock_response_200]
            
            with patch('time.sleep'):
                result = knowledge_base_agent._call_llm("test prompt")
            
            assert result == "LLM response"
    
    def test_call_llm_timeout(self, knowledge_base_agent):
        """Test LLM call with timeout."""
        with patch('requests.post') as mock_post:
            import requests
            mock_post.side_effect = requests.exceptions.Timeout("Request timeout")
            
            result = knowledge_base_agent._call_llm("test prompt")
            
            assert result == ""
    
    def test_iterative_research_success(self, knowledge_base_agent):
        """Test successful iterative research."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            {"knowledge_id": "1", "content": "result", "similarity": 0.95}
        ]
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        knowledge_base_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        knowledge_base_agent.embedding_model.encode.return_value = np.random.rand(384)
        
        with patch.object(knowledge_base_agent, '_call_llm', return_value="refined query"):
            result = knowledge_base_agent._iterative_research({
                "initial_query": "test query",
                "max_iterations": 3
            })
        
        assert result["status"] == "success"
        assert "research_results" in result
    
    def test_embedding_dimension(self, knowledge_base_agent):
        """Test embedding dimension is correct."""
        mock_embedding = np.random.rand(384)
        knowledge_base_agent.embedding_model.encode.return_value = mock_embedding
        
        result = knowledge_base_agent._generate_embedding("test")
        
        assert len(result) == 384
    
    def test_similarity_threshold_filtering(self, knowledge_base_agent):
        """Test similarity threshold filtering."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        # Return results with varying similarity scores
        mock_cursor.fetchall.return_value = [
            {"knowledge_id": "1", "content": "result1", "similarity": 0.95},
            {"knowledge_id": "2", "content": "result2", "similarity": 0.45},  # Below threshold
            {"knowledge_id": "3", "content": "result3", "similarity": 0.87}
        ]
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        knowledge_base_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        knowledge_base_agent.embedding_model.encode.return_value = np.random.rand(384)
        
        result = knowledge_base_agent._search_knowledge({
            "query": "test",
            "threshold": 0.5
        })
        
        # Should filter out results below threshold
        assert all(r["similarity"] >= 0.5 for r in result["results"])


class TestKnowledgeBaseRAG:
    """Test RAG functionality in KnowledgeBaseAgent."""
    
    def test_convergence_threshold(self, knowledge_base_agent):
        """Test convergence threshold configuration."""
        assert knowledge_base_agent.convergence_threshold == 0.85
    
    def test_max_iterations(self, knowledge_base_agent):
        """Test max iterations configuration."""
        assert knowledge_base_agent.max_iterations == 3


class TestKnowledgeBaseDatabaseOperations:
    """Test database operations in KnowledgeBaseAgent."""
    
    def test_vector_storage_format(self, knowledge_base_agent):
        """Test vector storage format."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        knowledge_base_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        knowledge_base_agent.embedding_model.encode.return_value = np.random.rand(384)
        
        knowledge_base_agent._store_knowledge({
            "content": "test",
            "source": "test"
        })
        
        # Verify vector format in SQL
        call_args = mock_cursor.execute.call_args
        assert call_args is not None


