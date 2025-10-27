"""
End-to-end tests for knowledge base workflow
Tests complete knowledge storage and retrieval cycle
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import numpy as np

from agents.online_knowledge_base_agent import KnowledgeBaseAgent


@pytest.fixture
def knowledge_base_e2e():
    """Create KnowledgeBaseAgent for E2E testing."""
    with patch('agents.online_knowledge_base_agent.DatabaseManager'):
        with patch('agents.online_knowledge_base_agent.SentenceTransformer'):
            agent = KnowledgeBaseAgent()
            agent.db_manager = Mock()
            agent.embedding_model = Mock()
            agent.api_key = "test-key"
            return agent


class TestKnowledgeBaseWorkflow:
    """Test complete knowledge base workflow."""
    
    def test_store_and_retrieve_knowledge(self, knowledge_base_e2e):
        """Test storing and retrieving knowledge."""
        agent = knowledge_base_e2e
        
        # Mock database
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        # Mock embedding
        agent.embedding_model.encode.return_value = np.random.rand(384)
        
        # Store knowledge
        store_result = agent._store_knowledge({
            "content": "Test knowledge content",
            "source": "test_source",
            "metadata": {"key": "value"}
        })
        
        assert store_result["status"] == "success"
        assert "knowledge_id" in store_result
        
        # Search knowledge
        mock_cursor.fetchall.return_value = [
            {"knowledge_id": store_result["knowledge_id"], "content": "Test knowledge content", "similarity": 0.95}
        ]
        
        search_result = agent._search_knowledge({
            "query": "test",
            "limit": 5
        })
        
        assert search_result["status"] == "success"
        assert len(search_result["results"]) > 0
    
    def test_iterative_research_workflow(self, knowledge_base_e2e):
        """Test iterative research workflow."""
        agent = knowledge_base_e2e
        
        # Mock database
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            {"knowledge_id": "1", "content": "result", "similarity": 0.95}
        ]
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        # Mock embedding
        agent.embedding_model.encode.return_value = np.random.rand(384)
        
        # Mock LLM
        with patch.object(agent, '_call_llm', return_value="refined query"):
            result = agent._iterative_research({
                "initial_query": "test query",
                "max_iterations": 3
            })
        
        assert result["status"] == "success"
        assert "research_results" in result
    
    def test_semantic_search_workflow(self, knowledge_base_e2e):
        """Test semantic search workflow."""
        agent = knowledge_base_e2e
        
        # Mock database
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            {"knowledge_id": "1", "content": "result1", "similarity": 0.95},
            {"knowledge_id": "2", "content": "result2", "similarity": 0.87},
            {"knowledge_id": "3", "content": "result3", "similarity": 0.45}  # Below threshold
        ]
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        # Mock embedding
        agent.embedding_model.encode.return_value = np.random.rand(384)
        
        # Search with threshold
        result = agent._search_knowledge({
            "query": "test",
            "threshold": 0.5,
            "limit": 10
        })
        
        assert result["status"] == "success"
        # Should filter out results below threshold
        assert all(r["similarity"] >= 0.5 for r in result["results"])


class TestKnowledgeStorageFormats:
    """Test different knowledge storage formats."""
    
    def test_store_text_knowledge(self, knowledge_base_e2e):
        """Test storing text knowledge."""
        agent = knowledge_base_e2e
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        agent.embedding_model.encode.return_value = np.random.rand(384)
        
        result = agent._store_knowledge({
            "content": "Text content",
            "source": "text_source"
        })
        
        assert result["status"] == "success"
    
    def test_store_knowledge_with_metadata(self, knowledge_base_e2e):
        """Test storing knowledge with metadata."""
        agent = knowledge_base_e2e
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        agent.embedding_model.encode.return_value = np.random.rand(384)
        
        result = agent._store_knowledge({
            "content": "Content",
            "source": "source",
            "metadata": {
                "author": "test",
                "date": "2025-10-26",
                "tags": ["tag1", "tag2"]
            }
        })
        
        assert result["status"] == "success"


class TestSearchQualityMetrics:
    """Test search quality metrics."""
    
    def test_similarity_score_calculation(self, knowledge_base_e2e):
        """Test similarity score calculation."""
        agent = knowledge_base_e2e
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            {"knowledge_id": "1", "content": "result", "similarity": 0.95},
            {"knowledge_id": "2", "content": "result", "similarity": 0.87},
            {"knowledge_id": "3", "content": "result", "similarity": 0.72}
        ]
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        agent.embedding_model.encode.return_value = np.random.rand(384)
        
        result = agent._search_knowledge({
            "query": "test",
            "limit": 10
        })
        
        assert result["status"] == "success"
        # Verify results are sorted by similarity
        similarities = [r["similarity"] for r in result["results"]]
        assert similarities == sorted(similarities, reverse=True)
    
    def test_threshold_filtering(self, knowledge_base_e2e):
        """Test threshold filtering."""
        agent = knowledge_base_e2e
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            {"knowledge_id": "1", "content": "result", "similarity": 0.95},
            {"knowledge_id": "2", "content": "result", "similarity": 0.87},
            {"knowledge_id": "3", "content": "result", "similarity": 0.45},
            {"knowledge_id": "4", "content": "result", "similarity": 0.30}
        ]
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        agent.embedding_model.encode.return_value = np.random.rand(384)
        
        result = agent._search_knowledge({
            "query": "test",
            "threshold": 0.5
        })
        
        assert result["status"] == "success"
        # All results should be above threshold
        assert all(r["similarity"] >= 0.5 for r in result["results"])


class TestRAGCycle:
    """Test RAG cycle."""
    
    def test_rag_convergence(self, knowledge_base_e2e):
        """Test RAG convergence."""
        agent = knowledge_base_e2e
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = [
            {"knowledge_id": "1", "content": "result", "similarity": 0.95}
        ]
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        agent.embedding_model.encode.return_value = np.random.rand(384)
        
        with patch.object(agent, '_call_llm', return_value="refined"):
            result = agent._iterative_research({
                "initial_query": "test",
                "max_iterations": 3
            })
        
        assert result["status"] == "success"


