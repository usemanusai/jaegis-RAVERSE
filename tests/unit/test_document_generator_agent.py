"""
Unit tests for DocumentGeneratorAgent
Tests document generation, LLM integration, and database persistence
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import psycopg2

from agents.online_document_generator_agent import DocumentGeneratorAgent


@pytest.fixture
def document_generator_agent():
    """Create a DocumentGeneratorAgent instance for testing."""
    with patch('agents.online_document_generator_agent.DatabaseManager'):
        agent = DocumentGeneratorAgent()
        agent.db_manager = Mock()
        agent.api_key = "test-key"
        return agent


class TestDocumentGeneratorAgent:
    """Test suite for DocumentGeneratorAgent."""
    
    def test_initialization(self, document_generator_agent):
        """Test agent initialization."""
        assert document_generator_agent.agent_type == "DocumentGenerator"
        assert document_generator_agent.max_retries == 3
        assert document_generator_agent.retry_backoff == 2
    
    def test_generate_manifest_success(self, document_generator_agent):
        """Test successful manifest generation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        document_generator_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(document_generator_agent, '_call_llm', return_value="Generated manifest"):
            result = document_generator_agent._generate_manifest({
                "analysis_id": "analysis123",
                "findings": ["finding1", "finding2"],
                "metadata": {"key": "value"}
            })
        
        assert result["status"] == "success"
        assert "manifest_id" in result
        mock_cursor.execute.assert_called()
    
    def test_generate_white_paper_success(self, document_generator_agent):
        """Test successful white paper generation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        document_generator_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(document_generator_agent, '_call_llm', return_value="Generated white paper"):
            result = document_generator_agent._generate_white_paper({
                "analysis_id": "analysis123",
                "research_data": {"key": "value"},
                "title": "Test White Paper"
            })
        
        assert result["status"] == "success"
        assert "white_paper_id" in result
        mock_cursor.execute.assert_called()
    
    def test_call_llm_success(self, document_generator_agent):
        """Test successful LLM call."""
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "Generated content"}}]
            }
            mock_post.return_value = mock_response
            
            result = document_generator_agent._call_llm("Generate document")
            
            assert result == "Generated content"
            mock_post.assert_called_once()
    
    def test_call_llm_with_retry(self, document_generator_agent):
        """Test LLM call with retry logic."""
        with patch('requests.post') as mock_post:
            mock_response_429 = Mock()
            mock_response_429.status_code = 429
            
            mock_response_200 = Mock()
            mock_response_200.status_code = 200
            mock_response_200.json.return_value = {
                "choices": [{"message": {"content": "Generated content"}}]
            }
            
            mock_post.side_effect = [mock_response_429, mock_response_200]
            
            with patch('time.sleep'):
                result = document_generator_agent._call_llm("Generate document")
            
            assert result == "Generated content"
    
    def test_generate_report_success(self, document_generator_agent):
        """Test successful report generation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        document_generator_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(document_generator_agent, '_call_llm', return_value="Generated report"):
            result = document_generator_agent._generate_report({
                "analysis_id": "analysis123",
                "format": "markdown",
                "data": {"key": "value"}
            })
        
        assert result["status"] == "success"
        assert "report_id" in result
    
    def test_database_error_handling(self, document_generator_agent):
        """Test database error handling."""
        document_generator_agent.db_manager.get_connection.side_effect = psycopg2.OperationalError("Connection failed")
        
        with pytest.raises(psycopg2.OperationalError):
            document_generator_agent._generate_manifest({
                "analysis_id": "analysis123",
                "findings": []
            })
    
    def test_execute_success(self, document_generator_agent):
        """Test successful agent execution."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        document_generator_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(document_generator_agent, '_call_llm', return_value="Generated"):
            result = document_generator_agent.execute({
                "action": "generate_manifest",
                "analysis_id": "analysis123",
                "findings": []
            })
        
        assert result["status"] == "success"
        assert result["agent_type"] == "DocumentGenerator"


class TestDocumentGeneration:
    """Test document generation functionality."""
    
    def test_manifest_format(self, document_generator_agent):
        """Test manifest format."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        document_generator_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(document_generator_agent, '_call_llm', return_value="Manifest content"):
            result = document_generator_agent._generate_manifest({
                "analysis_id": "analysis123",
                "findings": ["finding1"]
            })
        
        assert result["status"] == "success"
    
    def test_white_paper_format(self, document_generator_agent):
        """Test white paper format."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        document_generator_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(document_generator_agent, '_call_llm', return_value="White paper content"):
            result = document_generator_agent._generate_white_paper({
                "analysis_id": "analysis123",
                "research_data": {},
                "title": "Test"
            })
        
        assert result["status"] == "success"
    
    def test_report_format(self, document_generator_agent):
        """Test report format."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        document_generator_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(document_generator_agent, '_call_llm', return_value="Report content"):
            result = document_generator_agent._generate_report({
                "analysis_id": "analysis123",
                "format": "markdown",
                "data": {}
            })
        
        assert result["status"] == "success"


class TestLLMIntegration:
    """Test LLM integration."""
    
    def test_llm_timeout_handling(self, document_generator_agent):
        """Test LLM timeout handling."""
        with patch('requests.post') as mock_post:
            import requests
            mock_post.side_effect = requests.exceptions.Timeout("Request timeout")
            
            result = document_generator_agent._call_llm("Generate")
            
            assert result == ""
    
    def test_llm_rate_limiting(self, document_generator_agent):
        """Test LLM rate limiting."""
        with patch('requests.post') as mock_post:
            mock_response_429 = Mock()
            mock_response_429.status_code = 429
            
            mock_response_200 = Mock()
            mock_response_200.status_code = 200
            mock_response_200.json.return_value = {
                "choices": [{"message": {"content": "Generated"}}]
            }
            
            mock_post.side_effect = [mock_response_429, mock_response_200]
            
            with patch('time.sleep'):
                result = document_generator_agent._call_llm("Generate")
            
            assert result == "Generated"


class TestDocumentGeneratorDatabaseOperations:
    """Test database operations in DocumentGeneratorAgent."""
    
    def test_document_persistence(self, document_generator_agent):
        """Test document persistence."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        document_generator_agent.db_manager.get_connection.return_value.__enter__.return_value = mock_conn
        
        with patch.object(document_generator_agent, '_call_llm', return_value="Content"):
            document_generator_agent._generate_manifest({
                "analysis_id": "analysis123",
                "findings": []
            })
        
        # Verify database operation
        mock_cursor.execute.assert_called()
        mock_conn.commit.assert_called()


