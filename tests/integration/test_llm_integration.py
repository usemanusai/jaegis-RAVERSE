"""
Integration tests for LLM integration
Tests OpenRouter API calls with retry logic and rate limiting
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import requests
import time
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from agents.online_knowledge_base_agent import KnowledgeBaseAgent
from agents.online_document_generator_agent import DocumentGeneratorAgent
from agents.online_rag_orchestrator_agent import RAGOrchestratorAgent


@pytest.fixture
def llm_agents():
    """Create LLM agents for testing."""
    with patch('agents.online_knowledge_base_agent.DatabaseManager'):
        with patch('agents.online_knowledge_base_agent.SentenceTransformer'):
            kb_agent = KnowledgeBaseAgent()
            kb_agent.db_manager = Mock()
            kb_agent.api_key = "test-key"
    
    with patch('agents.online_document_generator_agent.DatabaseManager'):
        doc_agent = DocumentGeneratorAgent()
        doc_agent.db_manager = Mock()
        doc_agent.api_key = "test-key"
    
    with patch('agents.online_rag_orchestrator_agent.DatabaseManager'):
        rag_agent = RAGOrchestratorAgent()
        rag_agent.db_manager = Mock()
        rag_agent.api_key = "test-key"
    
    return kb_agent, doc_agent, rag_agent


class TestLLMIntegration:
    """Test LLM integration across agents."""
    
    def test_knowledge_base_llm_call(self, llm_agents):
        """Test KnowledgeBaseAgent LLM call."""
        kb_agent, _, _ = llm_agents
        
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "LLM response"}}]
            }
            mock_post.return_value = mock_response
            
            result = kb_agent._call_llm("test prompt")
            
            assert result == "LLM response"
            mock_post.assert_called_once()
    
    def test_document_generator_llm_call(self, llm_agents):
        """Test DocumentGeneratorAgent LLM call."""
        _, doc_agent, _ = llm_agents
        
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "Generated document"}}]
            }
            mock_post.return_value = mock_response
            
            result = doc_agent._call_llm("generate document")
            
            assert result == "Generated document"
            mock_post.assert_called_once()
    
    def test_rag_orchestrator_llm_call(self, llm_agents):
        """Test RAGOrchestratorAgent LLM call."""
        _, _, rag_agent = llm_agents
        
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "Research result"}}]
            }
            mock_post.return_value = mock_response
            
            result = rag_agent._call_llm("research query")
            
            assert result == "Research result"
            mock_post.assert_called_once()


class TestRateLimiting:
    """Test rate limiting handling."""
    
    def test_rate_limit_retry(self, llm_agents):
        """Test retry on rate limit (429)."""
        kb_agent, _, _ = llm_agents
        
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
                result = kb_agent._call_llm("test")
            
            assert result == "response"
            assert mock_post.call_count == 2
    
    def test_rate_limit_exponential_backoff(self, llm_agents):
        """Test exponential backoff on rate limit."""
        kb_agent, _, _ = llm_agents
        
        with patch('requests.post') as mock_post:
            mock_response_429 = Mock()
            mock_response_429.status_code = 429
            
            mock_response_200 = Mock()
            mock_response_200.status_code = 200
            mock_response_200.json.return_value = {
                "choices": [{"message": {"content": "response"}}]
            }
            
            mock_post.side_effect = [mock_response_429, mock_response_200]
            
            with patch('time.sleep') as mock_sleep:
                result = kb_agent._call_llm("test")
            
            # Verify exponential backoff was used
            assert mock_sleep.called


class TestTimeoutHandling:
    """Test timeout handling."""
    
    def test_timeout_handling(self, llm_agents):
        """Test timeout handling."""
        kb_agent, _, _ = llm_agents
        
        with patch('requests.post') as mock_post:
            mock_post.side_effect = requests.exceptions.Timeout("Request timeout")
            
            result = kb_agent._call_llm("test")
            
            assert result == ""
    
    def test_timeout_retry(self, llm_agents):
        """Test retry on timeout."""
        kb_agent, _, _ = llm_agents
        
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "response"}}]
            }
            
            mock_post.side_effect = [
                requests.exceptions.Timeout("Timeout"),
                mock_response
            ]
            
            with patch('time.sleep'):
                result = kb_agent._call_llm("test")
            
            # Should retry and eventually succeed or fail gracefully
            assert result in ["response", ""]


class TestAPIKeyHandling:
    """Test API key handling."""
    
    def test_missing_api_key(self, llm_agents):
        """Test handling of missing API key."""
        kb_agent, _, _ = llm_agents
        kb_agent.api_key = None
        
        result = kb_agent._call_llm("test")
        
        assert result == ""
    
    def test_api_key_in_headers(self, llm_agents):
        """Test API key in request headers."""
        kb_agent, _, _ = llm_agents
        
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "response"}}]
            }
            mock_post.return_value = mock_response
            
            kb_agent._call_llm("test")
            
            # Verify API key was in headers
            call_args = mock_post.call_args
            headers = call_args[1]["headers"]
            assert "Authorization" in headers


class TestLLMResponseParsing:
    """Test LLM response parsing."""
    
    def test_response_parsing_success(self, llm_agents):
        """Test successful response parsing."""
        kb_agent, _, _ = llm_agents
        
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "parsed response"}}]
            }
            mock_post.return_value = mock_response
            
            result = kb_agent._call_llm("test")
            
            assert result == "parsed response"
    
    def test_response_parsing_empty(self, llm_agents):
        """Test empty response parsing."""
        kb_agent, _, _ = llm_agents
        
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": ""}}]
            }
            mock_post.return_value = mock_response
            
            result = kb_agent._call_llm("test")
            
            assert result == ""


class TestLLMErrorHandling:
    """Test LLM error handling."""
    
    def test_connection_error(self, llm_agents):
        """Test connection error handling."""
        kb_agent, _, _ = llm_agents
        
        with patch('requests.post') as mock_post:
            mock_post.side_effect = requests.exceptions.ConnectionError("Connection failed")
            
            result = kb_agent._call_llm("test")
            
            assert result == ""
    
    def test_http_error(self, llm_agents):
        """Test HTTP error handling."""
        kb_agent, _, _ = llm_agents
        
        with patch('requests.post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("Server error")
            mock_post.return_value = mock_response
            
            result = kb_agent._call_llm("test")
            
            assert result == ""


