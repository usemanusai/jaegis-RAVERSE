import pytest
import os
from unittest.mock import Mock, patch, MagicMock
import json

from src.agents.llm_agent import LLMAgent, get_llm_agent
import src.agents.llm_agent as llm_agent_module

class TestLLMAgent:
    @pytest.fixture
    def mock_llm_agent(self):
        with patch('src.agents.llm_agent.ChatOpenAI') as mock_chat:
            agent = LLMAgent(api_key="test_key")
            # Replace the mock with a Mock we can easily configure
            agent.llm = Mock()
            return agent

    def test_analyze_assembly_json_decode_error(self, mock_llm_agent):
        # Configure the mock to return invalid JSON
        mock_response = Mock()
        mock_response.content = "Not a JSON string"
        mock_llm_agent.llm.invoke.return_value = mock_response

        # Call the function
        result = mock_llm_agent.analyze_assembly("mov eax, 1")

        # Verify it handled the JSONDecodeError properly
        assert "raw_analysis" in result
        assert result["raw_analysis"] == "Not a JSON string"

    def test_identify_password_check_json_decode_error(self, mock_llm_agent):
        mock_response = Mock()
        mock_response.content = "Invalid JSON"
        mock_llm_agent.llm.invoke.return_value = mock_response

        result = mock_llm_agent.identify_password_check("test code")

        assert "raw_analysis" in result
        assert result["raw_analysis"] == "Invalid JSON"

    def test_suggest_patch_location_json_decode_error(self, mock_llm_agent):
        mock_response = Mock()
        mock_response.content = "Invalid JSON"
        mock_llm_agent.llm.invoke.return_value = mock_response

        result = mock_llm_agent.suggest_patch_location("test code", {})

        assert "raw_suggestions" in result
        assert result["raw_suggestions"] == "Invalid JSON"

    def test_generate_patch_strategies_json_decode_error(self, mock_llm_agent):
        mock_response = Mock()
        mock_response.content = "Invalid JSON"
        mock_llm_agent.llm.invoke.return_value = mock_response

        result = mock_llm_agent.generate_patch_strategies("test code", "target")

        assert len(result) == 1
        assert "raw_strategies" in result[0]
        assert result[0]["raw_strategies"] == "Invalid JSON"


@pytest.fixture(autouse=True)
def reset_global_llm_agent():
    """Reset the global _llm_agent before and after each test."""
    original_agent = llm_agent_module._llm_agent
    llm_agent_module._llm_agent = None
    yield
    llm_agent_module._llm_agent = original_agent


@patch.dict(os.environ, {"OPENROUTER_API_KEY": "test_api_key"})
def test_get_llm_agent_returns_instance():
    """Test that get_llm_agent returns an instance of LLMAgent."""
    agent = get_llm_agent()
    assert isinstance(agent, LLMAgent)
    assert agent.api_key == "test_api_key"
    assert agent.model == LLMAgent.DEFAULT_MODEL
    assert agent.cache_manager is None


@patch.dict(os.environ, {"OPENROUTER_API_KEY": "test_api_key"})
def test_get_llm_agent_caches_instance():
    """Test that get_llm_agent reuses the globally cached instance."""
    agent1 = get_llm_agent()
    agent2 = get_llm_agent()

    assert agent1 is agent2


@patch.dict(os.environ, {"OPENROUTER_API_KEY": "test_api_key"})
def test_get_llm_agent_with_custom_parameters():
    """Test that get_llm_agent passes parameters correctly."""
    custom_model = "custom-model"
    mock_cache = MagicMock()

    agent = get_llm_agent(model=custom_model, cache_manager=mock_cache)

    assert isinstance(agent, LLMAgent)
    assert agent.model == custom_model
    assert agent.cache_manager is mock_cache
