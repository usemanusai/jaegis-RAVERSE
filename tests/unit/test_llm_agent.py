import pytest
import os
from unittest.mock import patch, MagicMock

from src.agents.llm_agent import get_llm_agent, LLMAgent
import src.agents.llm_agent as llm_agent_module

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
