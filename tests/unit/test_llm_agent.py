import pytest
from unittest.mock import Mock, patch
import json
from src.agents.llm_agent import LLMAgent, get_llm_agent

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
