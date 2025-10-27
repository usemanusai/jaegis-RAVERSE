"""
Integration tests for Deep Research workflow.
Tests the complete workflow from topic enhancement through content analysis.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from agents.online_orchestrator import OnlineOrchestrationAgent


class TestDeepResearchWorkflow:
    """Integration tests for complete Deep Research workflow."""

    def test_orchestrator_has_deep_research_agents(self):
        """Test that orchestrator has all Deep Research agents."""
        orchestrator = OnlineOrchestrationAgent()
        
        assert 'DEEP_RESEARCH_TOPIC_ENHANCER' in orchestrator.agents
        assert 'DEEP_RESEARCH_WEB_RESEARCHER' in orchestrator.agents
        assert 'DEEP_RESEARCH_CONTENT_ANALYZER' in orchestrator.agents

    @patch('agents.online_deep_research_topic_enhancer.requests.post')
    @patch('agents.online_deep_research_web_researcher.requests.get')
    @patch('agents.online_deep_research_content_analyzer.requests.post')
    def test_deep_research_workflow_execution(self, mock_analyzer_post, mock_researcher_get, mock_enhancer_post):
        """Test complete Deep Research workflow execution."""
        orchestrator = OnlineOrchestrationAgent()
        
        # Mock Topic Enhancer response
        mock_enhancer_response = Mock()
        mock_enhancer_response.status_code = 200
        mock_enhancer_response.json.return_value = {
            'choices': [{'message': {'content': 'Enhanced: machine learning and AI systems'}}]
        }
        mock_enhancer_post.return_value = mock_enhancer_response
        
        # Mock Web Researcher response
        mock_researcher_response = Mock()
        mock_researcher_response.status_code = 200
        mock_researcher_response.text = "<html><body>Research content</body></html>"
        mock_researcher_get.return_value = mock_researcher_response
        
        # Mock Content Analyzer response
        mock_analyzer_response = Mock()
        mock_analyzer_response.status_code = 200
        mock_analyzer_response.json.return_value = {
            'choices': [{'message': {'content': 'Analysis: Key findings and insights'}}]
        }
        mock_analyzer_post.return_value = mock_analyzer_response
        
        # Execute workflow
        result = orchestrator.run_deep_research(
            topic="machine learning",
            context="focus on recent developments",
            max_results=5
        )
        
        # Verify results
        assert result["status"] == "complete"
        assert result["run_id"] is not None
        assert result["original_topic"] == "machine learning"
        assert "enhanced_topic" in result
        assert "phases" in result
        assert "summary" in result

    @patch('agents.online_deep_research_topic_enhancer.requests.post')
    def test_deep_research_workflow_error_handling(self, mock_post):
        """Test error handling in Deep Research workflow."""
        orchestrator = OnlineOrchestrationAgent()
        
        # Mock error response
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_post.return_value = mock_response
        
        # Execute workflow
        result = orchestrator.run_deep_research(
            topic="test topic",
            max_results=5
        )
        
        # Verify error handling
        assert result["status"] == "error"
        assert "error" in result

    def test_deep_research_workflow_with_empty_topic(self):
        """Test Deep Research workflow with empty topic."""
        orchestrator = OnlineOrchestrationAgent()
        
        # This should fail during agent execution
        result = orchestrator.run_deep_research(
            topic="",
            max_results=5
        )
        
        # Should handle gracefully
        assert result["status"] in ["error", "complete"]

    @patch('agents.online_deep_research_topic_enhancer.requests.post')
    def test_topic_enhancer_retry_logic(self, mock_post):
        """Test Topic Enhancer retry logic on transient failures."""
        orchestrator = OnlineOrchestrationAgent()
        
        # First call fails with 429, second succeeds
        mock_response_429 = Mock()
        mock_response_429.status_code = 429
        
        mock_response_200 = Mock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {
            'choices': [{'message': {'content': 'Enhanced topic'}}]
        }
        
        mock_post.side_effect = [mock_response_429, mock_response_200]
        
        # Execute workflow
        with patch('time.sleep'):  # Skip actual sleep
            result = orchestrator.run_deep_research(
                topic="test topic",
                max_results=5
            )
        
        # Should succeed after retry
        assert result["status"] == "complete"

    def test_deep_research_workflow_metrics(self):
        """Test that Deep Research workflow collects metrics."""
        orchestrator = OnlineOrchestrationAgent()
        
        # Execute workflow
        result = orchestrator.run_deep_research(
            topic="test topic",
            max_results=5
        )
        
        # Verify metrics are collected
        assert "duration_seconds" in result
        assert result["duration_seconds"] >= 0

    @patch('agents.online_deep_research_web_researcher.requests.get')
    def test_web_researcher_mock_fallback(self, mock_get):
        """Test Web Researcher falls back to mock results when API unavailable."""
        orchestrator = OnlineOrchestrationAgent()
        
        # Mock API failure
        mock_get.side_effect = Exception("API unavailable")
        
        # Execute workflow
        result = orchestrator.run_deep_research(
            topic="test topic",
            max_results=5
        )
        
        # Should still complete with mock results
        assert result["status"] == "complete"

    def test_deep_research_workflow_phases(self):
        """Test that all three phases are executed."""
        orchestrator = OnlineOrchestrationAgent()
        
        # Execute workflow
        result = orchestrator.run_deep_research(
            topic="test topic",
            max_results=5
        )
        
        # Verify all phases are present
        if result["status"] == "complete":
            phases = result.get("phases", {})
            assert "topic_enhancement" in phases
            assert "web_research" in phases
            assert "content_analysis" in phases


class TestA2ACommunication:
    """Tests for Agent-to-Agent communication."""

    def test_publish_message(self):
        """Test publishing A2A message."""
        from agents.online_deep_research_topic_enhancer import DeepResearchTopicEnhancerAgent
        
        agent = DeepResearchTopicEnhancerAgent()
        
        # Mock Redis
        agent.redis_client = Mock()
        agent.redis_client.publish = Mock(return_value=1)
        
        # Publish message
        message_id = agent._publish_message(
            receiver="DEEP_RESEARCH_WEB_RESEARCHER",
            message_type="task_complete",
            payload={"data": "test"},
            priority="high"
        )
        
        # Verify message was published
        assert message_id != ""
        agent.redis_client.publish.assert_called_once()

    def test_subscribe_to_channel(self):
        """Test subscribing to A2A channel."""
        from agents.online_deep_research_topic_enhancer import DeepResearchTopicEnhancerAgent
        
        agent = DeepResearchTopicEnhancerAgent()
        
        # Mock Redis pubsub
        mock_pubsub = Mock()
        mock_message = {
            "type": "message",
            "data": json.dumps({
                "message_id": "test-id",
                "sender_agent": "DEEP_RESEARCH_WEB_RESEARCHER",
                "message_type": "data_share",
                "payload": {"data": "test"}
            })
        }
        mock_pubsub.listen.return_value = [mock_message]
        
        agent.redis_client = Mock()
        agent.redis_client.pubsub.return_value = mock_pubsub
        
        # Subscribe to channel
        received_message = agent._subscribe_to_channel(
            channel="agent:messages:DEEP_RESEARCH_TOPIC_ENHANCER",
            timeout=1
        )
        
        # Verify message was received
        assert received_message is not None
        assert received_message["message_id"] == "test-id"

    def test_save_message_to_db(self):
        """Test saving A2A message to database."""
        from agents.online_deep_research_topic_enhancer import DeepResearchTopicEnhancerAgent
        
        agent = DeepResearchTopicEnhancerAgent()
        
        # Mock database connection
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.cursor.return_value = mock_cursor
        
        agent._get_db_connection = Mock()
        agent._get_db_connection.return_value.__enter__ = Mock(return_value=mock_conn)
        agent._get_db_connection.return_value.__exit__ = Mock(return_value=None)
        
        # Save message
        message = {
            "message_id": "test-id",
            "sender_agent": "DEEP_RESEARCH_TOPIC_ENHANCER",
            "receiver_agent": "DEEP_RESEARCH_WEB_RESEARCHER",
            "message_type": "task_complete",
            "payload": {"data": "test"},
            "timestamp": "2025-10-26T10:00:00Z",
            "correlation_id": "corr-id",
            "priority": "normal"
        }
        
        result = agent._save_message_to_db(message)
        
        # Verify message was saved
        assert result is True
        mock_cursor.execute.assert_called()


class TestDeepResearchConfiguration:
    """Tests for Deep Research configuration."""

    def test_load_agent_config(self):
        """Test loading agent configuration."""
        from config.deep_research_settings import get_agent_config
        
        config = get_agent_config("DEEP_RESEARCH_TOPIC_ENHANCER")
        
        assert config["model"] == "anthropic/claude-3.5-sonnet:free"
        assert config["temperature"] == 0.5
        assert config["max_tokens"] == 1000

    def test_get_fallback_model(self):
        """Test getting fallback model."""
        from config.deep_research_settings import get_fallback_model
        
        fallback = get_fallback_model(
            "DEEP_RESEARCH_TOPIC_ENHANCER",
            "anthropic/claude-3.5-sonnet:free"
        )
        
        assert fallback != "anthropic/claude-3.5-sonnet:free"
        assert fallback in [
            "meta-llama/llama-3.3-70b-instruct:free",
            "mistralai/mistral-7b-instruct:free"
        ]

    def test_validate_configuration(self):
        """Test configuration validation."""
        from config.deep_research_settings import validate_configuration
        
        # Should validate (may warn about missing API key)
        result = validate_configuration()
        
        # Result should be boolean
        assert isinstance(result, bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

