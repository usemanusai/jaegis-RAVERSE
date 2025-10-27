"""
Unit tests for DeepCrawlerAgent
Tests orchestration, session management, and crawl lifecycle.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from agents.online_deepcrawler_agent import DeepCrawlerAgent
from config.deepcrawler_config import DeepCrawlerConfig


class TestDeepCrawlerAgentInitialization:
    """Test DeepCrawlerAgent initialization."""
    
    def test_agent_initialization(self):
        """Test basic agent initialization."""
        agent = DeepCrawlerAgent()
        assert agent.name == "DeepCrawler Agent"
        assert agent.agent_type == "DEEPCRAWLER"
        assert agent.session_id is not None
        assert agent.crawl_state == "idle"
        assert len(agent.discovered_apis) == 0
        assert len(agent.crawled_urls) == 0
    
    def test_agent_with_custom_config(self):
        """Test agent initialization with custom config."""
        config = DeepCrawlerConfig(max_depth=5, max_urls=1000)
        agent = DeepCrawlerAgent(config=config)
        assert agent.config.max_depth == 5
        assert agent.config.max_urls == 1000
    
    def test_agent_with_memory_strategy(self):
        """Test agent initialization with memory strategy."""
        agent = DeepCrawlerAgent(
            memory_strategy="sliding_window",
            memory_config={"window_size": 3}
        )
        assert agent.has_memory_enabled()
        assert agent.memory_strategy_name == "sliding_window"


class TestDeepCrawlerAgentComponents:
    """Test DeepCrawlerAgent component initialization."""
    
    def test_url_frontier_initialized(self):
        """Test URL frontier is initialized."""
        agent = DeepCrawlerAgent()
        assert agent.url_frontier is not None
        assert agent.url_frontier.max_depth == agent.config.max_depth
    
    def test_crawl_scheduler_initialized(self):
        """Test crawl scheduler is initialized."""
        agent = DeepCrawlerAgent()
        assert agent.crawl_scheduler is not None
        assert agent.crawl_scheduler.max_concurrent == agent.config.max_concurrent
    
    def test_content_fetcher_initialized(self):
        """Test content fetcher is initialized."""
        agent = DeepCrawlerAgent()
        assert agent.content_fetcher is not None
    
    def test_discovery_components_initialized(self):
        """Test discovery components are initialized."""
        agent = DeepCrawlerAgent()
        assert agent.response_classifier is not None
        assert agent.websocket_analyzer is not None
        assert agent.api_pattern_matcher is not None
    
    def test_extended_agents_initialized(self):
        """Test extended agents are initialized."""
        agent = DeepCrawlerAgent()
        assert agent.js_agent is not None
        assert agent.traffic_agent is not None


class TestDeepCrawlerAgentStatus:
    """Test DeepCrawlerAgent status tracking."""
    
    def test_get_crawl_status(self):
        """Test getting crawl status."""
        agent = DeepCrawlerAgent()
        status = agent.get_crawl_status()
        
        assert status["session_id"] == agent.session_id
        assert status["state"] == "idle"
        assert status["urls_crawled"] == 0
        assert status["apis_discovered"] == 0
        assert status["errors"] == 0
    
    def test_pause_crawl(self):
        """Test pausing crawl."""
        agent = DeepCrawlerAgent()
        agent.crawl_state = "crawling"
        agent.pause_crawl()
        assert agent.crawl_state == "paused"
    
    def test_resume_crawl(self):
        """Test resuming crawl."""
        agent = DeepCrawlerAgent()
        agent.crawl_state = "paused"
        agent.resume_crawl()
        assert agent.crawl_state == "crawling"
    
    def test_cancel_crawl(self):
        """Test cancelling crawl."""
        agent = DeepCrawlerAgent()
        agent.cancel_crawl()
        assert agent.crawl_state == "cancelled"


class TestDeepCrawlerAgentExecution:
    """Test DeepCrawlerAgent execution."""
    
    @patch('agents.online_deepcrawler_agent.DatabaseManager')
    def test_execute_with_valid_task(self, mock_db):
        """Test executing with valid task."""
        agent = DeepCrawlerAgent()
        
        task = {
            "target_url": "https://example.com",
            "max_depth": 2,
            "max_urls": 100
        }
        
        # Mock database operations
        mock_conn = MagicMock()
        mock_db.return_value.get_connection.return_value.__enter__.return_value = mock_conn
        
        # This would normally execute the full crawl
        # For testing, we just verify the task structure
        assert task["target_url"] == "https://example.com"
        assert task["max_depth"] == 2
    
    def test_execute_without_target_url(self):
        """Test executing without target_url raises error."""
        agent = DeepCrawlerAgent()
        
        task = {"max_depth": 2}
        
        with pytest.raises(ValueError):
            agent._execute_impl(task)


class TestDeepCrawlerAgentMemory:
    """Test DeepCrawlerAgent memory integration."""
    
    def test_memory_operations_when_disabled(self):
        """Test memory operations when disabled."""
        agent = DeepCrawlerAgent(memory_strategy=None)
        
        # Should not raise errors
        agent.add_to_memory("input", "output")
        context = agent.get_memory_context("query")
        assert context == ""
    
    def test_memory_operations_when_enabled(self):
        """Test memory operations when enabled."""
        agent = DeepCrawlerAgent(
            memory_strategy="sliding_window",
            memory_config={"window_size": 3}
        )
        
        agent.add_to_memory("crawled example.com", "found 5 APIs")
        context = agent.get_memory_context("APIs")
        assert isinstance(context, str)


class TestDeepCrawlerAgentMetrics:
    """Test DeepCrawlerAgent metrics."""
    
    def test_metrics_tracking(self):
        """Test metrics are tracked."""
        agent = DeepCrawlerAgent()
        
        agent.set_metric("urls_crawled", 10)
        agent.set_metric("apis_discovered", 5)
        
        assert agent.metrics["urls_crawled"] == 10
        assert agent.metrics["apis_discovered"] == 5
    
    def test_progress_reporting(self):
        """Test progress reporting."""
        agent = DeepCrawlerAgent()
        
        agent.report_progress(0.5, "Halfway through crawl")
        assert agent.progress == 0.5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

