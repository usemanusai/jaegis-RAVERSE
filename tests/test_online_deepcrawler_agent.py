import pytest
from unittest.mock import MagicMock, patch
from src.agents.online_deepcrawler_agent import DeepCrawlerAgent

@pytest.fixture
def mock_db():
    with patch("src.agents.online_deepcrawler_agent.DatabaseManager") as MockDB:
        yield MockDB

class TestDeepCrawlerAgent:
    """Test DeepCrawlerAgent."""

    def test_deepcrawler_initialization(self, mock_db):
        """Test DeepCrawler Agent initialization."""
        agent = DeepCrawlerAgent()
        assert agent.name == "DeepCrawler Agent"
        assert agent.agent_type == "DEEPCRAWLER"
        assert agent.crawl_state == "idle"
        assert isinstance(agent.discovered_apis, set)
        assert isinstance(agent.crawled_urls, set)
        assert isinstance(agent.errors, list)

    def test_deepcrawler_execute_missing_url(self, mock_db):
        """Test execute missing URL."""
        agent = DeepCrawlerAgent()
        with pytest.raises(ValueError, match="target_url is required"):
            agent._execute_impl({})

    @patch.object(DeepCrawlerAgent, "_initialize_crawl_session")
    @patch.object(DeepCrawlerAgent, "_crawl_phase")
    @patch.object(DeepCrawlerAgent, "_discover_apis_phase")
    @patch.object(DeepCrawlerAgent, "_document_phase")
    def test_deepcrawler_execute_success(self, mock_doc, mock_disc, mock_crawl, mock_init, mock_db):
        """Test successful crawl execution."""
        agent = DeepCrawlerAgent()
        agent.discovered_apis = {"api1", "api2"}
        agent.crawled_urls = {"url1", "url2", "url3"}
        mock_doc.return_value = {"doc": "test"}

        result = agent._execute_impl({"target_url": "http://example.com"})

        assert agent.crawl_state == "complete"
        assert result["target_url"] == "http://example.com"
        assert result["urls_crawled"] == 3
        assert result["apis_discovered"] == 2
        assert result["documentation"] == {"doc": "test"}

    def test_pause_resume_cancel(self, mock_db):
        """Test pause, resume, and cancel crawl operations."""
        agent = DeepCrawlerAgent()
        agent.pause_crawl()
        assert agent.crawl_state == "paused"
        agent.resume_crawl()
        assert agent.crawl_state == "crawling"
        agent.cancel_crawl()
        assert agent.crawl_state == "cancelled"

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
