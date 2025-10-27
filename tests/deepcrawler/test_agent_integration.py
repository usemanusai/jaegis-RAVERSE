"""
Integration tests for DeepCrawler agents
Tests coordination between DeepCrawlerAgent and APIDocumentationAgent.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from agents.online_deepcrawler_agent import DeepCrawlerAgent
from agents.online_api_documentation_agent import APIDocumentationAgent


class TestAgentCoordination:
    """Test coordination between crawling and documentation agents."""
    
    def test_deepcrawler_and_documentation_agents_work_together(self):
        """Test that both agents can be instantiated and work together."""
        crawler = DeepCrawlerAgent()
        documenter = APIDocumentationAgent(orchestrator=crawler)
        
        assert crawler.name == "DeepCrawler Agent"
        assert documenter.name == "API Documentation Agent"
        assert documenter.orchestrator == crawler
    
    def test_crawler_provides_data_to_documenter(self):
        """Test crawler can provide discovered APIs to documenter."""
        crawler = DeepCrawlerAgent()
        documenter = APIDocumentationAgent(orchestrator=crawler)
        
        # Simulate discovered APIs
        crawler.discovered_apis.add("https://example.com/api/users")
        crawler.discovered_apis.add("https://example.com/api/posts")
        
        discovered = list(crawler.discovered_apis)
        assert len(discovered) == 2
        
        # Documenter can process these
        apis = [
            {
                "endpoint": url,
                "method": "GET",
                "confidence": 0.95,
                "discovery_method": "pattern_matching",
                "authentication": None
            }
            for url in discovered
        ]
        
        spec = documenter._generate_openapi_spec(apis, "https://example.com")
        assert len(spec["paths"]) == 2


class TestMemoryIntegration:
    """Test memory integration between agents."""
    
    def test_agents_with_shared_memory_strategy(self):
        """Test agents can share memory strategy."""
        crawler = DeepCrawlerAgent(
            memory_strategy="sliding_window",
            memory_config={"window_size": 3}
        )
        
        documenter = APIDocumentationAgent(
            orchestrator=crawler,
            memory_strategy="sliding_window",
            memory_config={"window_size": 3}
        )
        
        assert crawler.has_memory_enabled()
        assert documenter.has_memory_enabled()
        assert crawler.memory_strategy_name == documenter.memory_strategy_name
    
    def test_crawler_stores_context_in_memory(self):
        """Test crawler stores crawl context in memory."""
        crawler = DeepCrawlerAgent(
            memory_strategy="sliding_window",
            memory_config={"window_size": 3}
        )
        
        crawler.add_to_memory(
            "Crawled https://example.com",
            "Found 5 APIs"
        )
        
        context = crawler.get_memory_context("APIs")
        assert isinstance(context, str)


class TestErrorHandling:
    """Test error handling in agent coordination."""
    
    def test_crawler_error_handling(self):
        """Test crawler handles errors gracefully."""
        crawler = DeepCrawlerAgent()
        
        # Simulate error
        crawler.errors.append({
            "url": "https://example.com/bad",
            "error": "Connection timeout",
            "timestamp": "2025-10-26T12:00:00"
        })
        
        assert len(crawler.errors) == 1
        assert crawler.errors[0]["error"] == "Connection timeout"
    
    def test_documenter_handles_empty_apis(self):
        """Test documenter handles empty API list."""
        documenter = APIDocumentationAgent()
        
        task = {
            "discovered_apis": [],
            "session_id": "test",
            "target_url": "https://example.com"
        }
        
        # Should not raise error
        spec = documenter._generate_openapi_spec([], "https://example.com")
        assert spec["paths"] == {}


class TestMetricsCollection:
    """Test metrics collection across agents."""
    
    def test_crawler_metrics(self):
        """Test crawler collects metrics."""
        crawler = DeepCrawlerAgent()
        
        crawler.set_metric("urls_crawled", 50)
        crawler.set_metric("apis_discovered", 10)
        crawler.set_metric("errors_encountered", 2)
        
        assert crawler.metrics["urls_crawled"] == 50
        assert crawler.metrics["apis_discovered"] == 10
        assert crawler.metrics["errors_encountered"] == 2
    
    def test_documenter_metrics(self):
        """Test documenter collects metrics."""
        documenter = APIDocumentationAgent()
        
        documenter.set_metric("apis_documented", 10)
        documenter.set_metric("openapi_spec_size", 5000)
        
        assert documenter.metrics["apis_documented"] == 10
        assert documenter.metrics["openapi_spec_size"] == 5000


class TestProgressTracking:
    """Test progress tracking across agents."""
    
    def test_crawler_progress_tracking(self):
        """Test crawler tracks progress."""
        crawler = DeepCrawlerAgent()
        
        crawler.report_progress(0.0, "Starting crawl")
        assert crawler.progress == 0.0
        
        crawler.report_progress(0.5, "Halfway through")
        assert crawler.progress == 0.5
        
        crawler.report_progress(1.0, "Complete")
        assert crawler.progress == 1.0
    
    def test_documenter_progress_tracking(self):
        """Test documenter tracks progress."""
        documenter = APIDocumentationAgent()
        
        documenter.report_progress(0.0, "Starting documentation")
        assert documenter.progress == 0.0
        
        documenter.report_progress(1.0, "Documentation complete")
        assert documenter.progress == 1.0


class TestStateManagement:
    """Test state management in agents."""
    
    def test_crawler_state_transitions(self):
        """Test crawler state transitions."""
        crawler = DeepCrawlerAgent()
        
        assert crawler.crawl_state == "idle"
        
        crawler.crawl_state = "initializing"
        assert crawler.crawl_state == "initializing"
        
        crawler.crawl_state = "crawling"
        assert crawler.crawl_state == "crawling"
        
        crawler.crawl_state = "complete"
        assert crawler.crawl_state == "complete"
    
    def test_crawler_pause_resume(self):
        """Test crawler pause and resume."""
        crawler = DeepCrawlerAgent()
        
        crawler.crawl_state = "crawling"
        crawler.pause_crawl()
        assert crawler.crawl_state == "paused"
        
        crawler.resume_crawl()
        assert crawler.crawl_state == "crawling"
    
    def test_crawler_cancel(self):
        """Test crawler cancellation."""
        crawler = DeepCrawlerAgent()
        
        crawler.crawl_state = "crawling"
        crawler.cancel_crawl()
        assert crawler.crawl_state == "cancelled"


class TestSessionManagement:
    """Test session management."""
    
    def test_crawler_session_id(self):
        """Test crawler has unique session ID."""
        crawler1 = DeepCrawlerAgent()
        crawler2 = DeepCrawlerAgent()
        
        assert crawler1.session_id != crawler2.session_id
        assert len(crawler1.session_id) > 0
        assert len(crawler2.session_id) > 0
    
    def test_crawler_status_includes_session(self):
        """Test crawler status includes session info."""
        crawler = DeepCrawlerAgent()
        status = crawler.get_crawl_status()
        
        assert status["session_id"] == crawler.session_id
        assert "state" in status
        assert "urls_crawled" in status
        assert "apis_discovered" in status


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

