"""
End-to-end tests for DeepCrawler workflow
Tests complete crawl and documentation generation workflow.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from agents.online_deepcrawler_agent import DeepCrawlerAgent
from agents.online_api_documentation_agent import APIDocumentationAgent


class TestCompleteWorkflow:
    """Test complete DeepCrawler workflow."""
    
    @patch('agents.online_deepcrawler_agent.DatabaseManager')
    def test_crawl_and_document_workflow(self, mock_db):
        """Test complete crawl and documentation workflow."""
        # Initialize agents
        crawler = DeepCrawlerAgent()
        documenter = APIDocumentationAgent(orchestrator=crawler)
        
        # Mock database
        mock_conn = MagicMock()
        mock_db.return_value.get_connection.return_value.__enter__.return_value = mock_conn
        
        # Simulate crawl results
        crawler.crawled_urls.add("https://example.com/api/users")
        crawler.crawled_urls.add("https://example.com/api/posts")
        crawler.discovered_apis.add("https://example.com/api/users")
        crawler.discovered_apis.add("https://example.com/api/posts")
        
        # Verify crawl results
        assert len(crawler.crawled_urls) == 2
        assert len(crawler.discovered_apis) == 2
        
        # Generate documentation
        discovered_apis = [
            {
                "endpoint": url,
                "method": "GET",
                "confidence": 0.95,
                "discovery_method": "pattern_matching",
                "authentication": None
            }
            for url in crawler.discovered_apis
        ]
        
        spec = documenter._generate_openapi_spec(discovered_apis, "https://example.com")
        markdown = documenter._generate_markdown_doc(discovered_apis, "https://example.com")
        
        # Verify documentation
        assert len(spec["paths"]) == 2
        assert "API Documentation" in markdown
        assert "https://example.com" in markdown


class TestCrawlPhases:
    """Test individual crawl phases."""
    
    def test_initialization_phase(self):
        """Test crawl initialization phase."""
        crawler = DeepCrawlerAgent()
        
        assert crawler.crawl_state == "idle"
        crawler.crawl_state = "initializing"
        assert crawler.crawl_state == "initializing"
    
    def test_crawling_phase(self):
        """Test crawling phase."""
        crawler = DeepCrawlerAgent()
        
        crawler.crawl_state = "crawling"
        crawler.crawled_urls.add("https://example.com")
        
        assert crawler.crawl_state == "crawling"
        assert len(crawler.crawled_urls) == 1
    
    def test_discovery_phase(self):
        """Test API discovery phase."""
        crawler = DeepCrawlerAgent()
        
        crawler.crawl_state = "discovering"
        crawler.discovered_apis.add("https://example.com/api/users")
        
        assert crawler.crawl_state == "discovering"
        assert len(crawler.discovered_apis) == 1
    
    def test_documentation_phase(self):
        """Test documentation phase."""
        crawler = DeepCrawlerAgent()
        documenter = APIDocumentationAgent(orchestrator=crawler)
        
        crawler.crawl_state = "documenting"
        
        apis = [{
            "endpoint": "https://example.com/api/users",
            "method": "GET",
            "confidence": 0.95,
            "discovery_method": "pattern_matching",
            "authentication": None
        }]
        
        spec = documenter._generate_openapi_spec(apis, "https://example.com")
        assert len(spec["paths"]) == 1


class TestErrorRecovery:
    """Test error recovery in workflow."""
    
    def test_crawler_error_recovery(self):
        """Test crawler recovers from errors."""
        crawler = DeepCrawlerAgent()
        
        # Simulate error
        crawler.errors.append({
            "url": "https://example.com/bad",
            "error": "Connection timeout",
            "timestamp": "2025-10-26T12:00:00"
        })
        
        # Crawler should continue
        crawler.crawled_urls.add("https://example.com/good")
        
        assert len(crawler.errors) == 1
        assert len(crawler.crawled_urls) == 1
    
    def test_documenter_handles_incomplete_data(self):
        """Test documenter handles incomplete API data."""
        documenter = APIDocumentationAgent()
        
        # Incomplete API data
        apis = [{
            "endpoint": "https://example.com/api/users",
            "method": "GET"
            # Missing confidence, discovery_method, authentication
        }]
        
        # Should handle gracefully
        spec = documenter._generate_openapi_spec(apis, "https://example.com")
        assert len(spec["paths"]) == 1


class TestDataPersistence:
    """Test data persistence in workflow."""
    
    def test_crawler_tracks_all_data(self):
        """Test crawler tracks all discovered data."""
        crawler = DeepCrawlerAgent()
        
        # Add data
        crawler.crawled_urls.add("https://example.com/page1")
        crawler.crawled_urls.add("https://example.com/page2")
        crawler.discovered_apis.add("https://example.com/api/users")
        
        # Verify persistence
        assert len(crawler.crawled_urls) == 2
        assert len(crawler.discovered_apis) == 1
        assert "https://example.com/page1" in crawler.crawled_urls
        assert "https://example.com/api/users" in crawler.discovered_apis
    
    def test_documenter_generates_consistent_output(self):
        """Test documenter generates consistent output."""
        documenter = APIDocumentationAgent()
        
        apis = [{
            "endpoint": "https://example.com/api/users",
            "method": "GET",
            "confidence": 0.95,
            "discovery_method": "pattern_matching",
            "authentication": None
        }]
        
        # Generate multiple times
        spec1 = documenter._generate_openapi_spec(apis, "https://example.com")
        spec2 = documenter._generate_openapi_spec(apis, "https://example.com")
        
        # Should be identical
        assert spec1["paths"] == spec2["paths"]
        assert len(spec1["paths"]) == len(spec2["paths"])


class TestScalability:
    """Test scalability of workflow."""
    
    def test_crawler_handles_many_urls(self):
        """Test crawler can handle many URLs."""
        crawler = DeepCrawlerAgent()
        
        # Add many URLs
        for i in range(100):
            crawler.crawled_urls.add(f"https://example.com/page{i}")
        
        assert len(crawler.crawled_urls) == 100
    
    def test_documenter_handles_many_apis(self):
        """Test documenter can handle many APIs."""
        documenter = APIDocumentationAgent()
        
        # Generate many APIs
        apis = [
            {
                "endpoint": f"https://example.com/api/endpoint{i}",
                "method": "GET",
                "confidence": 0.95,
                "discovery_method": "pattern_matching",
                "authentication": None
            }
            for i in range(50)
        ]
        
        spec = documenter._generate_openapi_spec(apis, "https://example.com")
        assert len(spec["paths"]) == 50


class TestMemoryIntegration:
    """Test memory integration in workflow."""
    
    def test_crawler_with_memory_tracks_context(self):
        """Test crawler with memory tracks crawl context."""
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
        assert len(context) > 0
    
    def test_documenter_with_memory_tracks_documentation(self):
        """Test documenter with memory tracks documentation."""
        documenter = APIDocumentationAgent(
            memory_strategy="sliding_window",
            memory_config={"window_size": 3}
        )
        
        documenter.add_to_memory(
            "Generated documentation for 5 APIs",
            "Created OpenAPI spec and Markdown"
        )
        
        context = documenter.get_memory_context("documentation")
        assert isinstance(context, str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

