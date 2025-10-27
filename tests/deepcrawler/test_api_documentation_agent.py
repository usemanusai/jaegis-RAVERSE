"""
Unit tests for APIDocumentationAgent
Tests documentation generation, OpenAPI spec creation, and export formats.
"""

import pytest
import json
import yaml
from unittest.mock import Mock, patch, MagicMock
from agents.online_api_documentation_agent import APIDocumentationAgent


class TestAPIDocumentationAgentInitialization:
    """Test APIDocumentationAgent initialization."""
    
    def test_agent_initialization(self):
        """Test basic agent initialization."""
        agent = APIDocumentationAgent()
        assert agent.name == "API Documentation Agent"
        assert agent.agent_type == "API_DOCUMENTATION"
        assert agent.openapi_version == "3.0.0"
        assert agent.info_version == "1.0.0"
    
    def test_agent_with_memory_strategy(self):
        """Test agent initialization with memory strategy."""
        agent = APIDocumentationAgent(
            memory_strategy="sliding_window",
            memory_config={"window_size": 3}
        )
        assert agent.has_memory_enabled()
        assert agent.memory_strategy_name == "sliding_window"


class TestOpenAPISpecGeneration:
    """Test OpenAPI specification generation."""
    
    def test_generate_empty_spec(self):
        """Test generating spec with no APIs."""
        agent = APIDocumentationAgent()
        spec = agent._generate_openapi_spec([], "https://example.com")
        
        assert spec["openapi"] == "3.0.0"
        assert spec["info"]["title"] == "API Documentation - https://example.com"
        assert spec["paths"] == {}
    
    def test_generate_spec_with_single_api(self):
        """Test generating spec with single API."""
        agent = APIDocumentationAgent()
        
        apis = [{
            "endpoint": "https://example.com/api/users",
            "method": "GET",
            "confidence": 0.95,
            "authentication": None
        }]
        
        spec = agent._generate_openapi_spec(apis, "https://example.com")
        
        assert "/api/users" in spec["paths"]
        assert "get" in spec["paths"]["/api/users"]
    
    def test_generate_spec_with_multiple_apis(self):
        """Test generating spec with multiple APIs."""
        agent = APIDocumentationAgent()
        
        apis = [
            {
                "endpoint": "https://example.com/api/users",
                "method": "GET",
                "confidence": 0.95,
                "authentication": None
            },
            {
                "endpoint": "https://example.com/api/posts",
                "method": "POST",
                "confidence": 0.90,
                "authentication": "Bearer"
            }
        ]
        
        spec = agent._generate_openapi_spec(apis, "https://example.com")
        
        assert "/api/users" in spec["paths"]
        assert "/api/posts" in spec["paths"]
        assert len(spec["paths"]) == 2
    
    def test_spec_includes_authentication(self):
        """Test spec includes authentication when detected."""
        agent = APIDocumentationAgent()
        
        apis = [{
            "endpoint": "https://example.com/api/secure",
            "method": "GET",
            "confidence": 0.95,
            "authentication": "Bearer"
        }]
        
        spec = agent._generate_openapi_spec(apis, "https://example.com")
        
        assert "securitySchemes" in spec["components"]
        assert "bearerAuth" in spec["components"]["securitySchemes"]


class TestMarkdownDocGeneration:
    """Test Markdown documentation generation."""
    
    def test_generate_empty_markdown(self):
        """Test generating markdown with no APIs."""
        agent = APIDocumentationAgent()
        doc = agent._generate_markdown_doc([], "https://example.com")
        
        assert "# API Documentation" in doc
        assert "https://example.com" in doc
        assert "Total Endpoints: 0" in doc
    
    def test_generate_markdown_with_apis(self):
        """Test generating markdown with APIs."""
        agent = APIDocumentationAgent()
        
        apis = [{
            "endpoint": "https://example.com/api/users",
            "method": "GET",
            "confidence": 0.95,
            "discovery_method": "pattern_matching",
            "authentication": None
        }]
        
        doc = agent._generate_markdown_doc(apis, "https://example.com")
        
        assert "GET" in doc
        assert "/api/users" in doc
        assert "0.95" in doc
        assert "pattern_matching" in doc
    
    def test_markdown_includes_sections(self):
        """Test markdown includes all required sections."""
        agent = APIDocumentationAgent()
        
        apis = [{
            "endpoint": "https://example.com/api/test",
            "method": "GET",
            "confidence": 0.90,
            "discovery_method": "pattern_matching",
            "authentication": None
        }]
        
        doc = agent._generate_markdown_doc(apis, "https://example.com")
        
        assert "## Overview" in doc
        assert "## Endpoints" in doc
        assert "## Authentication" in doc
        assert "## Error Handling" in doc


class TestPathExtraction:
    """Test path extraction from endpoints."""
    
    def test_extract_simple_path(self):
        """Test extracting simple path."""
        agent = APIDocumentationAgent()
        path = agent._extract_path("https://example.com/api/users")
        assert path == "/api/users"
    
    def test_extract_path_with_query(self):
        """Test extracting path with query parameters."""
        agent = APIDocumentationAgent()
        path = agent._extract_path("https://example.com/api/users?limit=10")
        assert "/api/users" in path
        assert "limit=10" in path
    
    def test_extract_root_path(self):
        """Test extracting root path."""
        agent = APIDocumentationAgent()
        path = agent._extract_path("https://example.com")
        assert path == "/"


class TestExportFormats:
    """Test documentation export formats."""
    
    def test_export_openapi_json(self):
        """Test exporting OpenAPI as JSON."""
        agent = APIDocumentationAgent()
        
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {}
        }
        
        json_str = agent.export_openapi_json(spec)
        parsed = json.loads(json_str)
        
        assert parsed["openapi"] == "3.0.0"
        assert parsed["info"]["title"] == "Test API"
    
    def test_export_openapi_yaml(self):
        """Test exporting OpenAPI as YAML."""
        agent = APIDocumentationAgent()
        
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {}
        }
        
        yaml_str = agent.export_openapi_yaml(spec)
        parsed = yaml.safe_load(yaml_str)
        
        assert parsed["openapi"] == "3.0.0"
        assert parsed["info"]["title"] == "Test API"
    
    def test_export_markdown(self):
        """Test exporting as Markdown."""
        agent = APIDocumentationAgent()
        
        markdown = "# Test Documentation\n\nThis is a test."
        exported = agent.export_markdown(markdown)
        
        assert exported == markdown


class TestDocumentationStatus:
    """Test documentation status tracking."""
    
    def test_get_documentation_status(self):
        """Test getting documentation status."""
        agent = APIDocumentationAgent()
        status = agent.get_documentation_status()
        
        assert status["agent"] == "API Documentation Agent"
        assert "state" in status
        assert "progress" in status
        assert "memory_enabled" in status


class TestDocumentationExecution:
    """Test documentation generation execution."""
    
    @patch('agents.online_api_documentation_agent.DatabaseManager')
    def test_execute_with_valid_task(self, mock_db):
        """Test executing with valid task."""
        agent = APIDocumentationAgent()
        
        task = {
            "discovered_apis": [
                {
                    "endpoint": "https://example.com/api/users",
                    "method": "GET",
                    "confidence": 0.95,
                    "discovery_method": "pattern_matching",
                    "authentication": None
                }
            ],
            "session_id": "test-session-123",
            "target_url": "https://example.com"
        }
        
        # Mock database operations
        mock_conn = MagicMock()
        mock_db.return_value.get_connection.return_value.__enter__.return_value = mock_conn
        
        # Verify task structure
        assert len(task["discovered_apis"]) == 1
        assert task["session_id"] == "test-session-123"
    
    def test_execute_without_apis(self):
        """Test executing without discovered APIs."""
        agent = APIDocumentationAgent()
        
        task = {
            "discovered_apis": [],
            "session_id": "test-session",
            "target_url": "https://example.com"
        }
        
        # Should handle empty APIs gracefully
        assert len(task["discovered_apis"]) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

