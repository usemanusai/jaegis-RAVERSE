"""
Tests for Deep Research agents.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from agents.online_deep_research_topic_enhancer import DeepResearchTopicEnhancerAgent
from agents.online_deep_research_web_researcher import DeepResearchWebResearcherAgent
from agents.online_deep_research_content_analyzer import DeepResearchContentAnalyzerAgent


class TestDeepResearchTopicEnhancerAgent:
    """Tests for Topic Enhancer Agent."""

    def test_agent_initialization(self):
        """Test agent initialization."""
        agent = DeepResearchTopicEnhancerAgent()
        assert agent.name == "Deep Research Topic Enhancer"
        assert agent.agent_type == "DEEP_RESEARCH_TOPIC_ENHANCER"
        assert agent.model == "anthropic/claude-3.5-sonnet:free"
        assert agent.temperature == 0.5

    def test_validate_inputs_valid(self):
        """Test input validation with valid inputs."""
        agent = DeepResearchTopicEnhancerAgent()
        task = {"topic": "machine learning"}
        assert agent.validate_inputs(task) is True

    def test_validate_inputs_invalid(self):
        """Test input validation with invalid inputs."""
        agent = DeepResearchTopicEnhancerAgent()
        
        # Missing topic
        assert agent.validate_inputs({}) is False
        
        # Empty topic
        assert agent.validate_inputs({"topic": ""}) is False
        
        # Non-string topic
        assert agent.validate_inputs({"topic": 123}) is False

    def test_prepare_prompt(self):
        """Test prompt preparation."""
        agent = DeepResearchTopicEnhancerAgent()
        topic = "artificial intelligence"
        context = "focus on recent developments"
        
        prompt = agent._prepare_prompt(topic, context)
        
        assert topic in prompt
        assert context in prompt
        assert "query optimization" in prompt.lower()

    def test_extract_keywords(self):
        """Test keyword extraction."""
        agent = DeepResearchTopicEnhancerAgent()
        text = "machine learning algorithms for natural language processing"
        
        keywords = agent._extract_keywords(text)
        
        assert len(keywords) > 0
        assert "machine" in keywords or "learning" in keywords

    def test_extract_entities(self):
        """Test entity extraction."""
        agent = DeepResearchTopicEnhancerAgent()
        text = "Google and Microsoft are developing AI systems"
        
        entities = agent._extract_entities(text)
        
        assert len(entities) > 0
        assert "Google" in entities or "Microsoft" in entities

    @patch('agents.online_deep_research_topic_enhancer.requests.post')
    def test_call_llm_success(self, mock_post):
        """Test successful LLM call."""
        agent = DeepResearchTopicEnhancerAgent()
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'choices': [{'message': {'content': 'Enhanced topic'}}]
        }
        mock_post.return_value = mock_response
        
        result = agent._call_llm("test prompt")
        
        assert result == "Enhanced topic"
        mock_post.assert_called_once()

    @patch('agents.online_deep_research_topic_enhancer.requests.post')
    def test_call_llm_retry_on_429(self, mock_post):
        """Test LLM retry on 429 status."""
        agent = DeepResearchTopicEnhancerAgent()
        
        # First call returns 429, second returns 200
        mock_response_429 = Mock()
        mock_response_429.status_code = 429
        
        mock_response_200 = Mock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {
            'choices': [{'message': {'content': 'Enhanced topic'}}]
        }
        
        mock_post.side_effect = [mock_response_429, mock_response_200]
        
        with patch('time.sleep'):  # Skip actual sleep
            result = agent._call_llm("test prompt")
        
        assert result == "Enhanced topic"
        assert mock_post.call_count == 2


class TestDeepResearchWebResearcherAgent:
    """Tests for Web Researcher Agent."""

    def test_agent_initialization(self):
        """Test agent initialization."""
        agent = DeepResearchWebResearcherAgent()
        assert agent.name == "Deep Research Web Researcher"
        assert agent.agent_type == "DEEP_RESEARCH_WEB_RESEARCHER"
        assert agent.model == "google/gemini-2.0-flash-exp:free"
        assert agent.temperature == 0.7

    def test_validate_inputs_valid(self):
        """Test input validation with valid inputs."""
        agent = DeepResearchWebResearcherAgent()
        task = {"query": "machine learning"}
        assert agent.validate_inputs(task) is True

    def test_validate_inputs_invalid(self):
        """Test input validation with invalid inputs."""
        agent = DeepResearchWebResearcherAgent()
        
        # Missing query
        assert agent.validate_inputs({}) is False
        
        # Empty query
        assert agent.validate_inputs({"query": ""}) is False

    def test_get_mock_search_results(self):
        """Test mock search results."""
        agent = DeepResearchWebResearcherAgent()
        results = agent._get_mock_search_results("test query")
        
        assert len(results) > 0
        assert "title" in results[0]
        assert "url" in results[0]
        assert "description" in results[0]

    @patch('agents.online_deep_research_web_researcher.requests.get')
    def test_scrape_url_success(self, mock_get):
        """Test successful URL scraping."""
        agent = DeepResearchWebResearcherAgent()
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Test content</body></html>"
        mock_get.return_value = mock_response
        
        result = agent._scrape_url("https://example.com")
        
        assert "Test content" in result
        mock_get.assert_called_once()

    @patch('agents.online_deep_research_web_researcher.requests.get')
    def test_scrape_url_failure(self, mock_get):
        """Test URL scraping failure."""
        agent = DeepResearchWebResearcherAgent()
        
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        result = agent._scrape_url("https://example.com")
        
        assert result == ""


class TestDeepResearchContentAnalyzerAgent:
    """Tests for Content Analyzer Agent."""

    def test_agent_initialization(self):
        """Test agent initialization."""
        agent = DeepResearchContentAnalyzerAgent()
        assert agent.name == "Deep Research Content Analyzer"
        assert agent.agent_type == "DEEP_RESEARCH_CONTENT_ANALYZER"
        assert agent.model == "meta-llama/llama-3.3-70b-instruct:free"
        assert agent.temperature == 0.6

    def test_validate_inputs_valid(self):
        """Test input validation with valid inputs."""
        agent = DeepResearchContentAnalyzerAgent()
        task = {"research_findings": {"search_results": []}}
        assert agent.validate_inputs(task) is True

    def test_validate_inputs_invalid(self):
        """Test input validation with invalid inputs."""
        agent = DeepResearchContentAnalyzerAgent()
        
        # Missing research_findings
        assert agent.validate_inputs({}) is False
        
        # Non-dict research_findings
        assert agent.validate_inputs({"research_findings": "not a dict"}) is False

    def test_extract_topics(self):
        """Test topic extraction."""
        agent = DeepResearchContentAnalyzerAgent()
        sources = [
            {"title": "Machine Learning Algorithms"},
            {"title": "Deep Learning Networks"}
        ]
        
        topics = agent._extract_topics(sources)
        
        assert len(topics) > 0
        assert "Machine" in topics or "Learning" in topics

    def test_extract_entities(self):
        """Test entity extraction."""
        agent = DeepResearchContentAnalyzerAgent()
        findings = [
            {"title": "Google AI Research"},
            {"title": "OpenAI GPT Models"}
        ]
        
        entities = agent._extract_entities(findings)
        
        assert len(entities) > 0
        assert "Google" in entities or "OpenAI" in entities

    def test_identify_patterns(self):
        """Test pattern identification."""
        agent = DeepResearchContentAnalyzerAgent()
        findings = {
            "search_results": [
                {"title": "Result 1"},
                {"title": "Result 2"},
                {"title": "Result 3"},
                {"title": "Result 4"},
                {"title": "Result 5"},
                {"title": "Result 6"}
            ],
            "detailed_findings": [
                {"title": "Finding 1"},
                {"title": "Finding 2"},
                {"title": "Finding 3"}
            ]
        }
        
        patterns = agent._identify_patterns(findings)
        
        assert len(patterns) > 0
        assert any(p["type"] == "source_diversity" for p in patterns)

    def test_create_synthesis(self):
        """Test synthesis creation."""
        agent = DeepResearchContentAnalyzerAgent()
        key_info = {
            "total_sources": 5,
            "main_topics": ["AI", "ML"],
            "key_entities": ["Google", "OpenAI"],
            "source_summary": [
                {"title": "Source 1", "url": "https://example.com"}
            ]
        }
        patterns = [{"type": "diversity", "description": "Multiple sources"}]
        insights = "Key insights here"
        
        synthesis = agent._create_synthesis(key_info, patterns, insights)
        
        assert "Research Synthesis" in synthesis
        assert "5" in synthesis
        assert "AI" in synthesis

    def test_generate_recommendations(self):
        """Test recommendation generation."""
        agent = DeepResearchContentAnalyzerAgent()
        insights = "Some insights"
        
        recommendations = agent._generate_recommendations(insights)
        
        assert len(recommendations) > 0
        assert all(isinstance(r, str) for r in recommendations)


class TestDeepResearchIntegration:
    """Integration tests for Deep Research workflow."""

    @patch('agents.online_deep_research_topic_enhancer.requests.post')
    def test_topic_enhancer_execute(self, mock_post):
        """Test topic enhancer execution."""
        agent = DeepResearchTopicEnhancerAgent()
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'choices': [{'message': {'content': 'Enhanced: machine learning and AI'}}]
        }
        mock_post.return_value = mock_response
        
        task = {"topic": "machine learning"}
        result = agent.execute(task)
        
        assert result["status"] == "success"
        assert "result" in result
        assert "original_topic" in result["result"]

    def test_web_researcher_execute(self):
        """Test web researcher execution."""
        agent = DeepResearchWebResearcherAgent()
        
        task = {"query": "test query", "max_results": 5}
        result = agent.execute(task)
        
        assert result["status"] == "success"
        assert "result" in result
        assert "search_results" in result["result"]

    @patch('agents.online_deep_research_content_analyzer.requests.post')
    def test_content_analyzer_execute(self, mock_post):
        """Test content analyzer execution."""
        agent = DeepResearchContentAnalyzerAgent()
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'choices': [{'message': {'content': 'Analysis complete'}}]
        }
        mock_post.return_value = mock_response
        
        task = {
            "research_findings": {
                "search_results": [{"title": "Result"}],
                "detailed_findings": [{"title": "Finding"}]
            },
            "query": "test"
        }
        result = agent.execute(task)
        
        assert result["status"] == "success"
        assert "result" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

