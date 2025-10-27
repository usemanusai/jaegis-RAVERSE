"""
Deep Research Web Researcher Agent
Performs web research using BraveSearch, Playwright, and content extraction.
"""

import os
import json
import requests
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
from .base_memory_agent import BaseMemoryAgent


class DeepResearchWebResearcherAgent(BaseMemoryAgent):
    """
    Web Researcher Agent - Conducts comprehensive web research.
    Uses BraveSearch for discovery and Playwright for dynamic content.

    Optional Memory Support:
        memory_strategy: Optional memory strategy (e.g., "retrieval")
        memory_config: Optional memory configuration dictionary
    """

    def __init__(
        self,
        orchestrator=None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        memory_strategy: Optional[str] = None,
        memory_config: Optional[Dict[str, Any]] = None
    ):
        """Initialize Web Researcher Agent."""
        super().__init__(
            name="Deep Research Web Researcher",
            agent_type="DEEP_RESEARCH_WEB_RESEARCHER",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model or "google/gemini-2.0-flash-exp:free"
        self.base_url = "https://openrouter.ai/api/v1"
        self.brave_api_key = os.getenv("BRAVE_SEARCH_API_KEY", "")
        self.temperature = 0.7
        self.max_tokens = 2000

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Execute web research."""
        query = task.get("query", "")
        max_results = task.get("max_results", 10)

        # Get memory context if available
        memory_context = self.get_memory_context(query)

        self.logger.info(f"Starting web research for: {query}")

        if not query:
            raise ValueError("Query is required")

        # Phase 1: Search
        self.report_progress(0.2, "Searching for relevant sources")
        search_results = self._search_web(query, max_results)

        # Phase 2: Scrape top results
        self.report_progress(0.5, "Extracting content from sources")
        detailed_findings = self._scrape_sources(search_results[:3])

        # Phase 3: Synthesize findings
        self.report_progress(0.8, "Synthesizing research findings")
        synthesis = self._synthesize_findings(query, detailed_findings)

        self.set_metric("sources_found", len(search_results))
        self.set_metric("sources_scraped", len(detailed_findings))

        result = {
            "query": query,
            "search_results": search_results,
            "detailed_findings": detailed_findings,
            "synthesis": synthesis,
            "timestamp": datetime.now().isoformat()
        }

        # Store in memory if enabled
        if result:
            self.add_to_memory(query, json.dumps(result, default=str))

        return result

    def _search_web(self, query: str, max_results: int = 10) -> List[Dict[str, Any]]:
        """Search web using BraveSearch API."""
        try:
            if not self.brave_api_key:
                self.logger.warning("BraveSearch API key not configured, using mock results")
                return self._get_mock_search_results(query)
            
            headers = {
                "Authorization": f"Bearer {self.brave_api_key}",
                "Accept": "application/json"
            }
            
            params = {
                "q": query,
                "count": max_results,
                "freshness": "1d"
            }
            
            response = requests.get(
                "https://api.search.brave.com/res/v1/web/search",
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                results = []
                for result in data.get("web", []):
                    results.append({
                        "title": result.get("title", ""),
                        "url": result.get("url", ""),
                        "description": result.get("description", ""),
                        "source": "BraveSearch"
                    })
                return results
            else:
                self.logger.warning(f"BraveSearch failed: {response.status_code}")
                return self._get_mock_search_results(query)
                
        except Exception as e:
            self.logger.warning(f"Search failed: {e}, using mock results")
            return self._get_mock_search_results(query)

    def _scrape_sources(self, sources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scrape content from sources."""
        detailed_findings = []
        
        for source in sources:
            try:
                # Try to scrape using requests first (faster)
                content = self._scrape_url(source["url"])
                
                detailed_findings.append({
                    "url": source["url"],
                    "title": source["title"],
                    "content": content[:1000],  # Limit content
                    "source": source.get("source", "Unknown")
                })
            except Exception as e:
                self.logger.debug(f"Failed to scrape {source['url']}: {e}")
                # Add source without content
                detailed_findings.append({
                    "url": source["url"],
                    "title": source["title"],
                    "content": source.get("description", ""),
                    "source": source.get("source", "Unknown")
                })
        
        return detailed_findings

    def _scrape_url(self, url: str) -> str:
        """Scrape content from URL."""
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                # Simple content extraction (can be enhanced with BeautifulSoup)
                text = response.text
                # Remove HTML tags (basic)
                import re
                text = re.sub('<[^<]+?>', '', text)
                return text[:2000]
            else:
                return ""
        except Exception as e:
            self.logger.debug(f"Scrape failed for {url}: {e}")
            return ""

    def _synthesize_findings(self, query: str, findings: List[Dict[str, Any]]) -> str:
        """Synthesize findings using LLM."""
        try:
            # Prepare context
            context = "\n\n".join([
                f"Source: {f['title']}\nURL: {f['url']}\nContent: {f['content'][:500]}"
                for f in findings
            ])
            
            prompt = f"""Based on the following research findings about "{query}", provide a comprehensive synthesis:

{context}

Please provide:
1. Key findings summary
2. Main themes and patterns
3. Important insights
4. Potential gaps or areas for further research"""
            
            synthesis = self._call_llm(prompt)
            return synthesis
            
        except Exception as e:
            self.logger.warning(f"Synthesis failed: {e}")
            return "Synthesis unavailable"

    def _call_llm(self, prompt: str, max_retries: int = 3) -> str:
        """Call LLM via OpenRouter with retry logic."""
        for attempt in range(max_retries):
            try:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                
                payload = {
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                    "stream": False
                }
                
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=30
                )
                
                if response.status_code == 200:
                    return response.json()['choices'][0]['message']['content']
                elif response.status_code in [429, 500, 502, 503, 504]:
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                    
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
        
        return "Analysis unavailable"

    def _get_mock_search_results(self, query: str) -> List[Dict[str, Any]]:
        """Return mock search results for testing."""
        return [
            {
                "title": f"Research on {query} - Source 1",
                "url": "https://example.com/research1",
                "description": f"Comprehensive information about {query}",
                "source": "Mock"
            },
            {
                "title": f"Analysis of {query} - Source 2",
                "url": "https://example.com/research2",
                "description": f"Detailed analysis of {query}",
                "source": "Mock"
            }
        ]

    def validate_inputs(self, task: Dict[str, Any]) -> bool:
        """Validate task inputs."""
        return "query" in task and isinstance(task["query"], str) and len(task["query"]) > 0

    def _format_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Format result for output."""
        return {
            "status": "success",
            "result": result,
            "artifacts": self.artifacts,
            "metrics": self.metrics
        }

    def _format_error(self, error: Exception) -> Dict[str, Any]:
        """Format error for output."""
        return {
            "status": "error",
            "error": str(error),
            "artifacts": self.artifacts,
            "metrics": self.metrics
        }

