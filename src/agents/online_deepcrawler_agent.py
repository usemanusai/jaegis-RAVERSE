"""
DeepCrawler Agent - Orchestrator for Intelligent Web Crawling
Coordinates URL frontier, crawl scheduling, content fetching, and API discovery.
Manages crawl sessions, error recovery, and result aggregation.
"""

import logging
import json
import asyncio
import uuid
from typing import Dict, Any, Optional, List, Set
from datetime import datetime
from contextlib import asynccontextmanager

from agents.base_memory_agent import BaseMemoryAgent
from agents.online_javascript_analysis_agent import JavaScriptAnalysisAgent
from agents.online_traffic_interception_agent import TrafficInterceptionAgent
from utils.url_frontier import URLFrontier
from utils.crawl_scheduler import CrawlScheduler
from utils.content_fetcher import ContentFetcher
from utils.response_classifier import ResponseClassifier
from utils.websocket_analyzer import WebSocketAnalyzer
from utils.api_pattern_matcher import APIPatternMatcher
from utils.database import DatabaseManager
from config.deepcrawler_config import DeepCrawlerConfig

logger = logging.getLogger(__name__)


class DeepCrawlerAgent(BaseMemoryAgent):
    """
    DeepCrawler Orchestrator Agent - Coordinates intelligent web crawling.
    
    Manages:
    - Crawl session lifecycle (initialize, crawl, discover, document, complete)
    - URL frontier with intelligent prioritization
    - Concurrent crawl scheduling with rate limiting
    - Content fetching with authentication support
    - API discovery through multiple techniques
    - Error recovery and retry logic
    - Result aggregation and persistence
    
    Optional Memory Support:
        memory_strategy: Optional memory strategy for context persistence
        memory_config: Optional memory configuration dictionary
    """

    def __init__(
        self,
        orchestrator=None,
        config: Optional[DeepCrawlerConfig] = None,
        memory_strategy: Optional[str] = None,
        memory_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize DeepCrawler Agent.
        
        Args:
            orchestrator: Reference to orchestration agent
            config: DeepCrawlerConfig instance (uses defaults if None)
            memory_strategy: Optional memory strategy name
            memory_config: Optional memory configuration
        """
        super().__init__(
            name="DeepCrawler Agent",
            agent_type="DEEPCRAWLER",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        
        self.config = config or DeepCrawlerConfig()
        self.db = DatabaseManager()
        
        # Core components
        self.url_frontier = URLFrontier(max_depth=self.config.max_depth)
        self.crawl_scheduler = CrawlScheduler(
            max_concurrent=self.config.max_concurrent,
            default_timeout=self.config.timeout
        )
        self.content_fetcher = ContentFetcher()
        
        # Discovery components
        self.response_classifier = ResponseClassifier()
        self.websocket_analyzer = WebSocketAnalyzer()
        self.api_pattern_matcher = APIPatternMatcher()
        
        # Extended agents
        self.js_agent = JavaScriptAnalysisAgent(orchestrator=self)
        self.traffic_agent = TrafficInterceptionAgent(orchestrator=self)
        
        # Session tracking
        self.session_id = str(uuid.uuid4())
        self.crawl_state = "idle"  # idle, initializing, crawling, discovering, documenting, complete, failed
        self.discovered_apis: Set[str] = set()
        self.crawled_urls: Set[str] = set()
        self.errors: List[Dict[str, Any]] = []
        
        logger.info(f"DeepCrawler Agent initialized (session: {self.session_id})")

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute crawl task with full lifecycle management.
        
        Args:
            task: Task configuration with target_url, max_depth, etc.
            
        Returns:
            Dictionary with crawl results and discovered APIs
        """
        try:
            self.report_progress(0.0, "Initializing crawl session")
            self.crawl_state = "initializing"
            
            # Extract task parameters
            target_url = task.get("target_url")
            if not target_url:
                raise ValueError("target_url is required")
            
            max_depth = task.get("max_depth", self.config.max_depth)
            max_urls = task.get("max_urls", self.config.max_urls)
            
            # Initialize crawl session in database
            self._initialize_crawl_session(target_url, max_depth)
            
            # Phase 1: Crawl
            self.report_progress(0.2, "Starting crawl phase")
            self.crawl_state = "crawling"
            self._crawl_phase(target_url, max_depth, max_urls)
            
            # Phase 2: Discover APIs
            self.report_progress(0.6, "Discovering APIs")
            self.crawl_state = "discovering"
            discovered_apis = self._discover_apis_phase()
            
            # Phase 3: Document
            self.report_progress(0.8, "Documenting results")
            self.crawl_state = "documenting"
            documentation = self._document_phase(discovered_apis)
            
            # Complete
            self.report_progress(1.0, "Crawl complete")
            self.crawl_state = "complete"
            
            # Set metrics
            self.set_metric("urls_crawled", len(self.crawled_urls))
            self.set_metric("apis_discovered", len(self.discovered_apis))
            self.set_metric("errors_encountered", len(self.errors))
            
            # Store in memory
            self.add_to_memory(
                f"Crawled {target_url}",
                f"Discovered {len(self.discovered_apis)} APIs from {len(self.crawled_urls)} URLs"
            )
            
            return {
                "session_id": self.session_id,
                "target_url": target_url,
                "urls_crawled": len(self.crawled_urls),
                "apis_discovered": len(self.discovered_apis),
                "discovered_apis": list(self.discovered_apis),
                "documentation": documentation,
                "errors": self.errors
            }
            
        except Exception as e:
            self.crawl_state = "failed"
            self.logger.error(f"Crawl failed: {e}", exc_info=True)
            self.errors.append({
                "phase": self.crawl_state,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
            raise

    def _initialize_crawl_session(self, target_url: str, max_depth: int) -> None:
        """Initialize crawl session in database."""
        try:
            with self.db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO raverse.crawl_sessions
                        (session_id, target_url, max_depth, status)
                        VALUES (%s, %s, %s, %s)
                    """, (self.session_id, target_url, max_depth, "running"))
            logger.info(f"Crawl session initialized: {self.session_id}")
        except Exception as e:
            logger.warning(f"Failed to initialize crawl session: {e}")

    def _crawl_phase(self, target_url: str, max_depth: int, max_urls: int) -> None:
        """Execute crawl phase with URL frontier and scheduling."""
        self.url_frontier.add_url(target_url, depth=0, discovered_by="seed")
        
        while not self.url_frontier.is_empty() and len(self.crawled_urls) < max_urls:
            url_info = self.url_frontier.get_next_url()
            if not url_info:
                break
            
            url = url_info["url"]
            depth = url_info["depth"]
            
            if depth > max_depth or url in self.crawled_urls:
                continue
            
            try:
                # Fetch content
                response = asyncio.run(self.content_fetcher.fetch_url(url))
                self.crawled_urls.add(url)
                
                # Extract new URLs
                new_urls = self._extract_urls(response, depth)
                for new_url in new_urls:
                    self.url_frontier.add_url(new_url, depth=depth+1, discovered_by="crawl")
                
                # Store in database
                self._store_crawled_url(url, depth, response)
                
            except Exception as e:
                logger.warning(f"Failed to crawl {url}: {e}")
                self.errors.append({
                    "url": url,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })

    def _discover_apis_phase(self) -> List[Dict[str, Any]]:
        """Discover APIs using multiple techniques."""
        discovered = []
        
        for url in self.crawled_urls:
            try:
                # Pattern matching
                pattern_result = self.api_pattern_matcher.match(url)
                if pattern_result.get("is_api"):
                    discovered.append({
                        "endpoint": url,
                        "method": "GET",
                        "confidence": pattern_result.get("confidence", 0.0),
                        "discovery_method": "pattern_matching"
                    })
                    self.discovered_apis.add(url)
                    
            except Exception as e:
                logger.warning(f"API discovery failed for {url}: {e}")
        
        return discovered

    def _document_phase(self, discovered_apis: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate documentation for discovered APIs."""
        return {
            "total_apis": len(discovered_apis),
            "apis": discovered_apis,
            "generated_at": datetime.now().isoformat()
        }

    def _extract_urls(self, response: Dict[str, Any], current_depth: int) -> List[str]:
        """Extract URLs from response content."""
        urls = []
        try:
            content = response.get("content", "")
            # Simple URL extraction (can be enhanced with regex)
            import re
            url_pattern = r'https?://[^\s"\'<>]+'
            urls = re.findall(url_pattern, content)
        except Exception as e:
            logger.debug(f"URL extraction failed: {e}")
        return urls

    def _store_crawled_url(self, url: str, depth: int, response: Dict[str, Any]) -> None:
        """Store crawled URL in database."""
        try:
            with self.db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO raverse.crawl_urls
                        (session_id, url, depth, status, crawled_at)
                        VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                    """, (self.session_id, url, depth, "crawled"))
        except Exception as e:
            logger.debug(f"Failed to store crawled URL: {e}")

    def get_crawl_status(self) -> Dict[str, Any]:
        """Get current crawl status."""
        return {
            "session_id": self.session_id,
            "state": self.crawl_state,
            "urls_crawled": len(self.crawled_urls),
            "apis_discovered": len(self.discovered_apis),
            "errors": len(self.errors),
            "progress": self.progress,
            "memory_enabled": self.has_memory_enabled()
        }

    def pause_crawl(self) -> None:
        """Pause ongoing crawl."""
        self.crawl_state = "paused"
        logger.info(f"Crawl paused: {self.session_id}")

    def resume_crawl(self) -> None:
        """Resume paused crawl."""
        if self.crawl_state == "paused":
            self.crawl_state = "crawling"
            logger.info(f"Crawl resumed: {self.session_id}")

    def cancel_crawl(self) -> None:
        """Cancel ongoing crawl."""
        self.crawl_state = "cancelled"
        logger.info(f"Crawl cancelled: {self.session_id}")

