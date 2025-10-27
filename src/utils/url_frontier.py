"""
URL Frontier for DeepCrawler - Intelligent URL Management
Handles URL prioritization, deduplication, and frontier management
Date: October 26, 2025
"""

import hashlib
import logging
import heapq
from typing import Optional, Dict, List, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
from datetime import datetime
import re

logger = logging.getLogger(__name__)


class URLFrontier:
    """
    Manages URL frontier with intelligent prioritization and deduplication.
    Uses priority queue for efficient URL selection and Bloom filter for deduplication.
    """
    
    # API pattern regex patterns
    API_PATTERNS = [
        r'/api/',
        r'/v\d+/',
        r'/graphql',
        r'/rest/',
        r'/services/',
        r'/endpoint/',
        r'\.json$',
        r'\.xml$',
    ]
    
    def __init__(self, max_depth: int = 3, max_urls: int = 10000):
        """
        Initialize URL frontier.
        
        Args:
            max_depth: Maximum crawl depth
            max_urls: Maximum URLs to store
        """
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.frontier = []  # Priority queue (min-heap)
        self.seen_urls = set()  # URL hashes for deduplication
        self.url_metadata = {}  # Store URL metadata
        self.stats = {
            'total_added': 0,
            'total_crawled': 0,
            'total_duplicates': 0,
            'total_failed': 0,
        }
    
    def _normalize_url(self, url: str) -> str:
        """
        Normalize URL for consistent comparison.
        
        Args:
            url: URL to normalize
            
        Returns:
            Normalized URL
        """
        try:
            parsed = urlparse(url)
            
            # Remove fragment
            scheme = parsed.scheme or 'https'
            netloc = parsed.netloc.lower()
            path = parsed.path or '/'
            
            # Sort query parameters
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                sorted_params = sorted(params.items())
                query = urlencode(sorted_params, doseq=True)
            else:
                query = ''
            
            # Remove trailing slash from path (except root)
            if path != '/' and path.endswith('/'):
                path = path.rstrip('/')
            
            # Reconstruct URL
            normalized = f"{scheme}://{netloc}{path}"
            if query:
                normalized += f"?{query}"
            
            return normalized
        except Exception as e:
            logger.warning(f"Error normalizing URL {url}: {e}")
            return url
    
    def _get_url_hash(self, url: str) -> str:
        """
        Get SHA256 hash of normalized URL.
        
        Args:
            url: URL to hash
            
        Returns:
            SHA256 hash
        """
        normalized = self._normalize_url(url)
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def _calculate_priority(self, url: str, depth: int, discovered_at: datetime) -> float:
        """
        Calculate priority score for URL.
        
        Priority = (depth_score * 0.5) + (pattern_score * 0.3) + (recency_score * 0.2)
        
        Args:
            url: URL to score
            depth: Current depth
            discovered_at: When URL was discovered
            
        Returns:
            Priority score (higher = crawl first)
        """
        # Depth score: prefer shallower URLs
        depth_score = max(0, (self.max_depth - depth) / self.max_depth)
        
        # Pattern score: prefer API-like URLs
        pattern_score = 0.0
        for pattern in self.API_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                pattern_score = 1.0
                break
        
        # Recency score: prefer recently discovered
        now = datetime.utcnow()
        age_seconds = (now - discovered_at).total_seconds()
        recency_score = max(0, 1.0 - (age_seconds / 86400))  # Decay over 24 hours
        
        priority = (depth_score * 0.5) + (pattern_score * 0.3) + (recency_score * 0.2)
        return priority
    
    def add_url(self, url: str, depth: int, discovered_by: str = 'manual',
                discovered_at: Optional[datetime] = None) -> bool:
        """
        Add URL to frontier if not duplicate.
        
        Args:
            url: URL to add
            depth: Current depth
            discovered_by: How URL was discovered (dynamic, static, websocket)
            discovered_at: When URL was discovered
            
        Returns:
            True if added, False if duplicate or invalid
        """
        if depth > self.max_depth:
            return False
        
        if len(self.frontier) >= self.max_urls:
            logger.warning(f"Frontier at max capacity ({self.max_urls})")
            return False
        
        url_hash = self._get_url_hash(url)
        
        if url_hash in self.seen_urls:
            self.stats['total_duplicates'] += 1
            return False
        
        discovered_at = discovered_at or datetime.utcnow()
        priority = self._calculate_priority(url, depth, discovered_at)
        
        # Use negative priority for min-heap (higher priority = lower value)
        heap_entry = (-priority, self.stats['total_added'], url)
        heapq.heappush(self.frontier, heap_entry)
        
        self.seen_urls.add(url_hash)
        self.url_metadata[url_hash] = {
            'url': url,
            'depth': depth,
            'priority': priority,
            'status': 'pending',
            'discovered_by': discovered_by,
            'discovered_at': discovered_at.isoformat(),
            'crawled_at': None,
        }
        
        self.stats['total_added'] += 1
        return True
    
    def get_next_url(self) -> Optional[Dict]:
        """
        Get next URL to crawl from frontier.
        
        Returns:
            URL metadata dict or None if frontier empty
        """
        while self.frontier:
            _, _, url = heapq.heappop(self.frontier)
            url_hash = self._get_url_hash(url)
            
            if url_hash in self.url_metadata:
                metadata = self.url_metadata[url_hash]
                if metadata['status'] == 'pending':
                    metadata['status'] = 'crawling'
                    return metadata
        
        return None
    
    def mark_crawled(self, url: str, success: bool = True):
        """
        Mark URL as crawled.
        
        Args:
            url: URL that was crawled
            success: Whether crawl was successful
        """
        url_hash = self._get_url_hash(url)
        
        if url_hash in self.url_metadata:
            metadata = self.url_metadata[url_hash]
            metadata['status'] = 'crawled' if success else 'failed'
            metadata['crawled_at'] = datetime.utcnow().isoformat()
            
            if success:
                self.stats['total_crawled'] += 1
            else:
                self.stats['total_failed'] += 1
    
    def is_duplicate(self, url: str) -> bool:
        """
        Check if URL is duplicate.
        
        Args:
            url: URL to check
            
        Returns:
            True if duplicate, False otherwise
        """
        url_hash = self._get_url_hash(url)
        return url_hash in self.seen_urls
    
    def get_stats(self) -> Dict:
        """
        Get frontier statistics.
        
        Returns:
            Statistics dictionary
        """
        return {
            **self.stats,
            'frontier_size': len(self.frontier),
            'unique_urls': len(self.seen_urls),
            'pending_urls': sum(1 for m in self.url_metadata.values() if m['status'] == 'pending'),
            'crawled_urls': sum(1 for m in self.url_metadata.values() if m['status'] == 'crawled'),
            'failed_urls': sum(1 for m in self.url_metadata.values() if m['status'] == 'failed'),
        }
    
    def get_frontier_size(self) -> int:
        """Get current frontier size."""
        return len(self.frontier)
    
    def is_empty(self) -> bool:
        """Check if frontier is empty."""
        return len(self.frontier) == 0
    
    def clear(self):
        """Clear frontier."""
        self.frontier.clear()
        self.seen_urls.clear()
        self.url_metadata.clear()
        logger.info("URL frontier cleared")

