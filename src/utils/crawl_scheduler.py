"""
Crawl Scheduler for DeepCrawler - Async Crawl Execution
Handles rate limiting, retries, and concurrent crawling
Date: October 26, 2025
"""

import asyncio
import logging
import time
from typing import Optional, Dict, Callable, Any
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


class CrawlScheduler:
    """
    Manages crawl scheduling with rate limiting, retries, and concurrency control.
    """
    
    def __init__(self, max_concurrent: int = 5, default_timeout: int = 30,
                 default_rate_limit: float = 20.0):
        """
        Initialize crawl scheduler.
        
        Args:
            max_concurrent: Maximum concurrent crawls
            default_timeout: Default timeout in seconds
            default_rate_limit: Default rate limit (requests per minute)
        """
        self.max_concurrent = max_concurrent
        self.default_timeout = default_timeout
        self.default_rate_limit = default_rate_limit
        
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.domain_locks = defaultdict(asyncio.Lock)
        self.domain_last_request = defaultdict(float)
        self.domain_rate_limits = defaultdict(lambda: default_rate_limit)
        
        self.crawl_stats = {
            'total_scheduled': 0,
            'total_completed': 0,
            'total_failed': 0,
            'total_retried': 0,
        }
    
    def _get_domain(self, url: str) -> str:
        """
        Extract domain from URL.
        
        Args:
            url: URL to extract domain from
            
        Returns:
            Domain name
        """
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception as e:
            logger.warning(f"Error extracting domain from {url}: {e}")
            return "unknown"
    
    async def _wait_for_rate_limit(self, domain: str):
        """
        Wait for rate limit to allow next request.
        
        Args:
            domain: Domain to check rate limit for
        """
        rate_limit = self.domain_rate_limits[domain]
        min_interval = 60.0 / rate_limit  # Seconds between requests
        
        last_request = self.domain_last_request[domain]
        elapsed = time.time() - last_request
        
        if elapsed < min_interval:
            wait_time = min_interval - elapsed
            logger.debug(f"Rate limiting {domain}: waiting {wait_time:.2f}s")
            await asyncio.sleep(wait_time)
        
        self.domain_last_request[domain] = time.time()
    
    async def _execute_with_retry(self, url: str, crawl_func: Callable,
                                  max_retries: int = 3) -> Optional[Any]:
        """
        Execute crawl function with exponential backoff retry.
        
        Args:
            url: URL being crawled
            crawl_func: Async function to execute
            max_retries: Maximum retry attempts
            
        Returns:
            Result from crawl_func or None if all retries failed
        """
        domain = self._get_domain(url)
        
        for attempt in range(max_retries + 1):
            try:
                # Wait for rate limit
                async with self.domain_locks[domain]:
                    await self._wait_for_rate_limit(domain)
                
                # Execute crawl with timeout
                result = await asyncio.wait_for(
                    crawl_func(url),
                    timeout=self.default_timeout
                )
                
                logger.info(f"Successfully crawled: {url}")
                return result
            
            except asyncio.TimeoutError:
                logger.warning(f"Timeout crawling {url} (attempt {attempt + 1}/{max_retries + 1})")
                if attempt < max_retries:
                    wait_time = 2 ** attempt
                    logger.info(f"Retrying {url} in {wait_time}s")
                    await asyncio.sleep(wait_time)
                    self.crawl_stats['total_retried'] += 1
            
            except Exception as e:
                logger.error(f"Error crawling {url} (attempt {attempt + 1}/{max_retries + 1}): {e}")
                if attempt < max_retries:
                    wait_time = 2 ** attempt
                    logger.info(f"Retrying {url} in {wait_time}s")
                    await asyncio.sleep(wait_time)
                    self.crawl_stats['total_retried'] += 1
        
        logger.error(f"Failed to crawl {url} after {max_retries + 1} attempts")
        return None
    
    async def schedule_crawl(self, url: str, crawl_func: Callable,
                            max_retries: int = 3) -> Optional[Any]:
        """
        Schedule a crawl with concurrency control.
        
        Args:
            url: URL to crawl
            crawl_func: Async function to execute
            max_retries: Maximum retry attempts
            
        Returns:
            Result from crawl_func or None if failed
        """
        async with self.semaphore:
            self.crawl_stats['total_scheduled'] += 1
            
            try:
                result = await self._execute_with_retry(url, crawl_func, max_retries)
                
                if result is not None:
                    self.crawl_stats['total_completed'] += 1
                else:
                    self.crawl_stats['total_failed'] += 1
                
                return result
            
            except Exception as e:
                logger.error(f"Unexpected error scheduling crawl for {url}: {e}")
                self.crawl_stats['total_failed'] += 1
                return None
    
    async def execute_crawls(self, urls: list, crawl_func: Callable,
                            max_retries: int = 3) -> Dict[str, Any]:
        """
        Execute multiple crawls concurrently.
        
        Args:
            urls: List of URLs to crawl
            crawl_func: Async function to execute for each URL
            max_retries: Maximum retry attempts per URL
            
        Returns:
            Dictionary mapping URLs to results
        """
        tasks = [
            self.schedule_crawl(url, crawl_func, max_retries)
            for url in urls
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            url: result
            for url, result in zip(urls, results)
            if not isinstance(result, Exception)
        }
    
    def set_domain_rate_limit(self, domain: str, requests_per_minute: float):
        """
        Set rate limit for specific domain.
        
        Args:
            domain: Domain name
            requests_per_minute: Requests per minute limit
        """
        if requests_per_minute <= 0:
            logger.warning(f"Invalid rate limit for {domain}: {requests_per_minute}")
            return
        
        self.domain_rate_limits[domain] = requests_per_minute
        logger.info(f"Set rate limit for {domain}: {requests_per_minute} req/min")
    
    def get_crawl_status(self) -> Dict:
        """
        Get crawl scheduler status.
        
        Returns:
            Status dictionary
        """
        return {
            **self.crawl_stats,
            'max_concurrent': self.max_concurrent,
            'default_timeout': self.default_timeout,
            'domains_tracked': len(self.domain_rate_limits),
        }
    
    def reset_stats(self):
        """Reset crawl statistics."""
        self.crawl_stats = {
            'total_scheduled': 0,
            'total_completed': 0,
            'total_failed': 0,
            'total_retried': 0,
        }
        logger.info("Crawl scheduler stats reset")

