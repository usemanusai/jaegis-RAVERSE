"""
Content Fetcher for DeepCrawler - Playwright-based Content Retrieval
Handles browser automation, JavaScript execution, and authentication
Date: October 26, 2025
"""

import logging
import json
from typing import Optional, Dict, Any
from playwright.async_api import async_playwright, Page, Browser, BrowserContext
import asyncio

logger = logging.getLogger(__name__)


class ContentFetcher:
    """
    Fetches content using Playwright with support for JavaScript execution,
    authentication, and session management.
    """
    
    def __init__(self, headless: bool = True, timeout: int = 30):
        """
        Initialize content fetcher.
        
        Args:
            headless: Run browser in headless mode
            timeout: Default timeout in seconds
        """
        self.headless = headless
        self.timeout = timeout
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.playwright = None
    
    async def initialize(self):
        """Initialize Playwright and browser."""
        try:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=self.headless)
            self.context = await self.browser.new_context()
            logger.info("ContentFetcher initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing ContentFetcher: {e}")
            raise
    
    async def close(self):
        """Close browser and Playwright."""
        try:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            logger.info("ContentFetcher closed successfully")
        except Exception as e:
            logger.error(f"Error closing ContentFetcher: {e}")
    
    async def _create_page(self) -> Page:
        """
        Create new browser page.
        
        Returns:
            Playwright Page object
        """
        if not self.context:
            raise RuntimeError("ContentFetcher not initialized")
        
        page = await self.context.new_page()
        page.set_default_timeout(self.timeout * 1000)
        return page
    
    async def handle_auth(self, page: Page, auth_type: str, credentials: Dict[str, str]):
        """
        Handle authentication for page.
        
        Args:
            page: Playwright page
            auth_type: Type of authentication (basic, bearer, cookie)
            credentials: Authentication credentials
        """
        try:
            if auth_type == 'basic':
                username = credentials.get('username', '')
                password = credentials.get('password', '')
                await page.context.set_extra_http_headers({
                    'Authorization': f'Basic {username}:{password}'
                })
            
            elif auth_type == 'bearer':
                token = credentials.get('token', '')
                await page.context.set_extra_http_headers({
                    'Authorization': f'Bearer {token}'
                })
            
            elif auth_type == 'cookie':
                cookies = credentials.get('cookies', [])
                if cookies:
                    await page.context.add_cookies(cookies)
            
            logger.info(f"Applied {auth_type} authentication")
        except Exception as e:
            logger.error(f"Error handling {auth_type} authentication: {e}")
    
    async def execute_javascript(self, page: Page, script: str) -> Any:
        """
        Execute JavaScript on page.
        
        Args:
            page: Playwright page
            script: JavaScript code to execute
            
        Returns:
            Result from JavaScript execution
        """
        try:
            result = await page.evaluate(script)
            logger.debug(f"JavaScript executed successfully")
            return result
        except Exception as e:
            logger.error(f"Error executing JavaScript: {e}")
            return None
    
    async def fetch_url(self, url: str, wait_for: Optional[str] = None,
                       auth: Optional[Dict] = None) -> Optional[Dict]:
        """
        Fetch URL content using Playwright.
        
        Args:
            url: URL to fetch
            wait_for: CSS selector to wait for before returning
            auth: Authentication credentials dict with 'type' and 'credentials'
            
        Returns:
            Response data dictionary or None if failed
        """
        page = None
        try:
            page = await self._create_page()
            
            # Handle authentication if provided
            if auth:
                await self.handle_auth(page, auth.get('type', 'bearer'), 
                                      auth.get('credentials', {}))
            
            # Navigate to URL
            response = await page.goto(url, wait_until='networkidle')
            
            if not response:
                logger.warning(f"No response from {url}")
                return None
            
            # Wait for element if specified
            if wait_for:
                try:
                    await page.wait_for_selector(wait_for, timeout=self.timeout * 1000)
                except Exception as e:
                    logger.warning(f"Timeout waiting for selector {wait_for}: {e}")
            
            # Capture response data
            response_data = {
                'url': page.url,
                'status': response.status,
                'headers': dict(response.headers),
                'html': await page.content(),
                'cookies': await page.context.cookies(),
            }
            
            logger.info(f"Successfully fetched {url} (status: {response.status})")
            return response_data
        
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            return None
        
        finally:
            if page:
                await page.close()
    
    async def capture_response(self, url: str, auth: Optional[Dict] = None) -> Optional[Dict]:
        """
        Capture detailed response information.
        
        Args:
            url: URL to capture
            auth: Authentication credentials
            
        Returns:
            Detailed response dictionary
        """
        page = None
        captured_requests = []
        
        try:
            page = await self._create_page()
            
            # Capture network requests
            def handle_response(response):
                if response.request.resource_type in ['fetch', 'xhr']:
                    captured_requests.append({
                        'url': response.url,
                        'method': response.request.method,
                        'status': response.status,
                        'headers': dict(response.headers),
                    })
            
            page.on('response', handle_response)
            
            # Handle authentication
            if auth:
                await self.handle_auth(page, auth.get('type', 'bearer'),
                                      auth.get('credentials', {}))
            
            # Navigate to URL
            response = await page.goto(url, wait_until='networkidle')
            
            if not response:
                return None
            
            # Get page content
            html = await page.content()
            
            response_data = {
                'url': page.url,
                'status': response.status,
                'headers': dict(response.headers),
                'html_length': len(html),
                'captured_requests': captured_requests,
                'cookies': await page.context.cookies(),
                'local_storage': await page.evaluate('() => JSON.stringify(localStorage)'),
            }
            
            logger.info(f"Captured response from {url}: {len(captured_requests)} requests")
            return response_data
        
        except Exception as e:
            logger.error(f"Error capturing response from {url}: {e}")
            return None
        
        finally:
            if page:
                await page.close()
    
    async def get_page_apis(self, url: str) -> Optional[list]:
        """
        Extract API calls from page.
        
        Args:
            url: URL to analyze
            
        Returns:
            List of API endpoints found
        """
        page = None
        apis = []
        
        try:
            page = await self._create_page()
            
            # Capture fetch and XHR calls
            def handle_response(response):
                if response.request.resource_type in ['fetch', 'xhr']:
                    apis.append({
                        'url': response.url,
                        'method': response.request.method,
                        'status': response.status,
                    })
            
            page.on('response', handle_response)
            
            # Navigate and wait for network idle
            await page.goto(url, wait_until='networkidle')
            
            logger.info(f"Found {len(apis)} API calls on {url}")
            return apis
        
        except Exception as e:
            logger.error(f"Error extracting APIs from {url}: {e}")
            return None
        
        finally:
            if page:
                await page.close()

