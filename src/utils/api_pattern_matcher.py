"""
API Pattern Matcher for DeepCrawler - API Endpoint Pattern Recognition
Identifies and validates API endpoints using pattern matching
Date: October 26, 2025
"""

import logging
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class APIPatternMatcher:
    """
    Matches and validates API endpoints using regex patterns and heuristics.
    """
    
    # API endpoint patterns
    PATTERNS = {
        'rest_api': r'(?:https?://)?(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/api/[a-zA-Z0-9/_-]+)',
        'versioned_api': r'(?:/v\d+)?(?:/api)?/[a-zA-Z0-9/_-]+',
        'graphql': r'(?:https?://)?[^\s]+/graphql',
        'rest_resource': r'/(?:users|posts|comments|products|orders|items|resources|data|content)/(?:\d+|[a-zA-Z0-9-]+)',
        'json_endpoint': r'(?:https?://)?[^\s]+\.json(?:\?.*)?$',
        'xml_endpoint': r'(?:https?://)?[^\s]+\.xml(?:\?.*)?$',
    }
    
    # HTTP methods
    HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
    
    def __init__(self):
        """Initialize API pattern matcher."""
        self.matched_endpoints = []
    
    def match(self, url: str) -> Dict[str, Any]:
        """
        Match URL against API patterns.
        
        Args:
            url: URL to match
            
        Returns:
            Match result with confidence score
        """
        result = {
            'url': url,
            'is_api': False,
            'confidence': 0.0,
            'matched_patterns': [],
            'reasons': [],
        }
        
        # Check against each pattern
        for pattern_name, pattern in self.PATTERNS.items():
            if re.search(pattern, url, re.IGNORECASE):
                result['matched_patterns'].append(pattern_name)
                result['confidence'] += 0.2
                result['reasons'].append(f"Matched {pattern_name} pattern")
        
        # Additional heuristics
        result['confidence'] += self._check_url_structure(url)
        result['confidence'] += self._check_query_parameters(url)
        result['confidence'] += self._check_path_segments(url)
        
        # Normalize confidence
        result['confidence'] = min(1.0, result['confidence'])
        
        # Determine if API
        result['is_api'] = result['confidence'] >= 0.6
        
        return result
    
    def _check_url_structure(self, url: str) -> float:
        """
        Check URL structure for API indicators.
        
        Args:
            url: URL to check
            
        Returns:
            Confidence score (0.0-0.2)
        """
        score = 0.0
        
        # Check for API keywords
        api_keywords = ['api', 'v1', 'v2', 'v3', 'graphql', 'rest', 'services', 'endpoint']
        for keyword in api_keywords:
            if keyword in url.lower():
                score += 0.1
                break
        
        # Check for resource patterns
        resource_keywords = ['users', 'posts', 'comments', 'products', 'orders', 'items']
        for keyword in resource_keywords:
            if f'/{keyword}' in url.lower():
                score += 0.1
                break
        
        return min(0.2, score)
    
    def _check_query_parameters(self, url: str) -> float:
        """
        Check query parameters for API indicators.
        
        Args:
            url: URL to check
            
        Returns:
            Confidence score (0.0-0.1)
        """
        if '?' not in url:
            return 0.0
        
        query_string = url.split('?')[1]
        
        # Check for common API query parameters
        api_params = ['filter', 'sort', 'limit', 'offset', 'page', 'per_page', 'format', 'api_key']
        for param in api_params:
            if param in query_string.lower():
                return 0.1
        
        return 0.0
    
    def _check_path_segments(self, url: str) -> float:
        """
        Check path segments for API indicators.
        
        Args:
            url: URL to check
            
        Returns:
            Confidence score (0.0-0.1)
        """
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            # Check for numeric IDs (common in REST APIs)
            if re.search(r'/\d+(?:/|$)', path):
                return 0.1
            
            # Check for UUID patterns
            if re.search(r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', path):
                return 0.1
        
        except Exception as e:
            logger.warning(f"Error checking path segments: {e}")
        
        return 0.0
    
    def is_api_url(self, url: str) -> bool:
        """
        Check if URL is an API endpoint.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is API, False otherwise
        """
        result = self.match(url)
        return result['is_api']
    
    def get_api_version(self, url: str) -> Optional[str]:
        """
        Extract API version from URL.
        
        Args:
            url: URL to analyze
            
        Returns:
            API version string or None
        """
        # Check for version patterns
        version_patterns = [
            r'/v(\d+(?:\.\d+)*)',
            r'/api/v(\d+(?:\.\d+)*)',
            r'version=(\d+(?:\.\d+)*)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def extract_resource_name(self, url: str) -> Optional[str]:
        """
        Extract resource name from URL.
        
        Args:
            url: URL to analyze
            
        Returns:
            Resource name or None
        """
        try:
            parsed = urlparse(url)
            path = parsed.path
            
            # Extract last meaningful path segment
            segments = [s for s in path.split('/') if s and not s.isdigit()]
            
            if segments:
                # Return last segment (usually the resource)
                resource = segments[-1]
                # Remove file extensions
                resource = re.sub(r'\.(json|xml|html)$', '', resource, flags=re.IGNORECASE)
                return resource
        
        except Exception as e:
            logger.warning(f"Error extracting resource name: {e}")
        
        return None
    
    def extract_parameters(self, url: str) -> Dict[str, List[str]]:
        """
        Extract path and query parameters from URL.
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary with path_params and query_params
        """
        parameters = {
            'path_params': [],
            'query_params': [],
        }
        
        try:
            parsed = urlparse(url)
            
            # Extract path parameters (numeric IDs, UUIDs)
            path = parsed.path
            
            # Numeric IDs
            numeric_ids = re.findall(r'/(\d+)(?:/|$)', path)
            parameters['path_params'].extend(numeric_ids)
            
            # UUIDs
            uuids = re.findall(r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', path)
            parameters['path_params'].extend(uuids)
            
            # Extract query parameters
            if parsed.query:
                query_params = parsed.query.split('&')
                for param in query_params:
                    if '=' in param:
                        key = param.split('=')[0]
                        parameters['query_params'].append(key)
        
        except Exception as e:
            logger.warning(f"Error extracting parameters: {e}")
        
        return parameters
    
    def detect_rest_verbs(self, url: str, method: Optional[str] = None) -> List[str]:
        """
        Detect REST verbs (HTTP methods) for URL.
        
        Args:
            url: URL to analyze
            method: Optional HTTP method
            
        Returns:
            List of likely HTTP methods
        """
        likely_methods = []
        
        # If method provided, return it
        if method and method.upper() in self.HTTP_METHODS:
            return [method.upper()]
        
        # Infer from URL patterns
        path = urlparse(url).path.lower()
        
        # Collection endpoints typically support GET, POST
        if path.endswith(('s', 'list', 'items', 'data')):
            likely_methods.extend(['GET', 'POST'])
        
        # Item endpoints typically support GET, PUT, DELETE
        if re.search(r'/\d+(?:/|$)', path) or re.search(r'/[a-f0-9-]{36}(?:/|$)', path):
            likely_methods.extend(['GET', 'PUT', 'DELETE', 'PATCH'])
        
        # Default to GET if no pattern matched
        if not likely_methods:
            likely_methods.append('GET')
        
        return list(set(likely_methods))

