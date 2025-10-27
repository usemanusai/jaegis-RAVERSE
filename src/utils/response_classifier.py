"""
Response Classifier for DeepCrawler - API Response Classification
Classifies HTTP responses as API or non-API with confidence scoring
Date: October 26, 2025
"""

import logging
import json
import re
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class ResponseClassifier:
    """
    Classifies HTTP responses to determine if they are API responses.
    Uses multiple heuristics and confidence scoring.
    """
    
    # Confidence thresholds
    API_CONFIDENCE_THRESHOLD = 0.6
    
    # Content type patterns
    API_CONTENT_TYPES = [
        'application/json',
        'application/xml',
        'text/xml',
        'application/ld+json',
        'application/vnd.api+json',
        'application/hal+json',
    ]
    
    # Authentication headers
    AUTH_HEADERS = [
        'Authorization',
        'X-API-Key',
        'X-Auth-Token',
        'X-Access-Token',
        'API-Key',
        'Token',
    ]
    
    def __init__(self, threshold: float = 0.6):
        """
        Initialize response classifier.
        
        Args:
            threshold: Confidence threshold for API classification
        """
        self.threshold = threshold
    
    def classify(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify response as API or not.
        
        Args:
            response: Response dictionary with status, headers, body
            
        Returns:
            Classification result with confidence score
        """
        classification = {
            'is_api': False,
            'confidence': 0.0,
            'reasons': [],
            'content_type': response.get("headers", {}).get("Content-Type", ""),
            'status_code': response.get("status_code", 0),
        }
        
        # Analyze different aspects
        classification['confidence'] += self._analyze_content_type(response)
        classification['confidence'] += self._analyze_structure(response)
        classification['confidence'] += self._detect_auth(response)
        classification['confidence'] += self._analyze_url_pattern(response)
        classification['confidence'] += self._analyze_status_code(response)
        
        # Normalize confidence to 0-1 range
        classification['confidence'] = min(1.0, classification['confidence'])
        
        # Determine if API
        classification['is_api'] = classification['confidence'] >= self.threshold
        
        return classification
    
    def _analyze_content_type(self, response: Dict[str, Any]) -> float:
        """
        Analyze content type header.
        
        Args:
            response: Response dictionary
            
        Returns:
            Confidence score (0.0-0.3)
        """
        headers = response.get("headers", {})
        content_type = headers.get("Content-Type", "").lower()
        
        if not content_type:
            return 0.0
        
        # Check for API content types
        for api_type in self.API_CONTENT_TYPES:
            if api_type in content_type:
                logger.debug(f"Found API content type: {api_type}")
                return 0.3
        
        return 0.0
    
    def _analyze_structure(self, response: Dict[str, Any]) -> float:
        """
        Analyze response body structure.
        
        Args:
            response: Response dictionary
            
        Returns:
            Confidence score (0.0-0.3)
        """
        body = response.get("body", "")
        
        if not body:
            return 0.0
        
        try:
            # Try to parse as JSON
            if body.strip().startswith(("{", "[")):
                data = json.loads(body)
                
                # Check for common API response structures
                if isinstance(data, dict):
                    # Check for common API keys
                    api_keys = ['data', 'result', 'results', 'items', 'error', 'message', 'status']
                    if any(key in data for key in api_keys):
                        logger.debug("Found common API response structure")
                        return 0.3
                    
                    # Check for nested structure
                    if len(data) > 0 and any(isinstance(v, (dict, list)) for v in data.values()):
                        logger.debug("Found nested JSON structure")
                        return 0.2
                
                elif isinstance(data, list):
                    logger.debug("Found JSON array structure")
                    return 0.25
        
        except (json.JSONDecodeError, ValueError):
            pass
        
        # Check for XML structure
        if body.strip().startswith("<?xml") or body.strip().startswith("<"):
            logger.debug("Found XML structure")
            return 0.2
        
        return 0.0
    
    def _detect_auth(self, response: Dict[str, Any]) -> float:
        """
        Detect authentication headers.
        
        Args:
            response: Response dictionary
            
        Returns:
            Confidence score (0.0-0.2)
        """
        headers = response.get("headers", {})
        
        for auth_header in self.AUTH_HEADERS:
            if auth_header in headers:
                logger.debug(f"Found authentication header: {auth_header}")
                return 0.2
        
        return 0.0
    
    def _analyze_url_pattern(self, response: Dict[str, Any]) -> float:
        """
        Analyze URL pattern for API indicators.
        
        Args:
            response: Response dictionary
            
        Returns:
            Confidence score (0.0-0.4)
        """
        url = response.get("url", "").lower()
        
        if not url:
            return 0.0
        
        # Check for API patterns
        api_patterns = [
            r'/api/',
            r'/v\d+/',
            r'/graphql',
            r'/rest/',
            r'/services/',
            r'/endpoint/',
            r'\.json$',
            r'\.xml$',
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, url):
                logger.debug(f"Found API pattern: {pattern}")
                return 0.4
        
        # Check for resource patterns
        resource_patterns = [
            r'/users',
            r'/posts',
            r'/comments',
            r'/products',
            r'/orders',
            r'/items',
            r'/resources',
        ]
        
        for pattern in resource_patterns:
            if re.search(pattern, url):
                logger.debug(f"Found resource pattern: {pattern}")
                return 0.2
        
        return 0.0
    
    def _analyze_status_code(self, response: Dict[str, Any]) -> float:
        """
        Analyze HTTP status code.
        
        Args:
            response: Response dictionary
            
        Returns:
            Confidence score (0.0-0.1)
        """
        status = response.get("status_code", 0)
        
        # API responses typically use 2xx, 4xx, or 5xx
        if 200 <= status < 600:
            return 0.05
        
        return 0.0
    
    def is_api_response(self, response: Dict[str, Any]) -> bool:
        """
        Check if response is an API response.
        
        Args:
            response: Response dictionary
            
        Returns:
            True if response is API, False otherwise
        """
        classification = self.classify(response)
        return classification['is_api']
    
    def analyze_structure(self, body: str) -> Dict[str, Any]:
        """
        Analyze response body structure.
        
        Args:
            body: Response body
            
        Returns:
            Structure analysis dictionary
        """
        analysis = {
            'type': 'unknown',
            'is_json': False,
            'is_xml': False,
            'is_html': False,
            'structure': None,
        }
        
        if not body:
            return analysis
        
        body_stripped = body.strip()
        
        # Check for JSON
        if body_stripped.startswith(("{", "[")):
            try:
                analysis['structure'] = json.loads(body)
                analysis['is_json'] = True
                analysis['type'] = 'json'
                return analysis
            except:
                pass
        
        # Check for XML
        if body_stripped.startswith("<?xml") or body_stripped.startswith("<"):
            analysis['is_xml'] = True
            analysis['type'] = 'xml'
            return analysis
        
        # Check for HTML
        if body_stripped.startswith("<!DOCTYPE") or body_stripped.startswith("<html"):
            analysis['is_html'] = True
            analysis['type'] = 'html'
            return analysis
        
        return analysis
    
    def detect_auth(self, headers: Dict[str, str]) -> bool:
        """
        Detect if authentication is required.
        
        Args:
            headers: Response headers
            
        Returns:
            True if authentication detected, False otherwise
        """
        for auth_header in self.AUTH_HEADERS:
            if auth_header in headers:
                return True
        
        return False
    
    def calculate_confidence(self, response: Dict[str, Any]) -> float:
        """
        Calculate confidence score for response.
        
        Args:
            response: Response dictionary
            
        Returns:
            Confidence score (0.0-1.0)
        """
        classification = self.classify(response)
        return classification['confidence']

