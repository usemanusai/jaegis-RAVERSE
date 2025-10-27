"""
Reconnaissance Agent for RAVERSE Online.
Identifies tech stack, endpoints, and authentication flows.
"""

import logging
import json
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import requests
from datetime import datetime

from .base_memory_agent import BaseMemoryAgent

logger = logging.getLogger(__name__)


class ReconnaissanceAgent(BaseMemoryAgent):
    """
    Reconnaissance Agent - Identifies target technology stack, endpoints, and auth flows.

    Tools: Wappalyzer, Retire.js, Lighthouse, Chrome DevTools

    Optional Memory Support:
        memory_strategy: Optional memory strategy (e.g., "retrieval")
        memory_config: Optional memory configuration dictionary
    """

    def __init__(
        self,
        orchestrator=None,
        memory_strategy: Optional[str] = None,
        memory_config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            name="Reconnaissance Agent",
            agent_type="RECON",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute reconnaissance on target.

        Args:
            task: {
                "target_url": "https://example.com",
                "scope": {...},
                "options": {...}
            }
        """
        target_url = task.get("target_url")
        scope = task.get("scope", {})
        options = task.get("options", {})

        if not target_url:
            raise ValueError("target_url required")

        # Get memory context if available
        memory_context = self.get_memory_context(target_url)

        # Validate authorization
        if not self.validate_authorization(target_url, scope):
            return self.skip("Target not in authorized scope")

        self.logger.info(f"Starting reconnaissance on {target_url}")

        results = {
            "target_url": target_url,
            "timestamp": datetime.now().isoformat(),
            "tech_stack": {},
            "endpoints": [],
            "auth_flows": {},
            "headers": {},
            "cookies": []
        }

        try:
            # Step 1: Detect tech stack
            self.report_progress(0.2, "Detecting technology stack")
            results["tech_stack"] = self._detect_tech_stack(target_url)

            # Step 2: Discover endpoints
            self.report_progress(0.5, "Discovering endpoints")
            results["endpoints"] = self._discover_endpoints(target_url)

            # Step 3: Map authentication flows
            self.report_progress(0.8, "Mapping authentication flows")
            results["auth_flows"] = self._map_auth_flows(target_url)

            # Step 4: Collect response headers
            self.report_progress(0.95, "Collecting response headers")
            results["headers"] = self._collect_headers(target_url)

            self.report_progress(1.0, "Reconnaissance complete")

            # Add artifacts
            self.add_artifact("tech_stack_report", results["tech_stack"], "Technology stack detection")
            self.add_artifact("endpoints_list", results["endpoints"], "Discovered endpoints")
            self.add_artifact("auth_flows_map", results["auth_flows"], "Authentication flows")

            # Set metrics
            self.set_metric("endpoints_discovered", len(results["endpoints"]))
            self.set_metric("tech_components", len(results["tech_stack"]))

            # Store in memory if enabled
            if results:
                self.add_to_memory(target_url, json.dumps(results, default=str))

            return results

        except Exception as e:
            self.logger.error(f"Reconnaissance failed: {e}")
            raise

    def _detect_tech_stack(self, target_url: str) -> Dict[str, Any]:
        """Detect technology stack using headers and content analysis."""
        tech_stack = {}
        
        try:
            response = self.session.get(target_url, timeout=10, verify=False)
            
            # Analyze headers
            headers = response.headers
            
            # Server detection
            if 'Server' in headers:
                tech_stack['server'] = headers['Server']
            
            # Framework detection
            if 'X-Powered-By' in headers:
                tech_stack['framework'] = headers['X-Powered-By']
            
            # CMS detection
            if 'X-Generator' in headers:
                tech_stack['cms'] = headers['X-Generator']
            
            # Analyze HTML content for tech indicators
            if response.text:
                content = response.text.lower()
                
                # Common framework indicators
                frameworks = {
                    'react': 'React',
                    'vue.js': 'Vue.js',
                    'angular': 'Angular',
                    'jquery': 'jQuery',
                    'bootstrap': 'Bootstrap',
                    'django': 'Django',
                    'flask': 'Flask',
                    'express': 'Express.js',
                    'wordpress': 'WordPress',
                    'drupal': 'Drupal'
                }
                
                for indicator, name in frameworks.items():
                    if indicator in content:
                        tech_stack[name.lower()] = name
            
            self.logger.info(f"Detected tech stack: {tech_stack}")
            
        except Exception as e:
            self.logger.warning(f"Tech stack detection failed: {e}")
        
        return tech_stack

    def _discover_endpoints(self, target_url: str) -> List[Dict[str, Any]]:
        """Discover endpoints from target."""
        endpoints = []
        
        try:
            response = self.session.get(target_url, timeout=10, verify=False)
            
            # Extract URLs from HTML
            url_pattern = r'(?:href|src|action)=["\']([^"\']+)["\']'
            matches = re.findall(url_pattern, response.text)
            
            base_url = urlparse(target_url).scheme + "://" + urlparse(target_url).netloc
            
            for match in matches:
                # Normalize URL
                if match.startswith('http'):
                    full_url = match
                elif match.startswith('/'):
                    full_url = base_url + match
                else:
                    full_url = base_url + '/' + match
                
                # Extract path
                path = urlparse(full_url).path
                
                endpoints.append({
                    "url": full_url,
                    "path": path,
                    "type": self._classify_endpoint(path)
                })
            
            # Remove duplicates
            endpoints = list({ep['url']: ep for ep in endpoints}.values())
            
            self.logger.info(f"Discovered {len(endpoints)} endpoints")
            
        except Exception as e:
            self.logger.warning(f"Endpoint discovery failed: {e}")
        
        return endpoints

    def _classify_endpoint(self, path: str) -> str:
        """Classify endpoint type."""
        path_lower = path.lower()
        
        if '/api/' in path_lower:
            return 'api'
        elif '/admin' in path_lower:
            return 'admin'
        elif '/login' in path_lower or '/auth' in path_lower:
            return 'auth'
        elif '/static/' in path_lower or path_lower.endswith(('.js', '.css', '.png', '.jpg')):
            return 'static'
        else:
            return 'page'

    def _map_auth_flows(self, target_url: str) -> Dict[str, Any]:
        """Map authentication flows."""
        auth_flows = {
            "methods": [],
            "endpoints": [],
            "tokens": []
        }
        
        try:
            response = self.session.get(target_url, timeout=10, verify=False)
            content = response.text.lower()
            
            # Detect auth methods
            if 'oauth' in content:
                auth_flows['methods'].append('OAuth')
            if 'jwt' in content or 'bearer' in content:
                auth_flows['methods'].append('JWT')
            if 'session' in content or 'cookie' in content:
                auth_flows['methods'].append('Session/Cookie')
            if 'basic' in content:
                auth_flows['methods'].append('Basic Auth')
            
            # Detect auth endpoints
            auth_keywords = ['login', 'signin', 'auth', 'oauth', 'token']
            for keyword in auth_keywords:
                if keyword in content:
                    auth_flows['endpoints'].append(f"/{keyword}")
            
            self.logger.info(f"Detected auth flows: {auth_flows['methods']}")
            
        except Exception as e:
            self.logger.warning(f"Auth flow mapping failed: {e}")
        
        return auth_flows

    def _collect_headers(self, target_url: str) -> Dict[str, str]:
        """Collect response headers."""
        headers = {}
        
        try:
            response = self.session.get(target_url, timeout=10, verify=False)
            headers = dict(response.headers)
        except Exception as e:
            self.logger.warning(f"Header collection failed: {e}")
        
        return headers

