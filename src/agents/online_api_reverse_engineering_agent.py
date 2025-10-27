"""
API Reverse Engineering Agent for RAVERSE Online.
Maps endpoints, extracts schemas, and generates OpenAPI specifications.
"""

import logging
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import re

from .base_memory_agent import BaseMemoryAgent

logger = logging.getLogger(__name__)


class APIReverseEngineeringAgent(BaseMemoryAgent):
    """
    API Reverse Engineering Agent - Maps endpoints and generates OpenAPI specs.

    Tools: Swagger/OpenAPI, Postman, Insomnia, API Extractor

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
            name="API Reverse Engineering Agent",
            agent_type="API_REENG",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute API reverse engineering.

        Args:
            task: {
                "api_calls": [...],
                "traffic_data": {...},
                "options": {...}
            }
        """
        api_calls = task.get("api_calls", [])
        traffic_data = task.get("traffic_data", {})
        options = task.get("options", {})

        # Get memory context if available
        memory_context = self.get_memory_context("api_reverse_engineering")

        if not api_calls and not traffic_data:
            raise ValueError("api_calls or traffic_data required")

        self.logger.info(f"Starting API reverse engineering with {len(api_calls)} calls")

        results = {
            "timestamp": datetime.now().isoformat(),
            "endpoints": [],
            "endpoint_map": {},
            "authentication": {},
            "schemas": {},
            "openapi_spec": {},
            "postman_collection": {},
            "security_issues": []
        }

        try:
            # Step 1: Extract endpoints
            self.report_progress(0.2, "Extracting endpoints")
            results["endpoints"] = self._extract_endpoints(api_calls)
            results["endpoint_map"] = self._build_endpoint_map(results["endpoints"])

            # Step 2: Analyze authentication
            self.report_progress(0.4, "Analyzing authentication")
            results["authentication"] = self._analyze_authentication(api_calls)

            # Step 3: Extract schemas
            self.report_progress(0.6, "Extracting request/response schemas")
            results["schemas"] = self._extract_schemas(api_calls)

            # Step 4: Generate OpenAPI spec
            self.report_progress(0.8, "Generating OpenAPI specification")
            results["openapi_spec"] = self._generate_openapi_spec(results)

            # Step 5: Detect security issues
            self.report_progress(0.9, "Detecting security issues")
            results["security_issues"] = self._detect_security_issues(results)

            self.report_progress(1.0, "API reverse engineering complete")

            # Add artifacts
            self.add_artifact("endpoints", results["endpoints"], "Extracted endpoints")
            self.add_artifact("openapi_spec", results["openapi_spec"], "OpenAPI specification")
            self.add_artifact("security_issues", results["security_issues"], "Security issues found")

            # Set metrics
            self.set_metric("endpoints_found", len(results["endpoints"]))
            self.set_metric("security_issues_found", len(results["security_issues"]))

            # Store in memory if enabled
            if results:
                self.add_to_memory("api_reverse_engineering", json.dumps(results, default=str))

            return results

        except Exception as e:
            self.logger.error(f"API reverse engineering failed: {e}")
            raise

    def _extract_endpoints(self, api_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract unique endpoints from API calls."""
        endpoints = []
        seen = set()
        
        for call in api_calls:
            endpoint = call.get("endpoint", "")
            method = call.get("method", "GET")
            
            # Normalize endpoint (remove query params)
            normalized = re.sub(r'\?.*$', '', endpoint)
            
            key = f"{method}:{normalized}"
            if key not in seen:
                seen.add(key)
                endpoints.append({
                    "method": method,
                    "path": normalized,
                    "full_url": endpoint,
                    "parameters": self._extract_parameters(endpoint),
                    "requires_auth": call.get("has_auth", False)
                })
        
        self.logger.info(f"Extracted {len(endpoints)} unique endpoints")
        return endpoints

    def _extract_parameters(self, url: str) -> List[Dict[str, Any]]:
        """Extract parameters from URL."""
        parameters = []
        
        # Extract query parameters
        if '?' in url:
            query_string = url.split('?')[1]
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    parameters.append({
                        "name": key,
                        "value": value,
                        "type": "query"
                    })
        
        # Extract path parameters
        path_params = re.findall(r'/([a-zA-Z0-9_]+)/|/([a-zA-Z0-9_]+)$', url)
        for param in path_params:
            param_name = param[0] or param[1]
            if param_name and not param_name.startswith('api'):
                parameters.append({
                    "name": param_name,
                    "type": "path"
                })
        
        return parameters

    def _build_endpoint_map(self, endpoints: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Build endpoint map grouped by resource."""
        endpoint_map = {}
        
        for endpoint in endpoints:
            path = endpoint["path"]
            # Extract resource name (first path segment)
            parts = path.strip('/').split('/')
            resource = parts[0] if parts else "root"
            
            if resource not in endpoint_map:
                endpoint_map[resource] = []
            
            endpoint_map[resource].append(f"{endpoint['method']} {path}")
        
        return endpoint_map

    def _analyze_authentication(self, api_calls: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze authentication methods used."""
        auth_analysis = {
            "methods": [],
            "headers": [],
            "tokens": [],
            "cookie_based": False
        }
        
        for call in api_calls:
            headers = call.get("headers", {})
            
            # Check for Authorization header
            if "Authorization" in headers:
                auth_value = headers["Authorization"]
                if "Bearer" in auth_value:
                    auth_analysis["methods"].append("Bearer Token")
                elif "Basic" in auth_value:
                    auth_analysis["methods"].append("Basic Auth")
                elif "ApiKey" in auth_value:
                    auth_analysis["methods"].append("API Key")
                
                auth_analysis["tokens"].append(auth_value[:50] + "...")
            
            # Check for API key in headers
            for header_name in headers:
                if "key" in header_name.lower() or "token" in header_name.lower():
                    auth_analysis["headers"].append(header_name)
            
            # Check for cookies
            if "Cookie" in headers:
                auth_analysis["cookie_based"] = True
        
        # Remove duplicates
        auth_analysis["methods"] = list(set(auth_analysis["methods"]))
        auth_analysis["headers"] = list(set(auth_analysis["headers"]))
        
        return auth_analysis

    def _extract_schemas(self, api_calls: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract request/response schemas."""
        schemas = {
            "requests": {},
            "responses": {}
        }
        
        for call in api_calls:
            endpoint = call.get("endpoint", "")
            
            # Extract request schema
            if "body" in call:
                schemas["requests"][endpoint] = {
                    "type": "object",
                    "properties": self._infer_schema(call.get("body", {}))
                }
            
            # Extract response schema (would need response data)
            schemas["responses"][endpoint] = {
                "type": "object",
                "properties": {}
            }
        
        return schemas

    def _infer_schema(self, data: Any) -> Dict[str, Any]:
        """Infer JSON schema from data."""
        if isinstance(data, dict):
            properties = {}
            for key, value in data.items():
                properties[key] = {
                    "type": type(value).__name__,
                    "example": value
                }
            return properties
        
        return {}

    def _generate_openapi_spec(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate OpenAPI specification."""
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Reverse Engineered API",
                "version": "1.0.0",
                "description": "API specification generated by RAVERSE Online"
            },
            "servers": [
                {"url": "https://api.example.com"}
            ],
            "paths": {},
            "components": {
                "securitySchemes": {}
            }
        }
        
        # Add endpoints to paths
        for endpoint in results.get("endpoints", []):
            path = endpoint["path"]
            method = endpoint["method"].lower()
            
            if path not in spec["paths"]:
                spec["paths"][path] = {}
            
            spec["paths"][path][method] = {
                "summary": f"{method.upper()} {path}",
                "parameters": endpoint.get("parameters", []),
                "security": [{"bearerAuth": []}] if endpoint.get("requires_auth") else []
            }
        
        # Add security schemes
        auth = results.get("authentication", {})
        if "Bearer Token" in auth.get("methods", []):
            spec["components"]["securitySchemes"]["bearerAuth"] = {
                "type": "http",
                "scheme": "bearer"
            }
        
        return spec

    def _detect_security_issues(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect security issues in API."""
        issues = []
        
        # Check for unencrypted endpoints
        for endpoint in results.get("endpoints", []):
            if not endpoint["path"].startswith("https"):
                issues.append({
                    "severity": "high",
                    "type": "unencrypted_endpoint",
                    "endpoint": endpoint["path"],
                    "description": "Endpoint may not use HTTPS"
                })
        
        # Check for missing authentication
        for endpoint in results.get("endpoints", []):
            if not endpoint.get("requires_auth"):
                issues.append({
                    "severity": "medium",
                    "type": "missing_authentication",
                    "endpoint": endpoint["path"],
                    "description": "Endpoint does not require authentication"
                })
        
        return issues

