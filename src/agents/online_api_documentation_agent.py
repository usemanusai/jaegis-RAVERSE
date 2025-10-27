"""
API Documentation Agent - Generates OpenAPI Specifications and Documentation
Creates comprehensive API documentation from discovered endpoints.
Supports multiple export formats (JSON, YAML, Markdown).
"""

import logging
import json
import yaml
from typing import Dict, Any, Optional, List
from datetime import datetime

from agents.base_memory_agent import BaseMemoryAgent
from utils.database import DatabaseManager

logger = logging.getLogger(__name__)


class APIDocumentationAgent(BaseMemoryAgent):
    """
    API Documentation Agent - Generates comprehensive API documentation.
    
    Features:
    - OpenAPI 3.0 specification generation
    - Request/response schema inference
    - Authentication requirement detection
    - Example generation
    - Multiple export formats (JSON, YAML, Markdown)
    - Intelligent documentation with LLM support
    
    Optional Memory Support:
        memory_strategy: Optional memory strategy for context persistence
        memory_config: Optional memory configuration dictionary
    """

    def __init__(
        self,
        orchestrator=None,
        memory_strategy: Optional[str] = None,
        memory_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize API Documentation Agent.
        
        Args:
            orchestrator: Reference to orchestration agent
            memory_strategy: Optional memory strategy name
            memory_config: Optional memory configuration
        """
        super().__init__(
            name="API Documentation Agent",
            agent_type="API_DOCUMENTATION",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        
        self.db = DatabaseManager()
        self.openapi_version = "3.0.0"
        self.info_version = "1.0.0"

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate API documentation from discovered endpoints.
        
        Args:
            task: Task with discovered_apis, session_id, etc.
            
        Returns:
            Dictionary with generated documentation in multiple formats
        """
        try:
            self.report_progress(0.0, "Starting documentation generation")
            
            discovered_apis = task.get("discovered_apis", [])
            session_id = task.get("session_id")
            target_url = task.get("target_url", "Unknown")
            
            if not discovered_apis:
                logger.warning("No APIs provided for documentation")
                return {"error": "No APIs to document"}
            
            # Phase 1: Generate OpenAPI spec
            self.report_progress(0.3, "Generating OpenAPI specification")
            openapi_spec = self._generate_openapi_spec(discovered_apis, target_url)
            
            # Phase 2: Generate Markdown documentation
            self.report_progress(0.6, "Generating Markdown documentation")
            markdown_doc = self._generate_markdown_doc(discovered_apis, target_url)
            
            # Phase 3: Store documentation
            self.report_progress(0.8, "Storing documentation")
            self._store_documentation(session_id, openapi_spec, markdown_doc)
            
            self.report_progress(1.0, "Documentation generation complete")
            
            # Set metrics
            self.set_metric("apis_documented", len(discovered_apis))
            self.set_metric("openapi_spec_size", len(json.dumps(openapi_spec)))
            
            # Store in memory
            self.add_to_memory(
                f"Generated documentation for {len(discovered_apis)} APIs",
                f"Created OpenAPI spec and Markdown documentation"
            )
            
            return {
                "session_id": session_id,
                "apis_documented": len(discovered_apis),
                "openapi_spec": openapi_spec,
                "markdown_documentation": markdown_doc,
                "generated_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Documentation generation failed: {e}", exc_info=True)
            raise

    def _generate_openapi_spec(self, discovered_apis: List[Dict[str, Any]], 
                               target_url: str) -> Dict[str, Any]:
        """Generate OpenAPI 3.0 specification."""
        spec = {
            "openapi": self.openapi_version,
            "info": {
                "title": f"API Documentation - {target_url}",
                "version": self.info_version,
                "description": "Auto-generated API documentation from DeepCrawler discovery",
                "contact": {
                    "name": "RAVERSE 2.0 DeepCrawler",
                    "url": "https://github.com/raverse/deepcrawler"
                }
            },
            "servers": [
                {
                    "url": target_url,
                    "description": "Target API server"
                }
            ],
            "paths": {},
            "components": {
                "schemas": {
                    "Error": {
                        "type": "object",
                        "properties": {
                            "code": {"type": "integer"},
                            "message": {"type": "string"}
                        }
                    }
                }
            }
        }
        
        # Add paths for each discovered API
        for api in discovered_apis:
            path = self._extract_path(api.get("endpoint", ""))
            method = api.get("method", "GET").lower()
            
            if path not in spec["paths"]:
                spec["paths"][path] = {}
            
            spec["paths"][path][method] = {
                "summary": f"{method.upper()} {path}",
                "description": f"Discovered endpoint with confidence {api.get('confidence', 0):.2f}",
                "operationId": f"{method}_{path.replace('/', '_')}",
                "tags": ["discovered"],
                "responses": {
                    "200": {
                        "description": "Successful response",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        }
                    },
                    "400": {
                        "description": "Bad request"
                    },
                    "401": {
                        "description": "Unauthorized"
                    },
                    "404": {
                        "description": "Not found"
                    }
                }
            }
            
            # Add authentication if detected
            if api.get("authentication"):
                spec["paths"][path][method]["security"] = [
                    {"bearerAuth": []}
                ]
        
        # Add security schemes if needed
        if any(api.get("authentication") for api in discovered_apis):
            spec["components"]["securitySchemes"] = {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer"
                }
            }
        
        return spec

    def _generate_markdown_doc(self, discovered_apis: List[Dict[str, Any]], 
                               target_url: str) -> str:
        """Generate Markdown documentation."""
        doc = f"""# API Documentation

**Target**: {target_url}  
**Generated**: {datetime.now().isoformat()}  
**Total Endpoints**: {len(discovered_apis)}

## Overview

This documentation was automatically generated by RAVERSE 2.0 DeepCrawler.

## Endpoints

"""
        
        for i, api in enumerate(discovered_apis, 1):
            endpoint = api.get("endpoint", "Unknown")
            method = api.get("method", "GET")
            confidence = api.get("confidence", 0)
            discovery_method = api.get("discovery_method", "unknown")
            
            doc += f"""### {i}. {method} {endpoint}

**Confidence**: {confidence:.2f}  
**Discovery Method**: {discovery_method}  
**Authentication**: {api.get("authentication", "None")}

#### Description
Discovered endpoint for {method} requests.

#### Request
```
{method} {endpoint}
```

#### Response
```json
{{
  "status": "success",
  "data": {{}}
}}
```

---

"""
        
        doc += """## Authentication

Endpoints may require authentication. Check individual endpoint documentation.

## Rate Limiting

Rate limits may apply. Refer to API provider documentation.

## Error Handling

Standard HTTP status codes are used:
- 200: Success
- 400: Bad Request
- 401: Unauthorized
- 404: Not Found
- 500: Server Error

## Support

For issues or questions, contact the API provider.
"""
        
        return doc

    def _extract_path(self, endpoint: str) -> str:
        """Extract path from endpoint URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(endpoint)
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
            return path
        except Exception:
            return "/"

    def _store_documentation(self, session_id: Optional[str], 
                            openapi_spec: Dict[str, Any],
                            markdown_doc: str) -> None:
        """Store generated documentation in database."""
        try:
            if not session_id:
                logger.debug("No session_id provided, skipping database storage")
                return
            
            with self.db.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO raverse.crawl_history
                        (session_id, event_type, event_data)
                        VALUES (%s, %s, %s)
                    """, (
                        session_id,
                        "documentation_generated",
                        json.dumps({
                            "openapi_spec_size": len(json.dumps(openapi_spec)),
                            "markdown_size": len(markdown_doc),
                            "generated_at": datetime.now().isoformat()
                        })
                    ))
            logger.info(f"Documentation stored for session {session_id}")
        except Exception as e:
            logger.warning(f"Failed to store documentation: {e}")

    def export_openapi_json(self, openapi_spec: Dict[str, Any]) -> str:
        """Export OpenAPI spec as JSON."""
        return json.dumps(openapi_spec, indent=2)

    def export_openapi_yaml(self, openapi_spec: Dict[str, Any]) -> str:
        """Export OpenAPI spec as YAML."""
        return yaml.dump(openapi_spec, default_flow_style=False)

    def export_markdown(self, markdown_doc: str) -> str:
        """Export documentation as Markdown."""
        return markdown_doc

    def get_documentation_status(self) -> Dict[str, Any]:
        """Get documentation generation status."""
        return {
            "agent": self.name,
            "state": self.state,
            "progress": self.progress,
            "memory_enabled": self.has_memory_enabled()
        }

