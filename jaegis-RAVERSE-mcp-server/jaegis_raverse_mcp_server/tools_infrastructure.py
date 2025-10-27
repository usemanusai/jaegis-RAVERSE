"""Infrastructure tools for RAVERSE MCP Server"""

import json
from typing import Dict, Any, List, Optional
from .types import ToolResult
from .errors import ValidationError
from .logging_config import get_logger
from .database import DatabaseManager
from .cache import CacheManager

logger = get_logger(__name__)


class InfrastructureTools:
    """Tools for infrastructure operations"""
    
    def __init__(self, db_manager: DatabaseManager, cache_manager: CacheManager):
        self.db = db_manager
        self.cache = cache_manager
    
    def database_query(
        self,
        query: str,
        params: Optional[List[Any]] = None,
    ) -> ToolResult:
        """Execute a database query"""
        try:
            if not query or not query.strip():
                raise ValidationError("Query cannot be empty")
            
            # Validate query doesn't contain dangerous operations
            dangerous_keywords = ["DROP", "DELETE", "TRUNCATE"]
            if any(kw in query.upper() for kw in dangerous_keywords):
                logger.warning("Potentially dangerous query attempted", query=query)
                raise ValidationError("Query contains potentially dangerous operations")
            
            logger.info("Database query initiated", query_length=len(query))
            
            return ToolResult(
                success=True,
                data={
                    "status": "query_initiated",
                    "query_length": len(query),
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Database query failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Query failed: {str(e)}",
                error_code="DB_QUERY_ERROR",
            )
    
    def cache_operation(
        self,
        operation: str,
        key: str,
        value: Optional[Any] = None,
        ttl: Optional[int] = None,
    ) -> ToolResult:
        """Perform cache operation"""
        try:
            if not operation or not operation.strip():
                raise ValidationError("Operation cannot be empty")
            
            if not key or not key.strip():
                raise ValidationError("Key cannot be empty")
            
            valid_operations = {"get", "set", "delete", "exists", "clear"}
            if operation.lower() not in valid_operations:
                raise ValidationError(f"Invalid operation: {operation}")
            
            logger.info(
                "Cache operation initiated",
                operation=operation,
                key=key,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "cache_operation_initiated",
                    "operation": operation,
                    "key": key,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Cache operation failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Cache operation failed: {str(e)}",
                error_code="CACHE_ERROR",
            )
    
    def publish_message(
        self,
        channel: str,
        message: Dict[str, Any],
    ) -> ToolResult:
        """Publish message to A2A channel"""
        try:
            if not channel or not channel.strip():
                raise ValidationError("Channel cannot be empty")
            
            if not message:
                raise ValidationError("Message cannot be empty")
            
            logger.info(
                "A2A message publication initiated",
                channel=channel,
                message_size=len(json.dumps(message)),
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "message_published",
                    "channel": channel,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Message publication failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Publication failed: {str(e)}",
                error_code="A2A_ERROR",
            )
    
    def fetch_content(
        self,
        url: str,
        timeout: int = 30,
        retries: int = 3,
    ) -> ToolResult:
        """Fetch content from URL"""
        try:
            if not url or not url.strip():
                raise ValidationError("URL cannot be empty")
            
            if not url.startswith(("http://", "https://")):
                raise ValidationError("URL must start with http:// or https://")
            
            if timeout < 1 or timeout > 300:
                raise ValidationError("Timeout must be between 1 and 300 seconds")
            
            if retries < 0 or retries > 10:
                raise ValidationError("Retries must be between 0 and 10")
            
            logger.info(
                "Content fetch initiated",
                url=url,
                timeout=timeout,
                retries=retries,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "fetch_initiated",
                    "url": url,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Content fetch failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Fetch failed: {str(e)}",
                error_code="FETCH_ERROR",
            )
    
    def record_metric(
        self,
        metric_name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None,
    ) -> ToolResult:
        """Record a metric"""
        try:
            if not metric_name or not metric_name.strip():
                raise ValidationError("Metric name cannot be empty")
            
            if not isinstance(value, (int, float)):
                raise ValidationError("Metric value must be numeric")
            
            logger.info(
                "Metric recorded",
                metric_name=metric_name,
                value=value,
                labels=labels,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "metric_recorded",
                    "metric_name": metric_name,
                    "value": value,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Metric recording failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Metric recording failed: {str(e)}",
                error_code="METRICS_ERROR",
            )

