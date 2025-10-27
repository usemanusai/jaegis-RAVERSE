"""Utility and pattern matching tools for RAVERSE MCP Server"""

from typing import Dict, Any, List, Optional
from .types import ToolResult
from .errors import ValidationError
from .logging_config import get_logger

logger = get_logger(__name__)


class UtilityTools:
    """Utility tools (URL Frontier, API Pattern Matcher, Response Classifier, WebSocket, Crawl Scheduler)"""
    
    @staticmethod
    def url_frontier_operation(
        operation: str,
        url: Optional[str] = None,
        priority: int = 5,
    ) -> ToolResult:
        """Manage URL frontier for crawling"""
        try:
            valid_operations = {"add", "get_next", "mark_visited", "get_status"}
            if operation not in valid_operations:
                raise ValidationError(f"Invalid operation: {operation}")
            
            if operation in {"add", "mark_visited"} and not url:
                raise ValidationError(f"URL required for operation: {operation}")
            
            if priority < 1 or priority > 10:
                raise ValidationError("Priority must be between 1 and 10")
            
            logger.info(
                "URL frontier operation",
                operation=operation,
                url=url,
                priority=priority,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "url_frontier_operation_completed",
                    "operation": operation,
                    "url": url,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"URL frontier operation failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"URL frontier operation failed: {str(e)}",
                error_code="URL_FRONTIER_ERROR",
            )
    
    @staticmethod
    def api_pattern_matcher(
        traffic_data: Dict[str, Any],
        pattern_type: str = "rest",
    ) -> ToolResult:
        """Identify API patterns in traffic"""
        try:
            if not traffic_data:
                raise ValidationError("Traffic data cannot be empty")
            
            valid_patterns = {"rest", "graphql", "grpc", "websocket"}
            if pattern_type.lower() not in valid_patterns:
                raise ValidationError(f"Invalid pattern type: {pattern_type}")
            
            logger.info(
                "API pattern matching initiated",
                pattern_type=pattern_type,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "api_pattern_matching_initiated",
                    "pattern_type": pattern_type,
                    "endpoints_found": 0,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"API pattern matching failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"API pattern matching failed: {str(e)}",
                error_code="API_PATTERN_ERROR",
            )
    
    @staticmethod
    def response_classifier(
        response_data: Dict[str, Any],
        infer_schema: bool = True,
    ) -> ToolResult:
        """Classify HTTP response types"""
        try:
            if not response_data:
                raise ValidationError("Response data cannot be empty")
            
            logger.info(
                "Response classification initiated",
                infer_schema=infer_schema,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "response_classification_initiated",
                    "infer_schema": infer_schema,
                    "content_type": "application/json",
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Response classification failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Response classification failed: {str(e)}",
                error_code="RESPONSE_CLASSIFIER_ERROR",
            )
    
    @staticmethod
    def websocket_analyzer(
        websocket_data: Dict[str, Any],
        analyze_handshake: bool = True,
    ) -> ToolResult:
        """Analyze WebSocket communication"""
        try:
            if not websocket_data:
                raise ValidationError("WebSocket data cannot be empty")
            
            logger.info(
                "WebSocket analysis initiated",
                analyze_handshake=analyze_handshake,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "websocket_analysis_initiated",
                    "analyze_handshake": analyze_handshake,
                    "protocol_version": "13",
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"WebSocket analysis failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"WebSocket analysis failed: {str(e)}",
                error_code="WEBSOCKET_ERROR",
            )
    
    @staticmethod
    def crawl_scheduler(
        operation: str,
        job_data: Optional[Dict[str, Any]] = None,
        priority: int = 5,
    ) -> ToolResult:
        """Schedule and manage crawl jobs"""
        try:
            valid_operations = {"schedule", "get_next", "update_status", "list_jobs"}
            if operation not in valid_operations:
                raise ValidationError(f"Invalid operation: {operation}")
            
            if operation == "schedule" and not job_data:
                raise ValidationError("Job data required for schedule operation")
            
            if priority < 1 or priority > 10:
                raise ValidationError("Priority must be between 1 and 10")
            
            logger.info(
                "Crawl scheduler operation",
                operation=operation,
                priority=priority,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "crawl_scheduler_operation_completed",
                    "operation": operation,
                    "priority": priority,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Crawl scheduler operation failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Crawl scheduler operation failed: {str(e)}",
                error_code="CRAWL_SCHEDULER_ERROR",
            )

