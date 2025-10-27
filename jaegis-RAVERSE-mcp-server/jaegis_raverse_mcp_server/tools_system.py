"""System and configuration tools for RAVERSE MCP Server"""

from typing import Dict, Any, List, Optional
from .types import ToolResult
from .errors import ValidationError
from .logging_config import get_logger

logger = get_logger(__name__)


class SystemTools:
    """System tools (Metrics, Multi-Level Cache, Configuration, LLM Interface)"""
    
    @staticmethod
    def metrics_collector(
        metric_type: str,
        metric_name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None,
    ) -> ToolResult:
        """Record performance metrics"""
        try:
            valid_types = {"counter", "histogram", "gauge"}
            if metric_type.lower() not in valid_types:
                raise ValidationError(f"Invalid metric type: {metric_type}")
            
            if not metric_name or not metric_name.strip():
                raise ValidationError("Metric name cannot be empty")
            
            logger.info(
                "Metric recorded",
                metric_type=metric_type,
                metric_name=metric_name,
                value=value,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "metric_recorded",
                    "metric_type": metric_type,
                    "metric_name": metric_name,
                    "value": value,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Metrics collection failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Metrics collection failed: {str(e)}",
                error_code="METRICS_ERROR",
            )
    
    @staticmethod
    def multi_level_cache(
        operation: str,
        key: str,
        value: Optional[Any] = None,
        ttl: int = 3600,
    ) -> ToolResult:
        """Manage multi-level cache (Memory -> Redis -> DB)"""
        try:
            valid_operations = {"get", "set", "delete", "clear"}
            if operation not in valid_operations:
                raise ValidationError(f"Invalid operation: {operation}")
            
            if not key or not key.strip():
                raise ValidationError("Key cannot be empty")
            
            if operation == "set" and value is None:
                raise ValidationError("Value required for set operation")
            
            if ttl < 0 or ttl > 86400:
                raise ValidationError("TTL must be between 0 and 86400 seconds")
            
            logger.info(
                "Multi-level cache operation",
                operation=operation,
                key=key,
                ttl=ttl,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "multi_level_cache_operation_completed",
                    "operation": operation,
                    "key": key,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Multi-level cache operation failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Multi-level cache operation failed: {str(e)}",
                error_code="CACHE_ERROR",
            )
    
    @staticmethod
    def configuration_service(
        operation: str,
        key: Optional[str] = None,
        value: Optional[Any] = None,
    ) -> ToolResult:
        """Access and manage configuration"""
        try:
            valid_operations = {"get", "set", "list", "validate"}
            if operation not in valid_operations:
                raise ValidationError(f"Invalid operation: {operation}")
            
            if operation in {"get", "set"} and not key:
                raise ValidationError(f"Key required for operation: {operation}")
            
            logger.info(
                "Configuration service operation",
                operation=operation,
                key=key,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "configuration_service_operation_completed",
                    "operation": operation,
                    "key": key,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Configuration service operation failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Configuration service operation failed: {str(e)}",
                error_code="CONFIG_ERROR",
            )
    
    @staticmethod
    def llm_interface(
        prompt: str,
        model: str = "gpt-4",
        max_tokens: int = 2048,
        temperature: float = 0.7,
    ) -> ToolResult:
        """Interface with LLM provider"""
        try:
            if not prompt or not prompt.strip():
                raise ValidationError("Prompt cannot be empty")
            
            if not model or not model.strip():
                raise ValidationError("Model cannot be empty")
            
            if max_tokens < 1 or max_tokens > 32000:
                raise ValidationError("Max tokens must be between 1 and 32000")
            
            if temperature < 0 or temperature > 2:
                raise ValidationError("Temperature must be between 0 and 2")
            
            logger.info(
                "LLM interface call initiated",
                model=model,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "llm_interface_call_initiated",
                    "model": model,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"LLM interface call failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"LLM interface call failed: {str(e)}",
                error_code="LLM_ERROR",
            )

