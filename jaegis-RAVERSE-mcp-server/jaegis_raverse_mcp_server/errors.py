"""Error types and exception handling for RAVERSE MCP Server"""

from typing import Optional, Any, Dict


class RAVERSEMCPError(Exception):
    """Base exception for RAVERSE MCP Server"""
    
    def __init__(
        self,
        message: str,
        error_code: str = "UNKNOWN_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary"""
        return {
            "error": self.error_code,
            "message": self.message,
            "details": self.details,
        }


class ConfigurationError(RAVERSEMCPError):
    """Configuration error"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CONFIGURATION_ERROR", details)


class DatabaseError(RAVERSEMCPError):
    """Database operation error"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "DATABASE_ERROR", details)


class CacheError(RAVERSEMCPError):
    """Cache operation error"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "CACHE_ERROR", details)


class ValidationError(RAVERSEMCPError):
    """Input validation error"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "VALIDATION_ERROR", details)


class ToolExecutionError(RAVERSEMCPError):
    """Tool execution error"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "TOOL_EXECUTION_ERROR", details)


class LLMError(RAVERSEMCPError):
    """LLM API error"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "LLM_ERROR", details)


class BinaryAnalysisError(RAVERSEMCPError):
    """Binary analysis error"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "BINARY_ANALYSIS_ERROR", details)


class WebAnalysisError(RAVERSEMCPError):
    """Web analysis error"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "WEB_ANALYSIS_ERROR", details)


class NotFoundError(RAVERSEMCPError):
    """Resource not found error"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "NOT_FOUND_ERROR", details)


class TimeoutError(RAVERSEMCPError):
    """Operation timeout error"""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, "TIMEOUT_ERROR", details)

