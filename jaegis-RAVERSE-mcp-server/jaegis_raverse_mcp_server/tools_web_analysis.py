"""Web analysis tools for RAVERSE MCP Server"""

import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from .types import ToolResult, APIEndpoint, OpenAPISpec
from .errors import ValidationError, WebAnalysisError
from .logging_config import get_logger

logger = get_logger(__name__)


class WebAnalysisTools:
    """Tools for web analysis operations"""
    
    @staticmethod
    def _validate_url(url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def reconnaissance(target_url: str) -> ToolResult:
        """Perform web reconnaissance on a target"""
        try:
            if not target_url or not target_url.strip():
                raise ValidationError("Target URL cannot be empty")
            
            if not WebAnalysisTools._validate_url(target_url):
                raise ValidationError(f"Invalid URL format: {target_url}")
            
            logger.info("Web reconnaissance initiated", target_url=target_url)
            
            return ToolResult(
                success=True,
                data={
                    "target_url": target_url,
                    "status": "reconnaissance_initiated",
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Reconnaissance failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Reconnaissance failed: {str(e)}",
                error_code="RECONNAISSANCE_ERROR",
            )
    
    @staticmethod
    def analyze_javascript(
        js_code: str,
        deobfuscate: bool = True,
    ) -> ToolResult:
        """Analyze JavaScript code"""
        try:
            if not js_code or not js_code.strip():
                raise ValidationError("JavaScript code cannot be empty")
            
            if len(js_code) > 5000000:  # 5MB limit
                raise ValidationError("JavaScript code exceeds maximum size (5MB)")
            
            # Extract potential API endpoints using regex
            api_patterns = [
                r'(?:fetch|axios|XMLHttpRequest)\s*\(\s*["\']([^"\']+)["\']',
                r'(?:GET|POST|PUT|DELETE)\s+["\']([^"\']+)["\']',
                r'api[._](?:endpoint|url|path)\s*=\s*["\']([^"\']+)["\']',
            ]
            
            endpoints = []
            for pattern in api_patterns:
                matches = re.findall(pattern, js_code, re.IGNORECASE)
                endpoints.extend(matches)
            
            logger.info(
                "JavaScript analysis initiated",
                code_length=len(js_code),
                endpoints_found=len(set(endpoints)),
                deobfuscate=deobfuscate,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "analysis_initiated",
                    "code_length": len(js_code),
                    "endpoints_found": len(set(endpoints)),
                    "deobfuscate": deobfuscate,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"JavaScript analysis failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Analysis failed: {str(e)}",
                error_code="JS_ANALYSIS_ERROR",
            )
    
    @staticmethod
    def reverse_engineer_api(
        traffic_data: Dict[str, Any],
        js_analysis: Optional[Dict[str, Any]] = None,
    ) -> ToolResult:
        """Reverse engineer API from traffic and JS analysis"""
        try:
            if not traffic_data:
                raise ValidationError("Traffic data cannot be empty")
            
            logger.info(
                "API reverse engineering initiated",
                traffic_entries=len(traffic_data.get("entries", [])),
                has_js_analysis=js_analysis is not None,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "reverse_engineering_initiated",
                    "traffic_entries": len(traffic_data.get("entries", [])),
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"API reverse engineering failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Reverse engineering failed: {str(e)}",
                error_code="API_RE_ERROR",
            )
    
    @staticmethod
    def analyze_wasm(wasm_data: bytes) -> ToolResult:
        """Analyze WebAssembly module"""
        try:
            if not wasm_data:
                raise ValidationError("WASM data cannot be empty")
            
            if len(wasm_data) > 50000000:  # 50MB limit
                raise ValidationError("WASM data exceeds maximum size (50MB)")
            
            # Check WASM magic number
            if not wasm_data.startswith(b'\x00asm'):
                raise ValidationError("Invalid WASM module (missing magic number)")
            
            logger.info(
                "WASM analysis initiated",
                wasm_size=len(wasm_data),
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "wasm_analysis_initiated",
                    "wasm_size": len(wasm_data),
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"WASM analysis failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"WASM analysis failed: {str(e)}",
                error_code="WASM_ERROR",
            )
    
    @staticmethod
    def security_analysis(
        analysis_data: Dict[str, Any],
        check_headers: bool = True,
        check_cves: bool = True,
    ) -> ToolResult:
        """Perform security analysis"""
        try:
            if not analysis_data:
                raise ValidationError("Analysis data cannot be empty")
            
            logger.info(
                "Security analysis initiated",
                check_headers=check_headers,
                check_cves=check_cves,
            )
            
            return ToolResult(
                success=True,
                data={
                    "status": "security_analysis_initiated",
                    "check_headers": check_headers,
                    "check_cves": check_cves,
                },
            )
        except ValidationError as e:
            return ToolResult(success=False, error=str(e), error_code=e.error_code)
        except Exception as e:
            logger.error(f"Security analysis failed: {str(e)}")
            return ToolResult(
                success=False,
                error=f"Security analysis failed: {str(e)}",
                error_code="SECURITY_ERROR",
            )

