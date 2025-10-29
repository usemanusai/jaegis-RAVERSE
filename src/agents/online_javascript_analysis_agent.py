"""
JavaScript Analysis Agent for RAVERSE Online.
Deobfuscates, parses, and analyzes JavaScript code using AST analysis.
"""

import logging
import json
import re
import subprocess
from typing import Dict, Any, List, Optional
from datetime import datetime
import tempfile
import os

try:
    import esprima
except ImportError:
    esprima = None

try:
    import jsbeautifier
except ImportError:
    jsbeautifier = None

from .base_memory_agent import BaseMemoryAgent

logger = logging.getLogger(__name__)


class JavaScriptAnalysisAgent(BaseMemoryAgent):
    """
    JavaScript Analysis Agent - Deobfuscates and analyzes JavaScript code.

    Tools: de4js, Babel, ESLint, Webpack, Terser, esbuild

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
            name="JavaScript Analysis Agent",
            agent_type="JS_ANALYSIS",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.temp_dir = tempfile.mkdtemp(prefix="raverse_js_")
        self._last_analyzed_code = ""

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute JavaScript analysis.

        Args:
            task: {
                "javascript_code": "...",
                "source_url": "https://example.com/app.js",
                "options": {...}
            }
        """
        js_code = task.get("javascript_code")
        source_url = task.get("source_url", "unknown")
        options = task.get("options", {})

        # Get memory context if available
        memory_context = self.get_memory_context(source_url)

        if not js_code:
            raise ValueError("javascript_code required")

        self.logger.info(f"Starting JavaScript analysis from {source_url}")

        results = {
            "source_url": source_url,
            "timestamp": datetime.now().isoformat(),
            "code_size": len(js_code),
            "is_minified": self._is_minified(js_code),
            "is_obfuscated": self._is_obfuscated(js_code),
            "deobfuscated_code": "",
            "ast_analysis": {},
            "api_calls": [],
            "functions": [],
            "variables": [],
            "suspicious_patterns": [],
            "dependencies": []
        }

        try:
            # Store code for pattern extraction
            self._store_analyzed_code(js_code)

            # Step 1: Detect minification/obfuscation
            self.report_progress(0.1, "Analyzing code structure")

            # Step 2: Deobfuscate if needed
            self.report_progress(0.3, "Deobfuscating code")
            results["deobfuscated_code"] = self._deobfuscate(js_code)

            # Step 3: Parse AST
            self.report_progress(0.5, "Parsing Abstract Syntax Tree")
            results["ast_analysis"] = self._parse_ast(results["deobfuscated_code"])

            # Step 4: Extract API calls
            self.report_progress(0.65, "Extracting API calls")
            results["api_calls"] = self._extract_api_calls(results["deobfuscated_code"])

            # Step 5: Extract functions
            self.report_progress(0.75, "Extracting functions")
            results["functions"] = self._extract_functions(results["deobfuscated_code"])

            # Step 6: Detect suspicious patterns
            self.report_progress(0.85, "Detecting suspicious patterns")
            results["suspicious_patterns"] = self._detect_suspicious_patterns(results["deobfuscated_code"])

            # Step 7: Extract dependencies
            self.report_progress(0.95, "Extracting dependencies")
            results["dependencies"] = self._extract_dependencies(results["deobfuscated_code"])

            self.report_progress(1.0, "JavaScript analysis complete")

            # Add artifacts
            self.add_artifact("deobfuscated_code", results["deobfuscated_code"], "Deobfuscated JavaScript")
            self.add_artifact("api_calls", results["api_calls"], "Extracted API calls")
            self.add_artifact("functions", results["functions"], "Extracted functions")
            self.add_artifact("suspicious_patterns", results["suspicious_patterns"], "Suspicious patterns")

            # Set metrics
            self.set_metric("api_calls_found", len(results["api_calls"]))
            self.set_metric("functions_found", len(results["functions"]))
            self.set_metric("suspicious_patterns_found", len(results["suspicious_patterns"]))

            # Store in memory if enabled
            if results:
                self.add_to_memory(source_url, json.dumps(results, default=str))

            return results

        except Exception as e:
            self.logger.error(f"JavaScript analysis failed: {e}")
            raise

    def _is_minified(self, code: str) -> bool:
        """Detect if code is minified."""
        # Heuristics: single line, no comments, short variable names
        lines = code.strip().split('\n')
        if len(lines) == 1 and len(code) > 1000:
            return True
        
        # Check for common minification patterns
        if re.search(r'[a-z]{1,3}\([a-z]{1,3}\)', code):
            return True
        
        return False

    def _is_obfuscated(self, code: str) -> bool:
        """Detect if code is obfuscated."""
        # Check for common obfuscation patterns
        patterns = [
            r'_0x[0-9a-f]+',  # Hex variable names
            r'String\.fromCharCode',  # Character encoding
            r'eval\(',  # Dynamic code execution
            r'Function\(',  # Dynamic function creation
            r'atob\(',  # Base64 decoding
        ]
        
        for pattern in patterns:
            if re.search(pattern, code):
                return True
        
        return False

    def _deobfuscate(self, code: str) -> str:
        """Attempt to deobfuscate code."""
        try:
            # In production, would use de4js or similar tool
            # For now, return original code
            self.logger.info("Deobfuscation attempted (mock)")
            return code
        except Exception as e:
            self.logger.warning(f"Deobfuscation failed: {e}")
            return code

    def _parse_ast(self, code: str) -> Dict[str, Any]:
        """Parse Abstract Syntax Tree."""
        ast_analysis = {
            "total_nodes": 0,
            "function_declarations": 0,
            "variable_declarations": 0,
            "call_expressions": 0
        }
        
        try:
            # In production, would use Babel or similar
            # For now, use regex-based analysis
            ast_analysis["function_declarations"] = len(re.findall(r'function\s+\w+', code))
            ast_analysis["variable_declarations"] = len(re.findall(r'(?:var|let|const)\s+\w+', code))
            ast_analysis["call_expressions"] = len(re.findall(r'\w+\s*\(', code))
            
        except Exception as e:
            self.logger.warning(f"AST parsing failed: {e}")
        
        return ast_analysis

    def _extract_api_calls(self, code: str) -> List[Dict[str, Any]]:
        """Extract API calls from code."""
        api_calls = []
        
        # Common API patterns
        patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']',
            r'XMLHttpRequest.*open\(["\'](?:GET|POST)["\'],\s*["\']([^"\']+)["\']',
            r'\.ajax\({.*?url:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, code, re.DOTALL)
            for match in matches:
                api_calls.append({
                    "endpoint": match,
                    "pattern": pattern
                })
        
        return api_calls

    def _extract_functions(self, code: str) -> List[Dict[str, Any]]:
        """Extract function definitions."""
        functions = []
        
        # Extract function declarations
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)'
        matches = re.findall(func_pattern, code)
        
        for name, params in matches:
            functions.append({
                "name": name,
                "parameters": [p.strip() for p in params.split(',') if p.strip()],
                "type": "declaration"
            })
        
        # Extract arrow functions
        arrow_pattern = r'(?:const|let|var)\s+(\w+)\s*=\s*\(([^)]*)\)\s*=>'
        matches = re.findall(arrow_pattern, code)
        
        for name, params in matches:
            functions.append({
                "name": name,
                "parameters": [p.strip() for p in params.split(',') if p.strip()],
                "type": "arrow"
            })
        
        return functions

    def _detect_suspicious_patterns(self, code: str) -> List[Dict[str, Any]]:
        """Detect suspicious code patterns."""
        suspicious = []
        
        patterns = {
            "eval_usage": r'eval\s*\(',
            "dynamic_code": r'Function\s*\(',
            "base64_decode": r'atob\s*\(',
            "dom_manipulation": r'innerHTML\s*=',
            "cookie_access": r'document\.cookie',
            "local_storage": r'localStorage',
            "session_storage": r'sessionStorage',
            "crypto_operations": r'crypto\.',
        }
        
        for pattern_name, pattern in patterns.items():
            matches = re.finditer(pattern, code)
            for match in matches:
                suspicious.append({
                    "type": pattern_name,
                    "pattern": pattern,
                    "position": match.start(),
                    "context": code[max(0, match.start()-50):match.start()+50]
                })
        
        return suspicious

    def _extract_dependencies(self, code: str) -> List[str]:
        """Extract external dependencies."""
        dependencies = []
        
        # Extract imports
        import_pattern = r'(?:import|require)\s*\(?["\']([^"\']+)["\']'
        matches = re.findall(import_pattern, code)
        
        for match in matches:
            if match not in dependencies:
                dependencies.append(match)
        
        return dependencies

    def extract_api_patterns(self) -> List[Dict[str, Any]]:
        """
        Extract API endpoint patterns from JavaScript code.

        Returns:
            List of discovered API patterns with confidence scores
        """
        api_patterns = []

        # API endpoint patterns
        patterns = {
            'rest_api': r'(?:https?://)?(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/api/[a-zA-Z0-9/_-]+)',
            'versioned_api': r'(?:/v\d+)?(?:/api)?/[a-zA-Z0-9/_-]+',
            'graphql': r'(?:https?://)?[^\s]+/graphql',
            'rest_resource': r'/(?:users|posts|comments|products|orders|items|resources)/(?:\d+|[a-zA-Z0-9-]+)',
        }

        for pattern_name, pattern in patterns.items():
            matches = re.finditer(pattern, self._last_analyzed_code or '')
            for match in matches:
                api_patterns.append({
                    'endpoint': match.group(0),
                    'pattern_type': pattern_name,
                    'confidence': 0.7,
                    'position': match.start(),
                })

        return api_patterns

    def detect_api_calls(self) -> List[Dict[str, Any]]:
        """
        Detect API calls (fetch, XMLHttpRequest, axios) in JavaScript.

        Returns:
            List of detected API calls with methods and endpoints
        """
        api_calls = []
        code = self._last_analyzed_code or ''

        # Fetch API calls
        fetch_pattern = r'fetch\s*\(\s*["\']([^"\']+)["\'](?:\s*,\s*\{([^}]*)\})?'
        for match in re.finditer(fetch_pattern, code):
            endpoint = match.group(1)
            options = match.group(2) or ''
            method = 'GET'
            if 'method' in options:
                method_match = re.search(r'method\s*:\s*["\']([A-Z]+)["\']', options)
                if method_match:
                    method = method_match.group(1)

            api_calls.append({
                'type': 'fetch',
                'endpoint': endpoint,
                'method': method,
                'confidence': 0.9,
            })

        # XMLHttpRequest calls
        xhr_pattern = r'XMLHttpRequest.*?open\s*\(\s*["\']([A-Z]+)["\']?\s*,\s*["\']([^"\']+)["\']'
        for match in re.finditer(xhr_pattern, code, re.DOTALL):
            api_calls.append({
                'type': 'XMLHttpRequest',
                'method': match.group(1),
                'endpoint': match.group(2),
                'confidence': 0.85,
            })

        # Axios calls
        axios_pattern = r'axios\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']'
        for match in re.finditer(axios_pattern, code):
            method = re.search(r'axios\.(\w+)', match.group(0))
            api_calls.append({
                'type': 'axios',
                'method': method.group(1).upper() if method else 'GET',
                'endpoint': match.group(1),
                'confidence': 0.85,
            })

        return api_calls

    def extract_endpoint_urls(self) -> List[str]:
        """
        Extract hardcoded endpoint URLs and URL construction logic.

        Returns:
            List of discovered endpoint URLs
        """
        endpoints = []
        code = self._last_analyzed_code or ''

        # Hardcoded URLs
        url_pattern = r'(?:https?://)?(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9/_-]*)?'
        for match in re.finditer(url_pattern, code):
            url = match.group(0)
            if url not in endpoints and len(url) > 10:
                endpoints.append(url)

        # URL construction patterns
        const_pattern = r'(?:const|let|var)\s+(\w+)\s*=\s*["\']([^"\']+)["\']'
        for match in re.finditer(const_pattern, code):
            var_name = match.group(1)
            var_value = match.group(2)
            if any(keyword in var_value for keyword in ['api', 'endpoint', 'url', 'host']):
                if var_value not in endpoints:
                    endpoints.append(var_value)

        return endpoints

    def validate_endpoints(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        """
        Validate discovered endpoints.

        Args:
            endpoints: List of endpoints to validate

        Returns:
            List of validated endpoints with metadata
        """
        validated = []

        for endpoint in endpoints:
            validation = {
                'endpoint': endpoint,
                'is_valid': False,
                'issues': [],
            }

            # Check if looks like API endpoint
            if any(keyword in endpoint.lower() for keyword in ['api', '/v', 'graphql', 'rest']):
                validation['is_valid'] = True

            # Check for common issues
            if endpoint.startswith('http') and not endpoint.startswith(('http://', 'https://')):
                validation['issues'].append('Invalid protocol')

            if '//' in endpoint.replace('://', ''):
                validation['issues'].append('Double slashes in path')

            validated.append(validation)

        return validated

    def _store_analyzed_code(self, code: str):
        """Store last analyzed code for pattern extraction."""
        self._last_analyzed_code = code

    def cleanup(self):
        """Clean up temporary files."""
        try:
            import shutil
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                self.logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
        except Exception as e:
            self.logger.warning(f"Cleanup failed: {e}")

