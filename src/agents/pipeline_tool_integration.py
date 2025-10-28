"""
Pipeline Tool Integration - Bridges agents with MCP tools and external services.
Provides tool registry, execution, and result handling.
"""

import logging
import asyncio
from typing import Any, Dict, Optional, Callable, List
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger("RAVERSE.TOOL_INTEGRATION")


@dataclass
class ToolDefinition:
    """Tool definition and metadata"""
    name: str
    description: str
    category: str
    handler: Callable
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any] = None
    timeout: int = 30
    retry_on_failure: bool = True
    cache_results: bool = False


@dataclass
class ToolExecutionResult:
    """Result from tool execution"""
    tool_name: str
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    execution_time: float = 0.0
    cached: bool = False


class ToolRegistry:
    """Registry for managing tools"""
    
    def __init__(self):
        self.tools: Dict[str, ToolDefinition] = {}
        self.execution_cache: Dict[str, ToolExecutionResult] = {}
        self.execution_history: List[ToolExecutionResult] = []
    
    def register_tool(self, tool_def: ToolDefinition):
        """Register a tool"""
        self.tools[tool_def.name] = tool_def
        logger.info(f"Registered tool: {tool_def.name} (Category: {tool_def.category})")
    
    def get_tool(self, tool_name: str) -> Optional[ToolDefinition]:
        """Get tool by name"""
        return self.tools.get(tool_name)
    
    def list_tools(self, category: Optional[str] = None) -> List[ToolDefinition]:
        """List tools, optionally filtered by category"""
        tools = list(self.tools.values())
        if category:
            tools = [t for t in tools if t.category == category]
        return tools
    
    def get_tool_schema(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get tool schema for MCP"""
        tool = self.get_tool(tool_name)
        if not tool:
            return None
        
        return {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema
        }
    
    def get_all_tool_schemas(self) -> List[Dict[str, Any]]:
        """Get all tool schemas for MCP"""
        return [self.get_tool_schema(name) for name in self.tools.keys()]


class ToolExecutor:
    """Executes tools with error handling and caching"""
    
    def __init__(self, registry: ToolRegistry):
        self.registry = registry
    
    async def execute_tool(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        use_cache: bool = True
    ) -> ToolExecutionResult:
        """Execute a tool"""
        tool = self.registry.get_tool(tool_name)
        if not tool:
            return ToolExecutionResult(
                tool_name=tool_name,
                success=False,
                error=f"Tool not found: {tool_name}",
                error_code="TOOL_NOT_FOUND"
            )
        
        # Check cache
        cache_key = self._get_cache_key(tool_name, parameters)
        if use_cache and tool.cache_results and cache_key in self.registry.execution_cache:
            cached_result = self.registry.execution_cache[cache_key]
            cached_result.cached = True
            logger.debug(f"Using cached result for {tool_name}")
            return cached_result
        
        start_time = datetime.now()
        
        try:
            # Execute tool with timeout
            result_data = await asyncio.wait_for(
                self._call_tool(tool, parameters),
                timeout=tool.timeout
            )
            
            result = ToolExecutionResult(
                tool_name=tool_name,
                success=True,
                data=result_data,
                execution_time=(datetime.now() - start_time).total_seconds()
            )
            
            # Cache result
            if tool.cache_results:
                self.registry.execution_cache[cache_key] = result
            
            self.registry.execution_history.append(result)
            logger.info(f"Tool {tool_name} executed successfully")
            
            return result
            
        except asyncio.TimeoutError:
            result = ToolExecutionResult(
                tool_name=tool_name,
                success=False,
                error=f"Tool timeout after {tool.timeout}s",
                error_code="TIMEOUT",
                execution_time=(datetime.now() - start_time).total_seconds()
            )
            self.registry.execution_history.append(result)
            return result
            
        except Exception as e:
            result = ToolExecutionResult(
                tool_name=tool_name,
                success=False,
                error=str(e),
                error_code="EXECUTION_ERROR",
                execution_time=(datetime.now() - start_time).total_seconds()
            )
            self.registry.execution_history.append(result)
            logger.error(f"Tool {tool_name} failed: {e}")
            return result
    
    async def _call_tool(self, tool: ToolDefinition, parameters: Dict[str, Any]) -> Any:
        """Call tool handler"""
        if asyncio.iscoroutinefunction(tool.handler):
            return await tool.handler(**parameters)
        else:
            return tool.handler(**parameters)
    
    def _get_cache_key(self, tool_name: str, parameters: Dict[str, Any]) -> str:
        """Generate cache key"""
        import json
        import hashlib
        param_str = json.dumps(parameters, sort_keys=True, default=str)
        param_hash = hashlib.md5(param_str.encode()).hexdigest()
        return f"{tool_name}:{param_hash}"
    
    def get_execution_history(self) -> List[ToolExecutionResult]:
        """Get execution history"""
        return self.registry.execution_history
    
    def get_tool_stats(self, tool_name: str) -> Dict[str, Any]:
        """Get statistics for a tool"""
        executions = [e for e in self.registry.execution_history if e.tool_name == tool_name]
        
        if not executions:
            return {"tool_name": tool_name, "executions": 0}
        
        successful = sum(1 for e in executions if e.success)
        failed = sum(1 for e in executions if not e.success)
        avg_time = sum(e.execution_time for e in executions) / len(executions)
        
        return {
            "tool_name": tool_name,
            "total_executions": len(executions),
            "successful": successful,
            "failed": failed,
            "success_rate": successful / len(executions),
            "avg_execution_time": avg_time
        }


class ToolChain:
    """Chains multiple tools together"""
    
    def __init__(self, executor: ToolExecutor):
        self.executor = executor
        self.chain: List[Dict[str, Any]] = []
    
    def add_step(self, tool_name: str, parameters: Dict[str, Any], output_key: str = None):
        """Add tool to chain"""
        self.chain.append({
            "tool_name": tool_name,
            "parameters": parameters,
            "output_key": output_key or tool_name
        })
    
    async def execute(self) -> Dict[str, Any]:
        """Execute tool chain"""
        results = {}
        
        for step in self.chain:
            tool_name = step["tool_name"]
            parameters = step["parameters"]
            output_key = step["output_key"]
            
            # Replace parameter placeholders with previous results
            resolved_params = self._resolve_parameters(parameters, results)
            
            result = await self.executor.execute_tool(tool_name, resolved_params)
            results[output_key] = result
            
            if not result.success:
                logger.error(f"Tool chain failed at {tool_name}")
                return {"success": False, "error": result.error, "results": results}
        
        return {"success": True, "results": results}
    
    def _resolve_parameters(self, parameters: Dict[str, Any], results: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve parameter placeholders"""
        resolved = {}
        
        for key, value in parameters.items():
            if isinstance(value, str) and value.startswith("$"):
                # Reference to previous result
                ref_key = value[1:]
                if ref_key in results:
                    resolved[key] = results[ref_key].data
                else:
                    resolved[key] = value
            else:
                resolved[key] = value
        
        return resolved

