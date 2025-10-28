"""
MCP Pipeline Integration - Bridges AI Agent Pipeline with MCP Server.
Enables agents to use MCP tools and exposes pipeline as MCP tools.
"""

import asyncio
import json
import logging
from typing import Any, Dict, Optional, List
from dataclasses import asdict

from .pipeline_orchestrator import PipelineOrchestrator, PipelineConfig

logger = logging.getLogger("RAVERSE.MCP_INTEGRATION")


class MCPPipelineIntegration:
    """Integrates AI Agent Pipeline with MCP Server"""
    
    def __init__(self, orchestrator: PipelineOrchestrator):
        self.orchestrator = orchestrator
        self.mcp_tools: Dict[str, Dict[str, Any]] = {}
        self._register_pipeline_tools()
    
    def _register_pipeline_tools(self):
        """Register pipeline operations as MCP tools"""
        self.mcp_tools = {
            "execute_workflow": {
                "name": "execute_workflow",
                "description": "Execute a complete AI Agent Pipeline workflow",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "workflow_name": {"type": "string", "description": "Name of the workflow"},
                        "tasks": {
                            "type": "array",
                            "description": "List of tasks to execute",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "agent_type": {"type": "string"},
                                    "agent_name": {"type": "string"},
                                    "action": {"type": "string"},
                                    "parameters": {"type": "object"},
                                    "priority": {"type": "integer"},
                                    "timeout": {"type": "integer"}
                                },
                                "required": ["agent_type", "action"]
                            }
                        },
                        "parallel": {"type": "boolean", "description": "Execute tasks in parallel"}
                    },
                    "required": ["workflow_name", "tasks"]
                }
            },
            "get_execution_status": {
                "name": "get_execution_status",
                "description": "Get status of a pipeline execution",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "execution_id": {"type": "string", "description": "Execution ID"}
                    },
                    "required": ["execution_id"]
                }
            },
            "list_agents": {
                "name": "list_agents",
                "description": "List all registered agents in the pipeline",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            "list_tools": {
                "name": "list_tools",
                "description": "List all registered tools in the pipeline",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            "call_tool": {
                "name": "call_tool",
                "description": "Call a registered tool",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tool_name": {"type": "string", "description": "Name of the tool"},
                        "parameters": {"type": "object", "description": "Tool parameters"}
                    },
                    "required": ["tool_name"]
                }
            },
            "store_state": {
                "name": "store_state",
                "description": "Store state in the pipeline",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "string", "description": "State key"},
                        "value": {"type": "object", "description": "State value"}
                    },
                    "required": ["key", "value"]
                }
            },
            "get_state": {
                "name": "get_state",
                "description": "Retrieve state from the pipeline",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "string", "description": "State key"}
                    },
                    "required": ["key"]
                }
            }
        }
    
    def get_mcp_tools(self) -> List[Dict[str, Any]]:
        """Get all pipeline tools in MCP format"""
        return list(self.mcp_tools.values())
    
    async def handle_mcp_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP tool call"""
        try:
            if tool_name == "execute_workflow":
                return await self._handle_execute_workflow(arguments)
            elif tool_name == "get_execution_status":
                return await self._handle_get_execution_status(arguments)
            elif tool_name == "list_agents":
                return await self._handle_list_agents(arguments)
            elif tool_name == "list_tools":
                return await self._handle_list_tools(arguments)
            elif tool_name == "call_tool":
                return await self._handle_call_tool(arguments)
            elif tool_name == "store_state":
                return await self._handle_store_state(arguments)
            elif tool_name == "get_state":
                return await self._handle_get_state(arguments)
            else:
                return {
                    "success": False,
                    "error": f"Unknown tool: {tool_name}",
                    "error_code": "UNKNOWN_TOOL"
                }
        except Exception as e:
            logger.error(f"Error handling MCP tool {tool_name}: {e}")
            return {
                "success": False,
                "error": str(e),
                "error_code": "EXECUTION_ERROR"
            }
    
    async def _handle_execute_workflow(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle execute_workflow MCP tool"""
        workflow_name = args.get("workflow_name")
        tasks = args.get("tasks", [])
        parallel = args.get("parallel", False)
        
        if not workflow_name or not tasks:
            return {
                "success": False,
                "error": "workflow_name and tasks are required",
                "error_code": "INVALID_ARGS"
            }
        
        execution = await self.orchestrator.execute_workflow(workflow_name, tasks, parallel)
        
        return {
            "success": True,
            "data": {
                "execution_id": execution.execution_id,
                "workflow_name": execution.workflow_name,
                "status": execution.status,
                "success_count": execution.success_count,
                "failure_count": execution.failure_count,
                "total_duration": execution.total_duration
            }
        }
    
    async def _handle_get_execution_status(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get_execution_status MCP tool"""
        execution_id = args.get("execution_id")
        if not execution_id:
            return {
                "success": False,
                "error": "execution_id is required",
                "error_code": "INVALID_ARGS"
            }
        
        status = self.orchestrator.get_execution_status(execution_id)
        if not status:
            return {
                "success": False,
                "error": f"Execution not found: {execution_id}",
                "error_code": "NOT_FOUND"
            }
        
        return {"success": True, "data": status}
    
    async def _handle_list_agents(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle list_agents MCP tool"""
        agents = self.orchestrator.list_agents()
        return {
            "success": True,
            "data": {
                "agents": agents,
                "count": len(agents)
            }
        }
    
    async def _handle_list_tools(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle list_tools MCP tool"""
        tools = self.orchestrator.list_tools()
        return {
            "success": True,
            "data": {
                "tools": tools,
                "count": len(tools)
            }
        }
    
    async def _handle_call_tool(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle call_tool MCP tool"""
        tool_name = args.get("tool_name")
        parameters = args.get("parameters", {})
        
        if not tool_name:
            return {
                "success": False,
                "error": "tool_name is required",
                "error_code": "INVALID_ARGS"
            }
        
        try:
            result = self.orchestrator.call_tool(tool_name, **parameters)
            return {"success": True, "data": result}
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "error_code": "TOOL_ERROR"
            }
    
    async def _handle_store_state(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle store_state MCP tool"""
        key = args.get("key")
        value = args.get("value")
        
        if not key:
            return {
                "success": False,
                "error": "key is required",
                "error_code": "INVALID_ARGS"
            }
        
        self.orchestrator.store_state(key, value)
        return {"success": True, "data": {"key": key, "stored": True}}
    
    async def _handle_get_state(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get_state MCP tool"""
        key = args.get("key")
        if not key:
            return {
                "success": False,
                "error": "key is required",
                "error_code": "INVALID_ARGS"
            }
        
        value = self.orchestrator.get_state(key)
        if value is None:
            return {
                "success": False,
                "error": f"State not found: {key}",
                "error_code": "NOT_FOUND"
            }
        
        return {"success": True, "data": {"key": key, "value": value}}

