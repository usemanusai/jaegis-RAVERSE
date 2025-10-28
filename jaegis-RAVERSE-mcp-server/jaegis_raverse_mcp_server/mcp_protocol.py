"""MCP Protocol Handler for RAVERSE MCP Server"""

import json
import sys
import asyncio
from typing import Any, Dict, Optional
from .logging_config import get_logger

logger = get_logger(__name__)

MCP_VERSION = "2024-11-05"


class MCPProtocolHandler:
    """Handles MCP JSON-RPC protocol communication"""

    def __init__(self, mcp_server):
        self.mcp_server = mcp_server
        self.request_id = 0

    async def handle_message(self, message: str) -> Optional[str]:
        """Handle incoming MCP message"""
        try:
            data = json.loads(message)
            method = data.get("method")
            params = data.get("params", {})
            request_id = data.get("id")

            logger.debug(f"MCP Request: {method} (id={request_id})")

            # Handle initialize
            if method == "initialize":
                return self._handle_initialize(request_id, params)

            # Handle list_tools
            elif method == "tools/list":
                return self._handle_list_tools(request_id)

            # Handle call_tool
            elif method == "tools/call":
                return await self._handle_call_tool(request_id, params)

            # Handle list_resources
            elif method == "resources/list":
                return self._handle_list_resources(request_id)

            # Handle list_prompts
            elif method == "prompts/list":
                return self._handle_list_prompts(request_id)

            else:
                return self._error_response(
                    request_id, -32601, f"Method not found: {method}"
                )

        except json.JSONDecodeError as e:
            return self._error_response(None, -32700, f"Parse error: {str(e)}")
        except Exception as e:
            logger.error(f"Error handling message: {str(e)}")
            return self._error_response(None, -32603, f"Internal error: {str(e)}")

    def _handle_initialize(self, request_id: int, params: Dict) -> str:
        """Handle initialize request"""
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": MCP_VERSION,
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {},
                },
                "serverInfo": {
                    "name": "raverse-mcp-server",
                    "version": "1.0.9",
                },
            },
        }
        return json.dumps(response)

    def _handle_list_tools(self, request_id: int) -> str:
        """Handle tools/list request"""
        try:
            # Lazy initialize server if needed
            if not hasattr(self.mcp_server, '_initialized'):
                self.mcp_server._initialize()
                self.mcp_server._initialized = True

            tools = self.mcp_server.get_tools_list()
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"tools": tools},
            }
            return json.dumps(response)
        except Exception as e:
            logger.error(f"Error listing tools: {str(e)}")
            return self._error_response(request_id, -32603, f"Error listing tools: {str(e)}")

    async def _handle_call_tool(self, request_id: int, params: Dict) -> str:
        """Handle tools/call request"""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        logger.info(f"Calling tool: {tool_name}")

        result = await self.mcp_server.handle_tool_call(tool_name, arguments)

        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": json.dumps(result)}]},
        }
        return json.dumps(response)

    def _handle_list_resources(self, request_id: int) -> str:
        """Handle resources/list request"""
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"resources": []},
        }
        return json.dumps(response)

    def _handle_list_prompts(self, request_id: int) -> str:
        """Handle prompts/list request"""
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"prompts": []},
        }
        return json.dumps(response)

    def _error_response(self, request_id: Optional[int], code: int, message: str) -> str:
        """Generate error response"""
        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }
        return json.dumps(response)


async def run_mcp_server(mcp_server):
    """Run MCP server with stdio transport"""
    protocol_handler = MCPProtocolHandler(mcp_server)

    logger.info("RAVERSE MCP Server started (stdio transport)")

    try:
        loop = asyncio.get_event_loop()

        while True:
            # Read from stdin
            line = await loop.run_in_executor(None, sys.stdin.readline)

            if not line:
                break

            line = line.strip()
            if not line:
                continue

            # Handle message
            response = await protocol_handler.handle_message(line)

            if response:
                print(response, flush=True)

    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
    finally:
        mcp_server.shutdown()

