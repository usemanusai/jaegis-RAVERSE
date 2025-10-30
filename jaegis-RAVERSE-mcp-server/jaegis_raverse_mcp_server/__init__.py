"""
JAEGIS RAVERSE MCP Server
Model Context Protocol server for RAVERSE AI Multi-Agent Binary Patching System
"""

__version__ = "1.0.11"
__author__ = "RAVERSE Team"
__license__ = "MIT"

from .server import MCPServer, main

__all__ = ["MCPServer", "main"]

