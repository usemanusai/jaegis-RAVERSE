#!/usr/bin/env python3
"""Test MCP Protocol Implementation"""

import json
import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from jaegis_raverse_mcp_server.server import MCPServer
from jaegis_raverse_mcp_server.mcp_protocol import MCPProtocolHandler


async def test_mcp_protocol():
    """Test MCP protocol implementation"""
    print("🧪 Testing RAVERSE MCP Protocol Implementation\n")

    # Create server
    server = MCPServer()
    handler = MCPProtocolHandler(server)

    # Test 1: Initialize
    print("✅ Test 1: Initialize Request")
    init_msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    })
    response = await handler.handle_message(init_msg)
    result = json.loads(response)
    assert result["id"] == 1
    assert "result" in result
    print(f"   Response: {json.dumps(result, indent=2)}\n")

    # Test 2: List Tools
    print("✅ Test 2: List Tools Request")
    list_tools_msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    })
    response = await handler.handle_message(list_tools_msg)
    result = json.loads(response)
    assert result["id"] == 2
    assert "result" in result
    tools = result["result"]["tools"]
    print(f"   Found {len(tools)} tools:")
    for tool in tools[:5]:
        print(f"   - {tool['name']}: {tool['description']}")
    print(f"   ... and {len(tools) - 5} more tools\n")

    # Test 3: Call Tool
    print("✅ Test 3: Call Tool Request")
    call_tool_msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "disassemble_binary",
            "arguments": {
                "binary_path": "/tmp/test.bin",
                "architecture": "x86"
            }
        }
    })
    response = await handler.handle_message(call_tool_msg)
    result = json.loads(response)
    assert result["id"] == 3
    print(f"   Response: {json.dumps(result, indent=2)}\n")

    # Test 4: List Resources
    print("✅ Test 4: List Resources Request")
    list_resources_msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "resources/list"
    })
    response = await handler.handle_message(list_resources_msg)
    result = json.loads(response)
    assert result["id"] == 4
    print(f"   Response: {json.dumps(result, indent=2)}\n")

    print("✅ All MCP Protocol Tests Passed!")
    print(f"\n📊 Summary:")
    print(f"   - MCP Version: 2024-11-05")
    print(f"   - Total Tools: {len(tools)}")
    print(f"   - Protocol: JSON-RPC 2.0")
    print(f"   - Transport: stdio")


if __name__ == "__main__":
    asyncio.run(test_mcp_protocol())

