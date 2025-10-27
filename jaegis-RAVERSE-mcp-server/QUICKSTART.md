# RAVERSE MCP Server - Quick Start Guide

Get the MCP server running in 5 minutes.

## Prerequisites

- Python 3.13+
- PostgreSQL 17 (or Docker)
- Redis 8.2 (or Docker)

## Option 1: Docker (Recommended)

### 1. Start Services

```bash
# Start PostgreSQL and Redis
docker run -d --name raverse-postgres \
  -e POSTGRES_USER=raverse \
  -e POSTGRES_PASSWORD=raverse_secure_password_2025 \
  -e POSTGRES_DB=raverse \
  -p 5432:5432 \
  pgvector/pgvector:pg17

docker run -d --name raverse-redis \
  -p 6379:6379 \
  redis:8.2
```

### 2. Configure MCP Server

```bash
cd jaegis-RAVERSE-mcp-server
cp .env.example .env
```

Edit `.env`:
```env
DATABASE_URL=postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse
REDIS_URL=redis://localhost:6379/0
LLM_API_KEY=your_openrouter_key_here
LOG_LEVEL=INFO
```

### 3. Install & Run

```bash
pip install -e .
raverse-mcp-server
```

You should see:
```
Initializing RAVERSE MCP Server
RAVERSE MCP Server initialized successfully
```

## Option 2: Local Development

### 1. Setup

```bash
cd jaegis-RAVERSE-mcp-server
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your database and Redis URLs
```

### 3. Run

```bash
raverse-mcp-server
```

## Testing

### Run Tests

```bash
pytest tests/ -v
```

### Test a Tool

```python
from jaegis_raverse_mcp_server import MCPServer
import asyncio

async def test():
    server = MCPServer()
    
    # Test disassemble_binary tool
    result = await server.handle_tool_call(
        "disassemble_binary",
        {"binary_path": "/bin/ls"}
    )
    
    print(result)
    server.shutdown()

asyncio.run(test())
```

## Using with Claude

### 1. Install Claude Desktop

Download from https://claude.ai/download

### 2. Configure MCP Server

Edit `~/.config/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "raverse": {
      "command": "python",
      "args": ["-m", "jaegis_raverse_mcp_server.server"],
      "env": {
        "DATABASE_URL": "postgresql://raverse:password@localhost:5432/raverse",
        "REDIS_URL": "redis://localhost:6379/0",
        "LLM_API_KEY": "your_key"
      }
    }
  }
}
```

### 3. Use in Claude

In Claude, you can now use RAVERSE tools:

```
"Analyze this binary for vulnerabilities"
"Search the knowledge base for similar code patterns"
"Perform security analysis on this API"
```

## Common Tasks

### Disassemble a Binary

```python
result = await server.handle_tool_call(
    "disassemble_binary",
    {"binary_path": "/path/to/binary"}
)
```

### Search Knowledge Base

```python
result = await server.handle_tool_call(
    "search_knowledge_base",
    {
        "query": "buffer overflow patterns",
        "limit": 5,
        "threshold": 0.7
    }
)
```

### Analyze JavaScript

```python
result = await server.handle_tool_call(
    "analyze_javascript",
    {
        "js_code": "fetch('/api/users').then(r => r.json())",
        "deobfuscate": True
    }
)
```

### Perform Security Analysis

```python
result = await server.handle_tool_call(
    "security_analysis",
    {
        "analysis_data": {"endpoints": [], "headers": {}},
        "check_headers": True,
        "check_cves": True
    }
)
```

## Troubleshooting

### Database Connection Error

```
Error: Failed to initialize database pool
```

**Solution:**
1. Check PostgreSQL is running: `psql -h localhost -U raverse -d raverse -c "SELECT 1"`
2. Verify DATABASE_URL in .env
3. Check credentials

### Redis Connection Error

```
Error: Failed to connect to Redis
```

**Solution:**
1. Check Redis is running: `redis-cli ping`
2. Verify REDIS_URL in .env
3. Check Redis is accessible on the configured port

### Tool Not Found

```
Error: Unknown tool: tool_name
```

**Solution:**
1. Check tool name spelling
2. Verify feature flag is enabled (e.g., ENABLE_BINARY_ANALYSIS=true)
3. See TOOLS_REGISTRY.md for complete tool list

### Permission Denied

```
Error: Permission denied
```

**Solution:**
1. Check file permissions: `ls -la /path/to/file`
2. Run with appropriate permissions
3. Check user has read access

## Next Steps

1. **Read Documentation**
   - TOOLS_REGISTRY.md - Complete tool reference
   - INTEGRATION_GUIDE.md - Integration with other systems
   - DEPLOYMENT.md - Production deployment

2. **Explore Tools**
   - Try each tool category
   - Review error handling
   - Test with your data

3. **Integrate**
   - Add to Docker Compose
   - Connect to Claude
   - Build custom clients

## Support

- **Documentation**: See README.md and other .md files
- **Issues**: Check logs with `LOG_LEVEL=DEBUG`
- **Examples**: See tests/test_tools.py

## What's Next?

The MCP server provides 18 core tools across 4 categories:
- **Binary Analysis** (4 tools)
- **Knowledge Base** (4 tools)
- **Web Analysis** (5 tools)
- **Infrastructure** (5 tools)

Additional capabilities can be implemented in future phases. See TOOLS_REGISTRY.md for the complete specification.

