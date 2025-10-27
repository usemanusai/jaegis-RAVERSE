# RAVERSE MCP Server - Integration Guide

This guide explains how to integrate the JAEGIS RAVERSE MCP Server with the main RAVERSE project and other systems.

## Overview

The MCP Server is a standalone component that exposes RAVERSE capabilities through the Model Context Protocol. It can be:
1. Run as a separate service
2. Integrated into the main RAVERSE Docker Compose setup
3. Used as a library in Python applications
4. Accessed via MCP clients (Claude, other AI models)

## Installation

### Option 1: Standalone Installation

```bash
cd jaegis-RAVERSE-mcp-server
pip install -e .
```

### Option 2: Development Installation

```bash
cd jaegis-RAVERSE-mcp-server
pip install -e ".[dev]"
```

## Configuration

### Environment Variables

Create a `.env` file in the MCP server directory:

```bash
cp .env.example .env
```

Key variables to configure:

```env
# Database connection (must match main RAVERSE database)
DATABASE_URL=postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse

# Redis connection (must match main RAVERSE Redis)
REDIS_URL=redis://localhost:6379/0

# LLM configuration
LLM_API_KEY=your_openrouter_key
LLM_MODEL=meta-llama/llama-2-70b-chat

# Feature flags
ENABLE_BINARY_ANALYSIS=true
ENABLE_WEB_ANALYSIS=true
ENABLE_KNOWLEDGE_BASE=true
ENABLE_INFRASTRUCTURE=true
```

## Running the Server

### Standalone Mode

```bash
raverse-mcp-server
```

### Docker Integration

Add to `docker-compose.yml`:

```yaml
raverse-mcp-server:
  build:
    context: ./jaegis-RAVERSE-mcp-server
    dockerfile: Dockerfile
  container_name: raverse-mcp-server
  environment:
    DATABASE_URL: postgresql://raverse:raverse_secure_password_2025@postgres:5432/raverse
    REDIS_URL: redis://redis:6379/0
    LLM_API_KEY: ${OPENROUTER_API_KEY}
    LOG_LEVEL: INFO
  ports:
    - "8001:8001"
  depends_on:
    postgres:
      condition: service_healthy
    redis:
      condition: service_healthy
  networks:
    - raverse-network
  restart: unless-stopped
```

### Python Integration

```python
from jaegis_raverse_mcp_server import MCPServer
import asyncio

async def main():
    server = MCPServer()
    
    # Call a tool
    result = await server.handle_tool_call(
        "disassemble_binary",
        {"binary_path": "/path/to/binary"}
    )
    
    print(result)
    server.shutdown()

asyncio.run(main())
```

## Integration with Main RAVERSE

### Shared Resources

The MCP Server shares the following resources with main RAVERSE:

1. **PostgreSQL Database**
   - Same database instance
   - Same schema and tables
   - Vector search via pgvector

2. **Redis Cache**
   - Same Redis instance
   - Shared cache keys
   - A2A message channels

3. **LLM API**
   - Same OpenRouter API key
   - Same model configuration

### Data Flow

```
RAVERSE Agents
    ↓
PostgreSQL (shared)
    ↓
MCP Server ← → Redis (shared)
    ↓
MCP Clients (Claude, etc.)
```

## MCP Client Configuration

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "raverse": {
      "command": "python",
      "args": ["-m", "jaegis_raverse_mcp_server.server"],
      "env": {
        "DATABASE_URL": "postgresql://...",
        "REDIS_URL": "redis://...",
        "LLM_API_KEY": "your_key"
      }
    }
  }
}
```

### Custom MCP Client

```python
import mcp.client.stdio

async def main():
    async with mcp.client.stdio.stdio_client(
        "python",
        "-m",
        "jaegis_raverse_mcp_server.server"
    ) as client:
        # Use tools
        result = await client.call_tool(
            "disassemble_binary",
            {"binary_path": "/path/to/binary"}
        )
```

## API Integration

### REST API Wrapper (Optional)

Create a FastAPI wrapper to expose MCP tools via HTTP:

```python
from fastapi import FastAPI
from jaegis_raverse_mcp_server import MCPServer

app = FastAPI()
server = MCPServer()

@app.post("/tools/{tool_name}")
async def call_tool(tool_name: str, arguments: dict):
    return await server.handle_tool_call(tool_name, arguments)
```

## Monitoring

### Prometheus Metrics

The MCP Server exports Prometheus metrics:

```
raverse_mcp_tool_calls_total
raverse_mcp_tool_errors_total
raverse_mcp_tool_duration_seconds
raverse_mcp_cache_hits_total
raverse_mcp_database_queries_total
```

### Logging

All operations are logged with structured logging:

```json
{
  "timestamp": "2025-10-27T10:00:00Z",
  "level": "INFO",
  "logger": "jaegis_raverse_mcp_server.server",
  "message": "Tool call received",
  "tool_name": "disassemble_binary"
}
```

## Testing

### Unit Tests

```bash
cd jaegis-RAVERSE-mcp-server
pytest tests/test_tools.py -v
```

### Integration Tests

```bash
# Requires running PostgreSQL and Redis
pytest tests/ -v --integration
```

### End-to-End Tests

```bash
# Start services
docker-compose up -d

# Run tests
pytest tests/e2e/ -v
```

## Troubleshooting

### Database Connection Issues

```bash
# Check PostgreSQL is running
psql -h localhost -U raverse -d raverse -c "SELECT 1"

# Check connection string in .env
DATABASE_URL=postgresql://raverse:password@localhost:5432/raverse
```

### Redis Connection Issues

```bash
# Check Redis is running
redis-cli ping

# Check connection string in .env
REDIS_URL=redis://localhost:6379/0
```

### Tool Execution Errors

Check logs for detailed error messages:

```bash
# View logs
tail -f logs/raverse-mcp.log

# Increase log level
LOG_LEVEL=DEBUG raverse-mcp-server
```

## Performance Tuning

### Database Connection Pool

```env
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=40
```

### Cache Configuration

```env
CACHE_TTL_SECONDS=7200
```

### Concurrency

```env
MAX_CONCURRENT_TASKS=20
```

## Security Considerations

1. **Credentials**: Use environment variables, never hardcode
2. **Database**: Use parameterized queries (automatic)
3. **Input Validation**: All inputs validated (automatic)
4. **Rate Limiting**: Implement at reverse proxy level
5. **Authentication**: Add authentication layer if exposing via HTTP

## Deployment

### Production Checklist

- [ ] Environment variables configured
- [ ] Database backups enabled
- [ ] Redis persistence enabled
- [ ] Monitoring configured
- [ ] Logging configured
- [ ] Health checks enabled
- [ ] Resource limits set
- [ ] Security groups configured

### Scaling

For high-load scenarios:

1. Run multiple MCP server instances
2. Use load balancer (nginx, HAProxy)
3. Increase database connection pool
4. Increase Redis memory
5. Enable caching for frequently accessed data

## Support

For issues and questions:
1. Check logs for error messages
2. Review configuration
3. Verify database and Redis connectivity
4. Consult TOOLS_REGISTRY.md for tool specifications

