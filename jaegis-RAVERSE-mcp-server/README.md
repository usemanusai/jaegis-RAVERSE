# JAEGIS RAVERSE MCP Server

Production-ready Model Context Protocol (MCP) server for RAVERSE - AI Multi-Agent Binary Patching System.

## 📊 Package Distribution

[![NPM Version](https://img.shields.io/npm/v/raverse-mcp-server.svg)](https://www.npmjs.com/package/raverse-mcp-server)
[![NPM Downloads](https://img.shields.io/npm/dt/raverse-mcp-server.svg)](https://www.npmjs.com/package/raverse-mcp-server)
[![PyPI Version](https://img.shields.io/pypi/v/jaegis-raverse-mcp-server.svg)](https://pypi.org/project/jaegis-raverse-mcp-server/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/jaegis-raverse-mcp-server.svg)](https://pypi.org/project/jaegis-raverse-mcp-server/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.13+](https://img.shields.io/badge/Python-3.13%2B-blue)](https://www.python.org/)

## Overview

This MCP server exposes 35 core capabilities from RAVERSE 2.0 as standardized MCP tools, enabling seamless integration with Claude, other AI models, and external systems.

## Features

### Binary Analysis Tools (4 tools)
- **Disassemble Binary**: Convert machine code to human-readable assembly
- **Generate Code Embedding**: Create semantic vectors for code snippets
- **Apply Patch**: Programmatically modify binary files
- **Verify Patch**: Confirm patch application and integrity

### Knowledge Base & RAG Tools (4 tools)
- **Ingest Content**: Add content to knowledge base
- **Search Knowledge Base**: Find relevant content via semantic search
- **Retrieve Entry**: Get specific knowledge base entries
- **Delete Entry**: Remove entries from knowledge base

### Web Analysis Tools (5 tools)
- **Reconnaissance**: Gather intelligence about web targets
- **Analyze JavaScript**: Extract logic and API calls from JS code
- **Reverse Engineer API**: Generate OpenAPI specs from traffic
- **Analyze WASM**: Decompile and analyze WebAssembly modules
- **Security Analysis**: Identify vulnerabilities and security issues

### Infrastructure Tools (5 tools)
- **Database Query**: Execute parameterized database queries
- **Cache Operation**: Manage Redis cache operations
- **Publish Message**: Send A2A protocol messages
- **Fetch Content**: Download web content with retry logic
- **Record Metric**: Track performance metrics

### Advanced Analysis Tools (5 tools)
- **Logic Identification**: Identify logic patterns in code
- **Traffic Interception**: Intercept and analyze network traffic
- **Generate Report**: Generate comprehensive analysis reports
- **RAG Orchestration**: Execute RAG workflow
- **Deep Research**: Perform deep research on topics

### Management Tools (4 tools)
- **Version Management**: Manage component versions
- **Quality Gate**: Enforce quality standards
- **Governance Check**: Check governance rules
- **Generate Document**: Generate structured documents

### Utility Tools (5 tools)
- **URL Frontier Operation**: Manage URL frontier for crawling
- **API Pattern Matcher**: Identify API patterns in traffic
- **Response Classifier**: Classify HTTP responses
- **WebSocket Analyzer**: Analyze WebSocket communication
- **Crawl Scheduler**: Schedule crawl jobs

### System Tools (4 tools)
- **Metrics Collector**: Record performance metrics
- **Multi-Level Cache**: Manage multi-level cache
- **Configuration Service**: Access configuration
- **LLM Interface**: Interface with LLM provider

### NLP & Validation Tools (2 tools)
- **Natural Language Interface**: Process natural language commands
- **PoC Validation**: Validate vulnerabilities with PoC

**Total: 35 Tools Across 9 Categories**

## Installation

### Prerequisites
- Python 3.13+
- PostgreSQL 17 with pgvector
- Redis 8.2
- OpenRouter API key (for LLM features)

### Quick Start (Recommended)

#### Option 1: NPX (Fastest - No Installation Required)
```bash
# Run the latest version without installation
npx raverse-mcp-server@latest

# Or with specific version
npx raverse-mcp-server@1.0.2

# Verify it works
npx raverse-mcp-server@latest --version
```

#### Option 2: NPM (Global Installation)
```bash
# Install globally
npm install -g raverse-mcp-server

# Run the server
raverse-mcp-server

# Verify installation
raverse-mcp-server --version
```

#### Option 3: PyPI (Python Package)
```bash
# Install via pip
pip install jaegis-raverse-mcp-server

# Run the server
python -m jaegis_raverse_mcp_server.server

# Verify installation
python -m jaegis_raverse_mcp_server.server --version
```

#### Option 4: Docker
```bash
# Pull and run Docker image
docker run -d \
  -e DATABASE_URL="postgresql://user:pass@host/db" \
  -e REDIS_URL="redis://localhost:6379" \
  -e OPENROUTER_API_KEY="sk-or-v1-..." \
  -p 8000:8000 \
  raverse/mcp-server:latest
```

### Detailed Setup (From Source)

1. **Clone and navigate to directory**:
```bash
cd jaegis-RAVERSE-mcp-server
```

2. **Create virtual environment**:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -e .
```

4. **Configure environment**:
```bash
cp .env.example .env
# Edit .env with your configuration
```

### Installation Guides

- **[Complete Installation Guide](INSTALLATION.md)** - Detailed instructions for all methods
- **[Quick Start Guide](QUICKSTART.md)** - Get running in 5 minutes
- **[MCP Client Setup](MCP_CLIENT_SETUP.md)** - Configure 20+ MCP clients

## Configuration

All configuration is managed via environment variables. See `.env.example` for all available options.

### Key Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | INFO | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `DATABASE_URL` | localhost | PostgreSQL connection string |
| `REDIS_URL` | localhost | Redis connection string |
| `LLM_API_KEY` | - | OpenRouter API key |
| `ENABLE_*` | true | Feature flags for tool categories |

## Usage

### Starting the Server

```bash
raverse-mcp-server
```

### Programmatic Usage

```python
from jaegis_raverse_mcp_server import MCPServer

server = MCPServer()
result = await server.handle_tool_call(
    "disassemble_binary",
    {"binary_path": "/path/to/binary"}
)
```

## Tool Reference

### Binary Analysis

#### disassemble_binary
Disassemble a binary file and extract structural information.

**Parameters:**
- `binary_path` (str): Path to binary file
- `architecture` (str, optional): Target architecture

**Returns:**
- `binary_hash`: SHA256 hash
- `file_size`: Size in bytes
- `status`: Operation status

#### generate_code_embedding
Generate semantic embedding for code content.

**Parameters:**
- `code_content` (str): Code to embed
- `model` (str): Embedding model name

**Returns:**
- `content_hash`: Content hash
- `status`: Operation status

#### apply_patch
Apply patches to binary file.

**Parameters:**
- `binary_path` (str): Binary file path
- `patches` (list): List of patch objects
- `backup` (bool): Create backup before patching

**Returns:**
- `patch_count`: Number of patches applied
- `status`: Operation status

#### verify_patch
Verify patch was applied correctly.

**Parameters:**
- `original_binary` (str): Original binary path
- `patched_binary` (str): Patched binary path

**Returns:**
- `original_hash`: Original binary hash
- `patched_hash`: Patched binary hash
- `hashes_match`: Whether hashes match

### Knowledge Base

#### ingest_content
Add content to knowledge base.

**Parameters:**
- `content` (str): Content to ingest
- `metadata` (dict, optional): Associated metadata

**Returns:**
- `content_hash`: Content hash
- `status`: Operation status

#### search_knowledge_base
Search for relevant content.

**Parameters:**
- `query` (str): Search query
- `limit` (int): Max results (1-100)
- `threshold` (float): Similarity threshold (0-1)

**Returns:**
- `query`: Original query
- `status`: Operation status

#### retrieve_entry
Get specific knowledge base entry.

**Parameters:**
- `entry_id` (str): Entry ID

**Returns:**
- `entry_id`: Entry ID
- `status`: Operation status

#### delete_entry
Delete knowledge base entry.

**Parameters:**
- `entry_id` (str): Entry ID

**Returns:**
- `entry_id`: Entry ID
- `status`: Operation status

### Web Analysis

#### reconnaissance
Perform web reconnaissance on target.

**Parameters:**
- `target_url` (str): Target URL

**Returns:**
- `target_url`: Target URL
- `status`: Operation status

#### analyze_javascript
Analyze JavaScript code.

**Parameters:**
- `js_code` (str): JavaScript code
- `deobfuscate` (bool): Deobfuscate code

**Returns:**
- `status`: Operation status
- `endpoints_found`: Number of endpoints found

#### reverse_engineer_api
Reverse engineer API from traffic.

**Parameters:**
- `traffic_data` (dict): Traffic data
- `js_analysis` (dict, optional): JS analysis results

**Returns:**
- `status`: Operation status

#### analyze_wasm
Analyze WebAssembly module.

**Parameters:**
- `wasm_data` (bytes): WASM module data

**Returns:**
- `status`: Operation status
- `wasm_size`: Module size

#### security_analysis
Perform security analysis.

**Parameters:**
- `analysis_data` (dict): Analysis data
- `check_headers` (bool): Check security headers
- `check_cves` (bool): Check for CVEs

**Returns:**
- `status`: Operation status

### Infrastructure

#### database_query
Execute database query.

**Parameters:**
- `query` (str): SQL query
- `params` (list, optional): Query parameters

**Returns:**
- `status`: Operation status

#### cache_operation
Perform cache operation.

**Parameters:**
- `operation` (str): Operation (get, set, delete, exists, clear)
- `key` (str): Cache key
- `value` (any, optional): Value for set operation
- `ttl` (int, optional): Time to live in seconds

**Returns:**
- `status`: Operation status

#### publish_message
Publish A2A message.

**Parameters:**
- `channel` (str): Channel name
- `message` (dict): Message content

**Returns:**
- `status`: Operation status

#### fetch_content
Fetch content from URL.

**Parameters:**
- `url` (str): URL to fetch
- `timeout` (int): Timeout in seconds
- `retries` (int): Number of retries

**Returns:**
- `status`: Operation status

#### record_metric
Record performance metric.

**Parameters:**
- `metric_name` (str): Metric name
- `value` (float): Metric value
- `labels` (dict, optional): Metric labels

**Returns:**
- `status`: Operation status

## Error Handling

All tools return structured error responses:

```json
{
  "success": false,
  "error": "Error message",
  "error_code": "ERROR_TYPE"
}
```

### Error Codes

- `VALIDATION_ERROR`: Input validation failed
- `DATABASE_ERROR`: Database operation failed
- `CACHE_ERROR`: Cache operation failed
- `BINARY_ANALYSIS_ERROR`: Binary analysis failed
- `WEB_ANALYSIS_ERROR`: Web analysis failed
- `TOOL_EXECUTION_ERROR`: Tool execution failed
- `UNKNOWN_TOOL`: Tool not found

## Logging

Structured logging with JSON output. Configure via `LOG_LEVEL` environment variable.

## Performance

- **Concurrent Tasks**: Configurable via `MAX_CONCURRENT_TASKS`
- **Cache TTL**: Configurable via `CACHE_TTL_SECONDS`
- **Request Timeout**: Configurable via `REQUEST_TIMEOUT_SECONDS`

## Security

- Input validation on all parameters
- Parameterized database queries
- Secure credential management via environment variables
- No hardcoded secrets

## Distribution

RAVERSE MCP Server is available through multiple distribution channels:

### NPM Package
```bash
npm install -g @raverse/mcp-server
```
- **Package**: [@raverse/mcp-server](https://www.npmjs.com/package/@raverse/mcp-server)
- **Registry**: https://registry.npmjs.org/

### PyPI Package
```bash
pip install jaegis-raverse-mcp-server
```
- **Package**: [jaegis-raverse-mcp-server](https://pypi.org/project/jaegis-raverse-mcp-server/)
- **Registry**: https://pypi.org/

### Docker Image
```bash
docker pull raverse/mcp-server:latest
```
- **Registry**: Docker Hub
- **Image**: raverse/mcp-server

### MCP Client Integration

The server is compatible with 20+ MCP clients including:
- Claude Desktop (Anthropic)
- Cursor
- Cline (VSCode)
- Roo Code (VSCode)
- Augment Code
- Continue.dev
- Windsurf (Codeium)
- Zed Editor
- And many more...

See [MCP_CLIENT_SETUP.md](MCP_CLIENT_SETUP.md) for detailed configuration guides.

## Documentation

- **[Installation Guide](INSTALLATION.md)** - Complete installation instructions
- **[Quick Start](QUICKSTART.md)** - Get running in 5 minutes
- **[MCP Client Setup](MCP_CLIENT_SETUP.md)** - Configure 20+ MCP clients
- **[Integration Guide](INTEGRATION_GUIDE.md)** - Integrate with RAVERSE
- **[Deployment Guide](DEPLOYMENT.md)** - Production deployment
- **[Tools Registry](TOOLS_REGISTRY_COMPLETE.md)** - Complete tool reference
- **[Package Distribution](PACKAGE_DISTRIBUTION.md)** - For package maintainers
- **[Publishing Guide](PUBLISHING.md)** - Publishing to npm and PyPI

## License

MIT License - See LICENSE file for details

## Support

For issues and questions, please refer to the main RAVERSE repository.

