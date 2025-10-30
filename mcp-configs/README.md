# RAVERSE MCP Server - Client Configurations

This directory contains MCP (Model Context Protocol) configuration files for integrating the RAVERSE MCP Server with 20+ AI coding assistants and IDEs.

## 📋 Supported Clients

### Anthropic
- **Claude Desktop** (`anthropic/claude-desktop.json`)
- **Claude Web** (`other/claude-web.json`)

### Code Editors
- **Cursor IDE** (`cursor/cursor.json`)
- **VS Code + Cline** (`vscode/vscode-cline.json`)
- **VS Code + Roo Code** (`vscode/vscode-roo-code.json`)
- **Windsurf IDE** (`other/windsurf.json`)
- **Zed Editor** (`zed/zed-editor.json`)

### Web-Based IDEs
- **Replit** (`other/replit.json`)
- **Bolt.new** (`other/bolt-new.json`)
- **v0.dev** (`other/v0-dev.json`)
- **Lovable.dev** (`other/lovable-dev.json`)

### AI Coding Assistants
- **Augment Code** (`other/augment-code.json`)
- **Manus AI** (`other/manus-ai.json`)
- **Devin AI** (`other/devin-ai.json`)
- **Continue.dev** (`other/continue-dev.json`)
- **Aider** (`other/aider.json`)

### Enterprise & Cloud
- **JetBrains AI Assistant** (`jetbrains/jetbrains-ai.json`)
- **GitHub Copilot** (`other/github-copilot.json`)
- **Sourcegraph Cody** (`other/sourcegraph-cody.json`)
- **Tabnine** (`other/tabnine.json`)
- **Amazon CodeWhisperer** (`other/amazon-codewhisperer.json`)

### Research & Analysis
- **Perplexity** (`other/perplexity.json`)
- **GPT-4 Web** (`other/gpt-4-web.json`)

---

## 🚀 Quick Setup

### Step 1: Choose Your Client

Select the configuration file for your AI coding assistant from the list above.

### Step 2: Copy Configuration

Copy the appropriate JSON file to your client's configuration directory:

**Claude Desktop (macOS):**
```bash
cp anthropic/claude-desktop.json ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**Claude Desktop (Windows):**
```bash
cp anthropic/claude-desktop.json "%APPDATA%\Claude\claude_desktop_config.json"
```

**Cursor IDE:**
```bash
cp cursor/cursor.json ~/.cursor/mcp_config.json
```

**VS Code (Cline):**
```bash
cp vscode/vscode-cline.json ~/.vscode/cline_mcp_config.json
```

### Step 3: Verify Configuration

Restart your client and verify the RAVERSE MCP Server is connected:

```bash
# Check if server is running
docker-compose ps

# View logs
cat installation.log
```

---

## 🔧 Configuration Details

All configuration files use the following settings:

```json
{
  "mcpServers": {
    "raverse": {
      "command": "npx",
      "args": ["-y", "raverse-mcp-server@latest"],
      "env": {
        "PROXY_URL": "https://raverse-mcp-proxy.use-manus-ai.workers.dev",
        "BACKEND_URL": "https://jaegis-raverse.onrender.com",
        "DATABASE_URL": "postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse",
        "REDIS_URL": "redis://:raverse_redis_password_2025@localhost:6379/0",
        "LOG_LEVEL": "INFO",
        "SERVER_VERSION": "1.0.8"
      }
    },
    "raverse-mcp-proxy": {
      "command": "npx",
      "args": ["-y", "raverse-mcp-proxy@latest"],
      "env": {
        "PROXY_URL": "https://raverse-mcp-proxy.use-manus-ai.workers.dev",
        "BACKEND_URL": "https://jaegis-raverse.onrender.com"
      }
    }
  }
}
```

### Environment Variables

**RAVERSE Server**:
- **PROXY_URL**: Cloudflare proxy URL for edge caching
- **BACKEND_URL**: Render backend URL for RAVERSE API
- **DATABASE_URL**: PostgreSQL connection string
- **REDIS_URL**: Redis connection string with password
- **LOG_LEVEL**: Logging level (INFO, DEBUG, ERROR)
- **SERVER_VERSION**: RAVERSE server version (1.0.8)

**RAVERSE MCP Proxy**:
- **PROXY_URL**: Cloudflare proxy URL
- **BACKEND_URL**: Render backend URL

---

## 📚 Available Tools

The RAVERSE MCP Server provides 35 tools across 9 categories:

### 1. Binary Analysis (4 tools)
- `disassemble_binary` - Convert machine code to assembly
- `generate_code_embedding` - Create semantic vectors for code
- `apply_patch` - Apply patches to binaries
- `verify_patch` - Verify patch application

### 2. Knowledge Base & RAG (4 tools)
- `ingest_content` - Add content to knowledge base
- `search_knowledge_base` - Semantic search
- `retrieve_entry` - Get specific entries
- `delete_entry` - Remove entries

### 3. Web Analysis (5 tools)
- `reconnaissance` - Gather web intelligence
- `analyze_javascript` - Analyze JS code
- `reverse_engineer_api` - Generate API specs
- `analyze_wasm` - Analyze WebAssembly
- `security_analysis` - Identify vulnerabilities

### 4. Infrastructure (5 tools)
- `database_query` - Execute database queries
- `cache_operation` - Manage cache
- `publish_message` - Publish A2A messages
- `fetch_content` - Download web content
- `record_metric` - Record metrics

### 5. Advanced Analysis (5 tools)
- `logic_identification` - Identify logic patterns
- `traffic_interception` - Intercept network traffic
- `generate_report` - Generate analysis reports
- `rag_orchestration` - Execute RAG workflow
- `deep_research` - Perform deep research

### 6. Management (4 tools)
- `version_management` - Manage versions
- `quality_gate` - Enforce quality standards
- `governance_check` - Check governance rules
- `generate_document` - Generate documents

### 7. Utilities (5 tools)
- `url_frontier_operation` - Manage URL frontier
- `api_pattern_matcher` - Identify API patterns
- `response_classifier` - Classify HTTP responses
- `websocket_analyzer` - Analyze WebSocket
- `crawl_scheduler` - Schedule crawl jobs

### 8. System (4 tools)
- `metrics_collector` - Record metrics
- `multi_level_cache` - Multi-level caching
- `configuration_service` - Configuration management
- `llm_interface` - LLM interface

### 9. NLP & Validation (2 tools)
- `nlp_analysis` - NLP analysis
- `input_validation` - Input validation

---

## ✅ Verification

### Test Connection

```bash
# Start the server
python -m jaegis_raverse_mcp_server.server

# In another terminal, test a tool
curl -X POST http://localhost:8000/tools/disassemble_binary \
  -H "Content-Type: application/json" \
  -d '{"binary_path": "/path/to/binary", "architecture": "x86_64"}'
```

### Check Logs

```bash
# View installation logs
cat installation.log

# View server logs
docker-compose logs raverse-app

# View PostgreSQL logs
docker-compose logs postgres

# View Redis logs
docker-compose logs redis
```

---

## 🔍 Troubleshooting

### Connection Failed

1. **Verify server is running:**
   ```bash
   docker-compose ps
   ```

2. **Check PostgreSQL connection:**
   ```bash
   psql postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse
   ```

3. **Check Redis connection:**
   ```bash
   redis-cli -h localhost -p 6379 -a raverse_redis_password_2025 ping
   ```

### Configuration Issues

1. **Invalid JSON:** Validate with `jq`:
   ```bash
   jq . anthropic/claude-desktop.json
   ```

2. **Wrong path:** Ensure config file is in correct directory

3. **Environment variables:** Verify `.env` file exists and has correct values

### Server Issues

1. **Check logs:**
   ```bash
   tail -50 installation.log
   ```

2. **Restart services:**
   ```bash
   docker-compose restart
   ```

3. **Rebuild containers:**
   ```bash
   docker-compose down -v
   python -m jaegis_raverse_mcp_server.auto_installer
   ```

---

## 📖 Documentation

- **MCP_SETUP_GUIDE.md** - Detailed setup for each client
- **QUICK_START.md** - Quick start guide
- **TROUBLESHOOTING.md** - Common issues and solutions
- **TOOLS_REGISTRY_COMPLETE.md** - Complete tools reference

---

## 🎯 Next Steps

1. **Choose your client** from the list above
2. **Copy the configuration** to your client's config directory
3. **Restart your client** to load the configuration
4. **Verify connection** by testing a tool
5. **Start using RAVERSE** with all 35 tools

---

## 📞 Support

- **Issues**: Check TROUBLESHOOTING.md
- **Documentation**: See MCP_SETUP_GUIDE.md
- **Logs**: Check installation.log and docker-compose logs
- **GitHub**: https://github.com/usemanusai/jaegis-RAVERSE

---

**Version**: 1.0.6  
**Last Updated**: 2025-10-28  
**Status**: ✅ Production Ready

