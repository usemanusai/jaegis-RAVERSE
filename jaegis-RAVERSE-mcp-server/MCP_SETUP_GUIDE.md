# RAVERSE MCP Server - Complete Setup Guide for 20+ Clients

**Version**: 1.0.6  
**Status**: ✅ Production Ready  
**Last Updated**: 2025-10-28

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Client Setup Instructions](#client-setup-instructions)
4. [Verification](#verification)
5. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required
- RAVERSE MCP Server v1.0.6 installed and running
- Python 3.13+
- Docker and Docker Compose
- PostgreSQL 17 (via Docker)
- Redis 8.2 (via Docker)

### Verify Installation

```bash
# Check server is running
docker-compose ps

# Check .env file exists
cat .env

# Test PostgreSQL connection
psql postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse -c "SELECT 1"

# Test Redis connection
redis-cli -h localhost -p 6379 -a raverse_redis_password_2025 ping
```

---

## Installation

### Step 1: Run Auto Installer

```bash
cd jaegis-RAVERSE-mcp-server
python -m jaegis_raverse_mcp_server.auto_installer
```

### Step 2: Verify Services

```bash
# Check Docker containers
docker-compose ps

# Expected output:
# NAME                COMMAND                  SERVICE      STATUS
# raverse-postgres    "docker-entrypoint..."   postgres     Up
# raverse-redis       "redis-server..."        redis        Up
```

### Step 3: Start Server

```bash
python -m jaegis_raverse_mcp_server.server
```

---

## Client Setup Instructions

### 1. Claude Desktop (macOS)

**Location**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```bash
# Copy configuration
cp mcp-configs/anthropic/claude-desktop.json \
  ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Restart Claude Desktop
# Menu → Quit Claude
# Reopen Claude
```

**Verify**: Look for "RAVERSE" in Claude's MCP settings

---

### 2. Claude Desktop (Windows)

**Location**: `%APPDATA%\Claude\claude_desktop_config.json`

```powershell
# Copy configuration
Copy-Item mcp-configs/anthropic/claude-desktop.json `
  -Destination "$env:APPDATA\Claude\claude_desktop_config.json"

# Restart Claude Desktop
```

---

### 3. Cursor IDE

**Location**: `~/.cursor/mcp_config.json` or `~/.config/cursor/mcp_config.json`

```bash
# Copy configuration
cp mcp-configs/cursor/cursor.json ~/.cursor/mcp_config.json

# Restart Cursor
```

---

### 4. VS Code + Cline

**Location**: `.vscode/settings.json` or Cline extension settings

```bash
# Copy configuration
cp mcp-configs/vscode/vscode-cline.json ~/.vscode/cline_mcp_config.json

# Restart VS Code
```

---

### 5. VS Code + Roo Code

**Location**: `.vscode/settings.json` or Roo Code extension settings

```bash
# Copy configuration
cp mcp-configs/vscode/vscode-roo-code.json ~/.vscode/roo_mcp_config.json

# Restart VS Code
```

---

### 6. Windsurf IDE

**Location**: `~/.windsurf/mcp_config.json`

```bash
# Copy configuration
cp mcp-configs/other/windsurf.json ~/.windsurf/mcp_config.json

# Restart Windsurf
```

---

### 7. Zed Editor

**Location**: `~/.config/zed/settings.json`

```bash
# Copy configuration
cp mcp-configs/zed/zed-editor.json ~/.config/zed/mcp_config.json

# Restart Zed
```

---

### 8. Replit

**Location**: Replit project settings

```bash
# Copy configuration to project
cp mcp-configs/other/replit.json .replit-mcp-config.json

# Commit and push
git add .replit-mcp-config.json
git commit -m "Add RAVERSE MCP configuration"
git push
```

---

### 9. Bolt.new

**Location**: Project settings or environment variables

```bash
# Set environment variables in Bolt.new project:
DATABASE_URL=postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse
REDIS_URL=redis://:raverse_redis_password_2025@localhost:6379/0
```

---

### 10. v0.dev

**Location**: Project environment settings

```bash
# Configure in v0.dev dashboard:
# Settings → Environment Variables
# Add the same variables as Bolt.new
```

---

### 11. Lovable.dev

**Location**: Project configuration

```bash
# Copy configuration
cp mcp-configs/other/lovable-dev.json .lovable-mcp-config.json
```

---

### 12. JetBrains AI Assistant

**Location**: `~/.config/JetBrains/*/options/mcp_config.json`

```bash
# Copy configuration
cp mcp-configs/jetbrains/jetbrains-ai.json \
  ~/.config/JetBrains/IntelliJIdea2024.1/options/mcp_config.json

# Restart JetBrains IDE
```

---

### 13. GitHub Copilot

**Location**: VS Code settings

```bash
# Configure in VS Code settings.json:
{
  "github.copilot.mcp": {
    "raverse": {
      "command": "python",
      "args": ["-m", "jaegis_raverse_mcp_server.server"]
    }
  }
}
```

---

### 14. Continue.dev

**Location**: `~/.continue/config.json`

```bash
# Copy configuration
cp mcp-configs/other/continue-dev.json ~/.continue/mcp_config.json

# Restart Continue
```

---

### 15. Aider

**Location**: `~/.aider/mcp_config.json`

```bash
# Copy configuration
cp mcp-configs/other/aider.json ~/.aider/mcp_config.json

# Restart Aider
```

---

### 16. Sourcegraph Cody

**Location**: VS Code extension settings

```bash
# Configure in VS Code settings.json:
{
  "cody.mcp": {
    "raverse": {
      "command": "python",
      "args": ["-m", "jaegis_raverse_mcp_server.server"]
    }
  }
}
```

---

### 17. Tabnine

**Location**: Tabnine settings

```bash
# Configure in Tabnine dashboard:
# Settings → MCP Servers
# Add RAVERSE configuration
```

---

### 18. Amazon CodeWhisperer

**Location**: AWS IDE settings

```bash
# Configure in your IDE settings:
# AWS Toolkit → CodeWhisperer → MCP Configuration
```

---

### 19. Manus AI

**Location**: `~/.manus/mcp_config.json`

```bash
# Copy configuration
cp mcp-configs/other/manus-ai.json ~/.manus/mcp_config.json
```

---

### 20. Devin AI

**Location**: Devin project settings

```bash
# Configure in Devin dashboard:
# Project Settings → MCP Servers
```

---

## Verification

### Test Connection

```bash
# Check if server is responding
curl -X GET http://localhost:8000/health

# Expected response:
# {"status": "healthy", "version": "1.0.6"}
```

### Test Tool

```bash
# Test a tool via curl
curl -X POST http://localhost:8000/tools/disassemble_binary \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/path/to/binary",
    "architecture": "x86_64"
  }'
```

### Check Logs

```bash
# View server logs
tail -50 installation.log

# View Docker logs
docker-compose logs -f raverse-app

# View PostgreSQL logs
docker-compose logs postgres

# View Redis logs
docker-compose logs redis
```

---

## Troubleshooting

### Connection Failed

**Problem**: Client cannot connect to RAVERSE MCP Server

**Solution**:
1. Verify server is running: `docker-compose ps`
2. Check .env file: `cat .env`
3. Verify credentials in config file
4. Check firewall settings
5. Restart client application

### Invalid Configuration

**Problem**: JSON syntax error in config file

**Solution**:
```bash
# Validate JSON
jq . mcp-configs/anthropic/claude-desktop.json

# Fix any syntax errors
# Ensure all quotes are properly escaped
```

### Database Connection Error

**Problem**: Cannot connect to PostgreSQL

**Solution**:
```bash
# Test connection
psql postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse

# If fails, restart PostgreSQL
docker-compose restart postgres

# Check logs
docker-compose logs postgres
```

### Redis Connection Error

**Problem**: Cannot connect to Redis

**Solution**:
```bash
# Test connection
redis-cli -h localhost -p 6379 -a raverse_redis_password_2025 ping

# If fails, restart Redis
docker-compose restart redis

# Check logs
docker-compose logs redis
```

---

## 📚 Available Tools

All 35 RAVERSE tools are available through MCP:

- **Binary Analysis**: disassemble_binary, generate_code_embedding, apply_patch, verify_patch
- **Knowledge Base**: ingest_content, search_knowledge_base, retrieve_entry, delete_entry
- **Web Analysis**: reconnaissance, analyze_javascript, reverse_engineer_api, analyze_wasm, security_analysis
- **Infrastructure**: database_query, cache_operation, publish_message, fetch_content, record_metric
- **Advanced Analysis**: logic_identification, traffic_interception, generate_report, rag_orchestration, deep_research
- **Management**: version_management, quality_gate, governance_check, generate_document
- **Utilities**: url_frontier_operation, api_pattern_matcher, response_classifier, websocket_analyzer, crawl_scheduler
- **System**: metrics_collector, multi_level_cache, configuration_service, llm_interface
- **NLP & Validation**: nlp_analysis, input_validation

---

## 🎯 Next Steps

1. Choose your client from the list above
2. Follow the setup instructions for your client
3. Verify the connection
4. Start using RAVERSE tools in your client
5. Check troubleshooting if you encounter issues

---

**Version**: 1.0.6  
**Status**: ✅ Production Ready  
**Support**: See TROUBLESHOOTING.md for more help

