# MCP Client Setup Guide - RAVERSE MCP Server

Complete configuration guide for integrating RAVERSE MCP Server with 20+ MCP-compatible clients.

**Table of Contents**
1. [Claude Desktop](#1-claude-desktop-anthropic)
2. [Cursor](#2-cursor)
3. [Cline (VSCode)](#3-cline-vscode-extension)
4. [Roo Code (VSCode)](#4-roo-code-vscode-extension)
5. [Augment Code](#5-augment-code)
6. [Continue.dev](#6-continuedev)
7. [Windsurf (Codeium)](#7-windsurf-codeium)
8. [Zed Editor](#8-zed-editor)
9. [VSCode with MCP Extension](#9-vscode-with-mcp-extension)
10. [Neovim with MCP Plugin](#10-neovim-with-mcp-plugin)
11. [Emacs with MCP](#11-emacs-with-mcp)
12. [JetBrains IDEs](#12-jetbrains-ides)
13. [Sublime Text with MCP](#13-sublime-text-with-mcp)
14. [Atom with MCP](#14-atom-with-mcp)
15. [Custom MCP Clients](#15-custom-mcp-clients)
16. [Web-based MCP Clients](#16-web-based-mcp-clients)
17. [Terminal-based MCP Clients](#17-terminal-based-mcp-clients)
18. [Browser Extensions](#18-browser-extensions-with-mcp)
19. [Mobile MCP Clients](#19-mobile-mcp-clients)
20. [Other Emerging Tools](#20-other-emerging-mcp-compatible-tools)

---

## 1. Claude Desktop (Anthropic)

### Installation
1. Download Claude Desktop from https://claude.ai/download
2. Install and launch the application

### Configuration

**File Location**: `~/.config/Claude/claude_desktop_config.json` (Linux/Mac) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows)

**Configuration**:
```json
{
  "mcpServers": {
    "raverse": {
      "command": "raverse-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/raverse",
        "REDIS_URL": "redis://localhost:6379",
        "OPENROUTER_API_KEY": "sk-or-v1-...",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Create the config file at the location above
3. Paste the configuration JSON
4. Restart Claude Desktop
5. Verify in Claude: "What tools are available?" - should list all 35 RAVERSE tools

### Troubleshooting
- **Tools not appearing**: Check that `raverse-mcp-server` is in PATH
- **Connection errors**: Verify DATABASE_URL and REDIS_URL are correct
- **Permission denied**: Ensure the config file is readable

---

## 2. Cursor

### Installation
1. Download Cursor from https://www.cursor.com/
2. Install and launch the application

### Configuration

**File Location**: `~/.cursor/mcp_config.json` (Linux/Mac) or `%APPDATA%\Cursor\mcp_config.json` (Windows)

**Configuration**:
```json
{
  "mcpServers": {
    "raverse": {
      "command": "raverse-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/raverse",
        "REDIS_URL": "redis://localhost:6379",
        "OPENROUTER_API_KEY": "sk-or-v1-...",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Create the config file at the location above
3. Paste the configuration JSON
4. Restart Cursor
5. Open Cursor settings and verify MCP server is connected

### Troubleshooting
- **MCP not loading**: Check Cursor logs in Help > Show Logs
- **Tools unavailable**: Verify Python 3.13+ is installed
- **Database connection failed**: Check PostgreSQL is running

---

## 3. Cline (VSCode Extension)

### Installation
1. Open VSCode
2. Go to Extensions (Ctrl+Shift+X / Cmd+Shift+X)
3. Search for "Cline"
4. Install the extension by Saoudrizwan

### Configuration

**File Location**: `.vscode/settings.json` in your workspace

**Configuration**:
```json
{
  "cline.mcpServers": {
    "raverse": {
      "command": "raverse-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/raverse",
        "REDIS_URL": "redis://localhost:6379",
        "OPENROUTER_API_KEY": "sk-or-v1-...",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Open `.vscode/settings.json` in your workspace
3. Add the configuration above
4. Reload VSCode window (Cmd+R / Ctrl+R)
5. Open Cline and verify tools are available

### Troubleshooting
- **Extension not loading**: Restart VSCode
- **MCP connection failed**: Check that raverse-mcp-server is executable
- **Tools not showing**: Verify LOG_LEVEL is not ERROR

---

## 4. Roo Code (VSCode Extension)

### Installation
1. Open VSCode
2. Go to Extensions (Ctrl+Shift+X / Cmd+Shift+X)
3. Search for "Roo Code"
4. Install the extension

### Configuration

**File Location**: `.vscode/settings.json` in your workspace

**Configuration**:
```json
{
  "rooCode.mcpServers": {
    "raverse": {
      "command": "raverse-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/raverse",
        "REDIS_URL": "redis://localhost:6379",
        "OPENROUTER_API_KEY": "sk-or-v1-...",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Configure `.vscode/settings.json` as shown above
3. Reload VSCode
4. Open Roo Code panel and verify connection

### Troubleshooting
- **Connection timeout**: Increase timeout in settings
- **Tools not available**: Check Python installation
- **Permission errors**: Run VSCode as administrator

---

## 5. Augment Code

### Installation
1. Visit https://www.augmentcode.com/
2. Install the IDE extension or use web version

### Configuration

**File Location**: `~/.augment/mcp_config.json`

**Configuration**:
```json
{
  "mcpServers": {
    "raverse": {
      "command": "raverse-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/raverse",
        "REDIS_URL": "redis://localhost:6379",
        "OPENROUTER_API_KEY": "sk-or-v1-...",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Create config file at `~/.augment/mcp_config.json`
3. Paste configuration
4. Restart Augment Code
5. Verify tools in the MCP panel

### Troubleshooting
- **Config not found**: Ensure directory exists
- **Connection refused**: Check if server is running
- **Tools missing**: Verify all 35 tools are listed

---

## 6. Continue.dev

### Installation
1. Install Continue extension in VSCode
2. Or use Continue.dev web interface

### Configuration

**File Location**: `~/.continue/config.json`

**Configuration**:
```json
{
  "mcpServers": {
    "raverse": {
      "command": "raverse-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/raverse",
        "REDIS_URL": "redis://localhost:6379",
        "OPENROUTER_API_KEY": "sk-or-v1-...",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Create config at `~/.continue/config.json`
3. Add configuration
4. Restart Continue
5. Test with a query

### Troubleshooting
- **Config parsing error**: Validate JSON syntax
- **Server not found**: Check PATH environment variable
- **Timeout errors**: Increase timeout in config

---

## 7. Windsurf (Codeium)

### Installation
1. Download Windsurf from https://codeium.com/windsurf
2. Install and launch

### Configuration

**File Location**: `~/.windsurf/mcp_config.json`

**Configuration**:
```json
{
  "mcpServers": {
    "raverse": {
      "command": "raverse-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/raverse",
        "REDIS_URL": "redis://localhost:6379",
        "OPENROUTER_API_KEY": "sk-or-v1-...",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Create config file
3. Paste configuration
4. Restart Windsurf
5. Verify in Windsurf settings

### Troubleshooting
- **MCP panel not showing**: Check Windsurf version
- **Connection failed**: Verify server is running
- **Tools not loading**: Check logs in Help menu

---

## 8. Zed Editor

### Installation
1. Download Zed from https://zed.dev/
2. Install and launch

### Configuration

**File Location**: `~/.config/zed/settings.json`

**Configuration**:
```json
{
  "mcp_servers": {
    "raverse": {
      "command": "raverse-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/raverse",
        "REDIS_URL": "redis://localhost:6379",
        "OPENROUTER_API_KEY": "sk-or-v1-...",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Edit `~/.config/zed/settings.json`
3. Add configuration
4. Restart Zed
5. Open MCP panel to verify

### Troubleshooting
- **Settings not loading**: Check JSON syntax
- **Server not found**: Verify npm installation
- **Permission denied**: Check file permissions

---

## 9. VSCode with MCP Extension

### Installation
1. Open VSCode
2. Install "MCP Client" extension from marketplace
3. Or search for "Model Context Protocol"

### Configuration

**File Location**: `.vscode/settings.json`

**Configuration**:
```json
{
  "mcp.servers": {
    "raverse": {
      "command": "raverse-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/raverse",
        "REDIS_URL": "redis://localhost:6379",
        "OPENROUTER_API_KEY": "sk-or-v1-...",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Install MCP extension in VSCode
3. Configure `.vscode/settings.json`
4. Reload VSCode
5. Check MCP panel for tools

### Troubleshooting
- **Extension not found**: Search marketplace for "MCP"
- **Connection error**: Check server logs
- **Tools not available**: Verify Python 3.13+

---

## 10. Neovim with MCP Plugin

### Installation
1. Install Neovim 0.9+
2. Install MCP plugin: `nvim-mcp` or similar

### Configuration

**File Location**: `~/.config/nvim/init.lua`

**Configuration**:
```lua
require('mcp').setup({
  servers = {
    raverse = {
      command = 'raverse-mcp-server',
      args = {},
      env = {
        DATABASE_URL = 'postgresql://user:password@localhost:5432/raverse',
        REDIS_URL = 'redis://localhost:6379',
        OPENROUTER_API_KEY = 'sk-or-v1-...',
        LOG_LEVEL = 'INFO'
      }
    }
  }
})
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Install MCP plugin for Neovim
3. Configure `init.lua`
4. Restart Neovim
5. Verify with `:MCP status`

### Troubleshooting
- **Plugin not loading**: Check plugin manager
- **Server not found**: Verify PATH
- **Lua errors**: Check syntax in init.lua

---

## 11. Emacs with MCP

### Installation
1. Install Emacs 28+
2. Install `emacs-mcp` package

### Configuration

**File Location**: `~/.emacs.d/init.el`

**Configuration**:
```elisp
(use-package emacs-mcp
  :config
  (setq mcp-servers
    '((raverse
       :command "raverse-mcp-server"
       :args ()
       :env (("DATABASE_URL" . "postgresql://user:password@localhost:5432/raverse")
             ("REDIS_URL" . "redis://localhost:6379")
             ("OPENROUTER_API_KEY" . "sk-or-v1-...")
             ("LOG_LEVEL" . "INFO"))))))
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Install emacs-mcp package
3. Configure `init.el`
4. Restart Emacs
5. Verify with `M-x mcp-status`

### Troubleshooting
- **Package not found**: Check MELPA repository
- **Server not starting**: Check Emacs messages buffer
- **Tools not available**: Verify Python installation

---

## 12. JetBrains IDEs

### Installation
1. Open JetBrains IDE (IntelliJ, PyCharm, WebStorm, etc.)
2. Install MCP plugin from marketplace

### Configuration

**File Location**: `~/.config/JetBrains/[IDE]/mcp_config.json`

**Configuration**:
```json
{
  "mcpServers": {
    "raverse": {
      "command": "raverse-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/raverse",
        "REDIS_URL": "redis://localhost:6379",
        "OPENROUTER_API_KEY": "sk-or-v1-...",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Install MCP plugin in JetBrains IDE
3. Configure MCP settings
4. Restart IDE
5. Verify in Tools > MCP

### Troubleshooting
- **Plugin not available**: Check IDE version compatibility
- **Server not found**: Verify npm installation
- **Connection timeout**: Check firewall settings

---

## 13. Sublime Text with MCP

### Installation
1. Install Sublime Text 4
2. Install Package Control
3. Install MCP package

### Configuration

**File Location**: `~/.config/sublime-text/Packages/User/mcp_config.json`

**Configuration**:
```json
{
  "mcp_servers": {
    "raverse": {
      "command": "raverse-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/raverse",
        "REDIS_URL": "redis://localhost:6379",
        "OPENROUTER_API_KEY": "sk-or-v1-...",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Install MCP package via Package Control
3. Configure settings
4. Restart Sublime Text
5. Verify in View > MCP

### Troubleshooting
- **Package not found**: Update Package Control
- **Server not responding**: Check console for errors
- **Tools not loading**: Verify Python path

---

## 14. Atom with MCP

### Installation
1. Install Atom editor
2. Install MCP package: `apm install mcp`

### Configuration

**File Location**: `~/.atom/mcp_config.json`

**Configuration**:
```json
{
  "mcpServers": {
    "raverse": {
      "command": "raverse-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "postgresql://user:password@localhost:5432/raverse",
        "REDIS_URL": "redis://localhost:6379",
        "OPENROUTER_API_KEY": "sk-or-v1-...",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Setup Steps
1. Install RAVERSE MCP Server: `npm install -g @raverse/mcp-server`
2. Install MCP package
3. Configure settings
4. Restart Atom
5. Verify in Packages > MCP

### Troubleshooting
- **apm command not found**: Add Atom to PATH
- **Package installation failed**: Check npm
- **Server not connecting**: Check firewall

---

## 15. Custom MCP Clients

### For Developers Building Custom MCP Clients

**Connection Details**:
```
Protocol: Model Context Protocol (MCP)
Transport: stdio
Command: raverse-mcp-server
Arguments: []
Environment Variables:
  - DATABASE_URL: PostgreSQL connection string
  - REDIS_URL: Redis connection string
  - OPENROUTER_API_KEY: LLM API key
  - LOG_LEVEL: DEBUG|INFO|WARNING|ERROR
```

**Available Tools**: 35 tools across 9 categories
- Binary Analysis (4)
- Knowledge Base & RAG (4)
- Web Analysis (5)
- Infrastructure (5)
- Advanced Analysis (5)
- Management (4)
- Utilities (5)
- System (4)
- NLP & Validation (2)

**Tool Discovery**:
```bash
raverse-mcp-server --list-tools
```

**Example Integration**:
```python
import subprocess
import json

# Start server
process = subprocess.Popen(
    ['raverse-mcp-server'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env={
        'DATABASE_URL': 'postgresql://...',
        'REDIS_URL': 'redis://...',
        'OPENROUTER_API_KEY': 'sk-or-v1-...'
    }
)

# Send MCP request
request = {
    'jsonrpc': '2.0',
    'id': 1,
    'method': 'tools/list',
    'params': {}
}

process.stdin.write(json.dumps(request).encode() + b'\n')
response = json.loads(process.stdout.readline().decode())
```

---

## 16. Web-based MCP Clients

### For Web Applications

**Setup**:
1. Deploy RAVERSE MCP Server to a server
2. Expose via HTTP/WebSocket
3. Configure CORS if needed

**Docker Deployment**:
```bash
docker run -d \
  -e DATABASE_URL="postgresql://..." \
  -e REDIS_URL="redis://..." \
  -e OPENROUTER_API_KEY="sk-or-v1-..." \
  -p 8000:8000 \
  raverse-mcp-server
```

**Web Client Configuration**:
```javascript
const mcpClient = new MCPClient({
  serverUrl: 'http://localhost:8000',
  transport: 'websocket'
});

await mcpClient.connect();
const tools = await mcpClient.listTools();
```

---

## 17. Terminal-based MCP Clients

### For CLI Tools

**Installation**:
```bash
npm install -g @raverse/mcp-server
```

**Usage**:
```bash
# Start server
raverse-mcp-server

# In another terminal, use tools
raverse-mcp-client call disassemble_binary --binary-path /bin/ls
```

**Configuration**:
```bash
export DATABASE_URL="postgresql://..."
export REDIS_URL="redis://..."
export OPENROUTER_API_KEY="sk-or-v1-..."
raverse-mcp-server
```

---

## 18. Browser Extensions with MCP

### For Browser-based AI Assistants

**Installation**:
1. Install browser extension for MCP support
2. Configure MCP server URL
3. Add RAVERSE server

**Configuration**:
```json
{
  "servers": [
    {
      "name": "RAVERSE",
      "url": "http://localhost:8000",
      "type": "mcp"
    }
  ]
}
```

---

## 19. Mobile MCP Clients

### For Mobile Applications

**Setup**:
1. Deploy RAVERSE MCP Server to cloud
2. Configure mobile app to connect
3. Use REST API wrapper

**Example (iOS/Android)**:
```swift
let client = MCPClient(serverURL: "https://raverse.example.com")
let tools = try await client.listTools()
```

---

## 20. Other Emerging MCP-Compatible Tools

### Future Support

As new MCP-compatible tools emerge, follow the same pattern:

1. **Identify the tool's MCP configuration location**
2. **Create configuration file** with RAVERSE server details
3. **Set environment variables** for database and API keys
4. **Restart the tool** and verify connection
5. **Test tool availability** in the tool's interface

### Common Configuration Pattern

Most MCP clients follow this pattern:
```json
{
  "mcpServers": {
    "raverse": {
      "command": "raverse-mcp-server",
      "args": [],
      "env": {
        "DATABASE_URL": "postgresql://...",
        "REDIS_URL": "redis://...",
        "OPENROUTER_API_KEY": "sk-or-v1-...",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

---

## General Troubleshooting

### Server Not Starting
```bash
# Check Python installation
python3 --version

# Check package installation
pip show jaegis-raverse-mcp-server

# Check npm installation
npm list -g @raverse/mcp-server
```

### Connection Issues
```bash
# Test database connection
psql $DATABASE_URL -c "SELECT 1"

# Test Redis connection
redis-cli -u $REDIS_URL ping

# Test server directly
raverse-mcp-server --version
```

### Tools Not Available
```bash
# Check logs
LOG_LEVEL=DEBUG raverse-mcp-server

# Verify all 35 tools
raverse-mcp-server --list-tools
```

### Environment Variables
```bash
# Verify environment
echo $DATABASE_URL
echo $REDIS_URL
echo $OPENROUTER_API_KEY

# Set for current session
export DATABASE_URL="postgresql://..."
export REDIS_URL="redis://..."
export OPENROUTER_API_KEY="sk-or-v1-..."
```

---

## Support

- **Documentation**: https://github.com/usemanusai/jaegis-RAVERSE
- **Issues**: https://github.com/usemanusai/jaegis-RAVERSE/issues
- **Discussions**: https://github.com/usemanusai/jaegis-RAVERSE/discussions

---

**Last Updated**: October 27, 2025
**Version**: 1.0.0

