# RAVERSE MCP Server - NPX Usage Guide

**Version**: 1.0.7  
**Status**: ✅ Production Ready  
**Last Updated**: 2025-10-28

---

## 🚀 Quick Start with NPX

### No Installation Required

Run RAVERSE MCP Server directly without installing anything:

```bash
npx -y raverse-mcp-server@latest
```

### What is NPX?

NPX is a package runner that comes with Node.js. It allows you to:
- Run packages without global installation
- Always use the latest version
- Avoid version conflicts
- Save disk space

---

## Installation Methods

### Method 1: NPX (Fastest)

```bash
# Run latest version
npx -y raverse-mcp-server@latest

# Run specific version
npx -y raverse-mcp-server@1.0.7

# Run with custom environment
npx -y raverse-mcp-server@latest -- --port 5001
```

### Method 2: NPM Global

```bash
# Install globally
npm install -g raverse-mcp-server

# Run
raverse-mcp-server

# Check version
raverse-mcp-server --version
```

### Method 3: PyPI

```bash
# Install from PyPI
pip install jaegis-raverse-mcp-server

# Run
raverse-mcp-server

# Check version
raverse-mcp-server --version
```

### Method 4: Docker

```bash
# Pull image
docker pull raverse/mcp-server:latest

# Run container
docker run -p 5000:5000 raverse/mcp-server:latest
```

---

## MCP Client Configuration

### Using NPX in MCP Configs

All MCP client configurations now use NPX:

```json
{
  "mcpServers": {
    "raverse": {
      "command": "npx",
      "args": ["-y", "raverse-mcp-server@latest"],
      "env": {
        "DATABASE_URL": "postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse",
        "REDIS_URL": "redis://:raverse_redis_password_2025@localhost:6379/0",
        "LOG_LEVEL": "INFO",
        "SERVER_VERSION": "1.0.7"
      }
    }
  }
}
```

### Supported Clients (20+)

- Claude Desktop (macOS, Windows, Linux)
- Cursor IDE
- VS Code + Cline
- VS Code + Roo Code
- Windsurf IDE
- Zed Editor
- JetBrains AI Assistant
- GitHub Copilot
- Sourcegraph Cody
- Tabnine
- Amazon CodeWhisperer
- Replit
- Bolt.new
- v0.dev
- Lovable.dev
- Augment Code
- Manus AI
- Devin AI
- Continue.dev
- Aider

---

## Environment Variables

### Required

```bash
DATABASE_URL=postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse
REDIS_URL=redis://:raverse_redis_password_2025@localhost:6379/0
```

### Optional

```bash
LOG_LEVEL=INFO              # DEBUG, INFO, WARNING, ERROR
SERVER_VERSION=1.0.7        # Server version
PORT=5000                   # Server port
HOST=localhost              # Server host
```

---

## Troubleshooting

### NPX Not Found

```bash
# Install Node.js from https://nodejs.org/
# NPX comes with Node.js 8.2.0+

# Verify installation
node --version
npx --version
```

### Port Already in Use

```bash
# Use different port
npx -y raverse-mcp-server@latest -- --port 5001

# Or kill existing process
lsof -i :5000
kill -9 <PID>
```

### Database Connection Error

```bash
# Verify PostgreSQL is running
docker-compose ps

# Check connection string
echo $DATABASE_URL

# Test connection
psql $DATABASE_URL -c "SELECT 1"
```

### Redis Connection Error

```bash
# Verify Redis is running
docker-compose ps

# Check connection string
echo $REDIS_URL

# Test connection
redis-cli -u $REDIS_URL ping
```

---

## Performance Tips

1. **Use NPX for Development**: Fast, no installation
2. **Use NPM for Production**: Faster startup after first run
3. **Use Docker for Isolation**: Best for production deployments
4. **Use PyPI for Python Projects**: Integrates with Python ecosystem

---

## Version Management

### Check Current Version

```bash
npx -y raverse-mcp-server@latest -- --version
```

### Update to Latest

```bash
# NPX always uses latest
npx -y raverse-mcp-server@latest

# NPM global
npm install -g raverse-mcp-server@latest

# PyPI
pip install --upgrade jaegis-raverse-mcp-server
```

### Pin Specific Version

```bash
# NPX
npx -y raverse-mcp-server@1.0.7

# NPM
npm install -g raverse-mcp-server@1.0.7

# PyPI
pip install jaegis-raverse-mcp-server==1.0.7
```

---

## Support

- **GitHub**: https://github.com/usemanusai/jaegis-RAVERSE
- **NPM**: https://www.npmjs.com/package/raverse-mcp-server
- **PyPI**: https://pypi.org/project/jaegis-raverse-mcp-server/
- **Issues**: https://github.com/usemanusai/jaegis-RAVERSE/issues

---

**RAVERSE MCP Server v1.0.7 - Production Ready** ✅

