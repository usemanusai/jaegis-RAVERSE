# RAVERSE MCP Server - Automated Installation Guide

## Overview

The RAVERSE MCP Server now includes fully automated installation scripts that handle the complete setup process without any user interaction.

**Installation time**: 5-10 minutes (depending on Docker image download)

---

## Prerequisites

### Required
- **Docker** (https://www.docker.com/products/docker-desktop)
- **Docker Compose** (usually included with Docker Desktop)
- **Python 3.8+** (for running the setup wizard)
- **Node.js 18+** (optional, for NPM installation)

### Optional
- **OpenRouter API Key** (for LLM features, can be added later)

---

## Installation Methods

### Method 1: Automated Shell Script (Linux/macOS)

**Fastest and easiest method for Unix-like systems**

```bash
# Clone the repository
git clone https://github.com/usemanusai/jaegis-RAVERSE.git
cd jaegis-RAVERSE/jaegis-RAVERSE-mcp-server

# Make script executable
chmod +x install.sh

# Run the automated installer
./install.sh

# Optional: Provide OpenRouter API key
./install.sh --api-key "sk-or-v1-your-key-here"
```

**What it does**:
1. ✅ Checks for Docker and Docker Compose
2. ✅ Starts PostgreSQL and Redis containers
3. ✅ Waits for services to be ready
4. ✅ Runs setup wizard in non-interactive mode
5. ✅ Creates .env configuration file
6. ✅ Verifies database and Redis connections
7. ✅ Displays success message

**Output**:
```
╔════════════════════════════════════════════════════════════════╗
║  RAVERSE MCP Server - Automated Installation                  ║
║  Version 1.0.5                                                ║
╚════════════════════════════════════════════════════════════════╝

[INFO] Starting automated installation...
[✓] Docker is installed
[✓] Docker Compose is installed
[✓] Services started
[✓] PostgreSQL is ready
[✓] Redis is ready
[✓] Setup wizard completed
[✓] .env file created
[✓] Database connection verified
[✓] Redis connection verified

╔════════════════════════════════════════════════════════════════╗
║  ✓ Installation completed successfully!                       ║
╚════════════════════════════════════════════════════════════════╝
```

---

### Method 2: Automated PowerShell Script (Windows)

**Fastest and easiest method for Windows**

```powershell
# Clone the repository
git clone https://github.com/usemanusai/jaegis-RAVERSE.git
cd jaegis-RAVERSE\jaegis-RAVERSE-mcp-server

# Run the automated installer
.\install.ps1

# Optional: Provide OpenRouter API key
.\install.ps1 -ApiKey "sk-or-v1-your-key-here"
```

**Note**: You may need to allow script execution:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

### Method 3: Python Auto Installer

**Cross-platform method using Python**

```bash
# From the package directory
cd jaegis-RAVERSE-mcp-server

# Run the auto installer
python -m jaegis_raverse_mcp_server.auto_installer

# Or with NPM
npm run install:auto
```

---

### Method 4: Manual Setup Wizard (Non-Interactive)

**For advanced users who want more control**

```bash
cd jaegis-RAVERSE-mcp-server

# Run setup wizard in non-interactive mode
python -m jaegis_raverse_mcp_server.setup_wizard \
    --non-interactive \
    --db-url "postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse" \
    --redis-url "redis://localhost:6379/0" \
    --api-key "sk-or-v1-your-key-here"
```

---

## Starting the Server

After installation, start the server with:

### Option 1: Python
```bash
cd jaegis-RAVERSE-mcp-server
python -m jaegis_raverse_mcp_server.server
```

### Option 2: NPM
```bash
npx raverse-mcp-server@latest
```

### Option 3: Node.js
```bash
node bin/raverse-mcp-server.js
```

---

## Verification

### Check Installation Log

```bash
# View installation log
cat installation.log

# Or on Windows
Get-Content installation.log -Tail 50
```

### Verify Services

```bash
# Check Docker containers
docker-compose ps

# Check PostgreSQL
docker exec raverse-postgres psql -U raverse -d raverse -c "SELECT 1;"

# Check Redis
docker exec raverse-redis redis-cli ping
```

### Verify Configuration

```bash
# Check .env file
cat .env

# Or on Windows
Get-Content .env
```

---

## Troubleshooting

### Docker Not Found

**Error**: `Docker is not installed`

**Solution**:
1. Install Docker Desktop: https://www.docker.com/products/docker-desktop
2. Restart your terminal
3. Run the installer again

### Docker Compose Not Found

**Error**: `Docker Compose is not installed`

**Solution**:
1. Update Docker Desktop to latest version
2. Docker Compose is usually included
3. Or install separately: https://docs.docker.com/compose/install/

### PostgreSQL Connection Failed

**Error**: `PostgreSQL failed to start`

**Solution**:
1. Check Docker logs: `docker-compose logs postgres`
2. Ensure port 5432 is not in use: `netstat -ano | findstr :5432`
3. Try restarting Docker: `docker-compose restart`

### Redis Connection Failed

**Error**: `Redis failed to start`

**Solution**:
1. Check Docker logs: `docker-compose logs redis`
2. Ensure port 6379 is not in use: `netstat -ano | findstr :6379`
3. Try restarting Docker: `docker-compose restart`

### Setup Wizard Failed

**Error**: `Setup wizard failed`

**Solution**:
1. Check installation log: `cat installation.log`
2. Ensure Python 3.8+ is installed: `python --version`
3. Try running setup wizard manually:
   ```bash
   python -m jaegis_raverse_mcp_server.setup_wizard --non-interactive
   ```

---

## Configuration

### Environment Variables

The installer creates a `.env` file with default configuration:

```env
DATABASE_URL=postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse
REDIS_URL=redis://localhost:6379/0
LLM_API_KEY=sk-or-v1-placeholder-key
LLM_PROVIDER=openrouter
LLM_MODEL=meta-llama/llama-3.1-70b-instruct
```

### Customization

To customize configuration:

1. **Edit .env file**:
   ```bash
   nano .env  # or your preferred editor
   ```

2. **Restart server**:
   ```bash
   python -m jaegis_raverse_mcp_server.server
   ```

### Adding OpenRouter API Key

1. Get your API key: https://openrouter.ai/keys
2. Edit `.env` file:
   ```env
   LLM_API_KEY=sk-or-v1-your-actual-key-here
   ```
3. Restart server

---

## Next Steps

1. **Start the server**: See "Starting the Server" section above
2. **Configure MCP client**: See `MCP_CLIENT_SETUP.md`
3. **Explore tools**: See `TOOLS_REGISTRY_COMPLETE.md`
4. **Read documentation**: See `README.md`

---

## Support

- **Issues**: https://github.com/usemanusai/jaegis-RAVERSE/issues
- **Documentation**: See `README.md` and other `.md` files
- **Logs**: Check `installation.log` for detailed information

---

## What's Installed

### Docker Containers

- **PostgreSQL 17** with pgvector extension
- **Redis 8.2** with persistence

### Python Packages

- RAVERSE MCP Server
- All dependencies (see `requirements.txt`)

### Configuration Files

- `.env` - Server configuration
- `installation.log` - Installation log

---

## Uninstallation

To remove the installation:

```bash
# Stop and remove Docker containers
docker-compose down

# Remove volumes (optional, keeps data)
docker-compose down -v

# Remove .env file (optional)
rm .env

# Remove installation log (optional)
rm installation.log
```

---

**Happy coding!** 🚀

