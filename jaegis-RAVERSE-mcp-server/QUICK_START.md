# RAVERSE MCP Server - Quick Start Guide

## ⚡ Fastest Way to Get Started

### Prerequisites
- Docker Desktop installed (https://www.docker.com/products/docker-desktop)
- Python 3.8+ installed
- Git installed

---

## 🚀 Installation (Choose One)

### Option 1: Automated Python Installer (Recommended)

```bash
# Navigate to the package directory
cd jaegis-RAVERSE-mcp-server

# Run the automated installer
python -m jaegis_raverse_mcp_server.auto_installer
```

**What it does**:
- Checks for Docker
- Starts PostgreSQL and Redis containers
- Creates .env configuration
- Verifies connections
- Ready to start server

**Time**: 5-10 minutes

---

### Option 2: Manual Docker Setup + Setup Wizard

```bash
# Start Docker containers
cd jaegis-RAVERSE-mcp-server
docker-compose up -d

# Wait 30 seconds for services to start
sleep 30

# Run setup wizard in non-interactive mode
python -m jaegis_raverse_mcp_server.setup_wizard --non-interactive
```

**Time**: 3-5 minutes

---

### Option 3: Step-by-Step Manual Setup

```bash
# 1. Start Docker containers
cd jaegis-RAVERSE-mcp-server
docker-compose up -d

# 2. Wait for services
docker-compose ps

# 3. Create .env file manually
cp .env.example .env

# 4. Edit .env if needed
nano .env  # or your preferred editor

# 5. Verify database connection
docker exec raverse-postgres psql -U raverse -d raverse -c "SELECT 1;"

# 6. Verify Redis connection
docker exec raverse-redis redis-cli ping
```

**Time**: 5-10 minutes

---

## ▶️ Starting the Server

After installation, start the server:

```bash
# Option 1: Python
cd jaegis-RAVERSE-mcp-server
python -m jaegis_raverse_mcp_server.server

# Option 2: NPM
npx raverse-mcp-server@latest

# Option 3: Node.js
node bin/raverse-mcp-server.js
```

**Expected output**:
```
[INFO] Starting RAVERSE MCP Server v1.0.5
[INFO] Connecting to PostgreSQL...
[INFO] Connecting to Redis...
[INFO] Server ready on port 3000
```

---

## ✅ Verification

### Check Docker Containers

```bash
docker-compose ps
```

**Expected output**:
```
NAME                COMMAND                  SERVICE      STATUS
raverse-postgres    "docker-entrypoint..."   postgres     Up 2 minutes
raverse-redis       "redis-server..."        redis        Up 2 minutes
```

### Check Configuration

```bash
cat .env
```

### Check Logs

```bash
# Installation log
cat installation.log

# Server logs (while running)
tail -f server.log
```

---

## 🔧 Troubleshooting

### Docker Not Found

```bash
# Install Docker Desktop
# https://www.docker.com/products/docker-desktop

# Verify installation
docker --version
docker-compose --version
```

### Port Already in Use

```bash
# Check what's using port 5432 (PostgreSQL)
netstat -ano | findstr :5432

# Or use Docker to check
docker ps
```

### PostgreSQL Connection Failed

```bash
# Check Docker logs
docker-compose logs postgres

# Restart containers
docker-compose restart

# Or restart from scratch
docker-compose down -v
docker-compose up -d
```

### Redis Connection Failed

```bash
# Check Docker logs
docker-compose logs redis

# Restart containers
docker-compose restart
```

### Setup Wizard Failed

```bash
# Check installation log
cat installation.log

# Try manual setup
python -m jaegis_raverse_mcp_server.setup_wizard --non-interactive
```

---

## 📋 Configuration

### Default Configuration

The `.env` file contains:

```env
DATABASE_URL=postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse
REDIS_URL=redis://localhost:6379/0
LLM_API_KEY=sk-or-v1-placeholder-key
LLM_PROVIDER=openrouter
LLM_MODEL=meta-llama/llama-3.1-70b-instruct
```

### Adding OpenRouter API Key

1. Get your key: https://openrouter.ai/keys
2. Edit `.env`:
   ```env
   LLM_API_KEY=sk-or-v1-your-actual-key-here
   ```
3. Restart server

---

## 🛑 Stopping the Server

```bash
# Stop the server (Ctrl+C in terminal)

# Stop Docker containers
docker-compose down

# Stop and remove volumes (careful!)
docker-compose down -v
```

---

## 📚 Next Steps

1. **Read the documentation**: See `README.md`
2. **Configure MCP client**: See `MCP_CLIENT_SETUP.md`
3. **Explore tools**: See `TOOLS_REGISTRY_COMPLETE.md`
4. **Check logs**: `cat installation.log`

---

## 💡 Tips

- **Keep containers running**: `docker-compose up -d` runs in background
- **View logs**: `docker-compose logs -f` shows live logs
- **Restart services**: `docker-compose restart` restarts all containers
- **Clean up**: `docker-compose down -v` removes everything

---

## 🆘 Need Help?

- Check `installation.log` for detailed error messages
- See `AUTOMATED_INSTALLATION_GUIDE.md` for comprehensive guide
- GitHub Issues: https://github.com/usemanusai/jaegis-RAVERSE/issues

---

**Happy coding!** 🚀

