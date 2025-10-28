# RAVERSE MCP Server - Troubleshooting Guide

## Common Issues and Solutions

---

## Issue 1: PowerShell Script Syntax Errors

### Error Message
```
Unexpected token 'Database' in expression or statement.
The string is missing the terminator: ".
Missing closing '}' in statement block or type definition.
```

### Cause
- Unicode characters (✓, ✗, ⚠) not supported in Windows PowerShell
- String encoding issues

### Solution

**Option 1: Use Python Installer (Recommended)**
```powershell
cd jaegis-RAVERSE-mcp-server
python -m jaegis_raverse_mcp_server.auto_installer
```

**Option 2: Manual Setup**
```powershell
# Start Docker containers
docker-compose up -d

# Wait 30 seconds
Start-Sleep -Seconds 30

# Run setup wizard
python -m jaegis_raverse_mcp_server.setup_wizard --non-interactive
```

**Option 3: Use Bash (if WSL installed)**
```bash
cd jaegis-RAVERSE-mcp-server
chmod +x install.sh
./install.sh
```

---

## Issue 2: Docker Compose Timeout

### Error Message
```
subprocess.TimeoutExpired: Command '['docker-compose', 'up', '-d']' timed out after 300 seconds
UnicodeEncodeError: 'charmap' codec can't encode character '\u2717'
```

### Cause
- Docker images taking too long to download/start
- Windows console encoding issues with Unicode characters
- Insufficient system resources

### Solution

**Option 1: Increase Timeout**
```bash
# Run with longer timeout (manually)
cd jaegis-RAVERSE-mcp-server
docker-compose up -d
# Wait 5-10 minutes for images to download
docker-compose ps
```

**Option 2: Pre-download Images**
```bash
# Download images first
docker pull pgvector/pgvector:pg17
docker pull redis:8.2

# Then start containers
docker-compose up -d
```

**Option 3: Check System Resources**
```bash
# Check available disk space
Get-Volume

# Check available memory
Get-ComputerInfo | Select-Object CsPhyicallyInstalledMemorySize

# Free up space if needed
docker system prune -a
```

**Option 4: Use WSL2 Backend**
- Docker Desktop Settings → General → WSL 2 based engine
- Restart Docker Desktop
- Try again

---

## Issue 3: PostgreSQL Connection Failed

### Error Message
```
FATAL: password authentication failed for user "raverse"
```

### Cause
- PostgreSQL container not fully initialized
- Wrong credentials in .env file
- Port 5432 already in use

### Solution

**Option 1: Wait Longer**
```bash
# Wait for PostgreSQL to be ready
docker-compose logs postgres

# Check if ready
docker exec raverse-postgres pg_isready -U raverse -d raverse

# If not ready, wait and try again
Start-Sleep -Seconds 30
docker exec raverse-postgres pg_isready -U raverse -d raverse
```

**Option 2: Restart PostgreSQL**
```bash
# Restart the container
docker-compose restart postgres

# Wait 30 seconds
Start-Sleep -Seconds 30

# Verify
docker exec raverse-postgres psql -U raverse -d raverse -c "SELECT 1;"
```

**Option 3: Check Port Conflict**
```bash
# Check if port 5432 is in use
netstat -ano | findstr :5432

# If in use, stop the process or use different port
# Edit docker-compose.yml and change port mapping
```

**Option 4: Rebuild from Scratch**
```bash
# Stop and remove everything
docker-compose down -v

# Remove images
docker rmi pgvector/pgvector:pg17

# Start fresh
docker-compose up -d

# Wait 2-3 minutes
Start-Sleep -Seconds 180

# Verify
docker exec raverse-postgres psql -U raverse -d raverse -c "SELECT 1;"
```

---

## Issue 4: Redis Connection Failed

### Error Message
```
ConnectionError: Error 111 connecting to localhost:6379
```

### Cause
- Redis container not started
- Port 6379 already in use
- Redis not responding

### Solution

**Option 1: Check Redis Status**
```bash
# Check if Redis is running
docker-compose ps redis

# Check Redis logs
docker-compose logs redis

# Test connection
docker exec raverse-redis redis-cli ping
```

**Option 2: Restart Redis**
```bash
# Restart the container
docker-compose restart redis

# Wait 10 seconds
Start-Sleep -Seconds 10

# Verify
docker exec raverse-redis redis-cli ping
```

**Option 3: Check Port Conflict**
```bash
# Check if port 6379 is in use
netstat -ano | findstr :6379

# If in use, stop the process or use different port
```

---

## Issue 5: .env File Not Created

### Error Message
```
FileNotFoundError: [Errno 2] No such file or directory: '.env'
```

### Cause
- Setup wizard didn't run successfully
- Wrong working directory
- Permission issues

### Solution

**Option 1: Create Manually**
```bash
# Copy example file
cp .env.example .env

# Verify
cat .env
```

**Option 2: Run Setup Wizard**
```bash
# Run setup wizard
python -m jaegis_raverse_mcp_server.setup_wizard --non-interactive

# Verify
cat .env
```

**Option 3: Check Permissions**
```bash
# Check if you can write to directory
ls -la

# If permission denied, change permissions
chmod 755 .

# Try again
python -m jaegis_raverse_mcp_server.setup_wizard --non-interactive
```

---

## Issue 6: Python Module Not Found

### Error Message
```
ModuleNotFoundError: No module named 'jaegis_raverse_mcp_server'
```

### Cause
- Package not installed
- Wrong working directory
- Virtual environment not activated

### Solution

**Option 1: Install Package**
```bash
# Install in development mode
pip install -e .

# Verify
python -c "import jaegis_raverse_mcp_server; print('OK')"
```

**Option 2: Activate Virtual Environment**
```bash
# On Windows
.venv\Scripts\Activate.ps1

# On Linux/macOS
source .venv/bin/activate

# Verify
python -m jaegis_raverse_mcp_server.auto_installer
```

**Option 3: Check Working Directory**
```bash
# Make sure you're in the right directory
pwd  # or cd on Windows

# Should be: jaegis-RAVERSE-mcp-server

# If not, navigate there
cd jaegis-RAVERSE-mcp-server
```

---

## Issue 7: Installation Log Shows Errors

### Solution

**Check the Log**
```bash
# View entire log
cat installation.log

# View last 50 lines
tail -50 installation.log

# Search for errors
grep ERROR installation.log

# Search for specific error
grep "PostgreSQL" installation.log
```

**Common Log Patterns**:
- `[OK]` - Success
- `[FAILED]` - Error occurred
- `[TIMEOUT]` - Command took too long
- `[ERROR]` - Exception occurred

---

## Issue 8: Server Won't Start

### Error Message
```
ConnectionRefusedError: [Errno 111] Connection refused
```

### Cause
- PostgreSQL or Redis not running
- .env file not configured correctly
- Port already in use

### Solution

**Option 1: Verify Services**
```bash
# Check Docker containers
docker-compose ps

# Should show both postgres and redis as "Up"

# If not, start them
docker-compose up -d
```

**Option 2: Verify Configuration**
```bash
# Check .env file
cat .env

# Verify database connection
docker exec raverse-postgres psql -U raverse -d raverse -c "SELECT 1;"

# Verify Redis connection
docker exec raverse-redis redis-cli ping
```

**Option 3: Check Logs**
```bash
# View server logs
python -m jaegis_raverse_mcp_server.server 2>&1 | head -50

# View Docker logs
docker-compose logs
```

---

## Quick Diagnostic Commands

```bash
# Check Docker status
docker-compose ps

# Check PostgreSQL
docker exec raverse-postgres psql -U raverse -d raverse -c "SELECT 1;"

# Check Redis
docker exec raverse-redis redis-cli ping

# Check .env file
cat .env

# Check installation log
tail -50 installation.log

# Check Python version
python --version

# Check Docker version
docker --version

# Check Docker Compose version
docker-compose --version
```

---

## Getting Help

1. **Check this guide** - Most issues are covered above
2. **Check installation.log** - Detailed error messages
3. **Check Docker logs** - `docker-compose logs`
4. **GitHub Issues** - https://github.com/usemanusai/jaegis-RAVERSE/issues
5. **Documentation** - See `README.md` and other `.md` files

---

## Still Having Issues?

**Collect diagnostic information**:
```bash
# Create diagnostic report
echo "=== System Info ===" > diagnostic.txt
python --version >> diagnostic.txt
docker --version >> diagnostic.txt
docker-compose --version >> diagnostic.txt

echo "=== Docker Status ===" >> diagnostic.txt
docker-compose ps >> diagnostic.txt

echo "=== Installation Log ===" >> diagnostic.txt
cat installation.log >> diagnostic.txt

echo "=== .env File ===" >> diagnostic.txt
cat .env >> diagnostic.txt

# Share diagnostic.txt with support
```

---

**Good luck!** 🚀

