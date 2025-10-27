# RAVERSE MCP Server - Installation Guide

Complete installation guide for all distribution methods.

## Table of Contents
1. [Quick Start](#quick-start)
2. [NPM Installation](#npm-installation)
3. [PyPI Installation](#pypi-installation)
4. [Docker Installation](#docker-installation)
5. [From Source](#from-source)
6. [Verification](#verification)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Option 1: NPM (Recommended for Most Users)
```bash
# Install globally
npm install -g @raverse/mcp-server

# Run the server
raverse-mcp-server

# In another terminal, verify installation
raverse-mcp-server --version
```

### Option 2: PyPI (Recommended for Python Developers)
```bash
# Install via pip
pip install jaegis-raverse-mcp-server

# Run the server
raverse-mcp-server

# Verify installation
raverse-mcp-server --version
```

### Option 3: Docker (Recommended for Production)
```bash
# Pull the image
docker pull raverse/mcp-server:latest

# Run the container
docker run -d \
  -e DATABASE_URL="postgresql://user:pass@host/db" \
  -e REDIS_URL="redis://localhost:6379" \
  -e OPENROUTER_API_KEY="sk-or-v1-..." \
  -p 8000:8000 \
  raverse/mcp-server:latest
```

---

## NPM Installation

### Prerequisites
- Node.js 18.0.0 or higher
- npm 9.0.0 or higher
- Python 3.13 or higher (required by the server)
- PostgreSQL 17 (for database features)
- Redis 8.2 (for caching features)

### Installation Steps

#### 1. Install Node.js (if not already installed)
```bash
# macOS with Homebrew
brew install node

# Ubuntu/Debian
sudo apt-get install nodejs npm

# Windows
# Download from https://nodejs.org/
```

#### 2. Install RAVERSE MCP Server
```bash
# Global installation (recommended)
npm install -g @raverse/mcp-server

# Or local installation in a project
npm install @raverse/mcp-server
```

#### 3. Verify Installation
```bash
# Check version
raverse-mcp-server --version

# Show help
raverse-mcp-server --help
```

#### 4. Configure Environment
```bash
# Create .env file in your working directory
cat > .env << EOF
DATABASE_URL=postgresql://user:password@localhost:5432/raverse
REDIS_URL=redis://localhost:6379
OPENROUTER_API_KEY=sk-or-v1-your-api-key
LOG_LEVEL=INFO
EOF
```

#### 5. Run the Server
```bash
# Start the server
raverse-mcp-server

# Or with custom environment
DATABASE_URL=postgresql://... REDIS_URL=redis://... raverse-mcp-server
```

### NPM Scripts

If installed locally in a project:
```bash
# Setup (installs Python dependencies)
npm run setup

# Start server
npm start

# Development mode (with debug logging)
npm run dev

# Run tests
npm test

# Check code quality
npm run lint

# Format code
npm run format
```

---

## PyPI Installation

### Prerequisites
- Python 3.13 or higher
- pip 23.0 or higher
- PostgreSQL 17 (for database features)
- Redis 8.2 (for caching features)

### Installation Steps

#### 1. Install Python (if not already installed)
```bash
# macOS with Homebrew
brew install python@3.13

# Ubuntu/Debian
sudo apt-get install python3.13 python3.13-venv python3.13-dev

# Windows
# Download from https://www.python.org/
```

#### 2. Create Virtual Environment (Recommended)
```bash
# Create virtual environment
python3.13 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

#### 3. Install RAVERSE MCP Server
```bash
# Install from PyPI
pip install jaegis-raverse-mcp-server

# Or install with development dependencies
pip install jaegis-raverse-mcp-server[dev]
```

#### 4. Verify Installation
```bash
# Check version
raverse-mcp-server --version

# Show help
raverse-mcp-server --help

# Check package info
pip show jaegis-raverse-mcp-server
```

#### 5. Configure Environment
```bash
# Create .env file
cat > .env << EOF
DATABASE_URL=postgresql://user:password@localhost:5432/raverse
REDIS_URL=redis://localhost:6379
OPENROUTER_API_KEY=sk-or-v1-your-api-key
LOG_LEVEL=INFO
EOF
```

#### 6. Run the Server
```bash
# Start the server
raverse-mcp-server

# Or with environment variables
export DATABASE_URL=postgresql://...
export REDIS_URL=redis://...
export OPENROUTER_API_KEY=sk-or-v1-...
raverse-mcp-server
```

### Python Development

```bash
# Install in development mode
pip install -e .

# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ --cov=jaegis_raverse_mcp_server

# Type checking
mypy jaegis_raverse_mcp_server/

# Code formatting
black jaegis_raverse_mcp_server/

# Linting
ruff check jaegis_raverse_mcp_server/
```

---

## Docker Installation

### Prerequisites
- Docker 20.10 or higher
- Docker Compose 2.0 or higher (optional)

### Installation Steps

#### 1. Pull Docker Image
```bash
# Pull from Docker Hub
docker pull raverse/mcp-server:latest

# Or build from source
git clone https://github.com/usemanusai/jaegis-RAVERSE.git
cd jaegis-RAVERSE/jaegis-RAVERSE-mcp-server
docker build -t raverse/mcp-server:latest .
```

#### 2. Create Environment File
```bash
# Create .env file
cat > .env << EOF
DATABASE_URL=postgresql://user:password@postgres:5432/raverse
REDIS_URL=redis://redis:6379
OPENROUTER_API_KEY=sk-or-v1-your-api-key
LOG_LEVEL=INFO
EOF
```

#### 3. Run Container
```bash
# Run with environment file
docker run -d \
  --name raverse-mcp \
  --env-file .env \
  -p 8000:8000 \
  raverse/mcp-server:latest

# Or run with individual environment variables
docker run -d \
  --name raverse-mcp \
  -e DATABASE_URL="postgresql://user:pass@postgres:5432/raverse" \
  -e REDIS_URL="redis://redis:6379" \
  -e OPENROUTER_API_KEY="sk-or-v1-..." \
  -p 8000:8000 \
  raverse/mcp-server:latest
```

#### 4. Verify Container
```bash
# Check container status
docker ps | grep raverse-mcp

# View logs
docker logs raverse-mcp

# Execute command in container
docker exec raverse-mcp raverse-mcp-server --version
```

### Docker Compose

Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  postgres:
    image: pgvector/pgvector:pg17-latest
    environment:
      POSTGRES_DB: raverse
      POSTGRES_USER: raverse
      POSTGRES_PASSWORD: raverse_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:8.2-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  raverse-mcp:
    build: .
    environment:
      DATABASE_URL: postgresql://raverse:raverse_password@postgres:5432/raverse
      REDIS_URL: redis://redis:6379
      OPENROUTER_API_KEY: ${OPENROUTER_API_KEY}
      LOG_LEVEL: INFO
    ports:
      - "8000:8000"
    depends_on:
      - postgres
      - redis

volumes:
  postgres_data:
  redis_data:
```

Run with Docker Compose:
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f raverse-mcp

# Stop services
docker-compose down
```

---

## From Source

### Prerequisites
- Git
- Python 3.13 or higher
- Node.js 18.0.0 or higher (optional)
- PostgreSQL 17
- Redis 8.2

### Installation Steps

#### 1. Clone Repository
```bash
git clone https://github.com/usemanusai/jaegis-RAVERSE.git
cd jaegis-RAVERSE/jaegis-RAVERSE-mcp-server
```

#### 2. Create Virtual Environment
```bash
python3.13 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

#### 3. Install Dependencies
```bash
# Install Python dependencies
pip install -e .

# Or with development dependencies
pip install -e ".[dev]"
```

#### 4. Configure Environment
```bash
cp .env.example .env
# Edit .env with your configuration
```

#### 5. Run the Server
```bash
# Start the server
raverse-mcp-server

# Or run directly
python -m jaegis_raverse_mcp_server.server
```

#### 6. Development Setup
```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with debug logging
LOG_LEVEL=DEBUG raverse-mcp-server
```

---

## Verification

### Verify Installation

```bash
# Check version
raverse-mcp-server --version

# Show help
raverse-mcp-server --help

# List available tools
raverse-mcp-server --list-tools

# Test database connection
raverse-mcp-server --test-db

# Test Redis connection
raverse-mcp-server --test-redis
```

### Test Server

```bash
# Start server in one terminal
raverse-mcp-server

# In another terminal, test a tool
curl -X POST http://localhost:8000/tools/disassemble_binary \
  -H "Content-Type: application/json" \
  -d '{"binary_path": "/bin/ls"}'
```

### Verify All 35 Tools

```bash
# List all tools
raverse-mcp-server --list-tools

# Should output:
# Binary Analysis (4 tools)
# - disassemble_binary
# - generate_code_embedding
# - apply_patch
# - verify_patch
# ... (and 31 more tools)
```

---

## Troubleshooting

### Python Not Found
```bash
# Check Python installation
python3 --version

# Or use python3.13 explicitly
python3.13 --version

# Add to PATH if needed
export PATH="/usr/local/opt/python@3.13/bin:$PATH"
```

### npm Not Found
```bash
# Check npm installation
npm --version

# Install Node.js from https://nodejs.org/
```

### Database Connection Failed
```bash
# Check PostgreSQL is running
psql --version

# Test connection
psql postgresql://user:password@localhost:5432/raverse

# Or use connection string
psql $DATABASE_URL
```

### Redis Connection Failed
```bash
# Check Redis is running
redis-cli --version

# Test connection
redis-cli -u redis://localhost:6379 ping

# Should return: PONG
```

### Permission Denied
```bash
# Make script executable
chmod +x bin/raverse-mcp-server.js

# Or run with python directly
python -m jaegis_raverse_mcp_server.server
```

### Module Not Found
```bash
# Reinstall dependencies
pip install --force-reinstall jaegis-raverse-mcp-server

# Or from source
pip install -e . --force-reinstall
```

### Port Already in Use
```bash
# Find process using port 8000
lsof -i :8000

# Kill process
kill -9 <PID>

# Or use different port
SERVER_PORT=8001 raverse-mcp-server
```

---

## Next Steps

1. **Configure MCP Client**: See [MCP_CLIENT_SETUP.md](MCP_CLIENT_SETUP.md)
2. **Quick Start**: See [QUICKSTART.md](QUICKSTART.md)
3. **Integration**: See [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)
4. **Deployment**: See [DEPLOYMENT.md](DEPLOYMENT.md)
5. **Tools Reference**: See [TOOLS_REGISTRY_COMPLETE.md](TOOLS_REGISTRY_COMPLETE.md)

---

**Last Updated**: October 27, 2025
**Version**: 1.0.0

