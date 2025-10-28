# RAVERSE MCP Server - Database Setup Guide

## Overview

The RAVERSE MCP Server requires PostgreSQL and Redis to be running. This guide will help you set them up on Windows.

---

## Option 1: Docker (Recommended - Easiest)

### Prerequisites
- Docker Desktop installed (https://www.docker.com/products/docker-desktop)

### Steps

1. **Start PostgreSQL and Redis with Docker Compose**:

```bash
cd C:\Users\Lenovo ThinkPad T480\Desktop\RAVERSE
docker-compose up -d
```

2. **Verify services are running**:

```bash
docker-compose ps
```

You should see:
```
NAME                COMMAND                  SERVICE             STATUS
raverse-postgres    "docker-entrypoint.s…"   postgres            Up 2 seconds
raverse-redis       "redis-server --appe…"   redis               Up 2 seconds
```

3. **Test the connection**:

```bash
docker exec raverse-postgres psql -U raverse -d raverse -c "SELECT 1;"
```

Expected output: `1`

4. **Run the RAVERSE MCP Server**:

```bash
cd jaegis-RAVERSE-mcp-server
python -m jaegis_raverse_mcp_server.server
```

---

## Option 2: Local Installation (Windows)

### PostgreSQL Setup

1. **Download PostgreSQL 17**:
   - Visit: https://www.postgresql.org/download/windows/
   - Download PostgreSQL 17 installer

2. **Install PostgreSQL**:
   - Run the installer
   - Set password for `postgres` user (remember this!)
   - Keep default port: 5432
   - Complete installation

3. **Create RAVERSE user and database**:

```bash
# Open Command Prompt or PowerShell
psql -U postgres

# In psql prompt, run:
CREATE USER raverse WITH PASSWORD 'raverse_secure_password_2025';
CREATE DATABASE raverse OWNER raverse;
GRANT ALL PRIVILEGES ON DATABASE raverse TO raverse;
\q
```

4. **Verify connection**:

```bash
psql -h localhost -U raverse -d raverse -c "SELECT 1;"
```

### Redis Setup

1. **Download Redis for Windows**:
   - Visit: https://github.com/microsoftarchive/redis/releases
   - Download `Redis-x64-X.X.X.msi`

2. **Install Redis**:
   - Run the installer
   - Keep default port: 6379
   - Complete installation

3. **Start Redis**:

```bash
# Redis should start automatically, or:
redis-server
```

4. **Verify connection**:

```bash
redis-cli ping
```

Expected output: `PONG`

---

## Option 3: WSL (Windows Subsystem for Linux)

### Prerequisites
- WSL2 installed
- Ubuntu 22.04 or later

### Steps

1. **Install PostgreSQL in WSL**:

```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo service postgresql start
```

2. **Create RAVERSE user**:

```bash
sudo -u postgres psql

# In psql:
CREATE USER raverse WITH PASSWORD 'raverse_secure_password_2025';
CREATE DATABASE raverse OWNER raverse;
GRANT ALL PRIVILEGES ON DATABASE raverse TO raverse;
\q
```

3. **Install Redis in WSL**:

```bash
sudo apt install redis-server
sudo service redis-server start
```

4. **Update .env file**:

```env
DATABASE_URL=postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse
REDIS_URL=redis://localhost:6379/0
```

5. **Run RAVERSE MCP Server**:

```bash
cd jaegis-RAVERSE-mcp-server
python -m jaegis_raverse_mcp_server.server
```

---

## Troubleshooting

### PostgreSQL Connection Failed

**Error**: `FATAL: password authentication failed for user "raverse"`

**Solution**:
1. Verify PostgreSQL is running
2. Check credentials in `.env` file
3. Verify user exists: `psql -U postgres -c "\du"`
4. Reset password: `ALTER USER raverse WITH PASSWORD 'raverse_secure_password_2025';`

### Redis Connection Failed

**Error**: `Error: connect ECONNREFUSED 127.0.0.1:6379`

**Solution**:
1. Verify Redis is running: `redis-cli ping`
2. Check port 6379 is not in use: `netstat -ano | findstr :6379`
3. Restart Redis service

### Port Already in Use

**Error**: `Address already in use`

**Solution**:
1. Find process using port: `netstat -ano | findstr :5432` (or :6379)
2. Kill process: `taskkill /PID <PID> /F`
3. Or change port in `.env` file

---

## Verification Checklist

- [ ] PostgreSQL running on localhost:5432
- [ ] Redis running on localhost:6379
- [ ] RAVERSE user created in PostgreSQL
- [ ] RAVERSE database created
- [ ] `.env` file configured with correct credentials
- [ ] `psql -U raverse -d raverse -c "SELECT 1;"` returns 1
- [ ] `redis-cli ping` returns PONG
- [ ] Server starts without database errors

---

## Next Steps

Once PostgreSQL and Redis are running:

1. **Run the server**:
```bash
cd jaegis-RAVERSE-mcp-server
python -m jaegis_raverse_mcp_server.server
```

2. **Expected output**:
```
{"event": "Starting RAVERSE MCP Server v1.0.5", ...}
{"event": "Initializing RAVERSE MCP Server", ...}
{"event": "RAVERSE MCP Server initialized successfully", ...}
```

3. **Server is ready** for MCP client connections!

---

## Support

- **Docker Issues**: https://docs.docker.com/desktop/
- **PostgreSQL Issues**: https://www.postgresql.org/docs/
- **Redis Issues**: https://redis.io/docs/
- **RAVERSE Issues**: https://github.com/usemanusai/jaegis-RAVERSE/issues

---

**Happy coding!** 🚀

