# RAVERSE Docker Deployment Guide

**Date:** October 25, 2025  
**Purpose:** Complete guide for deploying RAVERSE using Docker, PostgreSQL, and Redis

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Architecture](#architecture)
5. [Configuration](#configuration)
6. [Services](#services)
7. [Development Tools](#development-tools)
8. [Production Deployment](#production-deployment)
9. [Troubleshooting](#troubleshooting)
10. [Performance Tuning](#performance-tuning)

---

## Overview

RAVERSE now supports containerized deployment using Docker Compose with:
- **PostgreSQL 17** with pgvector extension for vector search
- **Redis 8.2** with RDB + AOF persistence for caching
- **RAVERSE Application** with full database integration
- **Optional Development Tools** (pgAdmin, RedisInsight)

### Benefits

- **Isolated Environment:** All dependencies containerized
- **Easy Setup:** One-command deployment
- **Production-Ready:** Optimized for performance and reliability
- **Scalable:** Resource limits and connection pooling
- **Persistent Data:** Volumes for database and cache
- **CPU-Optimized:** No GPU required, runs on 16-32GB RAM systems

---

## Prerequisites

### Required Software

1. **Docker Engine 28.5.1+**
   - Download: https://docs.docker.com/get-docker/
   - Verify: `docker --version`

2. **Docker Compose v2.40.2+**
   - Included with Docker Desktop
   - Verify: `docker-compose --version` or `docker compose version`

### System Requirements

- **CPU:** 4+ cores recommended
- **RAM:** 16GB minimum, 32GB recommended
- **Disk:** 20GB free space for images and volumes
- **OS:** Windows 10/11, macOS, Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+)

---

## Quick Start

### Windows (PowerShell)

```powershell
# 1. Clone repository
git clone https://github.com/your-org/raverse.git
cd raverse

# 2. Create .env file
Copy-Item .env.example .env

# 3. Edit .env and set OPENROUTER_API_KEY
notepad .env

# 4. Run quick start script
.\examples\docker_quickstart.ps1
```

### Linux/macOS (Bash)

```bash
# 1. Clone repository
git clone https://github.com/your-org/raverse.git
cd raverse

# 2. Create .env file
cp .env.example .env

# 3. Edit .env and set OPENROUTER_API_KEY
nano .env

# 4. Run quick start script
chmod +x examples/docker_quickstart.sh
./examples/docker_quickstart.sh
```

### Manual Start

```bash
# Build and start all services
docker-compose up -d --build

# Check service status
docker-compose ps

# View logs
docker-compose logs -f raverse-app
```

---

## Architecture

### Service Stack

```
┌─────────────────────────────────────────┐
│         RAVERSE Application             │
│  (Python 3.13, AI Agents, Analysis)     │
└─────────────┬───────────────────────────┘
              │
    ┌─────────┴─────────┐
    │                   │
┌───▼────────┐    ┌────▼──────┐
│ PostgreSQL │    │   Redis   │
│  (pgvector)│    │   (8.2)   │
│   Port:    │    │   Port:   │
│   5432     │    │   6379    │
└────────────┘    └───────────┘
```

### Network Configuration

- **Network:** `raverse-network` (bridge, 172.28.0.0/16)
- **Service Discovery:** Automatic DNS resolution between containers
- **Port Mapping:** Host ports mapped to container ports

### Volume Persistence

- `postgres_data`: PostgreSQL database files
- `redis_data`: Redis RDB and AOF files
- `pgadmin_data`: pgAdmin configuration (dev only)
- `redisinsight_data`: RedisInsight configuration (dev only)

---

## Configuration

### Environment Variables

Edit `.env` file with your configuration:

```bash
# Required
OPENROUTER_API_KEY=sk-or-v1-your-api-key-here

# Optional (defaults provided)
OPENROUTER_MODEL=meta-llama/llama-3.2-3b-instruct:free
POSTGRES_PASSWORD=raverse_secure_password_2025
REDIS_PASSWORD=raverse_redis_password_2025
LOG_LEVEL=INFO
```

### Resource Limits

Default limits in `docker-compose.yml`:

**PostgreSQL:**
- Memory: 2GB reserved, 4GB limit
- CPU: 1.0 reserved, 2.0 limit

**Redis:**
- Memory: 512MB reserved, 2GB limit
- CPU: 0.5 reserved, 1.0 limit

**RAVERSE App:**
- Memory: 2GB reserved, 8GB limit
- CPU: 2.0 reserved, 4.0 limit

---

## Services

### PostgreSQL (raverse-postgres)

**Image:** `pgvector/pgvector:pg17`  
**Port:** 5432  
**Database:** raverse  
**User:** raverse

**Features:**
- pgvector extension for vector similarity search
- Optimized for AI workloads
- Automatic schema initialization
- HNSW indexes for fast vector search

**Connection String:**
```
postgresql://raverse:raverse_secure_password_2025@localhost:5432/raverse
```

### Redis (raverse-redis)

**Image:** `redis:8.2`  
**Port:** 6379  
**Password:** raverse_redis_password_2025

**Features:**
- RDB + AOF persistence (dual persistence)
- 2GB max memory with LRU eviction
- fsync every second (balanced durability/performance)
- Multi-threaded I/O for CPU optimization

**Connection:**
```bash
redis-cli -h localhost -p 6379 -a raverse_redis_password_2025
```

### RAVERSE Application (raverse-app)

**Build:** Custom Dockerfile (multi-stage)  
**Base Image:** python:3.13-slim  
**User:** raverse (non-root for security)

**Features:**
- Automatic database connection
- LLM response caching
- Session management
- Binary analysis with vector search

---

## Development Tools

### pgAdmin (Optional)

**Port:** 5050  
**URL:** http://localhost:5050  
**Email:** admin@raverse.local  
**Password:** admin_password_2025

**Start:**
```bash
docker-compose --profile dev up -d pgadmin
```

**Add Server:**
1. Open http://localhost:5050
2. Right-click "Servers" → "Register" → "Server"
3. Name: RAVERSE
4. Host: postgres
5. Port: 5432
6. Username: raverse
7. Password: raverse_secure_password_2025

### RedisInsight (Optional)

**Port:** 5540  
**URL:** http://localhost:5540

**Start:**
```bash
docker-compose --profile dev up -d redisinsight
```

**Add Database:**
1. Open http://localhost:5540
2. Click "Add Redis Database"
3. Host: redis
4. Port: 6379
5. Password: raverse_redis_password_2025

---

## Production Deployment

### Security Hardening

1. **Change Default Passwords:**
```bash
# Generate strong passwords
openssl rand -base64 32

# Update .env file
POSTGRES_PASSWORD=<generated-password>
REDIS_PASSWORD=<generated-password>
```

2. **Use Secrets Management:**
```bash
# Docker Swarm secrets
echo "my-secret-password" | docker secret create postgres_password -
```

3. **Enable TLS/SSL:**
- Configure PostgreSQL SSL certificates
- Enable Redis TLS mode
- Use HTTPS for web interfaces

4. **Network Isolation:**
```yaml
# docker-compose.yml
networks:
  raverse-network:
    driver: bridge
    internal: true  # No external access
```

### Backup Strategy

**PostgreSQL Backup:**
```bash
# Automated daily backups
docker exec raverse-postgres pg_dump -U raverse raverse > backup_$(date +%Y%m%d).sql

# Restore
docker exec -i raverse-postgres psql -U raverse raverse < backup_20251025.sql
```

**Redis Backup:**
```bash
# RDB snapshot (automatic every 60s if 1000+ keys changed)
docker exec raverse-redis redis-cli -a raverse_redis_password_2025 BGSAVE

# Copy RDB file
docker cp raverse-redis:/data/dump.rdb ./backup/

# AOF backup (continuous)
docker cp raverse-redis:/data/appendonlydir ./backup/
```

### Monitoring

**Health Checks:**
```bash
# Check all services
docker-compose ps

# Check specific service
docker inspect raverse-postgres --format='{{.State.Health.Status}}'
```

**Logs:**
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f raverse-app

# Last 100 lines
docker-compose logs --tail=100 raverse-app
```

**Metrics:**
```bash
# Container stats
docker stats

# PostgreSQL stats
docker exec raverse-postgres psql -U raverse -c "SELECT * FROM pg_stat_database WHERE datname='raverse';"

# Redis stats
docker exec raverse-redis redis-cli -a raverse_redis_password_2025 INFO
```

---

## Troubleshooting

### Common Issues

**1. Services Not Starting**
```bash
# Check logs
docker-compose logs

# Restart services
docker-compose restart

# Rebuild from scratch
docker-compose down -v
docker-compose up -d --build
```

**2. Database Connection Errors**
```bash
# Check PostgreSQL is healthy
docker-compose ps postgres

# Test connection
docker exec raverse-postgres pg_isready -U raverse

# Check logs
docker-compose logs postgres
```

**3. Redis Connection Errors**
```bash
# Test connection
docker exec raverse-redis redis-cli -a raverse_redis_password_2025 PING

# Check logs
docker-compose logs redis
```

**4. Out of Memory**
```bash
# Check memory usage
docker stats

# Increase limits in docker-compose.yml
# Restart services
docker-compose up -d
```

---

## Performance Tuning

### PostgreSQL Optimization

**Increase Shared Buffers:**
```sql
-- In init script or manually
ALTER SYSTEM SET shared_buffers = '4GB';
ALTER SYSTEM SET effective_cache_size = '12GB';
ALTER SYSTEM SET maintenance_work_mem = '1GB';
```

**Vector Search Tuning:**
```sql
-- Adjust HNSW parameters for better performance
CREATE INDEX ON raverse.disassembly_cache 
USING hnsw (embedding vector_cosine_ops) 
WITH (m = 32, ef_construction = 128);

-- Set runtime parameter
SET hnsw.ef_search = 80;
```

### Redis Optimization

**Increase Max Memory:**
```yaml
# docker-compose.yml
command: >
  redis-server
  --maxmemory 4gb
  --maxmemory-policy allkeys-lru
```

**Enable More I/O Threads:**
```yaml
command: >
  redis-server
  --io-threads 8
  --io-threads-do-reads yes
```

### Application Optimization

**Increase Connection Pools:**
```bash
# .env
POSTGRES_MAX_CONN=20
REDIS_MAX_CONNECTIONS=100
```

**Adjust Cache TTL:**
```bash
# .env
CACHE_TTL_LLM=2592000  # 30 days
CACHE_TTL_ANALYSIS=604800  # 7 days
```

---

**Last Updated:** October 25, 2025  
**Version:** 2.0.0

