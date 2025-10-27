# Docker Publishing Guide

**Status**: Ready for Publishing
**Image**: raverse/mcp-server
**Version**: 1.0.0
**Registry**: Docker Hub

---

## Prerequisites

### 1. Docker Hub Account
- Account: usemanusai
- Email: use.manus.ai@gmail.com
- Status: ✅ Account exists

### 2. Docker CLI
- Version: Latest
- Status: ✅ Installed
- Command: `docker --version`

### 3. Dockerfile
- ✅ Dockerfile created
- ✅ Multi-stage build configured
- ✅ Health checks configured
- ✅ Environment variables documented

### 4. Image Configuration
- Base: python:3.13-slim
- Ports: 8000 (MCP server)
- Health check: Enabled
- Entrypoint: raverse-mcp-server

---

## Publishing Steps

### Step 1: Build Docker Image

```bash
cd jaegis-RAVERSE-mcp-server

# Build image with version tag
docker build -t raverse/mcp-server:1.0.0 .

# Tag as latest
docker tag raverse/mcp-server:1.0.0 raverse/mcp-server:latest

# Verify build
docker images | grep raverse/mcp-server
```

**Expected Output**:
```
REPOSITORY              TAG       IMAGE ID      CREATED      SIZE
raverse/mcp-server      1.0.0     [hash]        [time]       [size]
raverse/mcp-server      latest    [hash]        [time]       [size]
```

### Step 2: Test Docker Image

```bash
# Run container
docker run -d \
  --name raverse-test \
  -e DATABASE_URL="postgresql://user:pass@localhost:5432/raverse" \
  -e REDIS_URL="redis://localhost:6379" \
  -e OPENROUTER_API_KEY="sk-or-v1-..." \
  -p 8000:8000 \
  raverse/mcp-server:1.0.0

# Check logs
docker logs raverse-test

# Check health
docker ps | grep raverse-test

# Stop container
docker stop raverse-test
docker rm raverse-test
```

### Step 3: Login to Docker Hub

```bash
docker login

# When prompted:
# Username: usemanusai
# Password: [your-docker-password]
```

### Step 4: Verify Login

```bash
docker info | grep Username
# Expected: Username: usemanusai
```

### Step 5: Push to Docker Hub

```bash
# Push version tag
docker push raverse/mcp-server:1.0.0

# Push latest tag
docker push raverse/mcp-server:latest
```

**Expected Output**:
```
The push refers to repository [docker.io/raverse/mcp-server]
[hash]: Pushed
[hash]: Pushed
...
1.0.0: digest: sha256:[hash] size: [size]
latest: digest: sha256:[hash] size: [size]
```

---

## Post-Publishing Verification

### 1. Check Docker Hub Repository
- URL: https://hub.docker.com/r/raverse/mcp-server
- Verify tags 1.0.0 and latest are listed
- Verify description is correct
- Verify image details are shown

### 2. Test Image Pull

```bash
# Pull image
docker pull raverse/mcp-server:1.0.0

# Or latest
docker pull raverse/mcp-server:latest

# Verify
docker images | grep raverse/mcp-server
```

### 3. Test Image Run

```bash
# Run with environment variables
docker run -d \
  --name raverse-verify \
  -e DATABASE_URL="postgresql://user:pass@localhost:5432/raverse" \
  -e REDIS_URL="redis://localhost:6379" \
  -e OPENROUTER_API_KEY="sk-or-v1-..." \
  -p 8000:8000 \
  raverse/mcp-server:1.0.0

# Check status
docker ps | grep raverse-verify

# Check logs
docker logs raverse-verify

# Check health
docker inspect raverse-verify | grep -A 5 Health

# Stop and remove
docker stop raverse-verify
docker rm raverse-verify
```

### 4. Check Image Metadata

```bash
# Inspect image
docker inspect raverse/mcp-server:1.0.0

# Check image history
docker history raverse/mcp-server:1.0.0

# Check image size
docker images raverse/mcp-server
```

---

## Dockerfile Details

### Base Image
- python:3.13-slim
- Size: ~150MB
- Includes: Python 3.13, pip, basic utilities

### Build Stages
1. **Builder Stage**: Install dependencies
2. **Runtime Stage**: Copy artifacts, configure entrypoint

### Environment Variables
- DATABASE_URL: PostgreSQL connection string
- REDIS_URL: Redis connection string
- OPENROUTER_API_KEY: API key for LLM provider
- LOG_LEVEL: Logging level (default: INFO)

### Ports
- 8000: MCP server port

### Health Check
- Command: `raverse-mcp-server --health`
- Interval: 30 seconds
- Timeout: 10 seconds
- Retries: 3

### Entrypoint
- Command: `raverse-mcp-server`
- Args: Configurable

---

## Docker Compose Example

```yaml
version: '3.8'

services:
  raverse-mcp:
    image: raverse/mcp-server:1.0.0
    container_name: raverse-mcp-server
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://user:password@postgres:5432/raverse
      REDIS_URL: redis://redis:6379
      OPENROUTER_API_KEY: sk-or-v1-...
      LOG_LEVEL: INFO
    depends_on:
      - postgres
      - redis
    healthcheck:
      test: ["CMD", "raverse-mcp-server", "--health"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped

  postgres:
    image: postgres:17-alpine
    container_name: raverse-postgres
    environment:
      POSTGRES_DB: raverse
      POSTGRES_USER: raverse
      POSTGRES_PASSWORD: raverse
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:8.2-alpine
    container_name: raverse-redis
    restart: unless-stopped

volumes:
  postgres_data:
```

---

## Troubleshooting

### Issue: "Docker daemon not running"
**Solution**: Start Docker Desktop or Docker daemon

### Issue: "Unauthorized"
**Solution**: Run `docker login` and verify credentials

### Issue: "Image not found"
**Solution**: Verify image name and tag with `docker images`

### Issue: "Permission denied"
**Solution**: 
- Check Docker permissions
- Add user to docker group: `sudo usermod -aG docker $USER`

### Issue: "Health check failing"
**Solution**:
- Check environment variables
- Verify database and Redis connectivity
- Check logs: `docker logs [container-id]`

---

## Image Information

### Name
- Repository: raverse/mcp-server
- Namespace: raverse
- Image: mcp-server

### Tags
- 1.0.0 (version tag)
- latest (latest stable)

### Size
- Compressed: ~50-100MB
- Uncompressed: ~200-300MB

### Base Image
- python:3.13-slim

### Exposed Ports
- 8000 (MCP server)

### Environment Variables
- DATABASE_URL (required)
- REDIS_URL (required)
- OPENROUTER_API_KEY (required)
- LOG_LEVEL (optional, default: INFO)

### Health Check
- Enabled
- Command: raverse-mcp-server --health
- Interval: 30s
- Timeout: 10s
- Retries: 3

---

## Success Criteria

✅ Image built successfully
✅ Image pushed to Docker Hub
✅ Tags 1.0.0 and latest visible
✅ Image metadata correct
✅ Image pulls successfully
✅ Container runs successfully
✅ Health check passes
✅ All 35 tools accessible

---

**Status**: Ready for Publishing
**Next Step**: Execute publishing commands

