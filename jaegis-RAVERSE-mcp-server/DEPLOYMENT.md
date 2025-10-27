# RAVERSE MCP Server - Deployment Guide

Complete guide for deploying the RAVERSE MCP Server in various environments.

## Prerequisites

- Python 3.13+
- PostgreSQL 17 with pgvector
- Redis 8.2
- Docker & Docker Compose (for containerized deployment)
- OpenRouter API key (for LLM features)

## Local Development

### 1. Setup

```bash
# Clone and navigate
cd jaegis-RAVERSE-mcp-server

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Configure environment
cp .env.example .env
# Edit .env with your settings
```

### 2. Start Services

```bash
# In separate terminals:

# Terminal 1: PostgreSQL
docker run -d \
  -e POSTGRES_USER=raverse \
  -e POSTGRES_PASSWORD=raverse_secure_password_2025 \
  -e POSTGRES_DB=raverse \
  -p 5432:5432 \
  pgvector/pgvector:pg17

# Terminal 2: Redis
docker run -d \
  -p 6379:6379 \
  redis:8.2

# Terminal 3: MCP Server
raverse-mcp-server
```

### 3. Test

```bash
pytest tests/ -v
```

## Docker Deployment

### Single Container

```bash
# Build image
docker build -t raverse-mcp-server:1.0.0 .

# Run container
docker run -d \
  --name raverse-mcp \
  -e DATABASE_URL=postgresql://raverse:password@postgres:5432/raverse \
  -e REDIS_URL=redis://redis:6379/0 \
  -e LLM_API_KEY=your_key \
  -p 8001:8001 \
  raverse-mcp-server:1.0.0
```

### Docker Compose

Add to main `docker-compose.yml`:

```yaml
raverse-mcp-server:
  build:
    context: ./jaegis-RAVERSE-mcp-server
    dockerfile: Dockerfile
  container_name: raverse-mcp-server
  environment:
    DATABASE_URL: postgresql://raverse:raverse_secure_password_2025@postgres:5432/raverse
    REDIS_URL: redis://redis:6379/0
    LLM_API_KEY: ${OPENROUTER_API_KEY}
    LOG_LEVEL: INFO
  ports:
    - "8001:8001"
  depends_on:
    postgres:
      condition: service_healthy
    redis:
      condition: service_healthy
  networks:
    - raverse-network
  restart: unless-stopped
  healthcheck:
    test: ["CMD", "python", "-c", "import sys; sys.exit(0)"]
    interval: 30s
    timeout: 10s
    retries: 3
```

Start with:

```bash
docker-compose up -d raverse-mcp-server
```

## Kubernetes Deployment

### Deployment Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: raverse-mcp-server
  labels:
    app: raverse-mcp-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: raverse-mcp-server
  template:
    metadata:
      labels:
        app: raverse-mcp-server
    spec:
      containers:
      - name: raverse-mcp-server
        image: raverse-mcp-server:1.0.0
        ports:
        - containerPort: 8001
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: raverse-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: raverse-secrets
              key: redis-url
        - name: LLM_API_KEY
          valueFrom:
            secretKeyRef:
              name: raverse-secrets
              key: llm-api-key
        - name: LOG_LEVEL
          value: "INFO"
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          exec:
            command:
            - python
            - -c
            - import sys; sys.exit(0)
          initialDelaySeconds: 40
          periodSeconds: 30
        readinessProbe:
          exec:
            command:
            - python
            - -c
            - import sys; sys.exit(0)
          initialDelaySeconds: 10
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: raverse-mcp-server
spec:
  selector:
    app: raverse-mcp-server
  ports:
  - protocol: TCP
    port: 8001
    targetPort: 8001
  type: ClusterIP
```

Deploy with:

```bash
kubectl apply -f deployment.yaml
```

## Production Checklist

### Configuration
- [ ] Environment variables set correctly
- [ ] Database credentials secured
- [ ] LLM API key configured
- [ ] Log level appropriate for production
- [ ] Feature flags configured

### Database
- [ ] PostgreSQL running and accessible
- [ ] pgvector extension installed
- [ ] Database backups enabled
- [ ] Connection pooling configured
- [ ] Indexes created

### Cache
- [ ] Redis running and accessible
- [ ] Persistence enabled (RDB/AOF)
- [ ] Memory limits set
- [ ] Eviction policy configured

### Monitoring
- [ ] Prometheus scraping configured
- [ ] Grafana dashboards created
- [ ] Alerts configured
- [ ] Log aggregation enabled

### Security
- [ ] Firewall rules configured
- [ ] TLS/SSL enabled
- [ ] Authentication configured
- [ ] Rate limiting enabled
- [ ] Input validation verified

### Performance
- [ ] Connection pool size optimized
- [ ] Cache TTL configured
- [ ] Concurrent task limit set
- [ ] Request timeout configured

## Scaling

### Horizontal Scaling

```bash
# Run multiple instances
docker-compose up -d --scale raverse-mcp-server=3

# Or with Kubernetes
kubectl scale deployment raverse-mcp-server --replicas=5
```

### Load Balancing

Use nginx or HAProxy:

```nginx
upstream raverse_mcp {
    server localhost:8001;
    server localhost:8002;
    server localhost:8003;
}

server {
    listen 80;
    location / {
        proxy_pass http://raverse_mcp;
    }
}
```

## Monitoring

### Health Check

```bash
curl http://localhost:8001/health
```

### Metrics

```bash
curl http://localhost:8001/metrics
```

### Logs

```bash
# View logs
docker logs raverse-mcp-server

# Follow logs
docker logs -f raverse-mcp-server

# With timestamps
docker logs -f --timestamps raverse-mcp-server
```

## Troubleshooting

### Connection Issues

```bash
# Test database
psql -h localhost -U raverse -d raverse -c "SELECT 1"

# Test Redis
redis-cli ping

# Test LLM API
curl -H "Authorization: Bearer $LLM_API_KEY" https://api.openrouter.ai/api/v1/models
```

### Performance Issues

```bash
# Check resource usage
docker stats raverse-mcp-server

# Check database connections
psql -c "SELECT count(*) FROM pg_stat_activity"

# Check Redis memory
redis-cli info memory
```

### Error Logs

```bash
# View error logs
docker logs raverse-mcp-server | grep ERROR

# Increase log level
docker exec raverse-mcp-server \
  env LOG_LEVEL=DEBUG python -m jaegis_raverse_mcp_server.server
```

## Backup & Recovery

### Database Backup

```bash
pg_dump -h localhost -U raverse raverse > backup.sql
```

### Database Restore

```bash
psql -h localhost -U raverse raverse < backup.sql
```

### Redis Backup

```bash
redis-cli BGSAVE
cp /var/lib/redis/dump.rdb backup.rdb
```

## Rollback

```bash
# Revert to previous version
docker pull raverse-mcp-server:0.9.0
docker-compose up -d raverse-mcp-server
```

## Support

For deployment issues:
1. Check logs for error messages
2. Verify all prerequisites are met
3. Consult INTEGRATION_GUIDE.md
4. Review configuration in .env

