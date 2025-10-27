# RAVERSE Online - Deployment Guide

## Overview

RAVERSE Online is a multi-agent system for analyzing remote/online targets. This guide covers deployment using Docker Compose and Kubernetes.

## Prerequisites

- Docker 28.5.1+
- Docker Compose v2.40.2+
- Python 3.13+
- OpenRouter API key (for LLM integration)
- PostgreSQL 17 (or use Docker)
- Redis 8.2 (or use Docker)

## Quick Start with Docker Compose

### 1. Environment Setup

Create `.env` file:

```bash
OPENROUTER_API_KEY=your_api_key_here
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free
POSTGRES_PASSWORD=secure_password_here
GRAFANA_PASSWORD=grafana_password_here
```

### 2. Start Services

```bash
docker-compose -f docker-compose-online.yml up -d
```

### 3. Verify Services

```bash
# Check all services are running
docker-compose -f docker-compose-online.yml ps

# Check logs
docker-compose -f docker-compose-online.yml logs -f orchestrator
```

### 4. Access Dashboards

- **Grafana:** http://localhost:3000 (admin/admin)
- **Prometheus:** http://localhost:9090
- **Jaeger:** http://localhost:16686

## Running Analysis

### 1. Create Scope Configuration

Create `scope.json`:

```json
{
  "allowed_domains": ["example.com"],
  "allowed_paths": ["/api/", "/app/"],
  "authorization_type": "Authorized Penetration Test",
  "contact_info": {
    "name": "Security Team",
    "email": "security@example.com"
  }
}
```

### 2. Create Options Configuration

Create `options.json`:

```json
{
  "recon": {"enabled": true},
  "traffic": {"enabled": true, "duration_seconds": 60},
  "js_analysis": {"enabled": true},
  "security": {"enabled": true},
  "reporting": {"format": "markdown"}
}
```

### 3. Run Analysis

```bash
python raverse_online_cli.py https://example.com \
  --scope scope.json \
  --options options.json \
  --report markdown \
  --output ./results
```

## Kubernetes Deployment

### 1. Create Namespace

```bash
kubectl create namespace raverse-online
```

### 2. Create Secrets

```bash
kubectl create secret generic raverse-secrets \
  --from-literal=openrouter-api-key=YOUR_API_KEY \
  --from-literal=postgres-password=secure_password \
  -n raverse-online
```

### 3. Deploy Services

```bash
# PostgreSQL
kubectl apply -f k8s/postgres-deployment.yaml -n raverse-online

# Redis
kubectl apply -f k8s/redis-deployment.yaml -n raverse-online

# Prometheus
kubectl apply -f k8s/prometheus-deployment.yaml -n raverse-online

# Grafana
kubectl apply -f k8s/grafana-deployment.yaml -n raverse-online

# Orchestrator
kubectl apply -f k8s/orchestrator-deployment.yaml -n raverse-online

# Agents
kubectl apply -f k8s/agents-deployment.yaml -n raverse-online
```

### 4. Verify Deployment

```bash
kubectl get pods -n raverse-online
kubectl get svc -n raverse-online
```

### 5. Port Forwarding

```bash
# Grafana
kubectl port-forward -n raverse-online svc/grafana 3000:3000

# Prometheus
kubectl port-forward -n raverse-online svc/prometheus 9090:9090

# Jaeger
kubectl port-forward -n raverse-online svc/jaeger 16686:16686
```

## Configuration

### Agent Configuration

Each agent can be configured via environment variables:

```bash
# Reconnaissance Agent
RECON_TIMEOUT=30
RECON_VERIFY_SSL=false

# Traffic Interception Agent
TRAFFIC_DURATION=60
TRAFFIC_CAPTURE_HEADERS=true

# Security Analysis Agent
SECURITY_CHECK_HEADERS=true
SECURITY_CHECK_SSL=true
```

### Database Configuration

PostgreSQL connection string:

```
postgresql://raverse:password@postgres:5432/raverse_online
```

### Redis Configuration

Redis connection string:

```
redis://redis:6379
```

## Monitoring

### Prometheus Metrics

Available metrics:

- `raverse_agent_execution_time_seconds`
- `raverse_vulnerabilities_found`
- `raverse_endpoints_discovered`
- `raverse_api_calls_captured`

### Grafana Dashboards

Pre-built dashboards:

1. **Agent Performance** - Execution times and success rates
2. **Vulnerability Summary** - Findings by severity
3. **API Analysis** - Endpoint and call statistics
4. **System Health** - Resource usage and uptime

### Jaeger Tracing

Trace agent execution:

1. Open http://localhost:16686
2. Select service: `raverse-orchestrator`
3. View traces for each analysis run

## Troubleshooting

### Agent Not Starting

```bash
# Check logs
docker-compose -f docker-compose-online.yml logs agent-name

# Restart agent
docker-compose -f docker-compose-online.yml restart agent-name
```

### Database Connection Issues

```bash
# Check PostgreSQL
docker-compose -f docker-compose-online.yml exec postgres psql -U raverse -d raverse_online

# Check Redis
docker-compose -f docker-compose-online.yml exec redis redis-cli ping
```

### API Key Issues

```bash
# Verify API key
echo $OPENROUTER_API_KEY

# Update .env and restart
docker-compose -f docker-compose-online.yml restart orchestrator
```

## Performance Tuning

### Parallel Execution

```json
{
  "performance": {
    "parallel_agents": true,
    "max_concurrent_tasks": 5
  }
}
```

### Resource Limits

```yaml
resources:
  limits:
    memory: "2Gi"
    cpu: "1000m"
  requests:
    memory: "1Gi"
    cpu: "500m"
```

### Caching

Redis caching is enabled by default. Configure TTL:

```bash
REDIS_CACHE_TTL=3600  # 1 hour
```

## Security Best Practices

1. **API Keys:** Store in secrets, never in code
2. **SSL/TLS:** Enable for all connections
3. **Network:** Use private networks for inter-service communication
4. **Logging:** Enable audit logging for all operations
5. **RBAC:** Implement role-based access control
6. **Secrets:** Rotate API keys regularly

## Backup and Recovery

### Database Backup

```bash
docker-compose -f docker-compose-online.yml exec postgres \
  pg_dump -U raverse raverse_online > backup.sql
```

### Database Restore

```bash
docker-compose -f docker-compose-online.yml exec -T postgres \
  psql -U raverse raverse_online < backup.sql
```

## Scaling

### Horizontal Scaling

Deploy multiple agent instances:

```bash
docker-compose -f docker-compose-online.yml up -d --scale recon-agent=3
```

### Load Balancing

Use Kubernetes Service for load balancing:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: orchestrator-lb
spec:
  type: LoadBalancer
  selector:
    app: orchestrator
  ports:
    - port: 8000
      targetPort: 8000
```

## Support

For issues or questions:

1. Check logs: `docker-compose logs -f`
2. Review documentation: See README-Online.md
3. Contact: security@raverse.io

## Legal Compliance

⚠️ **IMPORTANT:** Ensure all analysis is:
- Authorized in writing
- Within defined scope
- Compliant with applicable laws (CFAA, GDPR, CCPA, etc.)
- Conducted by authorized personnel only

See README-Online.md for complete legal framework.

