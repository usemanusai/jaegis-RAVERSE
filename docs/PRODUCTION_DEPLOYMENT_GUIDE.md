# RAVERSE Online - Production Deployment Guide

**Version:** 1.0.0  
**Last Updated:** October 25, 2025  
**Status:** Production Ready

---

## 📋 Pre-Deployment Checklist

- [ ] All tests passing (>80% coverage)
- [ ] Security review completed
- [ ] Environment variables configured
- [ ] Database initialized
- [ ] SSL certificates ready
- [ ] Monitoring configured
- [ ] Backup strategy in place
- [ ] Incident response plan ready

---

## 🚀 Quick Start (Docker Compose)

### 1. Clone Repository
```bash
git clone https://github.com/your-org/raverse-online.git
cd raverse-online
```

### 2. Configure Environment
```bash
cp .env.example .env
# Edit .env with your settings
```

### 3. Start Services
```bash
docker-compose -f docker-compose-online.yml up -d
```

### 4. Verify Deployment
```bash
docker-compose -f docker-compose-online.yml ps
```

---

## 🔧 Configuration

### Environment Variables
```bash
# Database
POSTGRES_USER=raverse
POSTGRES_PASSWORD=secure_password_here
POSTGRES_DB=raverse_online

# Redis
REDIS_URL=redis://redis:6379

# AI/LLM
OPENROUTER_API_KEY=your_api_key_here
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free

# Monitoring
PROMETHEUS_RETENTION=15d
GRAFANA_PASSWORD=secure_password_here

# Jaeger
JAEGER_AGENT_HOST=jaeger
JAEGER_AGENT_PORT=6831
```

### Scope Configuration
Create `scope.json`:
```json
{
  "allowed_domains": ["example.com"],
  "allowed_paths": ["/api/*", "/admin/*"],
  "max_depth": 5,
  "authorization": "approved"
}
```

### Options Configuration
Create `options.json`:
```json
{
  "execution": {
    "mode": "full_pipeline",
    "parallel_execution": true,
    "max_workers": 4
  },
  "reporting": {
    "formats": ["json", "html", "pdf"]
  }
}
```

---

## 📊 Monitoring & Observability

### Grafana Dashboard
- **URL:** http://localhost:3000
- **Username:** admin
- **Password:** (from .env)

### Prometheus Metrics
- **URL:** http://localhost:9090
- **Metrics:** Agent performance, pipeline duration, error rates

### Jaeger Tracing
- **URL:** http://localhost:16686
- **Traces:** Full request tracing across all agents

---

## 🔐 Security Hardening

### 1. Network Security
```bash
# Use network policies
docker network create raverse-network --driver bridge
```

### 2. Database Security
```bash
# Enable SSL for PostgreSQL
# Update postgresql.conf:
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'
```

### 3. API Security
```bash
# Add rate limiting
# Add authentication
# Add CORS headers
```

### 4. Secrets Management
```bash
# Use Docker secrets or external vault
docker secret create db_password -
docker secret create api_key -
```

---

## 📈 Scaling

### Horizontal Scaling
```bash
# Scale individual agents
docker-compose -f docker-compose-online.yml up -d --scale recon-agent=3
```

### Kubernetes Deployment
```bash
# Deploy to Kubernetes
kubectl apply -f k8s/
kubectl scale deployment raverse-orchestrator --replicas=3
```

---

## 🧪 Testing

### Run Tests
```bash
pytest tests/ -v --cov=agents --cov-report=html
```

### Integration Tests
```bash
pytest tests/test_online_agents.py::TestIntegration -v
```

### End-to-End Tests
```bash
pytest tests/test_online_agents.py::TestEndToEnd -v
```

---

## 📝 Usage

### CLI Analysis
```bash
python raverse_online_cli.py https://example.com \
  --scope scope.json \
  --options options.json \
  --report pdf \
  --log-level INFO
```

### Docker Analysis
```bash
docker-compose -f docker-compose-online.yml exec orchestrator \
  python raverse_online_cli.py https://example.com \
  --scope /app/scope.json \
  --options /app/options.json
```

---

## 🔍 Troubleshooting

### Database Connection Issues
```bash
# Check PostgreSQL
docker-compose -f docker-compose-online.yml logs postgres

# Verify connection
psql -h localhost -U raverse -d raverse_online
```

### Redis Connection Issues
```bash
# Check Redis
docker-compose -f docker-compose-online.yml logs redis

# Verify connection
redis-cli -h localhost ping
```

### Agent Failures
```bash
# Check agent logs
docker-compose -f docker-compose-online.yml logs orchestrator

# Check specific agent
docker-compose -f docker-compose-online.yml logs recon-agent
```

---

## 📊 Performance Tuning

### Database Optimization
```sql
-- Create indexes
CREATE INDEX idx_agent_runs ON agent_runs(run_id);
CREATE INDEX idx_agent_state ON agent_state(agent_type);

-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM agent_runs;
```

### Redis Optimization
```bash
# Monitor Redis
redis-cli INFO stats

# Adjust memory policy
CONFIG SET maxmemory-policy allkeys-lru
```

### Agent Parallelization
```json
{
  "execution": {
    "parallel_execution": true,
    "max_workers": 8
  }
}
```

---

## 🔄 Backup & Recovery

### Database Backup
```bash
# Backup PostgreSQL
docker-compose -f docker-compose-online.yml exec postgres \
  pg_dump -U raverse raverse_online > backup.sql

# Restore
docker-compose -f docker-compose-online.yml exec postgres \
  psql -U raverse raverse_online < backup.sql
```

### Redis Backup
```bash
# Backup Redis
docker-compose -f docker-compose-online.yml exec redis \
  redis-cli BGSAVE

# Copy dump.rdb
docker cp raverse-redis:/data/dump.rdb ./redis_backup.rdb
```

---

## 📞 Support

- **Documentation:** See README-Online.md
- **Issues:** GitHub Issues
- **Security:** security@example.com
- **Support:** support@example.com

---

**Status: Production Ready** ✅

