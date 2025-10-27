# RAVERSE 2.0 Deployment Checklist

**Date:** October 25, 2025  
**Version:** 2.0.0

Use this checklist to ensure successful deployment of RAVERSE in any environment.

---

## Pre-Deployment Checklist

### System Requirements
- [ ] Docker Engine 28.5.1+ installed
- [ ] Docker Compose v2.40.2+ installed
- [ ] 16GB+ RAM available
- [ ] 4+ CPU cores available
- [ ] 20GB+ free disk space
- [ ] Network access to OpenRouter API

### Configuration
- [ ] `.env` file created from `.env.example`
- [ ] `OPENROUTER_API_KEY` set in `.env`
- [ ] PostgreSQL password changed from default (production only)
- [ ] Redis password changed from default (production only)
- [ ] Log level configured appropriately
- [ ] Cache TTL values reviewed and adjusted

### Security (Production Only)
- [ ] Strong passwords generated for PostgreSQL and Redis
- [ ] Secrets management configured (Docker secrets or external vault)
- [ ] Network isolation configured
- [ ] TLS/SSL certificates obtained (if exposing services)
- [ ] Firewall rules configured
- [ ] Non-root user verified in containers

---

## Deployment Steps

### Docker Deployment

#### Step 1: Clone Repository
```bash
git clone https://github.com/your-org/raverse.git
cd raverse
```
- [ ] Repository cloned successfully
- [ ] Current directory is project root

#### Step 2: Configure Environment
```bash
cp .env.example .env
# Edit .env with your settings
```
- [ ] `.env` file created
- [ ] `OPENROUTER_API_KEY` set
- [ ] Passwords updated (production)
- [ ] Other settings reviewed

#### Step 3: Build and Start Services
```bash
# Windows PowerShell
.\examples\docker_quickstart.ps1

# Linux/macOS
chmod +x examples/docker_quickstart.sh
./examples/docker_quickstart.sh
```
- [ ] Script executed successfully
- [ ] All services started
- [ ] Health checks passing

#### Step 4: Verify Services
```bash
docker-compose ps
```
Expected output:
```
NAME                STATUS              PORTS
raverse-postgres    Up (healthy)        0.0.0.0:5432->5432/tcp
raverse-redis       Up (healthy)        0.0.0.0:6379->6379/tcp
raverse-app         Up                  
```
- [ ] PostgreSQL status: Up (healthy)
- [ ] Redis status: Up (healthy)
- [ ] RAVERSE app status: Up

#### Step 5: Test Database Connection
```bash
# PostgreSQL
docker exec raverse-postgres pg_isready -U raverse

# Redis
docker exec raverse-redis redis-cli -a raverse_redis_password_2025 PING
```
- [ ] PostgreSQL responds: "accepting connections"
- [ ] Redis responds: "PONG"

#### Step 6: Verify Database Schema
```bash
docker exec raverse-postgres psql -U raverse -d raverse -c "\dt raverse.*"
```
Expected tables:
- [ ] raverse.binaries
- [ ] raverse.disassembly_cache
- [ ] raverse.analysis_results
- [ ] raverse.patch_history
- [ ] raverse.llm_cache
- [ ] raverse.vector_search_index

#### Step 7: Test Application
```bash
# Copy a test binary to binaries directory
cp /path/to/test.exe binaries/

# Run analysis
docker-compose exec raverse-app python main.py /app/binaries/test.exe
```
- [ ] Application starts without errors
- [ ] Binary analysis completes
- [ ] Results displayed

---

### Standalone Python Deployment

#### Step 1: Create Virtual Environment
```bash
# Windows
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux/macOS
python3 -m venv .venv
source .venv/bin/activate
```
- [ ] Virtual environment created
- [ ] Virtual environment activated

#### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```
- [ ] All dependencies installed successfully
- [ ] No error messages

#### Step 3: Configure Environment
```bash
cp .env.example .env
# Edit .env
```
- [ ] `.env` file created
- [ ] `OPENROUTER_API_KEY` set

#### Step 4: Test Application
```bash
python main.py test.exe --no-database
```
- [ ] Application runs in standalone mode
- [ ] Analysis completes successfully

---

## Post-Deployment Verification

### Functional Tests

#### Test 1: Configuration Display
```bash
python main.py --config
```
- [ ] Configuration displays correctly
- [ ] All settings show expected values

#### Test 2: Database Connectivity
```bash
# Run with database mode
python main.py test.exe
```
- [ ] Connects to PostgreSQL successfully
- [ ] Connects to Redis successfully
- [ ] Analysis completes
- [ ] Results cached

#### Test 3: Cache Verification
```bash
# Run same binary again
python main.py test.exe
```
- [ ] Cache hit detected in logs
- [ ] Analysis completes faster (<1 second)

#### Test 4: Standalone Mode
```bash
python main.py test.exe --no-database
```
- [ ] Runs without database connection
- [ ] Uses in-memory cache
- [ ] Analysis completes successfully

### Performance Tests

#### Test 5: Response Time
- [ ] First analysis: 5-15 seconds (acceptable)
- [ ] Cached analysis: <1 second (acceptable)
- [ ] LLM API call: 2-5 seconds (acceptable)

#### Test 6: Resource Usage
```bash
docker stats
```
- [ ] PostgreSQL memory: <4GB
- [ ] Redis memory: <2GB
- [ ] RAVERSE app memory: <8GB
- [ ] CPU usage: Reasonable during analysis

### Integration Tests

#### Test 7: Run Test Suite
```bash
# Windows
.\scripts\run_tests.ps1 -All -Coverage

# Linux/macOS
chmod +x scripts/run_tests.sh
./scripts/run_tests.sh --all --coverage
```
- [ ] All unit tests pass
- [ ] All integration tests pass (requires Docker)
- [ ] Coverage ≥70%

---

## Monitoring Setup

### Logs

#### Configure Log Rotation
```bash
# Add to docker-compose.yml for each service
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```
- [ ] Log rotation configured
- [ ] Log files not growing unbounded

#### Verify Logging
```bash
# View application logs
docker-compose logs -f raverse-app

# View PostgreSQL logs
docker-compose logs -f postgres

# View Redis logs
docker-compose logs -f redis
```
- [ ] Logs are being written
- [ ] Log format is correct
- [ ] No error messages

### Health Checks

#### Automated Health Monitoring
```bash
# Check all services
docker-compose ps

# Detailed health status
docker inspect raverse-postgres --format='{{.State.Health.Status}}'
docker inspect raverse-redis --format='{{.State.Health.Status}}'
```
- [ ] Health checks configured
- [ ] All services report "healthy"

---

## Backup Configuration

### PostgreSQL Backup

#### Manual Backup
```bash
docker exec raverse-postgres pg_dump -U raverse raverse > backup_$(date +%Y%m%d).sql
```
- [ ] Backup created successfully
- [ ] Backup file size reasonable

#### Automated Backup (Cron)
```bash
# Add to crontab
0 2 * * * docker exec raverse-postgres pg_dump -U raverse raverse > /backups/raverse_$(date +\%Y\%m\%d).sql
```
- [ ] Cron job configured
- [ ] Backup directory exists
- [ ] Permissions correct

### Redis Backup

#### Verify RDB Snapshots
```bash
docker exec raverse-redis redis-cli -a raverse_redis_password_2025 LASTSAVE
```
- [ ] RDB snapshots being created
- [ ] Snapshot frequency acceptable

#### Verify AOF Persistence
```bash
docker exec raverse-redis ls -lh /data/appendonlydir/
```
- [ ] AOF files exist
- [ ] AOF files being updated

---

## Security Hardening (Production)

### Network Security
- [ ] Firewall configured to block external access to PostgreSQL (5432)
- [ ] Firewall configured to block external access to Redis (6379)
- [ ] Only RAVERSE app can access databases
- [ ] TLS/SSL configured for external connections (if needed)

### Access Control
- [ ] PostgreSQL password changed from default
- [ ] Redis password changed from default
- [ ] pgAdmin disabled in production (or secured)
- [ ] RedisInsight disabled in production (or secured)

### Container Security
- [ ] Containers running as non-root user
- [ ] Resource limits configured
- [ ] Security scanning performed (docker scan)
- [ ] No unnecessary packages in images

---

## Troubleshooting

### Common Issues

#### Issue: Services won't start
```bash
# Check logs
docker-compose logs

# Restart services
docker-compose restart

# Rebuild from scratch
docker-compose down -v
docker-compose up -d --build
```
- [ ] Issue identified in logs
- [ ] Issue resolved

#### Issue: Database connection errors
```bash
# Check PostgreSQL
docker-compose ps postgres
docker-compose logs postgres

# Test connection
docker exec raverse-postgres pg_isready -U raverse
```
- [ ] PostgreSQL is running
- [ ] Connection successful

#### Issue: Redis connection errors
```bash
# Check Redis
docker-compose ps redis
docker-compose logs redis

# Test connection
docker exec raverse-redis redis-cli -a raverse_redis_password_2025 PING
```
- [ ] Redis is running
- [ ] Connection successful

---

## Production Readiness Checklist

### Before Going Live
- [ ] All tests passing
- [ ] Performance benchmarks acceptable
- [ ] Security hardening complete
- [ ] Backup strategy implemented
- [ ] Monitoring configured
- [ ] Log rotation configured
- [ ] Documentation reviewed
- [ ] Team trained on deployment
- [ ] Rollback plan documented
- [ ] Support contacts identified

### Go-Live
- [ ] Services deployed
- [ ] Health checks passing
- [ ] Monitoring active
- [ ] Backups running
- [ ] Team notified
- [ ] Documentation updated with production URLs

### Post-Go-Live
- [ ] Monitor logs for 24 hours
- [ ] Verify backups are working
- [ ] Test rollback procedure
- [ ] Document any issues encountered
- [ ] Update runbooks as needed

---

## Support Contacts

- **Technical Lead:** [Name/Email]
- **DevOps:** [Name/Email]
- **Security:** [Name/Email]
- **On-Call:** [Phone/Pager]

---

**Deployment Date:** _______________  
**Deployed By:** _______________  
**Environment:** [ ] Development [ ] Staging [ ] Production  
**Status:** [ ] Success [ ] Failed [ ] Partial

**Notes:**
_____________________________________________________________________________
_____________________________________________________________________________
_____________________________________________________________________________

