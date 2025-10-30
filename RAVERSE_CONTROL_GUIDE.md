# 🎮 RAVERSE APPLICATION - CONTROL & CONFIGURATION GUIDE

## 📋 Table of Contents
1. [Deployment Control](#deployment-control)
2. [Runtime Configuration](#runtime-configuration)
3. [API Testing](#api-testing)
4. [Performance Tuning](#performance-tuning)
5. [Monitoring & Alerts](#monitoring--alerts)

---

## 🚀 Deployment Control

### Render Dashboard Controls

#### 1. Manual Deployment
```
Dashboard → Select Service → Manual Deploy → Deploy latest commit
```

**When to use:**
- After code changes
- To apply fixes
- To test new features

**Expected time:** 2-5 minutes

---

#### 2. Restart Service
```
Dashboard → Select Service → Restart Service
```

**When to use:**
- Service is unresponsive
- Need to clear memory
- After configuration changes

**Expected time:** 30-60 seconds

---

#### 3. View Logs
```
Dashboard → Select Service → Logs
```

**What to look for:**
- Startup messages
- Error messages
- Performance metrics
- Request logs

---

#### 4. Environment Variables
```
Dashboard → Select Service → Environment
```

**Key variables:**
```
OPENROUTER_API_KEY=your-key-here
OPENROUTER_MODEL=meta-llama/llama-3.2-3b-instruct:free
PORT=10000 (auto-set by Render)
```

---

#### 5. Build Settings
```
Dashboard → Select Service → Settings → Build Command
```

**Current command:**
```bash
cd src && pip install --upgrade pip && pip install -r requirements.txt
```

---

#### 6. Start Command
```
Dashboard → Select Service → Settings → Start Command
```

**Current command:**
```bash
cd src && gunicorn app:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT
```

---

## ⚙️ Runtime Configuration

### 1. Worker Configuration

**Current Setup:**
- Workers: 4
- Worker Class: uvicorn.workers.UvicornWorker
- Bind: 0.0.0.0:$PORT

**To change workers:**
```bash
# Edit Procfile or render.yaml
# Change --workers 4 to --workers 8 (for example)
# Redeploy
```

**Worker recommendations:**
- Small app: 2-4 workers
- Medium app: 4-8 workers
- Large app: 8-16 workers

---

### 2. Timeout Configuration

**Current Setup:**
- Gunicorn timeout: 30 seconds (default)
- Health check timeout: 30 seconds (Render)

**To change timeout:**
```bash
# Edit Procfile
gunicorn app:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --timeout 60
```

---

### 3. Logging Configuration

**Current Setup:**
- Level: INFO
- Output: stderr (STDIO safe)
- Format: timestamp - name - level - message

**To change log level:**
```python
# In src/app.py
logging.basicConfig(
    level=logging.DEBUG,  # Change to DEBUG, WARNING, ERROR
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

---

### 4. CORS Configuration

**Current Setup:**
- Allow origins: * (all)
- Allow credentials: True
- Allow methods: * (all)
- Allow headers: * (all)

**To restrict CORS:**
```python
# In src/app.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
```

---

## 🧪 API Testing

### 1. Test Health Endpoint
```bash
curl https://jaegis-raverse.onrender.com/health
```

**Expected response:**
```json
{
  "status": "healthy",
  "initialized": false,
  "service": "RAVERSE",
  "ready": true
}
```

---

### 2. Test Status Endpoint
```bash
curl https://jaegis-raverse.onrender.com/api/v1/status
```

**Expected response:**
```json
{
  "status": "operational",
  "version": "1.0.0",
  "initialized": false,
  "features": ["binary_analysis", "pattern_detection", "patch_generation", "validation"]
}
```

---

### 3. Test Info Endpoint
```bash
curl https://jaegis-raverse.onrender.com/api/v1/info
```

---

### 4. Test Analysis Endpoint
```bash
curl -X POST https://jaegis-raverse.onrender.com/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/path/to/binary",
    "model": "meta-llama/llama-3.2-3b-instruct:free",
    "use_database": false
  }'
```

---

### 5. Test Upload Endpoint
```bash
curl -X POST https://jaegis-raverse.onrender.com/api/v1/upload-and-analyze \
  -F "file=@/path/to/binary"
```

---

## 📈 Performance Tuning

### 1. Optimize Worker Count
```bash
# For CPU-bound tasks
workers = (2 * cpu_count) + 1

# For I/O-bound tasks
workers = (4 * cpu_count) + 1
```

---

### 2. Optimize Memory
```bash
# Monitor memory usage in Render dashboard
# If memory is high:
# 1. Reduce worker count
# 2. Upgrade Render plan
# 3. Implement caching
```

---

### 3. Optimize Response Time
```bash
# First request: 5-10 seconds (orchestrator init)
# Subsequent requests: <1 second (cached)

# To improve:
# 1. Pre-warm orchestrator on startup (not recommended)
# 2. Use caching for results
# 3. Implement request queuing
```

---

### 4. Enable Caching
```python
# In src/app.py
from functools import lru_cache

@lru_cache(maxsize=128)
def get_analysis_result(binary_hash):
    # Return cached result
    pass
```

---

## 📊 Monitoring & Alerts

### 1. Monitor Health
```bash
# Check every 5 minutes
watch -n 300 'curl https://jaegis-raverse.onrender.com/health'
```

---

### 2. Monitor Logs
```bash
# View last 100 lines
https://dashboard.render.com → Logs → Last 100 lines

# Search for errors
https://dashboard.render.com → Logs → Search "ERROR"
```

---

### 3. Monitor Performance
```
Dashboard → Metrics
- CPU usage
- Memory usage
- Request count
- Error rate
```

---

### 4. Set Up Alerts (Render Pro)
```
Dashboard → Alerts
- Service down
- High CPU
- High memory
- High error rate
```

---

### 5. Monitor Uptime
```
https://status.render.com
```

---

## 🔄 Deployment Workflow

### Step 1: Make Changes
```bash
# Edit code locally
git add .
git commit -m "your message"
git push origin main
```

### Step 2: Deploy
```
Dashboard → Manual Deploy → Deploy latest commit
```

### Step 3: Monitor
```
Dashboard → Logs → Watch for "Application is ready"
```

### Step 4: Test
```bash
curl https://jaegis-raverse.onrender.com/health
```

### Step 5: Verify
```bash
# Test all endpoints
# Monitor for errors
# Check performance
```

---

## 🆘 Emergency Controls

### 1. Rollback Deployment
```
Dashboard → Deployments → Select previous → Redeploy
```

---

### 2. Force Restart
```
Dashboard → Restart Service
```

---

### 3. Clear Build Cache
```
Dashboard → Settings → Clear Build Cache → Redeploy
```

---

### 4. Disable Service
```
Dashboard → Settings → Suspend Service
```

---

## ✅ Control Checklist

- [ ] Can access Render dashboard
- [ ] Can view logs
- [ ] Can trigger manual deployment
- [ ] Can restart service
- [ ] Can modify environment variables
- [ ] Can test health endpoint
- [ ] Can test API endpoints
- [ ] Can monitor performance
- [ ] Can handle errors
- [ ] Can rollback if needed

---

## 📞 Support

**Issues?**
1. Check logs: `Dashboard → Logs`
2. Test health: `curl /health`
3. Verify config: `Dashboard → Settings`
4. Check GitHub: `https://github.com/usemanusai/jaegis-RAVERSE`

**Status: ✅ FULLY CONTROLLABLE**

