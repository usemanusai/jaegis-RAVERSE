# 🚀 RAVERSE APPLICATION - COMPLETE USAGE GUIDE

## 📋 Table of Contents
1. [Quick Start](#quick-start)
2. [Deployment Options](#deployment-options)
3. [API Endpoints](#api-endpoints)
4. [Configuration](#configuration)
5. [Monitoring & Control](#monitoring--control)
6. [Troubleshooting](#troubleshooting)

---

## 🚀 Quick Start

### Option 1: Deploy to Render (Recommended)

#### Step 1: Trigger Deployment
```bash
# Go to Render Dashboard
https://dashboard.render.com

# Select "raverse-api" service
# Click "Manual Deploy" → "Deploy latest commit"
```

#### Step 2: Wait for Deployment
- Deployment takes 2-5 minutes
- Watch logs for "Application is ready to accept requests"

#### Step 3: Access Application
```
https://jaegis-raverse.onrender.com
```

#### Step 4: Test Health
```bash
curl https://jaegis-raverse.onrender.com/health
```

---

### Option 2: Run Locally

#### Step 1: Install Dependencies
```bash
cd src
pip install -r requirements.txt
```

#### Step 2: Set Environment Variables
```bash
# Required for API calls
export OPENROUTER_API_KEY="your-api-key-here"

# Optional
export OPENROUTER_MODEL="meta-llama/llama-3.2-3b-instruct:free"
export PORT=8000
```

#### Step 3: Start Application
```bash
# Option A: Using Gunicorn (Production)
gunicorn app:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000

# Option B: Using Uvicorn (Development)
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

#### Step 4: Access Application
```
http://localhost:8000
```

---

## 📊 Deployment Options

### 1. Render (Cloud - Recommended)
**Pros:**
- ✅ Automatic deployments
- ✅ Free tier available
- ✅ Built-in monitoring
- ✅ Easy scaling

**Cons:**
- ❌ Cold starts on free tier
- ❌ Limited resources

**Setup:**
- Already configured in `render.yaml` and `Procfile`
- Just trigger deployment from dashboard

---

### 2. Local Development
**Pros:**
- ✅ Full control
- ✅ Fast iteration
- ✅ Easy debugging

**Cons:**
- ❌ Not accessible from internet
- ❌ Requires manual management

**Setup:**
```bash
cd src
uvicorn app:app --reload
```

---

### 3. Docker (Optional)
**Pros:**
- ✅ Consistent environment
- ✅ Easy deployment anywhere

**Cons:**
- ❌ Requires Docker setup

**Setup:**
```bash
# Create Dockerfile (if needed)
docker build -t raverse .
docker run -p 8000:8000 raverse
```

---

## 🔌 API Endpoints

### 1. Health Check
```bash
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "initialized": false,
  "service": "RAVERSE",
  "ready": true
}
```

---

### 2. Root Endpoint
```bash
GET /
```

**Response:**
```json
{
  "status": "ok",
  "service": "RAVERSE API",
  "version": "1.0.0",
  "description": "AI Multi-Agent Binary Patching System"
}
```

---

### 3. API Status
```bash
GET /api/v1/status
```

**Response:**
```json
{
  "status": "operational",
  "version": "1.0.0",
  "initialized": false,
  "features": [
    "binary_analysis",
    "pattern_detection",
    "patch_generation",
    "validation"
  ]
}
```

---

### 4. API Info
```bash
GET /api/v1/info
```

**Response:**
```json
{
  "name": "RAVERSE API",
  "version": "1.0.0",
  "description": "AI Multi-Agent Binary Patching System",
  "endpoints": {
    "health": "/health",
    "status": "/api/v1/status",
    "analyze": "/api/v1/analyze",
    "upload": "/api/v1/upload-and-analyze",
    "info": "/api/v1/info"
  }
}
```

---

### 5. Analyze Binary
```bash
POST /api/v1/analyze
Content-Type: application/json

{
  "binary_path": "/path/to/binary",
  "model": "meta-llama/llama-3.2-3b-instruct:free",
  "use_database": false
}
```

**Response:**
```json
{
  "success": true,
  "message": "Analysis completed",
  "results": {
    "binary_path": "/path/to/binary",
    "analysis": {...}
  }
}
```

---

### 6. Upload and Analyze
```bash
POST /api/v1/upload-and-analyze
Content-Type: multipart/form-data

file: <binary-file>
```

**Response:**
```json
{
  "success": true,
  "message": "Analysis completed",
  "results": {...}
}
```

---

## ⚙️ Configuration

### Environment Variables

```bash
# Required
OPENROUTER_API_KEY=your-api-key-here

# Optional
OPENROUTER_MODEL=meta-llama/llama-3.2-3b-instruct:free
PORT=8000
LOG_LEVEL=INFO
```

### Render Configuration

**File:** `render.yaml`

```yaml
services:
  - type: web
    name: raverse-api
    runtime: python
    pythonVersion: 3.13
    
    buildCommand: |
      cd src && \
      pip install --upgrade pip && \
      pip install -r requirements.txt
    
    startCommand: cd src && gunicorn app:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT
    
    healthCheckPath: /health
```

### Procfile Configuration

**File:** `Procfile`

```
web: cd src && gunicorn app:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT
```

---

## 📊 Monitoring & Control

### 1. Check Application Status
```bash
curl https://jaegis-raverse.onrender.com/health
```

### 2. View Render Logs
```
https://dashboard.render.com → Select Service → Logs
```

### 3. Monitor Performance
- CPU usage
- Memory usage
- Request count
- Error rate

### 4. Manual Deployment
```
https://dashboard.render.com → Manual Deploy → Deploy latest commit
```

### 5. Restart Service
```
https://dashboard.render.com → Restart Service
```

---

## 🔧 Troubleshooting

### Issue: HTTP 502 Error
**Solution:**
1. Check health endpoint: `curl /health`
2. View deployment logs
3. Verify OPENROUTER_API_KEY is set
4. Trigger manual deployment

### Issue: Service Keeps Restarting
**Solution:**
1. Check logs for errors
2. Verify environment variables
3. Check disk space
4. Try clearing build cache

### Issue: Slow First Request
**Solution:**
- This is normal! First request initializes orchestrator (5-10 seconds)
- Subsequent requests are fast

### Issue: API Returns 500 Error
**Solution:**
1. Check logs for specific error
2. Verify binary path exists
3. Verify OPENROUTER_API_KEY is valid
4. Check request format

---

## 📈 Performance Tips

1. **Use Render's free tier** for testing
2. **Monitor logs** regularly
3. **Cache results** for repeated analyses
4. **Use lazy loading** (already implemented)
5. **Scale workers** if needed

---

## 🔗 Useful Links

- **Repository:** https://github.com/usemanusai/jaegis-RAVERSE
- **Render Dashboard:** https://dashboard.render.com
- **API Documentation:** https://jaegis-raverse.onrender.com/docs
- **OpenRouter API:** https://openrouter.ai

---

## ✅ Summary

**To start using RAVERSE:**

1. **Deploy to Render** (recommended)
   - Go to dashboard
   - Click "Manual Deploy"
   - Wait 2-5 minutes

2. **Test the API**
   - Health: `curl /health`
   - Status: `curl /api/v1/status`
   - Analyze: `POST /api/v1/analyze`

3. **Monitor**
   - Check logs regularly
   - Monitor performance
   - Handle errors

4. **Scale**
   - Increase workers if needed
   - Upgrade Render plan if needed
   - Add caching if needed

**Status: ✅ READY TO USE**

