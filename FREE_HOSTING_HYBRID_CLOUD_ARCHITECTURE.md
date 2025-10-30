# 🌐 Free Hosting Setup Using a Hybrid-Cloud Architecture

## 📋 Overview

This comprehensive guide outlines a **100% free hybrid-cloud architecture** for hosting the RAVERSE MCP server (a Python application) with persistent uptime. This approach combines four free services to create a production-ready, always-on deployment.

**Key Benefits:**
- ✅ Completely free for personal/non-commercial use
- ✅ Always-on (no sleeping/cold starts)
- ✅ Persistent database and cache
- ✅ Permanent public URL
- ✅ Production-ready performance
- ✅ Scalable architecture

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    HYBRID-CLOUD ARCHITECTURE                │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐      ┌──────────────────┐             │
│  │  Cloudflare      │      │  UptimeRobot     │             │
│  │  Workers         │      │  (Keep-Alive)    │             │
│  │  (Public URL)    │      │  (Ping every 5m) │             │
│  └────────┬─────────┘      └────────┬─────────┘             │
│           │                         │                        │
│           └─────────────┬───────────┘                        │
│                         │                                    │
│                    ┌────▼─────┐                             │
│                    │  Render   │                             │
│                    │  (Python  │                             │
│                    │  App)     │                             │
│                    └────┬──────┘                             │
│                         │                                    │
│         ┌───────────────┼───────────────┐                   │
│         │               │               │                   │
│    ┌────▼────┐    ┌────▼────┐    ┌────▼────┐              │
│    │  Aiven  │    │  Aiven  │    │  Aiven  │              │
│    │Postgres │    │ Valkey  │    │ Backup  │              │
│    │   DB    │    │ Cache   │    │  (opt)  │              │
│    └─────────┘    └─────────┘    └─────────┘              │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Component Summary

| Component | Service | Cost | Purpose |
|-----------|---------|------|---------|
| **Database** | Aiven PostgreSQL | Free | Persistent data storage (always-on) |
| **Cache** | Aiven Valkey/Redis | Free | High-speed caching (always-on) |
| **Application** | Render | Free | Runs RAVERSE Python server |
| **Persistence** | UptimeRobot | Free | Pings every 5 mins to prevent sleeping |
| **Public URL** | Cloudflare Workers | Free | Permanent public-facing URL |

---

## 🚀 Step-by-Step Setup Guide

### Step 1: Set Up Free "Always-On" Database (Aiven)

Aiven provides free PostgreSQL and Redis (Valkey) services that never sleep.

#### 1.1 Create Aiven Account
```bash
# Go to https://aiven.io
# Sign up for free account
# Verify email
```

#### 1.2 Create PostgreSQL Database
1. Go to Aiven Dashboard
2. Click "Create Service"
3. Select "Aiven for PostgreSQL"
4. Choose "Free" plan
5. Name it: `raverse-pg-db`
6. Select region closest to you
7. Click "Create Service"

#### 1.3 Create Valkey Cache
1. Click "Create Service" again
2. Select "Aiven for Valkey"
3. Choose "Free" plan
4. Name it: `raverse-valkey-cache`
5. Select same region as PostgreSQL
6. Click "Create Service"

#### 1.4 Save Connection URIs
For both services:
1. Go to "Connection information" tab
2. Copy the "Service URI"
3. Save in secure location (you'll need these for Render)

**Example URIs:**
```
DATABASE_URL: postgres://user:password@host:port/dbname
CACHE_URL: redis://user:password@host:port
```

---

### Step 2: Deploy Backend Server (Render)

Render hosts the main RAVERSE Python application.

#### 2.1 Create Render Account
```bash
# Go to https://render.com
# Sign up with GitHub account
# Authorize Render to access your repositories
```

#### 2.2 Fork RAVERSE Repository
```bash
# Go to https://github.com/usemanusai/jaegis-RAVERSE
# Click "Fork" button
# Create fork in your account
```

#### 2.3 Create Web Service on Render
1. Go to Render Dashboard
2. Click "New +" → "Web Service"
3. Select your forked RAVERSE repository
4. Click "Connect"

#### 2.4 Configure Render Settings
```
Name: raverse-mcp-server
Environment: Python 3
Region: Choose closest to you
Instance Type: Free
Build Command: cd src && pip install -r requirements.txt
Start Command: cd src && gunicorn app:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT
```

#### 2.5 Add Environment Variables
In Render dashboard, go to "Environment" and add:

```
OPENROUTER_API_KEY=your-api-key-here
DATABASE_URL=postgres://user:password@host:port/dbname
CACHE_URL=redis://user:password@host:port
OPENROUTER_MODEL=meta-llama/llama-3.2-3b-instruct:free
```

#### 2.6 Deploy
1. Click "Create Web Service"
2. Wait for deployment (2-5 minutes)
3. Copy your Render URL: `https://raverse-mcp-server.onrender.com`

---

### Step 3: Keep Backend Always-On (UptimeRobot)

Render's free tier sleeps after 15 minutes. UptimeRobot prevents this.

#### 3.1 Create UptimeRobot Account
```bash
# Go to https://uptimerobot.com
# Sign up for free account
# Verify email
```

#### 3.2 Create HTTP Monitor
1. Click "+ Add New Monitor"
2. Select "HTTP(s)" as monitor type
3. Friendly Name: `RAVERSE Keep-Alive`
4. URL: `https://raverse-mcp-server.onrender.com/health`
5. Monitoring Interval: `5 minutes`
6. Click "Create Monitor"

**Result:** UptimeRobot pings your app every 5 minutes, keeping it awake (Render sleeps after 15 minutes).

---

### Step 4: Create Public URL (Cloudflare Workers)

Cloudflare Workers provides a clean, permanent public URL.

#### 4.1 Create Cloudflare Account
```bash
# Go to https://cloudflare.com
# Sign up for free account
# Verify email
```

#### 4.2 Install Wrangler CLI
```bash
npm install --global wrangler
```

#### 4.3 Authenticate Wrangler
```bash
wrangler login
# Follow browser prompts to authorize
```

#### 4.4 Create Project Directory
```bash
mkdir raverse-mcp-proxy
cd raverse-mcp-proxy
```

#### 4.5 Create index.js
```javascript
// index.js - Proxy to Render backend
const BACKEND_URL = "https://raverse-mcp-server.onrender.com";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    url.hostname = new URL(BACKEND_URL).hostname;
    
    const forwardedRequest = new Request(url, request);
    forwardedRequest.headers.set("X-Forwarded-By", "Cloudflare-Worker");
    
    return await fetch(forwardedRequest);
  },
};
```

#### 4.6 Create wrangler.toml
```toml
name = "raverse-mcp-proxy"
main = "index.js"
compatibility_date = "2025-10-29"
```

#### 4.7 Deploy to Cloudflare
```bash
wrangler deploy
```

**Result:** You'll get a permanent URL like `https://raverse-mcp-proxy.use-manus-ai.workers.dev`

---

## 🔗 Integration with RAVERSE Render Deployment

### Current RAVERSE Deployment Status

RAVERSE is already successfully deployed on Render at:
```
https://jaegis-raverse.onrender.com
```

**Key Features:**
- ✅ FastAPI with lazy loading (fixed HTTP 502 issues)
- ✅ 4 Uvicorn workers for performance
- ✅ Health check endpoint at `/health`
- ✅ API endpoints for binary analysis
- ✅ Comprehensive documentation

### Integrating with Hybrid-Cloud Architecture

To integrate the existing RAVERSE deployment with the hybrid-cloud architecture:

#### Option 1: Use Existing Render Deployment
```bash
# In Cloudflare Workers proxy (index.js)
const BACKEND_URL = "https://jaegis-raverse.onrender.com";
```

#### Option 2: Create New Render Deployment with Database
```bash
# Fork repository
# Deploy to Render with Aiven credentials
# Add environment variables:
DATABASE_URL=<aiven-postgres-uri>
CACHE_URL=<aiven-valkey-uri>
```

---

## 🔧 Configuration for Cloudflare Workflows Integration

### Cloudflare Workflows Setup

Cloudflare Workflows can orchestrate RAVERSE analysis tasks:

```javascript
// workflows/raverse-analysis.js
import { WorkflowEntrypoint, WorkflowStep, WorkflowEvent } from 'cloudflare:workers';

export class RaverseAnalysisWorkflow extends WorkflowEntrypoint {
  async run(event, step) {
    const binaryPath = event.payload.binary_path;
    
    // Step 1: Validate binary
    const validation = await step.do('validate', async () => {
      const response = await fetch('https://jaegis-raverse.onrender.com/health');
      return response.ok;
    });
    
    // Step 2: Submit analysis
    const analysis = await step.do('analyze', async () => {
      const response = await fetch('https://jaegis-raverse.onrender.com/api/v1/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ binary_path: binaryPath, use_database: false })
      });
      return response.json();
    });
    
    // Step 3: Process results
    const results = await step.do('process', async () => {
      return {
        status: 'completed',
        analysis: analysis,
        timestamp: new Date().toISOString()
      };
    });
    
    return results;
  }
}

export default new RaverseAnalysisWorkflow();
```

---

## 📋 Deployment Checklist

- [ ] Aiven PostgreSQL database created
- [ ] Aiven Valkey cache created
- [ ] Connection URIs saved securely
- [ ] Render account created
- [ ] RAVERSE repository forked
- [ ] Render web service configured
- [ ] Environment variables added to Render
- [ ] Render deployment successful
- [ ] UptimeRobot account created
- [ ] HTTP monitor configured
- [ ] Cloudflare account created
- [ ] Wrangler CLI installed
- [ ] Cloudflare Workers proxy deployed
- [ ] All endpoints tested and working

---

## ✅ Verification Steps

### Test Aiven Connections
```bash
# Test PostgreSQL
psql "postgres://user:password@host:port/dbname"

# Test Valkey
redis-cli -u "redis://user:password@host:port"
```

### Test Render Deployment
```bash
curl https://jaegis-raverse.onrender.com/health
curl https://jaegis-raverse.onrender.com/api/v1/status
```

### Test UptimeRobot
```
Check UptimeRobot dashboard for successful pings
```

### Test Cloudflare Workers
```bash
curl https://raverse-mcp-proxy.use-manus-ai.workers.dev/health
```

---

## 📞 Troubleshooting

### Render Service Sleeping
- **Issue:** Service returns 502 errors
- **Solution:** Verify UptimeRobot is pinging correctly (check dashboard)

### Database Connection Errors
- **Issue:** Cannot connect to Aiven
- **Solution:** Verify DATABASE_URL and CACHE_URL in Render environment

### Cloudflare Workers Timeout
- **Issue:** Requests timeout through Cloudflare
- **Solution:** Check Render backend is responding, increase timeout in wrangler.toml

---

## 🎯 Summary

This hybrid-cloud architecture provides:
- ✅ **Zero cost** for personal/non-commercial use
- ✅ **Always-on** operation (no sleeping)
- ✅ **Persistent** database and cache
- ✅ **Scalable** design
- ✅ **Production-ready** performance
- ✅ **Easy to maintain** and monitor

**Total Setup Time:** ~30 minutes
**Maintenance:** Minimal (mostly automated)

---

## 🔗 Useful Links

- **Aiven:** https://aiven.io
- **Render:** https://render.com
- **UptimeRobot:** https://uptimerobot.com
- **Cloudflare:** https://cloudflare.com
- **RAVERSE Repository:** https://github.com/usemanusai/jaegis-RAVERSE
- **RAVERSE Deployment:** https://jaegis-raverse.onrender.com

---

**Status: ✅ COMPLETE AND READY TO DEPLOY**

