# ⚡ RAVERSE - QUICK START GUIDE

## 🎯 Start Using RAVERSE in 5 Minutes

### Step 1: Deploy to Render (1 minute)
```
1. Go to: https://dashboard.render.com
2. Select: "raverse-api" service
3. Click: "Manual Deploy" → "Deploy latest commit"
4. Wait: 2-5 minutes for deployment
```

### Step 2: Test Health (30 seconds)
```bash
curl https://jaegis-raverse.onrender.com/health
```

**Expected:**
```json
{"status": "healthy", "ready": true}
```

### Step 3: Test API (1 minute)
```bash
curl https://jaegis-raverse.onrender.com/api/v1/status
```

### Step 4: Analyze Binary (2 minutes)
```bash
curl -X POST https://jaegis-raverse.onrender.com/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "binary_path": "/path/to/binary",
    "use_database": false
  }'
```

### Step 5: Monitor (ongoing)
```
Dashboard → Logs → Watch for errors
```

---

## 🔌 API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/health` | GET | Health check |
| `/` | GET | Root info |
| `/api/v1/status` | GET | API status |
| `/api/v1/info` | GET | API info |
| `/api/v1/analyze` | POST | Analyze binary |
| `/api/v1/upload-and-analyze` | POST | Upload & analyze |

---

## 🎮 Control Commands

### Deploy
```
Dashboard → Manual Deploy → Deploy latest commit
```

### Restart
```
Dashboard → Restart Service
```

### View Logs
```
Dashboard → Logs
```

### Set Environment Variables
```
Dashboard → Environment → Add variable
```

---

## ⚙️ Configuration

### Environment Variables
```bash
OPENROUTER_API_KEY=your-key-here
OPENROUTER_MODEL=meta-llama/llama-3.2-3b-instruct:free
PORT=10000 (auto)
```

### Workers
```
Current: 4 workers
Edit: Procfile or render.yaml
```

---

## 📊 Performance

| Metric | Value |
|--------|-------|
| Startup Time | <1 second |
| Health Check | <10ms |
| First Request | 5-10 seconds |
| Subsequent Requests | <1 second |

---

## 🆘 Troubleshooting

### HTTP 502 Error
```
1. Check: curl /health
2. View: Dashboard → Logs
3. Fix: Manual Deploy
```

### Service Restarting
```
1. Check logs for errors
2. Verify OPENROUTER_API_KEY
3. Restart service
```

### Slow First Request
```
Normal! Orchestrator initializes on first request.
Subsequent requests are fast.
```

---

## 🔗 Links

- **Dashboard:** https://dashboard.render.com
- **Application:** https://jaegis-raverse.onrender.com
- **Repository:** https://github.com/usemanusai/jaegis-RAVERSE
- **API Docs:** https://jaegis-raverse.onrender.com/docs

---

## ✅ Checklist

- [ ] Deployment triggered
- [ ] Health endpoint responds
- [ ] API status shows operational
- [ ] Can make API requests
- [ ] Monitoring logs
- [ ] Ready to use

---

## 📞 Need Help?

1. **Check logs:** Dashboard → Logs
2. **Test health:** `curl /health`
3. **Read guides:**
   - `RAVERSE_USAGE_GUIDE.md` - Full usage guide
   - `RAVERSE_CONTROL_GUIDE.md` - Control & config
   - `RENDER_DEPLOYMENT_FINAL_FIX.md` - Deployment details

---

**Status: ✅ READY TO USE**

**Next: Trigger deployment and start analyzing binaries!**

