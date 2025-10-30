# RAVERSE Cloudflare Workflows Deployment Guide

## Complete Deployment Checklist

### Phase 1: Pre-Deployment Setup

#### 1.1 Verify Prerequisites
- [ ] Cloudflare account created and verified
- [ ] Render deployment running (https://jaegis-raverse.onrender.com)
- [ ] Node.js 18+ installed
- [ ] Wrangler CLI installed globally: `npm install -g wrangler`
- [ ] Git configured with GitHub credentials

#### 1.2 Clone Repository
```bash
cd C:/Users/Lenovo\ ThinkPad\ T480/Desktop/RAVERSE/workflows-starter
git status
```

#### 1.3 Install Dependencies
```bash
npm install
# or
pnpm install
```

### Phase 2: Cloudflare Configuration

#### 2.1 Authenticate with Cloudflare
```bash
npx wrangler login
# Follow browser prompt to authorize
```

#### 2.2 Create KV Namespaces
```bash
npm run kv:create
# Creates RAVERSE_CACHE and WORKFLOW_STATE namespaces
```

#### 2.3 Create D1 Database
```bash
npm run db:create
# Creates raverse-workflows database
```

#### 2.4 Initialize Database Schema
```bash
npm run db:init
# Initializes all tables and views
```

#### 2.5 Set Secrets
```bash
# Set OpenRouter API key
npx wrangler secret put OPENROUTER_API_KEY
# Paste your API key when prompted

# Set RAVERSE auth token (if needed)
npx wrangler secret put RAVERSE_AUTH_TOKEN
# Paste your token when prompted
```

### Phase 3: Local Testing

#### 3.1 Start Local Development Server
```bash
npm run dev
# Server runs on http://localhost:8787
```

#### 3.2 Test Health Endpoint
```bash
curl http://localhost:8787/health
```

#### 3.3 Create Test Workflow Instance
```bash
curl "http://localhost:8787/?type=binary-analysis&binaryPath=/test/binary"
```

#### 3.4 Run Integration Tests
```bash
npm run test:integration
```

### Phase 4: Production Deployment

#### 4.1 Build for Production
```bash
npm run build
```

#### 4.2 Deploy to Cloudflare
```bash
npm run deploy
# Deploys to https://raverse-workflows.use-manus-ai.workers.dev
```

#### 4.3 Verify Deployment
```bash
# Check health
curl https://raverse-workflows.use-manus-ai.workers.dev/health

# Create workflow instance
curl "https://raverse-workflows.use-manus-ai.workers.dev/?type=binary-analysis"

# Check instance status
curl "https://raverse-workflows.use-manus-ai.workers.dev/?instanceId=<id>&type=binary-analysis"
```

### Phase 5: Monitoring and Verification

#### 5.1 View Live Logs
```bash
npx wrangler tail
```

#### 5.2 Monitor Workflows
- Go to Cloudflare Dashboard
- Navigate to Workers → Workflows
- View workflow instances and execution history

#### 5.3 Check KV Namespace Usage
- Cloudflare Dashboard → Workers → KV
- Monitor RAVERSE_CACHE and WORKFLOW_STATE usage

#### 5.4 Monitor D1 Database
- Cloudflare Dashboard → Workers → D1
- Check raverse-workflows database performance

### Phase 6: Performance Optimization

#### 6.1 Configure Cache TTL
Edit `wrangler.jsonc`:
```json
"vars": {
  "CACHE_TTL_SECONDS": "3600"
}
```

#### 6.2 Adjust Retry Strategy
```json
"vars": {
  "MAX_RETRIES": "3",
  "RETRY_DELAY_MS": "1000"
}
```

#### 6.3 Set Workflow Timeout
```json
"vars": {
  "WORKFLOW_TIMEOUT_MINUTES": "30"
}
```

### Phase 7: Integration with RAVERSE

#### 7.1 Verify RAVERSE API Connectivity
```bash
curl https://jaegis-raverse.onrender.com/health
```

#### 7.2 Test Binary Analysis Workflow
```bash
curl -X POST "https://raverse-workflows.use-manus-ai.workers.dev/" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "binary-analysis",
    "binaryPath": "/path/to/binary",
    "analysisType": "comprehensive"
  }'
```

#### 7.3 Test Multi-Step Analysis
```bash
curl -X POST "https://raverse-workflows.use-manus-ai.workers.dev/" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "multi-step-analysis",
    "binaryPath": "/path/to/binary",
    "steps": [
      {"name": "disassembly", "type": "disassembly", "config": {}},
      {"name": "pattern", "type": "pattern", "config": {"dependsOn": ["disassembly"]}}
    ]
  }'
```

### Phase 8: Rollback Procedures

#### 8.1 Rollback to Previous Version
```bash
# View deployment history
npx wrangler deployments list

# Rollback to specific version
npx wrangler rollback --version <version-id>
```

#### 8.2 Emergency Disable
```bash
# Disable all workflows
npx wrangler publish --env production --dry-run
```

### Phase 9: Documentation and Handoff

#### 9.1 Update Documentation
- [ ] Update README.md with deployment info
- [ ] Document custom workflows
- [ ] Create runbooks for common issues
- [ ] Document monitoring procedures

#### 9.2 Team Training
- [ ] Train team on deployment process
- [ ] Document troubleshooting procedures
- [ ] Create escalation procedures
- [ ] Set up on-call rotation

### Phase 10: Post-Deployment

#### 10.1 Monitor for 24 Hours
- [ ] Check error rates
- [ ] Monitor performance metrics
- [ ] Verify cache hit rates
- [ ] Check database performance

#### 10.2 Optimize Based on Metrics
- [ ] Adjust cache TTL if needed
- [ ] Optimize retry strategy
- [ ] Fine-tune timeout values
- [ ] Update workflow configurations

## Troubleshooting

### Deployment Fails
1. Check Wrangler authentication: `npx wrangler whoami`
2. Verify account ID in wrangler.jsonc
3. Check for syntax errors: `npm run build`

### Workflows Not Executing
1. Verify KV namespaces are created
2. Check D1 database is initialized
3. Review workflow logs: `npx wrangler tail`

### Performance Issues
1. Check cache hit rates in KV
2. Monitor D1 query performance
3. Review workflow execution times
4. Adjust timeout and retry settings

### RAVERSE API Unreachable
1. Verify Render deployment is running
2. Check RAVERSE_API_URL in wrangler.jsonc
3. Test connectivity: `curl https://jaegis-raverse.onrender.com/health`

## Support and Escalation

- **Documentation**: See CLOUDFLARE_WORKFLOWS_SETUP.md
- **Issues**: Check GitHub issues
- **Logs**: Use `npx wrangler tail` for real-time logs
- **Metrics**: Check Cloudflare Dashboard

