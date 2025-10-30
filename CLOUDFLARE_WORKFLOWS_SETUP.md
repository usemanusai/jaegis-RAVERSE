# RAVERSE Cloudflare Workflows Integration Guide

## Overview

This guide provides comprehensive instructions for setting up and deploying RAVERSE with Cloudflare Workflows, creating a hybrid-cloud architecture that combines Cloudflare's edge network with Render's origin deployment.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Requests                          │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │  Cloudflare Workers (Edge)     │
        │  - Request routing             │
        │  - Edge caching (KV)           │
        │  - Workflow orchestration      │
        └────────────┬───────────────────┘
                     │
        ┌────────────▼───────────────────┐
        │  Cloudflare Workflows          │
        │  - Binary Analysis             │
        │  - Multi-Step Analysis (DAG)   │
        │  - Cache Management            │
        │  - Hybrid Routing              │
        └────────────┬───────────────────┘
                     │
        ┌────────────▼───────────────────┐
        │  Render Deployment             │
        │  - RAVERSE API                 │
        │  - FastAPI with lazy loading   │
        │  - 4 Uvicorn workers           │
        └────────────────────────────────┘
```

## Prerequisites

- Cloudflare account with Workers enabled
- Render account with RAVERSE deployed
- Node.js 18+ and npm/pnpm
- Wrangler CLI installed globally
- Git for version control

## Step 1: Initial Setup

### 1.1 Clone and Navigate

```bash
cd C:/Users/Lenovo\ ThinkPad\ T480/Desktop/RAVERSE/workflows-starter
```

### 1.2 Install Dependencies

```bash
npm install
# or
pnpm install
```

### 1.3 Authenticate with Cloudflare

```bash
npx wrangler login
```

## Step 2: Configure Environment

### 2.1 Update wrangler.jsonc

The configuration file includes:
- **Environment Variables**: RAVERSE_API_URL, cache TTL, retry settings
- **KV Namespaces**: RAVERSE_CACHE, WORKFLOW_STATE
- **D1 Database**: raverse-workflows for persistence
- **Workflows**: 4 workflow types for different analysis tasks

### 2.2 Set Secrets

```bash
# Set OpenRouter API key
npx wrangler secret put OPENROUTER_API_KEY

# Set RAVERSE authentication token (if needed)
npx wrangler secret put RAVERSE_AUTH_TOKEN
```

### 2.3 Create KV Namespaces

```bash
# Create cache namespace
npx wrangler kv:namespace create "RAVERSE_CACHE"
npx wrangler kv:namespace create "RAVERSE_CACHE" --preview

# Create state namespace
npx wrangler kv:namespace create "WORKFLOW_STATE"
npx wrangler kv:namespace create "WORKFLOW_STATE" --preview
```

### 2.4 Create D1 Database

```bash
# Create database
npx wrangler d1 create raverse-workflows

# Initialize schema
npx wrangler d1 execute raverse-workflows --file=./schema.sql
```

## Step 3: Workflow Implementation

### 3.1 Binary Analysis Workflow

Orchestrates single-step binary analysis with:
- Cache checking
- RAVERSE API calls with retry logic
- Result caching in KV
- Persistence in D1

**Usage:**
```bash
curl "https://raverse-workflows.use-manus-ai.workers.dev/?type=binary-analysis&binaryPath=/path/to/binary&analysisType=comprehensive"
```

### 3.2 Multi-Step Analysis Workflow

Implements DAG-based workflows with:
- Parallel independent step execution
- Sequential dependent step execution
- Result aggregation

**Usage:**
```bash
curl -X POST "https://raverse-workflows.use-manus-ai.workers.dev/" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "multi-step-analysis",
    "binaryPath": "/path/to/binary",
    "steps": [...],
    "parallelExecution": true
  }'
```

### 3.3 Cache Management Workflow

Handles cache operations:
- **invalidate**: Remove cached entries
- **refresh**: Update cache with fresh data
- **cleanup**: Remove expired entries
- **analyze**: Analyze cache performance

### 3.4 Hybrid Routing Workflow

Routes requests between edge and origin:
- Checks edge cache first
- Routes to Render if cache miss
- Caches responses for future requests

## Step 4: Deployment

### 4.1 Local Testing

```bash
npm run start
# or
pnpm start
```

### 4.2 Deploy to Cloudflare

```bash
npm run deploy
# or
pnpm deploy
```

### 4.3 Verify Deployment

```bash
# Check health
curl https://raverse-workflows.use-manus-ai.workers.dev/health

# Create workflow instance
curl "https://raverse-workflows.use-manus-ai.workers.dev/?type=binary-analysis"

# Check instance status
curl "https://raverse-workflows.use-manus-ai.workers.dev/?instanceId=<id>&type=binary-analysis"
```

## Step 5: Monitoring and Observability

### 5.1 View Logs

```bash
npx wrangler tail
```

### 5.2 Monitor Workflows

- Cloudflare Dashboard → Workers → Workflows
- View workflow instances and execution history
- Monitor performance metrics

### 5.3 Analytics

- Check KV namespace usage
- Monitor D1 database performance
- Review workflow execution times

## Troubleshooting

### Issue: Workflow timeout

**Solution**: Increase `WORKFLOW_TIMEOUT_MINUTES` in wrangler.jsonc

### Issue: Cache not working

**Solution**: Verify `ENABLE_EDGE_CACHING` is set to "true" and KV namespaces are created

### Issue: RAVERSE API unreachable

**Solution**: Check `RAVERSE_API_URL` and verify Render deployment is running

### Issue: D1 database errors

**Solution**: Ensure schema is initialized and database is created

## Performance Optimization

1. **Edge Caching**: Set appropriate TTL values
2. **Parallel Execution**: Use DAG workflows for independent steps
3. **Retry Strategy**: Configure exponential backoff
4. **Request Batching**: Group multiple requests

## Security Considerations

1. Use secrets for sensitive data (API keys, tokens)
2. Implement request validation
3. Use CORS headers appropriately
4. Monitor for suspicious activity
5. Rotate secrets regularly

## Next Steps

1. Deploy workflows to production
2. Configure monitoring and alerts
3. Implement custom workflows for specific use cases
4. Integrate with CI/CD pipeline
5. Set up automated testing

## Support

For issues or questions:
- Check Cloudflare Workflows documentation
- Review RAVERSE API documentation
- Check GitHub issues
- Contact support team

