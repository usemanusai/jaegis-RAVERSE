# RAVERSE MCP Proxy - Complete Setup Guide

This guide walks you through setting up the RAVERSE MCP Proxy on Cloudflare Workers.

## Overview

The RAVERSE MCP Proxy is a Cloudflare Worker that:
- Proxies requests to the RAVERSE backend on Render
- Provides edge caching for improved performance
- Handles CORS for cross-origin requests
- Implements automatic retry logic
- Performs periodic health checks

## Prerequisites

- Cloudflare account (free tier supported)
- Node.js 18+ installed
- Git installed
- RAVERSE backend deployed on Render (https://jaegis-raverse.onrender.com)

## Step-by-Step Setup

### Step 1: Install Wrangler Globally

```bash
npm install --global wrangler
```

Verify installation:
```bash
wrangler --version
```

### Step 2: Authenticate with Cloudflare

```bash
wrangler login
```

This opens a browser window to authorize Wrangler with your Cloudflare account.

### Step 3: Navigate to Project Directory

```bash
cd raverse-mcp-proxy
```

### Step 4: Install Dependencies

```bash
npm install
```

### Step 5: Configure Wrangler

Edit `wrangler.toml` and update:

```toml
account_id = "your-account-id"  # Get from Cloudflare dashboard
```

To find your account ID:
1. Go to https://dash.cloudflare.com/
2. Click on your account
3. Copy the Account ID from the right sidebar

### Step 6: Deploy to Cloudflare

```bash
npm run deploy
```

Expected output:
```
✨ Successfully published your Worker to
https://raverse-mcp-proxy.use-manus-ai.workers.dev
```

### Step 7: Verify Deployment

```bash
npm run health-check
```

Or manually:
```bash
curl https://raverse-mcp-proxy.use-manus-ai.workers.dev/health
```

Expected response:
```json
{
  "status": "healthy",
  "proxy": "operational",
  "backend": "operational",
  "timestamp": "2025-10-30T12:00:00Z"
}
```

## Configuration

### Environment Variables

Edit `index.js` to customize:

```javascript
const BACKEND_URL = "https://jaegis-raverse.onrender.com";
const CACHE_TTL = 3600; // 1 hour
const HEALTH_CHECK_INTERVAL = 300; // 5 minutes
```

### Caching Strategy

The proxy caches:
- GET requests with 200 status
- TTL: 1 hour (configurable)
- Cache key: Request URL + method

### Retry Logic

Failed requests are retried 3 times with exponential backoff:
- Attempt 1: Immediate
- Attempt 2: After 1 second
- Attempt 3: After 2 seconds

## Usage

### Direct Proxy Usage

Instead of connecting to Render directly:

```javascript
// Before
const RAVERSE_URL = "https://jaegis-raverse.onrender.com";

// After
const RAVERSE_URL = "https://raverse-mcp-proxy.use-manus-ai.workers.dev";
```

### API Endpoints

All RAVERSE endpoints are available through the proxy:

```bash
# Health check
curl https://raverse-mcp-proxy.use-manus-ai.workers.dev/health

# Binary analysis
curl -X POST https://raverse-mcp-proxy.use-manus-ai.workers.dev/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"binary_path": "/path/to/binary"}'

# Get results
curl https://raverse-mcp-proxy.use-manus-ai.workers.dev/api/results/123
```

## Development

### Local Development

```bash
npm run dev
```

Starts local server at http://localhost:8787

### Testing

```bash
npm run test
npm run test:integration
```

### Linting

```bash
npm run lint
npm run format
```

## Monitoring

### View Logs

Real-time logs:
```bash
npm run logs:live
```

Recent logs:
```bash
npm run logs
```

### Performance Metrics

The proxy collects metrics in Cloudflare Analytics Engine:
- Request count
- Cache hit rate
- Response times
- Error rates
- Backend availability

View metrics in Cloudflare Dashboard:
1. Go to https://dash.cloudflare.com/
2. Select your account
3. Go to Workers > Analytics

## Troubleshooting

### Backend Unreachable

Check backend health:
```bash
curl https://jaegis-raverse.onrender.com/health
```

If backend is down:
1. Check Render dashboard
2. Verify environment variables
3. Check application logs

### Cache Issues

Clear cache:
```bash
wrangler kv:key delete --namespace-id=raverse-mcp-cache "*"
```

Disable caching (development):
Edit `index.js` and comment out:
```javascript
// ctx.waitUntil(cache.put(...))
```

### Deployment Failures

Verify authentication:
```bash
wrangler whoami
```

Check account ID:
```bash
wrangler deployments list
```

View deployment logs:
```bash
npm run logs
```

## Performance Optimization

### Cache Hit Rate

Monitor cache hit rate in Cloudflare Dashboard:
- Target: >80% for GET requests
- Adjust TTL if needed

### Response Times

Target response times:
- Cache hit: <10ms
- Cache miss: 100-500ms
- With retry: <5 seconds

### Cost Optimization

Cloudflare Workers free tier includes:
- 100,000 requests/day
- Unlimited bandwidth
- Full caching support

For higher volumes, upgrade to paid plan.

## Integration with RAVERSE

### Cloudflare Workflows

Use the proxy in Cloudflare Workflows:

```javascript
const RAVERSE_URL = "https://raverse-mcp-proxy.use-manus-ai.workers.dev";

export class RaverseAnalysisWorkflow extends WorkflowEntrypoint {
  async run(event, step) {
    const analysis = await step.do('analyze', async () => {
      const response = await fetch(`${RAVERSE_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(event.payload)
      });
      return response.json();
    });
    return analysis;
  }
}
```

### MCP Clients

Configure MCP clients to use the proxy:

```json
{
  "mcpServers": {
    "raverse": {
      "command": "npx",
      "args": ["raverse-mcp-server@latest"],
      "env": {
        "RAVERSE_API_URL": "https://raverse-mcp-proxy.use-manus-ai.workers.dev"
      }
    }
  }
}
```

## Security

### CORS Headers

The proxy adds CORS headers for cross-origin requests:
- `Access-Control-Allow-Origin`: *
- `Access-Control-Allow-Methods`: GET, POST, PUT, DELETE, OPTIONS, PATCH
- `Access-Control-Allow-Headers`: Content-Type, Authorization, X-Requested-With

### Forwarded Headers

The proxy adds security headers:
- `X-Forwarded-By`: Cloudflare-Worker
- `X-Forwarded-Proto`: https
- `X-Forwarded-Host`: Original host
- `X-Real-IP`: Client IP

### Rate Limiting

To add rate limiting, edit `index.js`:

```javascript
const RATE_LIMIT = 100; // requests per minute
const rateLimitMap = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  const key = `${ip}:${Math.floor(now / 60000)}`;
  const count = (rateLimitMap.get(key) || 0) + 1;
  rateLimitMap.set(key, count);
  return count <= RATE_LIMIT;
}
```

## Deployment Checklist

- [ ] Cloudflare account created
- [ ] Wrangler installed globally
- [ ] Authenticated with Cloudflare
- [ ] Account ID configured in wrangler.toml
- [ ] Dependencies installed (npm install)
- [ ] Deployed to Cloudflare (npm run deploy)
- [ ] Health check passing
- [ ] Backend connectivity verified
- [ ] CORS headers present
- [ ] Caching working
- [ ] Logs accessible
- [ ] Monitoring configured

## Next Steps

1. **Monitor Performance**: Check Cloudflare Dashboard for metrics
2. **Optimize Caching**: Adjust TTL based on usage patterns
3. **Add Rate Limiting**: Implement rate limiting if needed
4. **Integrate with Workflows**: Use proxy in Cloudflare Workflows
5. **Set Up Alerts**: Configure alerts for errors and downtime

## Support

For issues or questions:
- Check [README.md](raverse-mcp-proxy/README.md)
- Review [Cloudflare Workers docs](https://developers.cloudflare.com/workers/)
- Check [RAVERSE docs](README.md)
- Open issue on [GitHub](https://github.com/usemanusai/jaegis-RAVERSE/issues)

## Related Documentation

- [RAVERSE Main README](README.md)
- [Cloudflare Workflows Setup](CLOUDFLARE_WORKFLOWS_SETUP.md)
- [Hybrid-Cloud Architecture](FREE_HOSTING_HYBRID_CLOUD_ARCHITECTURE.md)
- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)

