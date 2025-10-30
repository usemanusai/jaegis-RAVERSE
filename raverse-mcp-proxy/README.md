# RAVERSE MCP Proxy - Cloudflare Worker

A high-performance edge proxy for the RAVERSE MCP server running on Render. This Cloudflare Worker provides request routing, edge caching, CORS handling, and automatic retry logic.

## Features

✅ **Edge Caching** - Cache GET requests at Cloudflare edge for reduced latency
✅ **Request Routing** - Intelligent routing to RAVERSE backend on Render
✅ **CORS Support** - Full CORS headers for cross-origin requests
✅ **Retry Logic** - Automatic retry with exponential backoff
✅ **Health Checks** - Periodic health checks of backend service
✅ **Request Logging** - Comprehensive request and error logging
✅ **Performance** - Sub-50ms CPU time per request
✅ **Security** - Forwarded headers and hop-by-hop header removal

## Architecture

```
Client Request
    ↓
Cloudflare Worker (Edge)
    ├─ CORS handling
    ├─ Cache lookup
    ├─ Request forwarding
    └─ Response caching
    ↓
RAVERSE Backend (Render)
    ├─ https://jaegis-raverse.onrender.com
    └─ FastAPI with lazy loading
```

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Authenticate with Cloudflare

```bash
npx wrangler login
# Follow browser prompts to authorize
```

### 3. Deploy to Cloudflare

```bash
npm run deploy
```

### 4. Verify Deployment

```bash
npm run health-check
# or
curl https://raverse-mcp-proxy.use-manus-ai.workers.dev/health
```

## Configuration

### Environment Variables

The proxy uses the following configuration:

- `BACKEND_URL`: https://jaegis-raverse.onrender.com
- `CACHE_TTL`: 3600 seconds (1 hour)
- `HEALTH_CHECK_INTERVAL`: 300 seconds (5 minutes)

### Wrangler Configuration

Edit `wrangler.toml` to customize:

```toml
name = "raverse-mcp-proxy"
main = "index.js"
compatibility_date = "2025-10-29"

[[triggers.crons]]
cron = "*/5 * * * *"  # Health check every 5 minutes
```

## API Endpoints

### Health Check

```bash
GET /health
```

Response:
```json
{
  "status": "healthy",
  "proxy": "operational",
  "backend": "operational",
  "timestamp": "2025-10-30T12:00:00Z",
  "uptime": "24h"
}
```

### Proxy Endpoints

All other requests are proxied to the RAVERSE backend:

```bash
# Binary analysis
POST /api/analyze
GET /api/results/{id}

# Health check (backend)
GET /health

# Status
GET /status
```

## Development

### Local Development

```bash
npm run dev
```

This starts a local development server at `http://localhost:8787`

### Testing

```bash
npm run test
npm run test:integration
```

### Linting and Formatting

```bash
npm run lint
npm run format
```

## Deployment

### Production Deployment

```bash
npm run deploy:production
```

### View Logs

```bash
# Real-time logs
npm run logs:live

# Recent logs
npm run logs
```

## Performance Characteristics

- **Cache Hit Response**: <10ms
- **Cache Miss Response**: 100-500ms (depends on backend)
- **Retry Attempts**: 3 with exponential backoff
- **Timeout**: 30 seconds per request
- **CPU Limit**: 50ms per request

## Caching Strategy

### Cached Requests
- GET requests with 200 status code
- Cache TTL: 1 hour
- Cache key: Request URL + method

### Non-Cached Requests
- POST, PUT, DELETE, PATCH requests
- Requests with non-200 status codes
- Requests with Cache-Control: no-cache

## Error Handling

### Retry Logic

The proxy automatically retries failed requests with exponential backoff:

1. First attempt: Immediate
2. Second attempt: After 1 second
3. Third attempt: After 2 seconds

### Error Responses

```json
{
  "error": "Backend Service Unavailable",
  "message": "Connection timeout",
  "timestamp": "2025-10-30T12:00:00Z"
}
```

## Monitoring

### Health Checks

Scheduled health checks run every 5 minutes:

```bash
GET https://jaegis-raverse.onrender.com/health
```

### Metrics

Metrics are collected in Cloudflare Analytics Engine:

- Request count
- Cache hit rate
- Response times
- Error rates
- Backend availability

## Security

### Headers

The proxy adds security headers:

- `X-Forwarded-By`: Cloudflare-Worker
- `X-Forwarded-Proto`: https
- `X-Forwarded-Host`: Original host
- `X-Real-IP`: Client IP

### CORS

Full CORS support with:

- `Access-Control-Allow-Origin`: *
- `Access-Control-Allow-Methods`: GET, POST, PUT, DELETE, OPTIONS, PATCH
- `Access-Control-Allow-Headers`: Content-Type, Authorization, X-Requested-With

## Troubleshooting

### Backend Unreachable

```bash
# Check backend health
curl https://jaegis-raverse.onrender.com/health

# Check proxy logs
npm run logs:live
```

### Cache Issues

```bash
# Clear cache
wrangler kv:key delete --namespace-id=raverse-mcp-cache "*"

# Disable caching (development)
# Edit index.js and comment out cache.put()
```

### Deployment Issues

```bash
# Verify authentication
wrangler whoami

# Check account ID
wrangler deployments list

# View deployment logs
npm run logs
```

## Integration with RAVERSE

### Using the Proxy

Instead of connecting directly to Render:

```javascript
// Before
const RAVERSE_URL = "https://jaegis-raverse.onrender.com";

// After
const RAVERSE_URL = "https://raverse-mcp-proxy.use-manus-ai.workers.dev";
```

### Performance Benefits

- **Reduced latency**: Edge caching reduces response times
- **Improved reliability**: Automatic retry logic handles transient failures
- **Better availability**: Cloudflare's global network ensures uptime
- **Cost savings**: Reduced backend load through caching

## Support

For issues or questions:

1. Check the [troubleshooting guide](#troubleshooting)
2. Review [Cloudflare Workers documentation](https://developers.cloudflare.com/workers/)
3. Check [RAVERSE documentation](../README.md)
4. Open an issue on [GitHub](https://github.com/usemanusai/jaegis-RAVERSE/issues)

## License

MIT - See LICENSE file for details

## Related Documentation

- [RAVERSE Main README](../README.md)
- [Cloudflare Workflows Setup](../CLOUDFLARE_WORKFLOWS_SETUP.md)
- [Hybrid-Cloud Architecture](../FREE_HOSTING_HYBRID_CLOUD_ARCHITECTURE.md)
- [Cloudflare Workers Documentation](https://developers.cloudflare.com/workers/)

