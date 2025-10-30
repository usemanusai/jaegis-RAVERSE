# RAVERSE Cloudflare Workflows

Production-ready Cloudflare Workflows integration for RAVERSE binary analysis system. Implements a hybrid-cloud architecture combining Cloudflare's edge network with Render's origin deployment.

## Features

- **Binary Analysis Workflow**: Single-step binary analysis with caching and retry logic
- **Multi-Step Analysis Workflow**: DAG-based workflows with parallel and sequential execution
- **Cache Management Workflow**: Edge caching with invalidation, refresh, and cleanup
- **Hybrid Routing Workflow**: Intelligent routing between Cloudflare edge and Render origin
- **State Persistence**: D1 database for workflow history and analysis results
- **Edge Caching**: KV namespace for high-performance caching
- **Observability**: Comprehensive logging and metrics collection

## Quick Start

### Prerequisites
- Node.js 18+
- Cloudflare account
- Wrangler CLI: `npm install -g wrangler`
- RAVERSE deployed on Render

### Installation

```bash
# Install dependencies
npm install

# Authenticate with Cloudflare
npx wrangler login

# Setup infrastructure (KV, D1)
npm run setup

# Set secrets
npx wrangler secret put OPENROUTER_API_KEY
```

### Development

```bash
# Start local development server
npm run dev

# Run tests
npm run test

# Run integration tests
npm run test:integration
```

### Deployment

```bash
# Deploy to Cloudflare
npm run deploy

# Verify deployment
curl https://raverse-workflows.use-manus-ai.workers.dev/health
```

## Architecture

```
Client → Cloudflare Workers (Edge) → Cloudflare Workflows → Render (RAVERSE API)
                    ↓
            KV Cache (RAVERSE_CACHE)
            D1 Database (raverse-workflows)
```

## Workflows

### Binary Analysis Workflow
Analyzes a single binary with caching and retry logic.

```bash
curl "https://raverse-workflows.use-manus-ai.workers.dev/?type=binary-analysis&binaryPath=/path/to/binary&analysisType=comprehensive"
```

### Multi-Step Analysis Workflow
Executes multiple analysis steps with DAG dependencies.

```bash
curl -X POST "https://raverse-workflows.use-manus-ai.workers.dev/" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "multi-step-analysis",
    "binaryPath": "/path/to/binary",
    "steps": [...]
  }'
```

### Cache Management Workflow
Manages edge cache operations.

```bash
curl "https://raverse-workflows.use-manus-ai.workers.dev/?type=cache-management&action=invalidate"
```

### Hybrid Routing Workflow
Routes requests between edge and origin with caching.

```bash
curl -X POST "https://raverse-workflows.use-manus-ai.workers.dev/" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "hybrid-routing",
    "requestPath": "/api/analyze",
    "method": "POST",
    "useCache": true
  }'
```

## Configuration

Edit `wrangler.jsonc` to configure:
- RAVERSE API URL
- Cache TTL
- Retry strategy
- Workflow timeouts
- KV namespaces
- D1 database

## Monitoring

### View Logs
```bash
npx wrangler tail
```

### Check Workflows
- Cloudflare Dashboard → Workers → Workflows
- View instances and execution history

### Monitor Performance
- KV namespace usage
- D1 database performance
- Workflow execution times

## Documentation

- [Setup Guide](../CLOUDFLARE_WORKFLOWS_SETUP.md)
- [Deployment Guide](../CLOUDFLARE_DEPLOYMENT_GUIDE.md)
- [Cloudflare Workflows Docs](https://developers.cloudflare.com/workflows/)

## Scripts

- `npm run dev` - Start local development
- `npm run deploy` - Deploy to Cloudflare
- `npm run test` - Run unit tests
- `npm run test:integration` - Run integration tests
- `npm run build` - Build TypeScript
- `npm run lint` - Lint code
- `npm run format` - Format code
- `npm run setup` - Setup infrastructure
- `npm run verify` - Verify deployment

## Troubleshooting

### Workflows not executing
1. Check KV namespaces are created
2. Verify D1 database is initialized
3. Review logs: `npx wrangler tail`

### Cache not working
1. Verify `ENABLE_EDGE_CACHING` is true
2. Check KV namespace usage
3. Review cache TTL settings

### RAVERSE API unreachable
1. Verify Render deployment is running
2. Check `RAVERSE_API_URL` configuration
3. Test connectivity to RAVERSE

## Support

For issues or questions:
- Check documentation files
- Review Cloudflare Workflows docs
- Check GitHub issues
- Contact support team

## License

MIT

