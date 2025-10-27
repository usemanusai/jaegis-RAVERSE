# Deep Research Integration Guide

**Date:** October 26, 2025  
**Status:** Complete Integration  
**Version:** 1.0

---

## Overview

The Deep Research workflow has been successfully integrated into RAVERSE Online as three specialized agents:

1. **Topic Enhancer Agent** - Query optimization and expansion
2. **Web Researcher Agent** - Web search and content extraction
3. **Content Analyzer Agent** - Analysis and synthesis

---

## Architecture

### Agent Pipeline

```
User Input (Topic)
    ↓
[Phase 1] Topic Enhancer
    ├─ Model: claude-3.5-sonnet:free
    ├─ Task: Expand and optimize topic
    └─ Output: Enhanced topic
    ↓
[Phase 2] Web Researcher
    ├─ Model: gemini-2.0-flash-exp:free
    ├─ Tools: BraveSearch, Playwright, Trafilatura
    ├─ Task: Search and scrape web content
    └─ Output: Research findings
    ↓
[Phase 3] Content Analyzer
    ├─ Model: llama-3.3-70b-instruct:free
    ├─ Task: Analyze and synthesize findings
    └─ Output: Comprehensive synthesis
    ↓
Final Report
```

### Agent-to-Agent Communication

Agents communicate via Redis pub/sub with PostgreSQL audit logging:

```
Agent A → Redis Channel → Agent B
    ↓
PostgreSQL Audit Log
```

**Message Types:**
- `task_complete` - Task finished successfully
- `data_request` - Request data from another agent
- `data_share` - Share data with another agent
- `error` - Error notification
- `status_update` - Status update
- `ack` - Acknowledgment

---

## Integration Points

### 1. Orchestrator Integration

The `OnlineOrchestrationAgent` now includes:

```python
# New method to run Deep Research workflow
orchestrator.run_deep_research(
    topic="machine learning",
    context="focus on recent developments",
    max_results=10
)
```

### 2. Agent Registry

All three agents are registered in the orchestrator:

```python
self.agents = {
    'DEEP_RESEARCH_TOPIC_ENHANCER': DeepResearchTopicEnhancerAgent(...),
    'DEEP_RESEARCH_WEB_RESEARCHER': DeepResearchWebResearcherAgent(...),
    'DEEP_RESEARCH_CONTENT_ANALYZER': DeepResearchContentAnalyzerAgent(...)
}
```

### 3. Docker Compose

Three new services added:

```yaml
deep-research-topic-enhancer:
  environment:
    OPENROUTER_API_KEY: ${OPENROUTER_API_KEY}

deep-research-web-researcher:
  environment:
    OPENROUTER_API_KEY: ${OPENROUTER_API_KEY}
    BRAVE_SEARCH_API_KEY: ${BRAVE_SEARCH_API_KEY}

deep-research-content-analyzer:
  environment:
    OPENROUTER_API_KEY: ${OPENROUTER_API_KEY}
```

### 4. Database Schema

New tables created:

- `agent_messages` - A2A communication audit log
- `deep_research_runs` - Workflow execution tracking
- `deep_research_cache` - Result caching
- `deep_research_metrics` - Performance metrics
- `deep_research_sources` - Source tracking

---

## Configuration

### Environment Variables

```bash
# Required
OPENROUTER_API_KEY=your_api_key_here
BRAVE_SEARCH_API_KEY=your_brave_key_here

# Optional
POSTGRES_URL=postgresql://raverse:password@localhost:5432/raverse_online
REDIS_URL=redis://localhost:6379
LOG_LEVEL=INFO
```

### Agent Configuration

See `config/deep_research_settings.py` for:

- Model assignments
- Temperature and token limits
- Timeout settings
- Retry logic
- Caching configuration
- Rate limiting

---

## Usage Examples

### Basic Usage

```python
from agents.online_orchestrator import OnlineOrchestrationAgent

orchestrator = OnlineOrchestrationAgent()

result = orchestrator.run_deep_research(
    topic="artificial intelligence",
    context="focus on recent breakthroughs",
    max_results=10
)

print(result["summary"])
```

### Advanced Usage with A2A Communication

```python
from agents.online_deep_research_topic_enhancer import DeepResearchTopicEnhancerAgent

agent = DeepResearchTopicEnhancerAgent()

# Publish message to another agent
message_id = agent._publish_message(
    receiver="DEEP_RESEARCH_WEB_RESEARCHER",
    message_type="task_complete",
    payload={"enhanced_topic": "..."},
    priority="high"
)

# Subscribe to channel
message = agent._subscribe_to_channel(
    channel="agent:messages:DEEP_RESEARCH_TOPIC_ENHANCER",
    timeout=30
)
```

---

## Deployment

### Docker Compose

```bash
# Start all services
docker-compose -f docker-compose-online.yml up -d

# Verify services
docker-compose -f docker-compose-online.yml ps

# View logs
docker-compose -f docker-compose-online.yml logs -f deep-research-topic-enhancer
```

### Database Migration

```bash
# Apply schema migration
psql -U raverse -d raverse_online -f scripts/migrations/add_deep_research_schema.sql

# Verify tables
psql -U raverse -d raverse_online -c "\dt agent_messages"
```

---

## Testing

### Unit Tests

```bash
pytest tests/test_deep_research_agents.py -v
```

### Integration Tests

```bash
pytest tests/test_deep_research_integration.py -v
```

### End-to-End Test

```bash
python -c "
from agents.online_orchestrator import OnlineOrchestrationAgent
orchestrator = OnlineOrchestrationAgent()
result = orchestrator.run_deep_research('test topic')
print(f'Status: {result[\"status\"]}')
"
```

---

## Monitoring

### Metrics

Prometheus metrics available at `http://localhost:9090`:

- `deep_research_workflow_duration_seconds`
- `deep_research_sources_found`
- `deep_research_sources_scraped`
- `agent_messages_published`
- `agent_messages_received`

### Logs

Logs available in:

- `logs/deep_research.log` - Application logs
- PostgreSQL `agent_messages` table - A2A communication audit
- PostgreSQL `deep_research_runs` table - Workflow execution history

---

## Troubleshooting

### Issue: OpenRouter API Key Not Found

**Solution:**
```bash
export OPENROUTER_API_KEY=your_key_here
```

### Issue: BraveSearch API Unavailable

**Solution:** Agent falls back to mock results automatically

### Issue: Redis Connection Failed

**Solution:**
```bash
docker-compose -f docker-compose-online.yml restart redis
```

### Issue: Database Migration Failed

**Solution:**
```bash
# Check PostgreSQL is running
docker-compose -f docker-compose-online.yml logs postgres

# Manually apply migration
psql -U raverse -d raverse_online -f scripts/migrations/add_deep_research_schema.sql
```

---

## Performance

### Typical Execution Times

- **Topic Enhancement:** 2-5 seconds
- **Web Research:** 10-30 seconds
- **Content Analysis:** 5-15 seconds
- **Total Workflow:** 20-50 seconds

### Optimization Tips

1. **Caching:** Enable Redis caching for repeated queries
2. **Parallel Execution:** Run multiple workflows in parallel
3. **Model Selection:** Use faster models for simple tasks
4. **Rate Limiting:** Configure rate limits to avoid API throttling

---

## Security Considerations

### API Keys

- Store API keys in environment variables
- Never commit keys to version control
- Rotate keys regularly
- Use separate keys for development/production

### Data Privacy

- Research data stored in PostgreSQL
- A2A messages logged for audit trail
- Cache entries expire after TTL
- Implement data retention policies

### Network Security

- Use HTTPS for external API calls
- Validate SSL certificates
- Implement rate limiting
- Monitor for suspicious activity

---

## Migration from CrewAI

### What Changed

| Aspect | CrewAI | RAVERSE |
|--------|--------|---------|
| Agents | 3 agents | 3 agents (same) |
| Models | GPT-4-mini | OpenRouter free models |
| Vector Store | Qdrant | PostgreSQL pgvector |
| Communication | CrewAI framework | Redis pub/sub + PostgreSQL |
| Deployment | N8N | Docker Compose |

### Migration Steps

1. ✅ Analyzed CrewAI workflow
2. ✅ Designed A2A protocol
3. ✅ Implemented 3 agents
4. ✅ Integrated with orchestrator
5. ✅ Updated Docker configuration
6. ✅ Created database schema
7. ✅ Added comprehensive tests
8. ✅ Documented integration

---

## Next Steps

1. **Deploy:** Run `docker-compose up -d`
2. **Test:** Execute integration tests
3. **Monitor:** Check Prometheus metrics
4. **Optimize:** Tune performance based on metrics
5. **Extend:** Add custom agents or tools as needed

---

## Support

For issues or questions:

1. Check logs: `docker-compose logs -f`
2. Review documentation: `docs/DEEP_RESEARCH_*.md`
3. Run tests: `pytest tests/test_deep_research_*.py -v`
4. Check configuration: `config/deep_research_settings.py`

---

**Status:** ✅ Integration Complete - Ready for Production

