# Agent-to-Agent (A2A) Communication Protocol Design

**Date:** October 26, 2025  
**Status:** Phase 1.2 - Protocol Design Complete  
**Selected Protocol:** Redis Pub/Sub with PostgreSQL Audit Log

---

## Executive Summary

After researching FIPA-ACL, KQML, agent:// URI protocol, and event-driven architectures, we selected **Redis Pub/Sub** as the primary A2A communication mechanism for RAVERSE Online because:

✅ Already in RAVERSE infrastructure (Redis 8.2)  
✅ Low latency (<1ms) for agent coordination  
✅ Supports publish/subscribe pattern (natural for multi-agent)  
✅ Integrates with existing caching layer  
✅ PostgreSQL audit log for compliance & debugging  

---

## Protocol Overview

### Architecture

```
Agent A                    Redis Pub/Sub                  Agent B
   │                            │                            │
   ├─ Publish Message ─────────>│                            │
   │                            ├─ Route to Subscribers ────>│
   │                            │                            │
   │                       PostgreSQL Audit Log              │
   │                            │                            │
   │<─ Subscribe to Response ───┤<─ Publish Response ────────┤
   │                            │                            │
```

### Message Flow

1. **Agent A** publishes message to Redis channel: `agent:messages:{receiver_agent}`
2. **Redis** routes message to all subscribers
3. **Agent B** receives message from subscription
4. **PostgreSQL** logs message for audit trail
5. **Agent B** processes and publishes response
6. **Agent A** receives response from subscription

---

## Message Schema

### Standard Message Format

```json
{
  "message_id": "550e8400-e29b-41d4-a716-446655440000",
  "sender_agent": "deep_research_web_researcher",
  "receiver_agent": "deep_research_content_analyzer",
  "message_type": "task_complete|data_request|error|status_update|ack",
  "payload": {
    "data": {
      "research_findings": [...],
      "sources": [...],
      "metadata": {}
    },
    "metadata": {
      "timestamp": "2025-10-26T10:30:00Z",
      "version": "1.0"
    }
  },
  "timestamp": "2025-10-26T10:30:00Z",
  "correlation_id": "run-uuid-12345",
  "priority": "high|normal|low",
  "ttl_seconds": 3600,
  "retry_count": 0,
  "max_retries": 3
}
```

### Message Types

| Type | Purpose | Sender | Receiver |
|------|---------|--------|----------|
| `task_complete` | Task finished, results ready | Any | Orchestrator/Next Agent |
| `data_request` | Request data from another agent | Any | Any |
| `data_share` | Share data without request | Any | Any |
| `error` | Error occurred during execution | Any | Orchestrator |
| `status_update` | Progress update | Any | Orchestrator |
| `ack` | Acknowledge receipt | Any | Sender |

---

## Redis Channel Design

### Channel Naming Convention

```
agent:messages:{agent_name}          # Per-agent inbox
agent:broadcast                       # System-wide announcements
agent:errors                          # Error channel
agent:metrics                         # Metrics channel
agent:deadletter                      # Failed messages
```

### Example Channels

```
agent:messages:deep_research_web_researcher
agent:messages:deep_research_content_analyzer
agent:messages:deep_research_topic_enhancer
agent:broadcast
agent:errors
agent:deadletter
```

---

## Communication Patterns

### Pattern 1: Sequential Task Handoff

```
Topic Enhancer → Web Researcher → Content Analyzer → Orchestrator
```

**Implementation:**
1. Topic Enhancer publishes `task_complete` to `agent:messages:deep_research_web_researcher`
2. Web Researcher receives, processes, publishes `task_complete` to `agent:messages:deep_research_content_analyzer`
3. Content Analyzer receives, processes, publishes `task_complete` to `agent:messages:orchestrator`

### Pattern 2: Parallel Data Gathering

```
Web Researcher ──┐
                 ├─> Content Analyzer
API Analyzer ────┘
```

**Implementation:**
1. Both agents publish `data_share` to `agent:messages:deep_research_content_analyzer`
2. Content Analyzer waits for all messages (with timeout)
3. Processes combined data

### Pattern 3: Error Recovery

```
Agent A → Error → Orchestrator → Retry Agent A
```

**Implementation:**
1. Agent publishes `error` to `agent:errors`
2. Orchestrator receives error
3. Publishes retry task to agent's inbox
4. Agent retries with exponential backoff

---

## PostgreSQL Audit Log Schema

```sql
CREATE TABLE agent_messages (
    message_id UUID PRIMARY KEY,
    sender_agent VARCHAR(255) NOT NULL,
    receiver_agent VARCHAR(255) NOT NULL,
    message_type VARCHAR(50) NOT NULL,
    payload JSONB NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    correlation_id UUID NOT NULL,
    priority VARCHAR(20),
    status VARCHAR(50),
    retry_count INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    INDEX idx_correlation_id (correlation_id),
    INDEX idx_sender_agent (sender_agent),
    INDEX idx_receiver_agent (receiver_agent),
    INDEX idx_timestamp (timestamp)
);
```

---

## Error Handling & Retry Logic

### Retry Strategy

```
Attempt 1: Immediate
Attempt 2: Wait 1 second
Attempt 3: Wait 2 seconds
Attempt 4: Wait 4 seconds (max 3 retries = 7 seconds total)
```

### Dead Letter Queue

Messages that fail after max retries go to `agent:deadletter` for manual review.

---

## Implementation in OnlineBaseAgent

### New Methods

```python
def _publish_message(self, receiver: str, message_type: str, 
                    payload: Dict, priority: str = "normal") -> str:
    """Publish A2A message via Redis pub/sub."""
    message = {
        "message_id": str(uuid.uuid4()),
        "sender_agent": self.agent_type,
        "receiver_agent": receiver,
        "message_type": message_type,
        "payload": payload,
        "timestamp": datetime.utcnow().isoformat(),
        "correlation_id": self.run_id,
        "priority": priority,
        "ttl_seconds": 3600,
        "retry_count": 0,
        "max_retries": 3
    }
    
    # Publish to Redis
    channel = f"agent:messages:{receiver}"
    self.redis_client.publish(channel, json.dumps(message))
    
    # Log to PostgreSQL
    self._save_message_to_db(message)
    
    return message["message_id"]

def _subscribe_to_channel(self, channel: str, 
                         callback: Callable) -> None:
    """Subscribe to Redis channel with callback."""
    pubsub = self.redis_client.pubsub()
    pubsub.subscribe(channel)
    
    for message in pubsub.listen():
        if message["type"] == "message":
            try:
                data = json.loads(message["data"])
                callback(data)
            except Exception as e:
                self.logger.error(f"Error processing message: {e}")

def _save_message_to_db(self, message: Dict) -> None:
    """Save message to PostgreSQL audit log."""
    # Implementation in Phase 3
    pass
```

---

## Advantages & Trade-offs

### Advantages
✅ Low latency (<1ms)  
✅ Already in infrastructure  
✅ Simple to implement  
✅ Scales horizontally  
✅ PostgreSQL audit trail  

### Trade-offs
⚠️ No message persistence (Redis memory only)  
⚠️ No guaranteed delivery (fire-and-forget)  
⚠️ No ordering guarantees across channels  

### Mitigation
- PostgreSQL audit log provides persistence
- Retry logic with exponential backoff
- Correlation IDs for tracking

---

## Next Steps

1. **Phase 1.3:** Review existing RAVERSE architecture
2. **Phase 2:** Implement tool migration
3. **Phase 3:** Implement A2A in OnlineBaseAgent
4. **Phase 4:** Update infrastructure
5. **Phase 5:** Test A2A communication
6. **Phase 6:** Document and finalize

---

**Status:** ✅ Protocol Design Complete - Ready for Phase 1.3 (Architecture Review)

