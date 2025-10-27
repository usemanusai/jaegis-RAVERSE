# TASK 6: Agent-to-Agent (A2A) Protocol Research & Implementation

**Date:** October 26, 2025  
**Status:** IN_PROGRESS  

---

## PART 1: A2A PROTOCOL RESEARCH FINDINGS

### Industry Standards Overview

#### 1. FIPA-ACL (Foundation for Intelligent Physical Agents)
- **Era:** 1990s-2000s (established standard)
- **Semantics:** Mental-state semantics (beliefs, desires, intentions)
- **Format:** Lisp-like syntax
- **Pros:** Comprehensive, well-documented, formal semantics
- **Cons:** Complex, verbose, less suitable for modern web services
- **Use Case:** Enterprise agent systems, formal verification

#### 2. KQML (Knowledge Query and Manipulation Language)
- **Era:** 1990s (predecessor to FIPA-ACL)
- **Semantics:** Mental-state semantics
- **Format:** Lisp-like syntax
- **Pros:** Pioneering standard, influenced modern protocols
- **Cons:** Outdated, limited adoption
- **Use Case:** Legacy systems, academic research

#### 3. Google's A2A Protocol (Modern)
- **Era:** 2024-2025 (latest)
- **Semantics:** Structured communication with JSON
- **Format:** JSON-based messages
- **Pros:** Simple, modern, web-friendly, minimal overhead
- **Cons:** Newer, less formal semantics
- **Use Case:** Cloud-native agents, microservices

#### 4. RESTful Agent APIs
- **Era:** 2010s-present
- **Semantics:** HTTP-based request/response
- **Format:** JSON over HTTP
- **Pros:** Simple, widely understood, easy to implement
- **Cons:** Synchronous, not ideal for async messaging
- **Use Case:** Simple agent interactions, webhooks

#### 5. Message Queue Protocols (AMQP, MQTT)
- **Era:** 2000s-present
- **Semantics:** Publish/subscribe, async messaging
- **Format:** Binary or JSON
- **Pros:** Async, scalable, reliable delivery
- **Cons:** Requires message broker infrastructure
- **Use Case:** Distributed systems, event-driven architectures

---

## PART 2: RECOMMENDATION FOR RAVERSE 2.0

### Selected Protocol: **Hybrid JSON-based A2A**

**Rationale:**
- ✅ Simple and modern (JSON format)
- ✅ Compatible with existing Redis/PostgreSQL infrastructure
- ✅ Async messaging via Redis pub/sub
- ✅ Structured communication with clear semantics
- ✅ Easy to extend and customize
- ✅ Production-ready for cloud deployment

### Architecture

```
┌─────────────────────────────────────────────────────┐
│         RAVERSE 2.0 A2A Protocol Stack              │
├─────────────────────────────────────────────────────┤
│ Layer 1: Message Format (JSON)                      │
│ Layer 2: Transport (Redis pub/sub + PostgreSQL)     │
│ Layer 3: Semantics (Agent state + intent)           │
│ Layer 4: Orchestration (Agent coordinator)          │
└─────────────────────────────────────────────────────┘
```

---

## PART 3: MESSAGE FORMAT SPECIFICATION

### A2A Message Schema (JSON)

```json
{
  "message_id": "uuid-v4",
  "timestamp": "2025-10-26T12:34:56Z",
  "sender": "agent_0",
  "receiver": "agent_1",
  "message_type": "request|response|notification|error",
  "action": "analyze|execute|report|validate",
  "payload": {
    "data": {},
    "context": {},
    "metadata": {}
  },
  "correlation_id": "uuid-v4",
  "priority": "high|normal|low",
  "timeout_seconds": 300,
  "retry_count": 0,
  "status": "pending|processing|completed|failed"
}
```

### Message Types

1. **Request** - Agent A asks Agent B to perform action
2. **Response** - Agent B returns result to Agent A
3. **Notification** - Agent broadcasts event to all agents
4. **Error** - Agent reports failure with error details

---

## PART 4: IMPLEMENTATION COMPONENTS

### Component 1: A2A Message Handler
- Location: `utils/a2a_protocol.py`
- Responsibility: Message serialization/deserialization
- Methods: `create_message()`, `parse_message()`, `validate_message()`

### Component 2: Agent Communication Mixin
- Location: `agents/a2a_mixin.py`
- Responsibility: Add A2A capabilities to agents
- Methods: `send_message()`, `receive_message()`, `broadcast()`

### Component 3: Message Broker
- Location: `utils/message_broker.py`
- Responsibility: Redis pub/sub management
- Methods: `publish()`, `subscribe()`, `unsubscribe()`

### Component 4: Agent Registry
- Location: `utils/agent_registry.py`
- Responsibility: Track active agents and their capabilities
- Methods: `register_agent()`, `unregister_agent()`, `get_agent_info()`

### Component 5: Orchestrator Integration
- Location: `agents/online_orchestrator.py` (update)
- Responsibility: Coordinate agent communication
- Methods: `route_message()`, `handle_response()`, `manage_workflow()`

---

## PART 5: REDIS CHANNEL STRUCTURE

```
raverse:a2a:messages:{agent_id}        # Agent-specific inbox
raverse:a2a:broadcast                  # Broadcast channel
raverse:a2a:errors                     # Error notifications
raverse:a2a:metrics                    # Performance metrics
raverse:a2a:state:{agent_id}           # Agent state updates
```

---

## PART 6: POSTGRESQL SCHEMA ADDITIONS

### Table: agent_messages
```sql
CREATE TABLE agent_messages (
  id UUID PRIMARY KEY,
  sender VARCHAR(255),
  receiver VARCHAR(255),
  message_type VARCHAR(50),
  action VARCHAR(100),
  payload JSONB,
  status VARCHAR(50),
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  INDEX (sender, receiver, created_at)
);
```

### Table: agent_registry
```sql
CREATE TABLE agent_registry (
  id UUID PRIMARY KEY,
  agent_name VARCHAR(255) UNIQUE,
  agent_type VARCHAR(100),
  status VARCHAR(50),
  capabilities JSONB,
  last_heartbeat TIMESTAMP,
  created_at TIMESTAMP
);
```

---

## PART 7: IMPLEMENTATION PHASES

### Phase 1: Core A2A Protocol (Week 1)
- ✅ Define message schema
- ✅ Implement message handler
- ✅ Create message broker
- ✅ Add agent registry

### Phase 2: Agent Integration (Week 2)
- ⏳ Create A2A mixin
- ⏳ Update OnlineBaseAgent
- ⏳ Implement send/receive methods
- ⏳ Add error handling

### Phase 3: Orchestrator Wiring (Week 3)
- ⏳ Update online_orchestrator.py
- ⏳ Implement message routing
- ⏳ Add workflow coordination
- ⏳ Create agent lifecycle management

### Phase 4: Testing & Validation (Week 4)
- ⏳ Unit tests for A2A protocol
- ⏳ Integration tests for agent communication
- ⏳ End-to-end workflow tests
- ⏳ Performance benchmarks

---

## NEXT STEPS

1. ✅ Research A2A protocols (COMPLETE)
2. ⏳ Implement A2A message handler
3. ⏳ Create agent communication mixin
4. ⏳ Wire orchestrator
5. ⏳ Write tests
6. ⏳ Document integration


