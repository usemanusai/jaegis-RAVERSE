# RAVERSE 2.0 - System Architecture

**Date:** October 25, 2025  
**Version:** 2.0.0

---

## 🏗️ High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     RAVERSE 2.0 SYSTEM                          │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Enhanced Orchestrator                        │  │
│  │  (Coordinates all agents and manages workflow)           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                │
│         │                  │                  │                │
│    ┌────▼────┐      ┌─────▼─────┐     ┌─────▼─────┐          │
│    │Disassem │      │  Pattern  │     │    LLM    │          │
│    │  Agent  │      │   Agent   │     │   Agent   │          │
│    └────┬────┘      └─────┬─────┘     └─────┬─────┘          │
│         │                  │                  │                │
│         └──────────────────┼──────────────────┘                │
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                │
│         │                  │                  │                │
│    ┌────▼────┐      ┌─────▼─────┐     ┌─────▼─────┐          │
│    │  Patch  │      │Validation │     │ Semantic  │          │
│    │Generator│      │   Agent   │     │  Search   │          │
│    └─────────┘      └───────────┘     └───────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
    ┌────▼────┐      ┌─────▼─────┐     ┌─────▼─────┐
    │PostgreSQL│      │   Redis   │     │Prometheus │
    │ +pgvector│      │   Cache   │     │  Metrics  │
    └──────────┘      └───────────┘     └───────────┘
```

---

## 🔄 Data Flow

### 1. Analysis Workflow

```
Binary File
    │
    ▼
┌─────────────────┐
│ Binary Analyzer │
│  (PE/ELF)       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Disassembly     │
│ Agent           │
│ (Capstone)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Pattern Agent   │
│ (Recognition)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ LLM Agent       │
│ (Analysis)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Semantic Search │
│ (Embeddings)    │
└────────┬────────┘
         │
         ▼
    Analysis
    Results
```

### 2. Patching Workflow

```
Analysis Results
    │
    ▼
┌─────────────────┐
│ Patch Generator │
│ (6 Strategies)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Patch           │
│ Application     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Validation      │
│ Agent           │
└────────┬────────┘
         │
         ▼
    Patched
    Binary
```

---

## 🗄️ Database Schema

### Tables

```
raverse.binaries
├── id (PK)
├── file_name
├── file_hash (UNIQUE)
├── file_size
├── file_type
├── architecture
└── status

raverse.disassembly_cache
├── id (PK)
├── binary_id (FK)
├── address
├── opcode
├── operands
├── instruction
├── embedding (vector(384))
└── metadata (JSONB)

raverse.code_embeddings
├── id (PK)
├── binary_hash
├── code_snippet
├── embedding (vector(384))
├── metadata (JSONB)
└── created_at

raverse.patch_strategies
├── id (PK)
├── strategy_type
├── target_address
├── pattern_embedding (vector(384))
├── success_count
├── failure_count
├── success_rate (COMPUTED)
└── metadata (JSONB)

raverse.llm_cache
├── id (PK)
├── prompt_hash (UNIQUE)
├── model_name
├── response
├── access_count
└── last_accessed_at

raverse.cache_entries
├── id (PK)
├── namespace
├── key
├── value (BYTEA)
├── expires_at
└── created_at
```

---

## 🔌 Agent Architecture

### Disassembly Agent
```
┌──────────────────────────┐
│   Disassembly Agent      │
├──────────────────────────┤
│ • Capstone integration   │
│ • Function detection     │
│ • Control flow analysis  │
│ • String references      │
│ • Caching support        │
└──────────────────────────┘
```

### Pattern Agent
```
┌──────────────────────────┐
│     Pattern Agent        │
├──────────────────────────┤
│ • 5 pre-defined patterns │
│ • Regex matching         │
│ • LLM enhancement        │
│ • Confidence scoring     │
│ • Report generation      │
└──────────────────────────┘
```

### LLM Agent
```
┌──────────────────────────┐
│       LLM Agent          │
├──────────────────────────┤
│ • OpenRouter API         │
│ • FREE models default    │
│ • LangChain framework    │
│ • Response caching       │
│ • Rate limiting          │
└──────────────────────────┘
```

### Patch Generator
```
┌──────────────────────────┐
│    Patch Generator       │
├──────────────────────────┤
│ • 6 patch strategies     │
│ • NOP, JMP, RET, etc.    │
│ • Automatic application  │
│ • Success tracking       │
│ • Learning mechanism     │
└──────────────────────────┘
```

### Validation Agent
```
┌──────────────────────────┐
│   Validation Agent       │
├──────────────────────────┤
│ • Integrity validation   │
│ • Structure validation   │
│ • Disassembly check      │
│ • Execution testing      │
│ • Comprehensive reports  │
└──────────────────────────┘
```

---

## 💾 Caching Architecture

### Multi-Level Cache

```
┌─────────────────────────────────────────┐
│           Application Request           │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│  L1: In-Memory LRU Cache (1000 items)   │
│  • <1ms latency                         │
│  • Thread-safe                          │
│  • Automatic eviction                   │
└──────────────┬──────────────────────────┘
               │ Cache Miss
               ▼
┌─────────────────────────────────────────┐
│  L2: Redis Cache (1-hour TTL)           │
│  • <10ms latency                        │
│  • Shared across instances              │
│  • Automatic expiration                 │
└──────────────┬──────────────────────────┘
               │ Cache Miss
               ▼
┌─────────────────────────────────────────┐
│  L3: PostgreSQL Cache (24-hour TTL)     │
│  • <100ms latency                       │
│  • Persistent storage                   │
│  • Automatic cleanup                    │
└──────────────┬──────────────────────────┘
               │ Cache Miss
               ▼
         Compute Value
               │
               ▼
    Store in All Levels
```

---

## 📊 Monitoring Architecture

### Metrics Collection

```
┌─────────────────────────────────────────┐
│         Application Metrics             │
│  • Patches (total, success, failed)     │
│  • API calls (by provider, model)       │
│  • Cache hits/misses                    │
│  • Durations (patch, API, embedding)    │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│          Prometheus Server              │
│  • Scrapes metrics every 15s            │
│  • Stores time-series data              │
│  • Provides query interface             │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│           Grafana Dashboards            │
│  • 8 visualization panels               │
│  • Real-time updates                    │
│  • Alerting support                     │
└─────────────────────────────────────────┘
```

### Exporters

```
PostgreSQL ──► postgres-exporter ──► Prometheus
Redis      ──► redis-exporter    ──► Prometheus
Containers ──► cAdvisor          ──► Prometheus
System     ──► node-exporter     ──► Prometheus
```

---

## 🔐 Security Architecture

### Data Flow Security

```
User Input
    │
    ▼
┌─────────────────┐
│  Input          │
│  Validation     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Binary         │
│  Verification   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Sandboxed      │
│  Analysis       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Patch          │
│  Validation     │
└────────┬────────┘
         │
         ▼
    Safe Output
```

---

## 🐳 Docker Architecture

### Services

```
┌─────────────────────────────────────────┐
│         Docker Compose Stack            │
├─────────────────────────────────────────┤
│                                         │
│  Application Layer:                     │
│  ├── raverse-app (Python 3.11)          │
│                                         │
│  Data Layer:                            │
│  ├── raverse-postgres (PostgreSQL 17)   │
│  ├── raverse-redis (Redis 8.2)          │
│                                         │
│  Monitoring Layer:                      │
│  ├── raverse-prometheus                 │
│  ├── raverse-grafana                    │
│  ├── raverse-postgres-exporter          │
│  ├── raverse-redis-exporter             │
│  ├── raverse-cadvisor                   │
│  └── raverse-node-exporter              │
│                                         │
│  Development Layer (profile: dev):      │
│  ├── raverse-pgadmin                    │
│  └── raverse-redisinsight               │
└─────────────────────────────────────────┘
```

---

## 🔄 Deployment Architecture

### Production Deployment

```
┌─────────────────────────────────────────┐
│          Load Balancer (Optional)       │
└──────────────┬──────────────────────────┘
               │
    ┌──────────┴──────────┐
    │                     │
    ▼                     ▼
┌─────────┐         ┌─────────┐
│ RAVERSE │         │ RAVERSE │
│Instance1│         │Instance2│
└────┬────┘         └────┬────┘
     │                   │
     └─────────┬─────────┘
               │
    ┌──────────┴──────────┐
    │                     │
    ▼                     ▼
┌─────────┐         ┌─────────┐
│PostgreSQL│         │  Redis  │
│ Primary  │         │ Cluster │
└────┬────┘         └─────────┘
     │
     ▼
┌─────────┐
│PostgreSQL│
│ Replica  │
└─────────┘
```

---

## 📈 Scalability

### Horizontal Scaling

- **Application:** Multiple instances behind load balancer
- **Redis:** Redis Cluster for distributed caching
- **PostgreSQL:** Read replicas for query distribution
- **Monitoring:** Prometheus federation for multi-cluster

### Vertical Scaling

- **CPU:** Multi-core for parallel processing
- **RAM:** 16-32GB for in-memory caching
- **Disk:** SSD for database performance
- **Network:** High bandwidth for API calls

---

## 🎯 Performance Optimization

### Query Optimization

- HNSW indexes for vector search (O(log n))
- GIN indexes for JSONB queries
- Composite indexes for common queries
- Connection pooling (pgBouncer)

### Caching Strategy

- L1: Hot data (>90% hit rate)
- L2: Warm data (>80% hit rate)
- L3: Cold data (>70% hit rate)
- Cache warming on startup

### Batch Processing

- Embedding generation (batch size: 32)
- Database inserts (bulk operations)
- API calls (request batching)

---

**Architecture Date:** October 25, 2025  
**Version:** 2.0.0  
**Status:** Production Ready

