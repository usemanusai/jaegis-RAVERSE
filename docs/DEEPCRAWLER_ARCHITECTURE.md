# DeepCrawler Architecture Design - RAVERSE 2.0 Integration

**Design Date**: October 26, 2025  
**Status**: Phase 1, Task 1.3 Complete

---

## 1. AGENT ARCHITECTURE DECISION

### Chosen Approach: Hybrid (Extend + Create New)

**Strategy**:
1. **Extend** JavaScriptAnalysisAgent → API-specific pattern matching
2. **Extend** TrafficInterceptionAgent → WebSocket + API classification
3. **Create** DeepCrawlerAgent → Orchestrator for API discovery
4. **Create** Utility classes → URL frontier, deduplication, etc.

**Rationale**:
- Leverages 80% of existing code
- Clean separation of concerns
- Maintains RAVERSE patterns
- Enables specialized agent coordination

---

## 2. API DISCOVERY PIPELINE

### Step 1: Initialization
```
User Input (target URL, max depth, scope)
    ↓
DeepCrawlerAgent (Orchestrator)
    ├─ Validate authorization
    ├─ Initialize URL frontier
    ├─ Create crawl session (DB)
    └─ Start crawl
```

### Step 2: Navigation & Interaction
```
NavigationAgent (Extended from existing)
    ├─ Navigate to URL
    ├─ Identify interactive elements
    ├─ Click/fill/submit
    └─ Trigger dynamic content
```

### Step 3: Network Monitoring
```
TrafficInterceptionAgent (Extended)
    ├─ Intercept HTTP/HTTPS requests
    ├─ Capture WebSocket frames
    ├─ Extract authentication
    └─ Log all API calls
```

### Step 4: Code Analysis
```
JavaScriptAnalysisAgent (Extended)
    ├─ Download JS files
    ├─ Parse AST
    ├─ Find API patterns
    └─ Extract URL construction logic
```

### Step 5: API Classification
```
ResponseClassifier (New Utility)
    ├─ Detect JSON/XML/GraphQL
    ├─ Identify API-like structures
    ├─ Score confidence
    └─ Store in database
```

### Step 6: Documentation
```
APIDocumentationAgent (New)
    ├─ Collect discovered APIs
    ├─ Generate schemas (Pydantic)
    └─ Create OpenAPI spec
```

---

## 3. CRAWLING STRATEGY

### URL Frontier Management
```python
# Priority Queue Structure
{
    "url": "https://example.com/api/users",
    "depth": 2,
    "priority": 0.85,  # Higher = crawl first
    "status": "pending",  # pending, crawled, failed
    "discovered_by": "dynamic",  # dynamic, static, websocket
    "timestamp": "2025-10-26T10:00:00Z"
}

# Priority Calculation
priority = (
    (max_depth - current_depth) * 0.5 +  # Prefer shallower URLs
    (is_api_pattern * 0.3) +              # Prefer API-like URLs
    (discovery_recency * 0.2)             # Prefer recently discovered
)
```

### Intelligent Prioritization
1. **Depth-Based**: Shallower URLs first (breadth-first tendency)
2. **Pattern-Based**: API-like URLs prioritized
3. **Recency-Based**: Recently discovered URLs prioritized
4. **Interaction-Based**: URLs from interactive elements prioritized

### Deduplication Strategy
```python
# URL Normalization
def normalize_url(url):
    # Remove fragments
    # Sort query parameters
    # Lowercase domain
    # Remove trailing slashes
    return normalized_url

# Duplicate Detection
url_hash = sha256(normalize_url(url))
if url_hash in seen_urls:
    skip_crawl()
else:
    add_to_frontier()
```

---

## 4. API ENDPOINT DETECTION

### Pattern Matching Rules
```python
API_PATTERNS = [
    r"/api/",
    r"/v\d+/",
    r"/graphql",
    r"/rest/",
    r"/services/",
    r"/endpoint/",
    r"\.json$",
    r"\.xml$",
]

# Scoring
confidence = 0.0
if matches_pattern: confidence += 0.4
if json_response: confidence += 0.3
if auth_required: confidence += 0.2
if consistent_structure: confidence += 0.1
```

### JavaScript Code Analysis
```python
# Patterns to find in AST
patterns = [
    "fetch('/api/...')",
    "XMLHttpRequest.open('GET', '/api/...')",
    "axios.get('/api/...')",
    "const BASE_URL = '/api'",
    "const endpoint = '/api/' + id",
]

# Extract and validate
for pattern in patterns:
    if found_in_ast:
        extract_url()
        validate_with_dynamic_analysis()
```

### WebSocket Detection
```python
# Handshake Detection
if response.status == 101:  # Switching Protocols
    websocket_detected = True
    
# Frame Inspection
for frame in websocket_frames:
    if is_json(frame):
        parse_json()
        extract_api_patterns()
```

---

## 5. STATE MANAGEMENT

### Crawl Session State
```python
{
    "session_id": "uuid",
    "target_url": "https://example.com",
    "status": "running",  # running, completed, failed
    "start_time": "2025-10-26T10:00:00Z",
    "end_time": null,
    "max_depth": 3,
    "urls_crawled": 45,
    "urls_discovered": 120,
    "apis_found": 23,
    "errors": []
}
```

### Discovered API State
```python
{
    "session_id": "uuid",
    "endpoint_url": "https://api.example.com/v1/users",
    "http_method": "GET",
    "confidence_score": 0.95,
    "discovery_method": "dynamic",  # dynamic, static, websocket
    "request_headers": {...},
    "request_body_example": {...},
    "response_body_example": {...},
    "authentication": "Bearer token",
    "discovered_at": "2025-10-26T10:05:00Z"
}
```

---

## 6. DATABASE SCHEMA

### Tables
```sql
-- Crawl Sessions
CREATE TABLE crawl_sessions (
    id SERIAL PRIMARY KEY,
    session_id UUID UNIQUE NOT NULL,
    target_url TEXT NOT NULL,
    max_depth INTEGER DEFAULT 3,
    status VARCHAR(50) DEFAULT 'running',
    urls_crawled INTEGER DEFAULT 0,
    apis_found INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- URL Frontier
CREATE TABLE crawl_urls (
    id SERIAL PRIMARY KEY,
    session_id UUID REFERENCES crawl_sessions(session_id),
    url TEXT NOT NULL,
    depth INTEGER NOT NULL,
    priority FLOAT DEFAULT 0.5,
    status VARCHAR(50) DEFAULT 'pending',
    discovered_by VARCHAR(50),
    crawled_at TIMESTAMP,
    UNIQUE(session_id, url)
);

-- Discovered APIs
CREATE TABLE discovered_apis (
    id SERIAL PRIMARY KEY,
    session_id UUID REFERENCES crawl_sessions(session_id),
    endpoint_url TEXT NOT NULL,
    http_method VARCHAR(10),
    confidence_score FLOAT,
    discovery_method VARCHAR(100),
    request_example JSONB,
    response_example JSONB,
    authentication TEXT,
    discovered_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(session_id, endpoint_url, http_method)
);

-- Crawl History (Audit Trail)
CREATE TABLE crawl_history (
    id SERIAL PRIMARY KEY,
    session_id UUID REFERENCES crawl_sessions(session_id),
    event_type VARCHAR(100),
    event_data JSONB,
    timestamp TIMESTAMP DEFAULT NOW()
);
```

---

## 7. INTEGRATION WITH EXISTING SYSTEMS

### Memory System Integration
```python
# Use "medium" preset (hierarchical)
agent = DeepCrawlerAgent(
    memory_strategy="hierarchical",
    memory_config={
        "window_size": 3,
        "k": 2
    }
)

# Store crawl context
agent.add_to_memory(
    user_input=f"Crawl {target_url}",
    ai_response=json.dumps(discovered_apis)
)

# Retrieve context for next crawl
context = agent.get_memory_context(target_url)
```

### Redis Integration
```python
# Rate limiting per domain
redis.incr(f"crawl:domain:{domain}:requests")
redis.expire(f"crawl:domain:{domain}:requests", 60)

# Distributed state
redis.set(f"crawl:session:{session_id}:state", state_json)

# Shared URL frontier (for distributed crawling)
redis.zadd(f"crawl:frontier:{session_id}", {url: priority})
```

### LLM Integration
```python
# Model assignments
models = {
    "orchestrator": "qwen/qwen3-235b-a22b:free",
    "code_analysis": "deepseek/deepseek-v3-0324:free",
    "network_analysis": "tng/deepseek-r1t2-chimera:free",
    "captcha_solving": "openrouter/andromeda-alpha"
}

# Token-frugal usage
# Only call LLM for:
# - Complex decision making
# - Code analysis
# - CAPTCHA solving
# NOT for: JSON parsing, URL extraction, etc.
```

---

## 8. CONFIGURATION STRUCTURE

### DeepCrawler Config
```python
DEEPCRAWLER_CONFIG = {
    # Crawl Parameters
    "max_depth": 3,
    "max_urls_per_domain": 1000,
    "concurrent_requests": 5,
    "request_timeout": 30,
    
    # Politeness
    "respect_robots_txt": True,
    "rate_limit_per_domain": 1.0,  # seconds
    "user_agent": "RAVERSE-DeepCrawler/2.0",
    
    # API Discovery
    "api_patterns": [
        r"/api/",
        r"/v\d+/",
        r"/graphql",
    ],
    
    # Features
    "javascript_execution": True,
    "websocket_inspection": True,
    "network_interception": True,
    "captcha_solving": True,
    
    # Memory
    "memory_preset": "medium",
    
    # Output
    "generate_openapi": True,
    "export_format": "yaml",  # yaml or json
}
```

---

## 9. ERROR HANDLING & RESILIENCE

### Retry Strategy
```python
# Exponential backoff
retry_delays = [1, 2, 4, 8, 16]  # seconds

for attempt in range(5):
    try:
        response = fetch_url(url)
        break
    except Exception as e:
        if attempt < 4:
            time.sleep(retry_delays[attempt])
        else:
            log_error(url, e)
            mark_failed(url)
```

### Rate Limit Handling
```python
# 429 Too Many Requests
if response.status == 429:
    retry_after = response.headers.get('Retry-After', 60)
    time.sleep(int(retry_after))
    retry_request()
```

### Timeout Handling
```python
# Per-request timeout
try:
    response = fetch_url(url, timeout=30)
except TimeoutError:
    mark_failed(url)
    continue_crawl()
```

---

## 10. SECURITY & AUTHORIZATION

### Authorization Checks
```python
# Before crawling
if not validate_authorization(target_url, scope):
    raise UnauthorizedError("Target not in authorized scope")

# Respect robots.txt
if url_in_robots_disallowed(url):
    skip_url()

# Rate limiting compliance
if exceeds_rate_limit(domain):
    wait_and_retry()
```

### Authentication Handling
```python
# Capture during login
captured_auth = {
    "cookies": response.headers.get('Set-Cookie'),
    "bearer_token": extract_token(response.body),
    "api_key": extract_api_key(response.body),
}

# Apply to subsequent requests
for request in subsequent_requests:
    request.headers.update(captured_auth)
```

---

## 11. COMPONENT SPECIFICATIONS

### DeepCrawlerAgent (Orchestrator)
- **Responsibility**: Coordinate crawl, manage state, aggregate results
- **Inputs**: target_url, max_depth, scope
- **Outputs**: discovered_apis, openapi_spec
- **Dependencies**: All worker agents, database, Redis

### Extended JavaScriptAnalysisAgent
- **New Capability**: API pattern extraction from AST
- **New Methods**: extract_api_patterns(), validate_endpoints()
- **Integration**: Called by DeepCrawlerAgent during crawl

### Extended TrafficInterceptionAgent
- **New Capability**: WebSocket frame inspection, API classification
- **New Methods**: inspect_websocket(), classify_response()
- **Integration**: Runs in parallel with navigation

### URL Frontier (Utility)
- **Responsibility**: Manage crawl queue with priority
- **Methods**: add(), pop(), is_duplicate(), normalize()
- **Storage**: In-memory + Redis for distributed crawling

### Response Classifier (Utility)
- **Responsibility**: Classify responses as API or not
- **Methods**: classify(), score_confidence(), extract_schema()
- **Output**: Confidence score + API metadata

---

## 12. DATA FLOW DIAGRAM

```
┌─────────────────────────────────────────────────────────────┐
│ User Input: target_url, max_depth, scope                   │
└────────────────────┬────────────────────────────────────────┘
                     ↓
        ┌────────────────────────────┐
        │ DeepCrawlerAgent           │
        │ (Orchestrator)             │
        └────────────┬───────────────┘
                     ↓
        ┌────────────────────────────┐
        │ Initialize Crawl Session   │
        │ Create URL Frontier        │
        └────────────┬───────────────┘
                     ↓
        ┌────────────────────────────────────────────────────┐
        │ Crawl Loop (while URLs in frontier)                │
        ├────────────────────────────────────────────────────┤
        │                                                    │
        │  ┌──────────────────────────────────────────────┐ │
        │  │ NavigationAgent                              │ │
        │  │ - Navigate to URL                            │ │
        │  │ - Identify interactive elements              │ │
        │  │ - Trigger interactions                       │ │
        │  └──────────────────────────────────────────────┘ │
        │                     ↓                              │
        │  ┌──────────────────────────────────────────────┐ │
        │  │ TrafficInterceptionAgent (Extended)          │ │
        │  │ - Capture HTTP/HTTPS requests                │ │
        │  │ - Inspect WebSocket frames                   │ │
        │  │ - Extract authentication                     │ │
        │  └──────────────────────────────────────────────┘ │
        │                     ↓                              │
        │  ┌──────────────────────────────────────────────┐ │
        │  │ JavaScriptAnalysisAgent (Extended)           │ │
        │  │ - Download JS files                          │ │
        │  │ - Parse AST                                  │ │
        │  │ - Extract API patterns                       │ │
        │  └──────────────────────────────────────────────┘ │
        │                     ↓                              │
        │  ┌──────────────────────────────────────────────┐ │
        │  │ ResponseClassifier                           │ │
        │  │ - Classify as API or not                     │ │
        │  │ - Score confidence                           │ │
        │  │ - Store in database                          │ │
        │  └──────────────────────────────────────────────┘ │
        │                     ↓                              │
        │  ┌──────────────────────────────────────────────┐ │
        │  │ Update URL Frontier                          │ │
        │  │ - Add new URLs                               │ │
        │  │ - Deduplicate                                │ │
        │  │ - Prioritize                                 │ │
        │  └──────────────────────────────────────────────┘ │
        │                                                    │
        └────────────────────────────────────────────────────┘
                     ↓
        ┌────────────────────────────┐
        │ APIDocumentationAgent      │
        │ - Generate OpenAPI spec    │
        │ - Export results           │
        └────────────┬───────────────┘
                     ↓
        ┌────────────────────────────┐
        │ Output: discovered_apis    │
        │         openapi.yaml       │
        └────────────────────────────┘
```

---

## 13. NEXT STEPS

**Proceed to Task 1.4**: Implementation Plan
- Detailed task breakdown
- Time estimates
- Dependencies
- Risk assessment

---

**Architecture Status**: ✅ COMPLETE AND READY FOR IMPLEMENTATION

