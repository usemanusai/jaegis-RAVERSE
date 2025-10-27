# Deep Research Workflow Analysis

**Date:** October 26, 2025  
**Status:** Phase 1 - Analysis Complete  
**Source:** `agents/DEEP-RESEARCH Agents.json`

---

## Executive Summary

The CrewAI Deep Research workflow contains **3 main agents** designed for collaborative topic exploration with research capabilities. The workflow uses OpenRouter.ai for LLM access and includes web scraping, searching, and content extraction tools.

**Key Findings:**
- ✅ Uses OpenRouter.ai (free models available)
- ✅ Includes web research tools (BraveSearch, web scraping)
- ❌ Uses proprietary tools (Microsoft Word not found, but document generation needed)
- ❌ No A2A communication protocol implemented
- ❌ No database persistence for research results

---

## Agent Inventory

| Agent ID | Label | Role | Current Model | Tools | Status |
|----------|-------|------|----------------|-------|--------|
| `llmAgentflow_0` | Topic Enhancer | Query optimization expert | `anthropic/claude-3.5-sonnet:free` | None (LLM only) | ✅ Free Model |
| `agentAgentflow_0` | Agent 0 | Web Researcher | `google/gemini-2.0-flash-exp:free` | BraveSearch, WebScraper, Playwright, Trafilatura, curl | ✅ Free Model |
| `agentAgentflow_1` | Agent 1 | Content Analyzer | (Not specified in JSON) | BraveSearch, WebScraper, Playwright, Trafilatura, curl | ⚠️ Model Missing |

---

## Tool Assignments

### Agent 0 (Web Researcher)
**Current Tools:**
1. `webScraperTool` - Recursive scraping (max 50 pages, depth 1)
2. `braveSearchAPI` - Web search
3. `playwrightTool` - Browser automation (headless)
4. `trafilaturaTool` - Content extraction
5. `curlTool` - HTTP requests

**Assessment:** ✅ All tools are free/open-source and available in RAVERSE catalog

### Agent 1 (Content Analyzer)
**Current Tools:** Same as Agent 0 (inherited from workflow)

**Assessment:** ✅ Tool set appropriate for analysis

### Topic Enhancer (LLM Agent)
**Current Tools:** None (pure LLM)

**Assessment:** ✅ Appropriate for query optimization

---

## Model Configuration Analysis

### Current Models
1. **Topic Enhancer:** `anthropic/claude-3.5-sonnet:free`
   - Status: ✅ Free tier available on OpenRouter
   - Temperature: 0.5 (good for optimization)

2. **Agent 0:** `google/gemini-2.0-flash-exp:free`
   - Status: ✅ Free tier available on OpenRouter
   - Temperature: 0.7 (good for research)

3. **Agent 1:** Not specified
   - Status: ⚠️ Needs assignment
   - Recommendation: `meta-llama/llama-3.3-70b-instruct:free` (reasoning)

---

## Workflow Execution Flow

```
User Input (Topic)
    ↓
Topic Enhancer (LLM)
    ↓ (Enhanced Query)
Agent 0 (Web Researcher)
    ↓ (Research Findings)
Agent 1 (Content Analyzer)
    ↓ (Analysis & Synthesis)
Output (Comprehensive Report)
```

**Flow Type:** Sequential with inter-agent communication

---

## Knowledge Base Configuration

### Vector Store (Qdrant)
- **URL:** `https://8a9fae5f-1682-419d-8e2d-b59e8ecb6587.eu-west-1-0.aws.cloud.qdrant.io:6333`
- **Collection:** `n8n-qdrant`
- **Embedding Model:** HuggingFace Inference
- **Vector Dimension:** 1536
- **Similarity:** Cosine

**Assessment:** ⚠️ External dependency (not in RAVERSE infrastructure)

---

## Gap Analysis

### Missing Components
1. **A2A Communication Protocol**
   - Current: Direct message passing (implicit)
   - Needed: Explicit Redis pub/sub protocol

2. **Database Persistence**
   - Current: None (Qdrant only)
   - Needed: PostgreSQL for agent state, research results

3. **Agent 1 Model Assignment**
   - Current: Not specified
   - Needed: Assign appropriate free model

4. **Document Generation**
   - Current: Not implemented
   - Needed: Report generation (Markdown/PDF)

5. **Error Handling**
   - Current: Minimal
   - Needed: Retry logic, fallbacks, error recovery

6. **Metrics & Monitoring**
   - Current: None
   - Needed: Prometheus metrics, logging

---

## Integration Points with RAVERSE

### Existing Agents to Leverage
1. **OnlineBaseAgent** - Base class with persistence, caching, metrics
2. **OnlineOrchestrationAgent** - Pipeline coordination
3. **ReportingAgent** - Report generation (can be extended)
4. **AICoPilotAgent** - LLM integration patterns (retry logic)

### New Agents to Create
1. `OnlineDeepResearchTopicEnhancer` - Query optimization
2. `OnlineDeepResearchWebResearcher` - Web research
3. `OnlineDeepResearchContentAnalyzer` - Content analysis

### Pipeline Integration
- **Current RAVERSE Pipeline:** 8 phases (Recon → Traffic → JS → API → Security → AI → Validation → Reporting)
- **New Deep Research Pipeline:** 3 phases (Topic Enhancement → Web Research → Content Analysis)
- **Integration Strategy:** Add as optional Phase 9 (Deep Research) after Phase 8 (Reporting)

---

## Recommendations

### Priority 1 (Critical)
- [ ] Assign model to Agent 1
- [ ] Implement A2A communication protocol
- [ ] Add PostgreSQL persistence
- [ ] Implement error handling & retries

### Priority 2 (Important)
- [ ] Add Prometheus metrics
- [ ] Implement document generation
- [ ] Add comprehensive logging
- [ ] Create test suite

### Priority 3 (Nice-to-Have)
- [ ] Migrate from Qdrant to PostgreSQL pgvector
- [ ] Add caching layer (Redis)
- [ ] Implement parallel execution
- [ ] Add visualization dashboard

---

## Next Steps

1. **Phase 1.2:** Research A2A protocols and select best fit
2. **Phase 1.3:** Review existing RAVERSE architecture patterns
3. **Phase 2:** Migrate tools and models
4. **Phase 3:** Implement agents
5. **Phase 4:** Update infrastructure
6. **Phase 5:** Test and validate
7. **Phase 6:** Document and finalize

---

**Status:** ✅ Analysis Complete - Ready for Phase 1.2 (A2A Protocol Research)

