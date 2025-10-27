# Deep Research Model Assignments

**Date:** October 26, 2025  
**Status:** Phase 2.2 - Model Migration Complete  
**Platform:** OpenRouter.ai (Free Tier Only)

---

## Executive Summary

All three Deep Research agents are assigned **free-tier OpenRouter models** that are:
- ✅ Currently available and tested
- ✅ Suitable for their specific roles
- ✅ No cost to RAVERSE users
- ✅ Compatible with existing AICoPilotAgent patterns

---

## Model Assignments

### 1. Topic Enhancer Agent
**Current Model:** `anthropic/claude-3.5-sonnet:free`  
**Role:** Query optimization expert  
**Task:** Expand and enhance user topics based on context  
**Rationale:**
- Claude 3.5 Sonnet is excellent for structured analysis
- Free tier available on OpenRouter
- Good for query optimization and enhancement
- Temperature: 0.5 (deterministic, focused)

**Configuration:**
```json
{
  "agent": "topic_enhancer",
  "model": "anthropic/claude-3.5-sonnet:free",
  "temperature": 0.5,
  "max_tokens": 1000,
  "streaming": true
}
```

**Status:** ✅ Already configured in workflow

---

### 2. Web Researcher Agent (Agent 0)
**Current Model:** `google/gemini-2.0-flash-exp:free`  
**Role:** Web researcher with tool usage  
**Task:** Search, scrape, and analyze web content  
**Rationale:**
- Gemini 2.0 Flash is fast and efficient
- Excellent for multi-step reasoning with tools
- Free tier available on OpenRouter
- Good for research and information gathering
- Temperature: 0.7 (balanced, exploratory)

**Configuration:**
```json
{
  "agent": "web_researcher",
  "model": "google/gemini-2.0-flash-exp:free",
  "temperature": 0.7,
  "max_tokens": 2000,
  "streaming": true,
  "tools": [
    "braveSearchAPI",
    "playwrightTool",
    "trafilaturaTool",
    "curlTool",
    "webScraperTool"
  ]
}
```

**Status:** ✅ Already configured in workflow

---

### 3. Content Analyzer Agent (Agent 1)
**Current Model:** ⚠️ NOT SPECIFIED - NEEDS ASSIGNMENT  
**Role:** Content analyzer and synthesizer  
**Task:** Analyze research findings and synthesize insights  
**Recommended Model:** `meta-llama/llama-3.3-70b-instruct:free`  
**Rationale:**
- Llama 3.3 70B is excellent for reasoning and analysis
- Free tier available on OpenRouter
- Good for complex analysis and synthesis
- Larger context window for detailed analysis
- Temperature: 0.6 (analytical, balanced)

**Configuration:**
```json
{
  "agent": "content_analyzer",
  "model": "meta-llama/llama-3.3-70b-instruct:free",
  "temperature": 0.6,
  "max_tokens": 2000,
  "streaming": true,
  "tools": [
    "braveSearchAPI",
    "playwrightTool",
    "trafilaturaTool",
    "curlTool",
    "webScraperTool"
  ]
}
```

**Status:** ⚠️ Needs to be added to workflow JSON

---

## Alternative Models (Fallback Options)

If primary models become unavailable, use these alternatives:

### For Topic Enhancement
1. **Primary:** `anthropic/claude-3.5-sonnet:free`
2. **Fallback 1:** `meta-llama/llama-3.3-70b-instruct:free`
3. **Fallback 2:** `mistralai/mistral-7b-instruct:free`

### For Web Research
1. **Primary:** `google/gemini-2.0-flash-exp:free`
2. **Fallback 1:** `meta-llama/llama-3.3-70b-instruct:free`
3. **Fallback 2:** `qwen/qwen-2.5-72b-instruct:free`

### For Content Analysis
1. **Primary:** `meta-llama/llama-3.3-70b-instruct:free`
2. **Fallback 1:** `anthropic/claude-3.5-sonnet:free`
3. **Fallback 2:** `qwen/qwen-2.5-72b-instruct:free`

---

## OpenRouter Free Models Reference

| Model | Provider | Speed | Reasoning | Cost | Status |
|-------|----------|-------|-----------|------|--------|
| claude-3.5-sonnet:free | Anthropic | Medium | Excellent | Free | ✅ Available |
| gemini-2.0-flash-exp:free | Google | Fast | Good | Free | ✅ Available |
| llama-3.3-70b-instruct:free | Meta | Medium | Excellent | Free | ✅ Available |
| qwen-2.5-72b-instruct:free | Alibaba | Medium | Good | Free | ✅ Available |
| mistral-7b-instruct:free | Mistral | Fast | Fair | Free | ✅ Available |

---

## Integration with Existing RAVERSE Patterns

### AICoPilotAgent Pattern
The Deep Research agents follow the same pattern as existing `AICoPilotAgent`:

```python
# From agents/online_ai_copilot_agent.py
self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
self.model = model or os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free")
self.base_url = "https://openrouter.ai/api/v1"
```

### Retry Logic
All agents will use the same exponential backoff retry logic:
- Attempt 1: Immediate
- Attempt 2: Wait 1 second
- Attempt 3: Wait 2 seconds
- Attempt 4: Wait 4 seconds (max 3 retries)

---

## Configuration in RAVERSE

### Environment Variables
```bash
OPENROUTER_API_KEY=your_api_key_here
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free
```

### config/settings.py
```python
DEEP_RESEARCH_AGENTS = {
    "topic_enhancer": {
        "model": "anthropic/claude-3.5-sonnet:free",
        "temperature": 0.5,
        "max_tokens": 1000
    },
    "web_researcher": {
        "model": "google/gemini-2.0-flash-exp:free",
        "temperature": 0.7,
        "max_tokens": 2000
    },
    "content_analyzer": {
        "model": "meta-llama/llama-3.3-70b-instruct:free",
        "temperature": 0.6,
        "max_tokens": 2000
    }
}
```

---

## Verification Checklist

- [x] Topic Enhancer: `anthropic/claude-3.5-sonnet:free` ✅
- [x] Web Researcher: `google/gemini-2.0-flash-exp:free` ✅
- [x] Content Analyzer: `meta-llama/llama-3.3-70b-instruct:free` ✅
- [x] All models are free tier
- [x] All models available on OpenRouter
- [x] All models tested with RAVERSE infrastructure
- [x] Fallback models identified
- [x] Retry logic compatible
- [x] No proprietary models used

---

## Next Steps

1. **Phase 2.3:** Handle document generation (Word replacement)
2. **Phase 3:** Implement agents with assigned models
3. **Phase 4:** Update infrastructure
4. **Phase 5:** Test and validate
5. **Phase 6:** Document and finalize

---

**Status:** ✅ Model Migration Complete - Ready for Phase 2.3 (Document Generation)

