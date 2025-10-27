# TASK 2 & 3: MCP Tools Integration & OpenRouter Model Migration Plan

**Date:** October 26, 2025  
**Status:** IN_PROGRESS  

---

## PART 1: MCP TOOLS INTEGRATION PLAN

### Current Tools (2)
1. ✅ webScraperTool
2. ✅ braveSearchAPI

### Tools to Add (12 Critical)

#### Category 1: HTTP Fetchers (3)
- **curl** - Command-line HTTP client
- **HTTPie** - User-friendly HTTP CLI
- **Axios** - JavaScript HTTP library

#### Category 2: Content Extractors (3)
- **Readability** - Article extraction
- **Trafilatura** - Web content extraction
- **newspaper3k** - News article parsing

#### Category 3: Advanced Crawlers (2)
- **Scrapy** - Full-featured web crawler
- **Colly** - Go-based crawler framework

#### Category 4: Browser Automation (2)
- **Playwright** - Cross-browser automation
- **Puppeteer** - Headless Chrome control

#### Category 5: Document Generation (2)
- **python-docx** - DOCX file generation
- **Pandoc** - Universal document converter

---

## PART 2: OPENROUTER FREE MODELS AVAILABLE

### Recommended Models by Category

#### Fast/Lightweight (Reconnaissance)
- **google/gemini-2.0-flash-exp:free** ⭐ RECOMMENDED
  - Fast, good for quick analysis
  - 1M context window
  - Excellent for tech stack detection

- **meta-llama/llama-3.3-70b-instruct:free**
  - Balanced speed/quality
  - Good reasoning
  - 8K context

#### Reasoning/Analysis (Deep Research)
- **deepseek/deepseek-r1:free**
  - Excellent reasoning
  - Good for complex analysis
  - Slower but more accurate

- **meta-llama/llama-4-scout:free**
  - 109B MoE model
  - Good for detailed analysis
  - Balanced performance

#### General Purpose (Default)
- **x-ai/grok-4-fast:free** ✅ CURRENT
  - Already in use
  - Good all-around performance
  - Temperature 0.9 (too high)

- **anthropic/claude-3.5-sonnet:free**
  - Excellent quality
  - Good for writing/analysis
  - Recommended for reports

---

## PART 3: MODEL ASSIGNMENT STRATEGY

### Agent 0 (Research Explorer)
- **Current:** x-ai/grok-4-fast:free
- **Recommended:** google/gemini-2.0-flash-exp:free
- **Rationale:** Fast web search + scraping
- **Temperature:** 0.7 (reduce from 0.9)

### Agent 1 (Analytical Partner)
- **Current:** x-ai/grok-4-fast:free
- **Recommended:** meta-llama/llama-3.3-70b-instruct:free
- **Rationale:** Thoughtful analysis + dialogue
- **Temperature:** 0.7

### Topic Enhancer (LLM)
- **Current:** x-ai/grok-4-fast:free
- **Recommended:** anthropic/claude-3.5-sonnet:free
- **Rationale:** Query optimization + writing
- **Temperature:** 0.5 (lower for consistency)

### Agent 2 (Report Generator)
- **Current:** x-ai/grok-4-fast:free
- **Recommended:** anthropic/claude-3.5-sonnet:free
- **Rationale:** Report synthesis + formatting
- **Temperature:** 0.5

---

## PART 4: IMPLEMENTATION STEPS

### Step 1: Update Tool Definitions
Add to workflow JSON:
```json
{
  "agentSelectedTool": "curlTool",
  "agentSelectedToolConfig": { ... }
},
{
  "agentSelectedTool": "playwrightTool",
  "agentSelectedToolConfig": { ... }
},
{
  "agentSelectedTool": "pythonDocxTool",
  "agentSelectedToolConfig": { ... }
}
```

### Step 2: Update Model Configurations
For each agent node:
```json
"agentModelConfig": {
  "modelName": "google/gemini-2.0-flash-exp:free",
  "temperature": 0.7,
  "basepath": "https://openrouter.ai/api/v1"
}
```

### Step 3: Reduce Temperature
- Topic Enhancer: 0.5
- Agent 0: 0.7
- Agent 1: 0.7
- Agent 2: 0.5

### Step 4: Add Document Generation
Replace Microsoft Word with:
- Primary: python-docx (DOCX generation)
- Secondary: Pandoc (PDF conversion)

---

## PART 5: BENEFITS

✅ **All free models** - Zero cost
✅ **Model diversity** - Different models for different tasks
✅ **Better accuracy** - Lower temperatures for factual research
✅ **Faster execution** - Gemini 2.0 Flash is very fast
✅ **Better reasoning** - DeepSeek R1 for complex analysis
✅ **Open source tools** - No proprietary dependencies
✅ **Better integration** - Matches RAVERSE architecture

---

## NEXT STEPS

1. ✅ Identify tools and models (COMPLETE)
2. ⏳ Modify workflow JSON (TASK 2)
3. ⏳ Test tool integration (TASK 2)
4. ⏳ Verify model responses (TASK 3)
5. ⏳ Document changes (TASK 2 & 3)


