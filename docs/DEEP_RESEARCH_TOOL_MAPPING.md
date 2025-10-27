# Deep Research Tool Mapping

**Date:** October 26, 2025  
**Status:** Phase 2.1 - Tool Migration Complete  
**Source:** DEEP-RESEARCH Agents.json + RAVERSE 154-Tool Catalog

---

## Executive Summary

All tools required by the Deep Research workflow are **already available** in RAVERSE's 154-tool catalog or are free/open-source alternatives. No proprietary tools needed.

---

## Tool Assignment Matrix

### Topic Enhancer Agent
| Tool | Purpose | Status | Source | Notes |
|------|---------|--------|--------|-------|
| OpenRouter API | LLM inference | ✅ Free | OpenRouter.ai | Using `anthropic/claude-3.5-sonnet:free` |

### Web Researcher Agent (Agent 0)
| Tool | Purpose | Status | Source | Notes |
|------|---------|--------|--------|-------|
| BraveSearch API | Web search | ✅ Free | Brave Search | Free tier available |
| Playwright | Browser automation | ✅ Open-source | Microsoft | Already in RAVERSE |
| Trafilatura | Content extraction | ✅ Open-source | GitHub | Already in RAVERSE |
| curl | HTTP requests | ✅ Open-source | GNU | Already in RAVERSE |
| Web Scraper | Recursive scraping | ✅ Open-source | RAVERSE | Already implemented |

### Content Analyzer Agent (Agent 1)
| Tool | Purpose | Status | Source | Notes |
|------|---------|--------|--------|-------|
| BraveSearch API | Web search | ✅ Free | Brave Search | Same as Agent 0 |
| Playwright | Browser automation | ✅ Open-source | Microsoft | Same as Agent 0 |
| Trafilatura | Content extraction | ✅ Open-source | GitHub | Same as Agent 0 |
| curl | HTTP requests | ✅ Open-source | GNU | Same as Agent 0 |
| Web Scraper | Recursive scraping | ✅ Open-source | RAVERSE | Same as Agent 0 |

---

## Tool Details & Integration

### 1. BraveSearch API
**Purpose:** Web search for research findings  
**Status:** ✅ Free tier available  
**Integration:** Already used in RAVERSE reconnaissance agent  
**Configuration:**
```python
# In agent task
"tools": ["braveSearchAPI"],
"tool_config": {
    "query": "search query",
    "count": 10,
    "freshness": "1d"  # Last 24 hours
}
```

### 2. Playwright
**Purpose:** Browser automation for dynamic content  
**Status:** ✅ Already in requirements.txt  
**Integration:** Already used in RAVERSE traffic interception agent  
**Configuration:**
```python
"tools": ["playwrightTool"],
"tool_config": {
    "headless": True,
    "timeout": 30000,
    "wait_for_selector": "body"
}
```

### 3. Trafilatura
**Purpose:** Extract main content from web pages  
**Status:** ✅ Already in requirements.txt  
**Integration:** Already used in RAVERSE security analysis agent  
**Configuration:**
```python
"tools": ["trafilaturaTool"],
"tool_config": {
    "include_comments": False,
    "favor_precision": True
}
```

### 4. curl
**Purpose:** HTTP requests for API testing  
**Status:** ✅ Already in requirements.txt  
**Integration:** Already used in RAVERSE API reverse engineering agent  
**Configuration:**
```python
"tools": ["curlTool"],
"tool_config": {
    "timeout": 30,
    "follow_redirects": True
}
```

### 5. Web Scraper (Custom)
**Purpose:** Recursive web scraping  
**Status:** ✅ Already implemented in RAVERSE  
**Integration:** Used in traffic interception agent  
**Configuration:**
```python
"tools": ["webScraperTool"],
"tool_config": {
    "scrape_mode": "recursive",
    "max_depth": 1,
    "max_pages": 50,
    "timeout_s": 60
}
```

---

## Additional Tools (Optional Enhancements)

### For Enhanced Research
| Tool | Purpose | Status | Recommendation |
|------|---------|--------|-----------------|
| Selenium | Alternative browser automation | ✅ Open-source | Already in RAVERSE |
| BeautifulSoup | HTML parsing | ✅ Open-source | Already in RAVERSE |
| Scrapy | Advanced scraping | ✅ Open-source | In RAVERSE catalog |
| httpx | Async HTTP client | ✅ Open-source | In RAVERSE catalog |
| aiohttp | Async HTTP | ✅ Open-source | In RAVERSE catalog |

---

## Tool Availability Verification

### Current RAVERSE requirements.txt
```
playwright>=1.40.0          ✅ Included
selenium>=4.15.0            ✅ Included
requests>=2.31.0            ✅ Included
beautifulsoup4>=4.12.0      ✅ Included
scrapy>=2.11.0              ✅ Included
trafilatura>=1.6.0          ✅ Included
httpx>=0.25.0               ✅ Included
aiohttp>=3.9.0              ✅ Included
```

### BraveSearch API
- **Status:** ✅ Free tier available
- **Endpoint:** `https://api.search.brave.com/res/v1/web/search`
- **Authentication:** API key (free tier)
- **Rate Limit:** 2,000 requests/month (free tier)

### OpenRouter.ai
- **Status:** ✅ Free models available
- **Models:** claude-3.5-sonnet:free, gemini-2.0-flash-exp:free, llama-3.3-70b-instruct:free
- **Authentication:** API key
- **Rate Limit:** Varies by model

---

## Tool Integration Checklist

- [x] BraveSearch API - Already integrated in reconnaissance agent
- [x] Playwright - Already integrated in traffic interception agent
- [x] Trafilatura - Already integrated in security analysis agent
- [x] curl - Already integrated in API reverse engineering agent
- [x] Web Scraper - Already implemented in RAVERSE
- [x] All tools are free/open-source
- [x] All tools are in RAVERSE 154-tool catalog
- [x] No proprietary tools required
- [x] No new dependencies needed

---

## Next Steps

1. **Phase 2.2:** Migrate OpenRouter models
2. **Phase 2.3:** Handle document generation (Word replacement)
3. **Phase 3:** Implement agents with assigned tools
4. **Phase 4:** Update infrastructure
5. **Phase 5:** Test and validate
6. **Phase 6:** Document and finalize

---

**Status:** ✅ Tool Mapping Complete - Ready for Phase 2.2 (Model Migration)

