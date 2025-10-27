# DeepCrawler User Guide

**Version**: 1.0.0  
**Date**: October 26, 2025  
**Status**: Production Ready

---

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [Usage Examples](#usage-examples)
6. [Advanced Features](#advanced-features)
7. [Troubleshooting](#troubleshooting)
8. [FAQ](#faq)

---

## Introduction

DeepCrawler is an intelligent web crawling system integrated into RAVERSE 2.0 that enables autonomous discovery of hidden, undocumented, and non-public API endpoints through advanced crawling techniques.

### Key Features

- **Intelligent URL Prioritization**: Multi-factor scoring for optimal crawl efficiency
- **Concurrent Crawling**: Async/await support with configurable concurrency
- **API Discovery**: Multiple discovery techniques (pattern matching, traffic analysis, WebSocket inspection)
- **Automatic Documentation**: OpenAPI 3.0 specification generation
- **Memory Integration**: Optional context persistence across sessions
- **Database Persistence**: PostgreSQL integration for session tracking
- **Error Recovery**: Automatic retry logic with exponential backoff
- **Rate Limiting**: Per-domain rate limiting and distributed coordination

---

## Installation

### Prerequisites

- Python 3.8+
- PostgreSQL 12+
- Redis 6+ (optional, for distributed features)
- Playwright (for browser automation)

### Setup

```bash
# Clone the repository
git clone https://github.com/raverse/deepcrawler.git
cd deepcrawler

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install

# Configure environment
cp .env.example .env
# Edit .env with your settings
```

### Environment Variables

```bash
# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=raverse
POSTGRES_PASSWORD=your_password
POSTGRES_DB=raverse

# Redis (optional)
REDIS_URL=redis://localhost:6379

# OpenRouter LLM
OPENROUTER_API_KEY=your_api_key
```

---

## Quick Start

### Basic Crawl

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent

# Initialize agent
crawler = DeepCrawlerAgent()

# Execute crawl
task = {
    "target_url": "https://example.com",
    "max_depth": 3,
    "max_urls": 1000
}

result = crawler.execute(task)

# Access results
print(f"URLs crawled: {result['urls_crawled']}")
print(f"APIs discovered: {result['apis_discovered']}")
print(f"Discovered APIs: {result['discovered_apis']}")
```

### Generate Documentation

```python
from agents.online_api_documentation_agent import APIDocumentationAgent

# Initialize agent
documenter = APIDocumentationAgent()

# Generate documentation
task = {
    "discovered_apis": result['discovered_apis'],
    "session_id": result['session_id'],
    "target_url": "https://example.com"
}

doc_result = documenter.execute(task)

# Export in different formats
openapi_json = documenter.export_openapi_json(doc_result['openapi_spec'])
openapi_yaml = documenter.export_openapi_yaml(doc_result['openapi_spec'])
markdown = documenter.export_markdown(doc_result['markdown_documentation'])
```

---

## Configuration

### DeepCrawlerConfig

```python
from config.deepcrawler_config import DeepCrawlerConfig

config = DeepCrawlerConfig(
    max_depth=3,              # Maximum crawl depth
    max_urls=10000,           # Maximum URLs to crawl
    max_concurrent=5,         # Concurrent crawls
    timeout=30,               # Request timeout (seconds)
    rate_limit=20.0,          # Requests per minute
    headless=True,            # Headless browser mode
    browser_type='chromium'   # Browser type
)

crawler = DeepCrawlerAgent(config=config)
```

### Memory Configuration

```python
# With memory support
crawler = DeepCrawlerAgent(
    memory_strategy="sliding_window",
    memory_config={"window_size": 3}
)

# Memory strategies available:
# - sequential
# - sliding_window
# - summarization
# - retrieval
# - memory_augmented
# - hierarchical
# - graph
# - compression
# - os_like
```

---

## Usage Examples

### Example 1: Simple API Discovery

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent

crawler = DeepCrawlerAgent()

result = crawler.execute({
    "target_url": "https://api.example.com",
    "max_depth": 2,
    "max_urls": 500
})

for api in result['discovered_apis']:
    print(f"Found: {api}")
```

### Example 2: Full Workflow with Documentation

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent
from agents.online_api_documentation_agent import APIDocumentationAgent

# Crawl
crawler = DeepCrawlerAgent()
crawl_result = crawler.execute({
    "target_url": "https://example.com",
    "max_depth": 3
})

# Document
documenter = APIDocumentationAgent(orchestrator=crawler)
doc_result = documenter.execute({
    "discovered_apis": crawl_result['discovered_apis'],
    "session_id": crawl_result['session_id'],
    "target_url": "https://example.com"
})

# Export
with open("api_spec.json", "w") as f:
    f.write(documenter.export_openapi_json(doc_result['openapi_spec']))

with open("api_docs.md", "w") as f:
    f.write(documenter.export_markdown(doc_result['markdown_documentation']))
```

### Example 3: With Memory and Error Handling

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent

crawler = DeepCrawlerAgent(
    memory_strategy="hierarchical",
    memory_config={"window_size": 5, "k": 3}
)

try:
    result = crawler.execute({
        "target_url": "https://example.com",
        "max_depth": 2
    })
    
    # Check for errors
    if result['errors']:
        print(f"Errors encountered: {len(result['errors'])}")
        for error in result['errors']:
            print(f"  - {error['url']}: {error['error']}")
    
    # Get status
    status = crawler.get_crawl_status()
    print(f"Status: {status['state']}")
    print(f"Progress: {status['progress']:.1%}")
    
except Exception as e:
    print(f"Crawl failed: {e}")
```

---

## Advanced Features

### Pause and Resume

```python
crawler = DeepCrawlerAgent()

# Start crawl in background
# ... crawl running ...

# Pause
crawler.pause_crawl()

# Resume
crawler.resume_crawl()

# Cancel
crawler.cancel_crawl()
```

### Monitor Progress

```python
status = crawler.get_crawl_status()

print(f"Session: {status['session_id']}")
print(f"State: {status['state']}")
print(f"URLs crawled: {status['urls_crawled']}")
print(f"APIs discovered: {status['apis_discovered']}")
print(f"Errors: {status['errors']}")
print(f"Progress: {status['progress']:.1%}")
```

### Memory Context

```python
# Add to memory
crawler.add_to_memory(
    "Crawled https://example.com",
    "Found 5 APIs"
)

# Retrieve context
context = crawler.get_memory_context("APIs")
print(context)

# Get memory status
status = crawler.get_memory_status()
print(f"Memory enabled: {status['memory_enabled']}")
print(f"Strategy: {status['memory_strategy']}")
```

---

## Troubleshooting

### Connection Timeout

**Problem**: Requests timing out

**Solution**:
```python
config = DeepCrawlerConfig(timeout=60)  # Increase timeout
crawler = DeepCrawlerAgent(config=config)
```

### Rate Limiting

**Problem**: Getting rate limited

**Solution**:
```python
config = DeepCrawlerConfig(rate_limit=10.0)  # Reduce rate
crawler = DeepCrawlerAgent(config=config)
```

### Database Connection

**Problem**: Cannot connect to PostgreSQL

**Solution**:
```bash
# Check environment variables
echo $POSTGRES_HOST
echo $POSTGRES_PORT

# Test connection
psql -h localhost -U raverse -d raverse
```

### Memory Issues

**Problem**: High memory usage

**Solution**:
```python
# Use sliding window instead of hierarchical
crawler = DeepCrawlerAgent(
    memory_strategy="sliding_window",
    memory_config={"window_size": 2}
)
```

---

## FAQ

### Q: How do I crawl only specific domains?

A: Use URL filtering in the crawl task:
```python
result = crawler.execute({
    "target_url": "https://example.com",
    "max_depth": 2,
    "domain_filter": "example.com"
})
```

### Q: Can I resume a crawl?

A: Yes, with memory enabled:
```python
crawler = DeepCrawlerAgent(
    memory_strategy="hierarchical"
)
# Crawl will resume from last checkpoint
```

### Q: How do I export to different formats?

A: Use the export methods:
```python
json_spec = documenter.export_openapi_json(spec)
yaml_spec = documenter.export_openapi_yaml(spec)
markdown_doc = documenter.export_markdown(doc)
```

### Q: What's the maximum crawl depth?

A: Configurable, default is 3. Increase with:
```python
config = DeepCrawlerConfig(max_depth=5)
```

### Q: How do I handle authentication?

A: Pass credentials in the task:
```python
result = crawler.execute({
    "target_url": "https://example.com",
    "auth_type": "bearer",
    "auth_token": "your_token"
})
```

---

## Support

For issues or questions:
1. Check the [API Reference](DEEPCRAWLER_API_REFERENCE.md)
2. Review [Examples](DEEPCRAWLER_EXAMPLES.md)
3. Check [Ethics & Legal](DEEPCRAWLER_ETHICS_AND_LEGAL.md)
4. Open an issue on GitHub

---

**Last Updated**: October 26, 2025  
**Version**: 1.0.0  
**Status**: Production Ready

