# DeepCrawler Examples

**Version**: 1.0.0  
**Date**: October 26, 2025

---

## Table of Contents

1. [Basic Examples](#basic-examples)
2. [Advanced Examples](#advanced-examples)
3. [Integration Examples](#integration-examples)
4. [Error Handling Examples](#error-handling-examples)

---

## Basic Examples

### Example 1: Simple Crawl

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent

# Initialize
crawler = DeepCrawlerAgent()

# Execute crawl
result = crawler.execute({
    "target_url": "https://api.example.com",
    "max_depth": 2,
    "max_urls": 100
})

# Print results
print(f"Crawled {result['urls_crawled']} URLs")
print(f"Found {result['apis_discovered']} APIs")
for api in result['discovered_apis']:
    print(f"  - {api}")
```

### Example 2: Generate Documentation

```python
from agents.online_api_documentation_agent import APIDocumentationAgent

# Initialize
documenter = APIDocumentationAgent()

# Generate documentation
result = documenter.execute({
    "discovered_apis": [
        {
            "endpoint": "https://example.com/api/users",
            "method": "GET",
            "confidence": 0.95,
            "discovery_method": "pattern_matching",
            "authentication": None
        }
    ],
    "target_url": "https://example.com"
})

# Export
with open("api_spec.json", "w") as f:
    f.write(documenter.export_openapi_json(result['openapi_spec']))
```

### Example 3: Monitor Progress

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent
import time

crawler = DeepCrawlerAgent()

# Start crawl (in real scenario, this would be async)
# For demo, we'll check status
crawler.crawl_state = "crawling"
crawler.report_progress(0.0, "Starting crawl")

# Simulate progress
for i in range(0, 101, 10):
    crawler.report_progress(i / 100, f"Progress: {i}%")
    time.sleep(0.1)

status = crawler.get_crawl_status()
print(f"Final status: {status['state']}")
print(f"Progress: {status['progress']:.1%}")
```

---

## Advanced Examples

### Example 1: With Memory Support

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent

# Initialize with memory
crawler = DeepCrawlerAgent(
    memory_strategy="hierarchical",
    memory_config={"window_size": 5, "k": 3}
)

# Execute crawl
result = crawler.execute({
    "target_url": "https://example.com",
    "max_depth": 3
})

# Store in memory
crawler.add_to_memory(
    f"Crawled {result['target_url']}",
    f"Found {result['apis_discovered']} APIs"
)

# Retrieve context
context = crawler.get_memory_context("APIs discovered")
print(f"Memory context: {context}")

# Get memory status
status = crawler.get_memory_status()
print(f"Memory enabled: {status['memory_enabled']}")
print(f"Strategy: {status['memory_strategy']}")
```

### Example 2: Custom Configuration

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent
from config.deepcrawler_config import DeepCrawlerConfig

# Create custom config
config = DeepCrawlerConfig(
    max_depth=5,
    max_urls=5000,
    max_concurrent=10,
    timeout=60,
    rate_limit=10.0,
    headless=True,
    browser_type='chromium'
)

# Initialize with config
crawler = DeepCrawlerAgent(config=config)

# Execute
result = crawler.execute({
    "target_url": "https://example.com"
})

print(f"Crawled with custom config: {result['urls_crawled']} URLs")
```

### Example 3: Error Handling

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent

crawler = DeepCrawlerAgent()

try:
    result = crawler.execute({
        "target_url": "https://example.com",
        "max_depth": 2
    })
    
    # Check for errors
    if result['errors']:
        print(f"Encountered {len(result['errors'])} errors:")
        for error in result['errors']:
            print(f"  URL: {error['url']}")
            print(f"  Error: {error['error']}")
            print(f"  Time: {error['timestamp']}")
    
    print(f"Successfully crawled {result['urls_crawled']} URLs")
    
except Exception as e:
    print(f"Crawl failed: {e}")
    crawler.cancel_crawl()
```

### Example 4: Pause and Resume

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent

crawler = DeepCrawlerAgent()

# Start crawl
crawler.crawl_state = "crawling"

# Simulate some work
print("Crawling...")

# Pause
crawler.pause_crawl()
print(f"Paused. State: {crawler.crawl_state}")

# Resume
crawler.resume_crawl()
print(f"Resumed. State: {crawler.crawl_state}")

# Cancel
crawler.cancel_crawl()
print(f"Cancelled. State: {crawler.crawl_state}")
```

---

## Integration Examples

### Example 1: Full Workflow

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent
from agents.online_api_documentation_agent import APIDocumentationAgent

# Step 1: Crawl
print("Step 1: Crawling...")
crawler = DeepCrawlerAgent()
crawl_result = crawler.execute({
    "target_url": "https://example.com",
    "max_depth": 2,
    "max_urls": 500
})

print(f"  Crawled: {crawl_result['urls_crawled']} URLs")
print(f"  Found: {crawl_result['apis_discovered']} APIs")

# Step 2: Document
print("\nStep 2: Generating documentation...")
documenter = APIDocumentationAgent(orchestrator=crawler)
doc_result = documenter.execute({
    "discovered_apis": crawl_result['discovered_apis'],
    "session_id": crawl_result['session_id'],
    "target_url": crawl_result['target_url']
})

print(f"  Documented: {doc_result['apis_documented']} APIs")

# Step 3: Export
print("\nStep 3: Exporting...")
with open("api_spec.json", "w") as f:
    f.write(documenter.export_openapi_json(doc_result['openapi_spec']))
    print("  Exported: api_spec.json")

with open("api_spec.yaml", "w") as f:
    f.write(documenter.export_openapi_yaml(doc_result['openapi_spec']))
    print("  Exported: api_spec.yaml")

with open("api_docs.md", "w") as f:
    f.write(documenter.export_markdown(doc_result['markdown_documentation']))
    print("  Exported: api_docs.md")

print("\nWorkflow complete!")
```

### Example 2: Multiple Targets

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent
from agents.online_api_documentation_agent import APIDocumentationAgent

targets = [
    "https://api1.example.com",
    "https://api2.example.com",
    "https://api3.example.com"
]

results = []

for target in targets:
    print(f"Crawling {target}...")
    
    crawler = DeepCrawlerAgent()
    crawl_result = crawler.execute({
        "target_url": target,
        "max_depth": 2
    })
    
    documenter = APIDocumentationAgent(orchestrator=crawler)
    doc_result = documenter.execute({
        "discovered_apis": crawl_result['discovered_apis'],
        "session_id": crawl_result['session_id'],
        "target_url": target
    })
    
    results.append({
        "target": target,
        "urls_crawled": crawl_result['urls_crawled'],
        "apis_discovered": crawl_result['apis_discovered'],
        "documentation": doc_result['openapi_spec']
    })

print(f"\nProcessed {len(results)} targets")
for result in results:
    print(f"  {result['target']}: {result['apis_discovered']} APIs")
```

---

## Error Handling Examples

### Example 1: Handle Missing Target

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent

crawler = DeepCrawlerAgent()

try:
    result = crawler.execute({})  # Missing target_url
except ValueError as e:
    print(f"Error: {e}")
    print("Please provide target_url in task")
```

### Example 2: Handle Connection Errors

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent

crawler = DeepCrawlerAgent()

try:
    result = crawler.execute({
        "target_url": "https://invalid.local",
        "max_depth": 1
    })
except Exception as e:
    print(f"Connection error: {e}")
    print("Check target URL and network connectivity")
```

### Example 3: Handle Timeout

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent
from config.deepcrawler_config import DeepCrawlerConfig

# Increase timeout
config = DeepCrawlerConfig(timeout=120)
crawler = DeepCrawlerAgent(config=config)

try:
    result = crawler.execute({
        "target_url": "https://slow.example.com",
        "max_depth": 1
    })
except TimeoutError as e:
    print(f"Request timed out: {e}")
    print("Try increasing timeout or reducing max_depth")
```

### Example 4: Comprehensive Error Handling

```python
from agents.online_deepcrawler_agent import DeepCrawlerAgent
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

crawler = DeepCrawlerAgent()

try:
    result = crawler.execute({
        "target_url": "https://example.com",
        "max_depth": 2,
        "max_urls": 100
    })
    
    # Check results
    if result['urls_crawled'] == 0:
        logger.warning("No URLs crawled")
    
    if result['apis_discovered'] == 0:
        logger.warning("No APIs discovered")
    
    if result['errors']:
        logger.error(f"Encountered {len(result['errors'])} errors")
        for error in result['errors']:
            logger.error(f"  {error['url']}: {error['error']}")
    
    logger.info(f"Crawl complete: {result['urls_crawled']} URLs, {result['apis_discovered']} APIs")
    
except ValueError as e:
    logger.error(f"Invalid task: {e}")
except ConnectionError as e:
    logger.error(f"Connection failed: {e}")
except TimeoutError as e:
    logger.error(f"Request timed out: {e}")
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    crawler.cancel_crawl()
```

---

**Last Updated**: October 26, 2025  
**Version**: 1.0.0  
**Status**: Production Ready

