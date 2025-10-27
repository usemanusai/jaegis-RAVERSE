# DeepCrawler API Reference

**Version**: 1.0.0  
**Date**: October 26, 2025

---

## Table of Contents

1. [DeepCrawlerAgent](#deepcrawleragent)
2. [APIDocumentationAgent](#apidocumentationagent)
3. [Configuration](#configuration)
4. [Data Structures](#data-structures)

---

## DeepCrawlerAgent

### Class: `DeepCrawlerAgent`

Orchestrator for intelligent web crawling. Extends `BaseMemoryAgent`.

#### Constructor

```python
DeepCrawlerAgent(
    orchestrator=None,
    config: Optional[DeepCrawlerConfig] = None,
    memory_strategy: Optional[str] = None,
    memory_config: Optional[Dict[str, Any]] = None
)
```

**Parameters**:
- `orchestrator`: Reference to orchestration agent (optional)
- `config`: DeepCrawlerConfig instance (uses defaults if None)
- `memory_strategy`: Memory strategy name (optional)
- `memory_config`: Memory configuration dictionary (optional)

#### Methods

##### `execute(task: Dict[str, Any]) -> Dict[str, Any]`

Execute crawl task with full lifecycle management.

**Parameters**:
- `task`: Task configuration dictionary
  - `target_url` (required): URL to crawl
  - `max_depth` (optional): Maximum crawl depth (default: 3)
  - `max_urls` (optional): Maximum URLs to crawl (default: 10000)

**Returns**: Dictionary with crawl results

**Example**:
```python
result = crawler.execute({
    "target_url": "https://example.com",
    "max_depth": 2,
    "max_urls": 500
})
```

##### `get_crawl_status() -> Dict[str, Any]`

Get current crawl status.

**Returns**: Dictionary with status information
- `session_id`: Unique session identifier
- `state`: Current crawl state
- `urls_crawled`: Number of URLs crawled
- `apis_discovered`: Number of APIs discovered
- `errors`: Number of errors encountered
- `progress`: Progress percentage (0.0-1.0)
- `memory_enabled`: Whether memory is enabled

**Example**:
```python
status = crawler.get_crawl_status()
print(f"Progress: {status['progress']:.1%}")
```

##### `pause_crawl() -> None`

Pause ongoing crawl.

**Example**:
```python
crawler.pause_crawl()
```

##### `resume_crawl() -> None`

Resume paused crawl.

**Example**:
```python
crawler.resume_crawl()
```

##### `cancel_crawl() -> None`

Cancel ongoing crawl.

**Example**:
```python
crawler.cancel_crawl()
```

##### `add_to_memory(user_input: str, ai_response: str) -> None`

Add interaction to memory (if enabled).

**Parameters**:
- `user_input`: User input or task description
- `ai_response`: Agent response or result

**Example**:
```python
crawler.add_to_memory(
    "Crawled example.com",
    "Found 5 APIs"
)
```

##### `get_memory_context(query: str) -> str`

Retrieve context from memory based on query.

**Parameters**:
- `query`: Query to search memory for

**Returns**: Context string from memory

**Example**:
```python
context = crawler.get_memory_context("APIs")
```

---

## APIDocumentationAgent

### Class: `APIDocumentationAgent`

Generates OpenAPI specifications and documentation. Extends `BaseMemoryAgent`.

#### Constructor

```python
APIDocumentationAgent(
    orchestrator=None,
    memory_strategy: Optional[str] = None,
    memory_config: Optional[Dict[str, Any]] = None
)
```

**Parameters**:
- `orchestrator`: Reference to orchestration agent (optional)
- `memory_strategy`: Memory strategy name (optional)
- `memory_config`: Memory configuration dictionary (optional)

#### Methods

##### `execute(task: Dict[str, Any]) -> Dict[str, Any]`

Generate API documentation from discovered endpoints.

**Parameters**:
- `task`: Task configuration dictionary
  - `discovered_apis` (required): List of discovered APIs
  - `session_id` (optional): Crawl session ID
  - `target_url` (optional): Target URL

**Returns**: Dictionary with generated documentation

**Example**:
```python
result = documenter.execute({
    "discovered_apis": apis,
    "session_id": "session-123",
    "target_url": "https://example.com"
})
```

##### `export_openapi_json(openapi_spec: Dict[str, Any]) -> str`

Export OpenAPI spec as JSON.

**Parameters**:
- `openapi_spec`: OpenAPI specification dictionary

**Returns**: JSON string

**Example**:
```python
json_str = documenter.export_openapi_json(spec)
```

##### `export_openapi_yaml(openapi_spec: Dict[str, Any]) -> str`

Export OpenAPI spec as YAML.

**Parameters**:
- `openapi_spec`: OpenAPI specification dictionary

**Returns**: YAML string

**Example**:
```python
yaml_str = documenter.export_openapi_yaml(spec)
```

##### `export_markdown(markdown_doc: str) -> str`

Export documentation as Markdown.

**Parameters**:
- `markdown_doc`: Markdown documentation string

**Returns**: Markdown string

**Example**:
```python
md_str = documenter.export_markdown(doc)
```

##### `get_documentation_status() -> Dict[str, Any]`

Get documentation generation status.

**Returns**: Dictionary with status information

**Example**:
```python
status = documenter.get_documentation_status()
```

---

## Configuration

### Class: `DeepCrawlerConfig`

Configuration dataclass for DeepCrawler.

#### Attributes

```python
@dataclass
class DeepCrawlerConfig:
    max_depth: int = 3                    # Maximum crawl depth
    max_urls: int = 10000                 # Maximum URLs to crawl
    max_concurrent: int = 5               # Concurrent crawls
    timeout: int = 30                     # Request timeout (seconds)
    rate_limit: float = 20.0              # Requests per minute
    headless: bool = True                 # Headless browser mode
    browser_type: str = 'chromium'        # Browser type
    # ... 20+ more parameters
```

#### Methods

##### `validate() -> None`

Validate configuration parameters.

**Raises**: ValueError if configuration is invalid

**Example**:
```python
config = DeepCrawlerConfig(max_depth=5)
config.validate()
```

##### `to_dict() -> Dict[str, Any]`

Convert configuration to dictionary.

**Returns**: Configuration dictionary

**Example**:
```python
config_dict = config.to_dict()
```

---

## Data Structures

### Crawl Result

```python
{
    "session_id": "uuid-string",
    "target_url": "https://example.com",
    "urls_crawled": 100,
    "apis_discovered": 5,
    "discovered_apis": [
        "https://example.com/api/users",
        "https://example.com/api/posts"
    ],
    "documentation": {
        "total_apis": 5,
        "apis": [...]
    },
    "errors": [
        {
            "url": "https://example.com/bad",
            "error": "Connection timeout",
            "timestamp": "2025-10-26T12:00:00"
        }
    ]
}
```

### API Object

```python
{
    "endpoint": "https://example.com/api/users",
    "method": "GET",
    "confidence": 0.95,
    "discovery_method": "pattern_matching",
    "authentication": "Bearer",
    "request_example": {...},
    "response_example": {...}
}
```

### OpenAPI Spec

```python
{
    "openapi": "3.0.0",
    "info": {
        "title": "API Documentation",
        "version": "1.0.0",
        "description": "Auto-generated documentation"
    },
    "servers": [...],
    "paths": {
        "/api/users": {
            "get": {
                "summary": "GET /api/users",
                "responses": {...}
            }
        }
    },
    "components": {
        "schemas": {...},
        "securitySchemes": {...}
    }
}
```

### Status Object

```python
{
    "session_id": "uuid-string",
    "state": "crawling",  # idle, initializing, crawling, discovering, documenting, complete, failed
    "urls_crawled": 50,
    "apis_discovered": 5,
    "errors": 0,
    "progress": 0.5,
    "memory_enabled": True
}
```

---

## Error Handling

### Common Exceptions

#### ValueError
Raised when required parameters are missing or invalid.

```python
try:
    crawler.execute({})  # Missing target_url
except ValueError as e:
    print(f"Invalid task: {e}")
```

#### ConnectionError
Raised when unable to connect to target.

```python
try:
    result = crawler.execute({"target_url": "https://invalid.local"})
except ConnectionError as e:
    print(f"Connection failed: {e}")
```

#### TimeoutError
Raised when request times out.

```python
try:
    result = crawler.execute({"target_url": "https://slow.example.com"})
except TimeoutError as e:
    print(f"Request timed out: {e}")
```

---

## Memory Strategies

Available memory strategies:

- `sequential`: Sequential memory of all interactions
- `sliding_window`: Keep only N most recent turns
- `summarization`: Summarize old interactions
- `retrieval`: Retrieve relevant context
- `memory_augmented`: Augmented memory with attention
- `hierarchical`: Hierarchical memory structure
- `graph`: Graph-based memory
- `compression`: Compressed memory
- `os_like`: OS-like memory management

---

## Logging

DeepCrawler uses Python's standard logging module.

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Get logger
logger = logging.getLogger("RAVERSE.DEEPCRAWLER")
```

---

**Last Updated**: October 26, 2025  
**Version**: 1.0.0  
**Status**: Production Ready

