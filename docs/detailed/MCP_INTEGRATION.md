# MCP Server Integration Guide

## Overview

RAVERSE was developed with assistance from two Model Context Protocol (MCP) servers:
1. **Context7** - Library documentation retrieval
2. **Hyperbrowser** - Web research and scraping

This document explains how these MCP servers were used during development and how future developers can leverage them for extending RAVERSE.

---

## 1. Context7 MCP Server

### Purpose
Context7 provides up-to-date documentation for popular libraries directly from their source repositories. This ensures that code implementations use current best practices and correct API usage.

### Tools Available
- `resolve-library-id_Context_7` - Resolves package names to Context7-compatible library IDs
- `get-library-docs_Context_7` - Fetches documentation for a specific library and topic

### Usage in RAVERSE Development

#### Example 1: requests Library - Timeout Configuration
**Query:**
```python
get-library-docs_Context_7(
    context7CompatibleLibraryID="/psf/requests",
    topic="timeouts",
    tokens=3000
)
```

**Key Findings Applied:**
- Separate connect/read timeouts: `timeout=(10, 30)`
- Connect timeout should be short (3-10s) to detect network failures quickly
- Read timeout should be longer (20-60s) for API responses

**Implementation:**
```python
# agents/orchestrator.py, line 98
response = requests.post(url, headers=headers, json=data, timeout=(10, 30))
```

#### Example 2: requests Library - Session Objects
**Query:**
```python
get-library-docs_Context_7(
    context7CompatibleLibraryID="/psf/requests",
    topic="Session connection pooling keep-alive",
    tokens=3000
)
```

**Key Findings:**
- Sessions reuse TCP connections, reducing latency
- Use context manager (`with` statement) for automatic cleanup
- Configure retries with `HTTPAdapter` and `urllib3.Retry`

**Recommended Implementation (see OPENROUTER_OPTIMIZATION.md):**
```python
from urllib3.util import Retry
from requests.adapters import HTTPAdapter

session = requests.Session()
retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("https://", adapter)
```

#### Example 3: python-dotenv - Environment Variable Loading
**Query:**
```python
get-library-docs_Context_7(
    context7CompatibleLibraryID="/theskumar/python-dotenv",
    topic="load_dotenv usage",
    tokens=2000
)
```

**Key Findings:**
- `load_dotenv()` automatically searches for `.env` file
- Supports `override` parameter to force reload
- Can load from IO streams with `stream` parameter

**Implementation:**
```python
# agents/orchestrator.py, line 26
from dotenv import load_dotenv
load_dotenv()  # Automatically finds and loads .env file
```

### How to Use Context7 in Future Development

**Step 1: Resolve Library ID**
```python
resolve-library-id_Context_7(libraryName="pytest")
# Returns: /pytest-dev/pytest
```

**Step 2: Fetch Documentation**
```python
get-library-docs_Context_7(
    context7CompatibleLibraryID="/pytest-dev/pytest",
    topic="fixtures and monkeypatching",
    tokens=5000
)
```

**Step 3: Apply Findings**
- Review code snippets and best practices
- Update implementation to match current API
- Add inline comments referencing Context7 findings

---

## 2. Hyperbrowser MCP Server

### Purpose
Hyperbrowser provides web scraping, crawling, and browser automation capabilities. It was used to research best practices for binary patching, AI-powered reverse engineering, and OpenRouter API optimization.

### Tools Available
- `search_with_bing_hyperbrowser` - Search the web using Bing
- `scrape_webpage_hyperbrowser` - Extract content from a single URL
- `crawl_webpages_hyperbrowser` - Crawl multiple pages from a domain
- `extract_structured_data_hyperbrowser` - Extract structured data using a schema
- `browser_use_agent_hyperbrowser` - Fast browser automation agent
- `openai_computer_use_agent_hyperbrowser` - OpenAI-powered browser agent
- `claude_computer_use_agent_hyperbrowser` - Claude-powered browser agent

### Usage in RAVERSE Development

#### Example 1: PE Format Specification Research
**Query:**
```python
scrape_webpage_hyperbrowser(
    url="https://learn.microsoft.com/en-us/windows/win32/debug/pe-format",
    outputFormat=["markdown"]
)
```

**Key Findings Applied:**
- **RVA (Relative Virtual Address)** formula: `RVA = VA - ImageBase`
- **File Offset Calculation:** `FileOffset = RVA - SectionVirtualAddress + SectionPointerToRawData`
- **Section Alignment:** Memory alignment differs from file alignment

**Documentation Created:**
- `docs/BINARY_PATCHING_BEST_PRACTICES.md` - Section 1: VA-to-Offset Conversion

#### Example 2: x86 Instruction Set Research
**Query:**
```python
scrape_webpage_hyperbrowser(
    url="https://en.wikipedia.org/wiki/X86_instruction_listings",
    outputFormat=["markdown"]
)
```

**Key Findings Applied:**
- **Conditional Jump Opcodes:**
  - JE (Jump if Equal): `0x74` (short), `0x0F 0x84` (near)
  - JNE (Jump if Not Equal): `0x75` (short), `0x0F 0x85` (near)
- **Short vs Near Jumps:** Short jumps are 2 bytes, near jumps are 5-6 bytes
- **Instruction Semantics:** JE checks ZF=1, JNE checks ZF=0

**Documentation Created:**
- `docs/BINARY_PATCHING_BEST_PRACTICES.md` - Section 2: Conditional Jump Opcodes Reference

#### Example 3: OpenRouter API Research
**Query:**
```python
search_with_bing_hyperbrowser(
    query="OpenRouter API free tier rate limits meta-llama 3.3 70b instruct",
    numResults=8
)
```

**Key Findings:**
- Free-tier models have undocumented rate limits
- Community reports suggest variable response times (2-30s)
- Occasional 429/503 errors during peak usage
- No explicit requests-per-minute limit

**Documentation Created:**
- `docs/OPENROUTER_OPTIMIZATION.md` - Section 1: Rate Limits and Usage Constraints

### How to Use Hyperbrowser in Future Development

**Use Case 1: Research New Binary Formats**
```python
search_with_bing_hyperbrowser(
    query="Mach-O executable format virtual address to file offset",
    numResults=10
)

# Then scrape the most relevant result
scrape_webpage_hyperbrowser(
    url="https://developer.apple.com/documentation/...",
    outputFormat=["markdown"]
)
```

**Use Case 2: Find Best Practices**
```python
search_with_bing_hyperbrowser(
    query="LLM prompt engineering structured output JSON parsing",
    numResults=8
)
```

**Use Case 3: Extract Structured Data**
```python
extract_structured_data_hyperbrowser(
    urls=["https://openrouter.ai/docs/models"],
    prompt="Extract model names, pricing, and rate limits",
    schema={
        "type": "object",
        "properties": {
            "models": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "pricing": {"type": "string"},
                        "rate_limit": {"type": "string"}
                    }
                }
            }
        }
    }
)
```

---

## 3. MCP-Assisted Development Workflow

### Phase 1: Research (Before Coding)
1. **Identify knowledge gaps** (e.g., "How do I convert VA to file offset in PE files?")
2. **Use Hyperbrowser** to search for authoritative sources
3. **Scrape documentation** from official sources (Microsoft, Intel, etc.)
4. **Document findings** in markdown files (e.g., `docs/BINARY_PATCHING_BEST_PRACTICES.md`)

### Phase 2: Implementation (During Coding)
1. **Use Context7** to fetch current library documentation
2. **Verify API usage** against official docs (e.g., `requests.Session` best practices)
3. **Apply findings** to code with inline comments
4. **Reference MCP sources** in docstrings

### Phase 3: Validation (After Coding)
1. **Cross-reference** implementation with MCP-sourced documentation
2. **Update tests** based on library best practices
3. **Document deviations** from standard patterns (if any)

---

## 4. Example MCP Commands for RAVERSE Extensions

### Adding Support for ELF Binaries
```python
# Research ELF format
search_with_bing_hyperbrowser(
    query="ELF executable format program header virtual address offset",
    numResults=10
)

scrape_webpage_hyperbrowser(
    url="https://refspecs.linuxfoundation.org/elf/elf.pdf",
    outputFormat=["markdown"]
)

# Get library docs for ELF parsing
resolve-library-id_Context_7(libraryName="pyelftools")
get-library-docs_Context_7(
    context7CompatibleLibraryID="/eliben/pyelftools",
    topic="parsing program headers",
    tokens=5000
)
```

### Improving Test Coverage
```python
# Get pytest best practices
get-library-docs_Context_7(
    context7CompatibleLibraryID="/pytest-dev/pytest",
    topic="fixtures monkeypatching mocking",
    tokens=5000
)

# Research test patterns
search_with_bing_hyperbrowser(
    query="pytest best practices for testing API calls with mocks",
    numResults=8
)
```

### Optimizing AI Prompts
```python
# Research prompt engineering
search_with_bing_hyperbrowser(
    query="LLM prompt engineering for structured JSON output",
    numResults=10
)

scrape_webpage_hyperbrowser(
    url="https://platform.openai.com/docs/guides/prompt-engineering",
    outputFormat=["markdown"]
)
```

---

## 5. Benefits of MCP-Assisted Development

### Accuracy
- ✅ Always uses **current documentation** (not outdated training data)
- ✅ Fetches from **authoritative sources** (official docs, specifications)
- ✅ Reduces **hallucination risk** in AI-generated code

### Efficiency
- ✅ **Faster research** than manual web browsing
- ✅ **Structured extraction** of relevant information
- ✅ **Automated documentation** generation

### Maintainability
- ✅ **Traceable sources** for all implementation decisions
- ✅ **Easy updates** when libraries change
- ✅ **Clear documentation** of best practices

---

## 6. Future MCP Integration Opportunities

### Real-Time Documentation Lookup
**Idea:** Integrate Context7 into agent prompts for dynamic library usage

**Example:**
```python
# In DisassemblyAnalysisAgent
def disassemble(self, binary_path):
    # Fetch latest capstone documentation
    capstone_docs = context7.get_library_docs("/capstone-engine/capstone", "disassembly")
    
    # Use docs to construct accurate disassembly prompt
    prompt = f"Using Capstone library:\n{capstone_docs}\n\nDisassemble: {binary_path}"
```

### Automated Best Practice Validation
**Idea:** Use Hyperbrowser to validate code against current best practices

**Example:**
```python
# Before committing code
best_practices = hyperbrowser.search("Python requests Session best practices 2025")
validate_code_against_practices(code, best_practices)
```

---

## Conclusion

MCP servers (Context7 and Hyperbrowser) were instrumental in developing RAVERSE with current best practices and accurate library usage. Future developers should leverage these tools for:
- Researching new features (binary formats, AI models, etc.)
- Validating library usage against current documentation
- Documenting implementation decisions with authoritative sources

For questions or suggestions, see the main README.md or open an issue on GitHub.

