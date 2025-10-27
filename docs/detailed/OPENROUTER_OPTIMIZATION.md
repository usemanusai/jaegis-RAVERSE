# OpenRouter API Optimization Guide

## Overview

This document provides optimization strategies for using the OpenRouter API, with a focus on the free-tier `meta-llama/llama-3.3-70b-instruct:free` model used by RAVERSE. These recommendations are based on API best practices, community feedback, and Context7-sourced documentation for the `requests` library.

---

## 1. Rate Limits and Usage Constraints

### Free-Tier Model Specifications

**Model:** `meta-llama/llama-3.3-70b-instruct:free`

**Known Limitations:**
- **Rate Limiting:** Free-tier models have undocumented rate limits that vary by demand
- **Queue Priority:** Lower priority than paid requests during high traffic
- **Availability:** May be temporarily unavailable during peak usage
- **Context Window:** 128K tokens (input + output combined)
- **Max Output:** Typically limited to 2000-4000 tokens per request

**Observed Behavior (Community Reports):**
- Requests may be queued during high demand
- Occasional 429 (Too Many Requests) or 503 (Service Unavailable) errors
- Response times vary from 2-30 seconds depending on load
- No explicit requests-per-minute limit documented

### Recommended Request Patterns

**Best Practices:**
1. **Implement exponential backoff** for retry logic (already implemented in RAVERSE)
2. **Cache responses** when possible (implemented via SHA-256 binary hashing)
3. **Batch operations** to minimize total API calls
4. **Use connection pooling** with `requests.Session` (see Section 3)
5. **Set appropriate timeouts** to avoid hanging requests

**Example Retry Strategy (Current RAVERSE Implementation):**
```python
def call_openrouter(self, prompt, max_retries=3, retry_delay=1):
    for attempt in range(max_retries):
        try:
            response = requests.post(url, headers=headers, json=data, timeout=(10, 30))
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            wait_time = retry_delay * (2 ** attempt)  # Exponential backoff
            logger.warning(f"API call failed (attempt {attempt+1}/{max_retries}): {e}. Retrying in {wait_time}s...")
            time.sleep(wait_time)
    raise Exception("Max retries exceeded for API call.")
```

---

## 2. Token Usage Optimization

### Current Configuration
```python
data = {
    "model": "meta-llama/llama-3.3-70b-instruct:free",
    "messages": [{"role": "user", "content": prompt}],
    "max_tokens": 2000  # Current setting
}
```

### Optimization Strategies

#### Strategy 1: Minimize Prompt Length
**Technique:** Remove unnecessary verbosity from prompts

**Example - Before:**
```python
prompt = """
Please analyze the following disassembly output very carefully and identify the password verification logic.
I need you to find the exact memory address where the password comparison happens, and also the address
of the conditional jump instruction that follows it. Additionally, please provide the opcode byte that
should be used to patch the jump instruction.

[disassembly output]
"""
```

**Example - After:**
```python
prompt = """Analyze this disassembly to locate password verification logic:

[disassembly output]

Identify:
1. compare_addr: Address of string comparison
2. jump_addr: Address of conditional jump
3. opcode: Patch byte (0x74 for JE, 0x75 for JNE)

Respond ONLY with JSON:
{"compare_addr": "0x...", "jump_addr": "0x...", "opcode": "XX"}
"""
```

**Savings:** ~30-40% reduction in prompt tokens

#### Strategy 2: Request Structured Output
**Benefit:** Reduces response tokens and improves parsing reliability

**Implementation (Already in RAVERSE):**
```python
prompt = (
    "Respond ONLY with valid JSON in this exact format:\n"
    f"{sample_json}\n\n"
    "Do not include any explanatory text outside the JSON object."
)
```

**Result:** Response is typically 50-100 tokens vs 200-500 tokens for unstructured output

#### Strategy 3: Adjust max_tokens Based on Task
**Current:** Fixed 2000 tokens for all requests

**Recommended:**
```python
# For structured JSON responses (DAA, LIMA)
"max_tokens": 500  # Sufficient for JSON output

# For verification results (VA)
"max_tokens": 200  # Just need success/failure status

# For complex analysis (if needed)
"max_tokens": 2000  # Keep current value
```

**Potential Savings:** 60-75% reduction in output tokens for most RAVERSE operations

#### Strategy 4: Response Caching
**Current Implementation:**
```python
def _get_binary_hash(self, binary_path: str) -> str:
    with open(binary_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

# In run() method
binary_hash = self._get_binary_hash(binary_path)
if binary_hash in self.cache:
    logger.info("Using cached analysis for binary")
    return self.cache[binary_hash]
```

**Effectiveness:** Eliminates redundant API calls for same binary

---

## 3. Connection Pooling with requests.Session

### Benefits of Session Objects

**Advantages:**
1. **Connection Reuse:** TCP connections are kept alive and reused
2. **Reduced Latency:** Eliminates TCP handshake overhead for subsequent requests
3. **Cookie Persistence:** Automatic cookie handling (not needed for OpenRouter)
4. **Header Persistence:** Set headers once, apply to all requests
5. **Retry Configuration:** Centralized retry logic with urllib3

### Current Implementation (Direct requests.post)
```python
# In call_openrouter() method
response = requests.post(url, headers=headers, json=data, timeout=(10, 30))
```

**Issue:** Creates new TCP connection for each API call

### Recommended Implementation (Session-based)

**Step 1: Initialize Session in __init__**
```python
class OrchestratingAgent:
    def __init__(self, openrouter_api_key=None, model=None):
        # ... existing code ...
        
        # Initialize persistent session
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.openrouter_api_key}",
            "Content-Type": "application/json"
        })
```

**Step 2: Use Session in call_openrouter**
```python
def call_openrouter(self, prompt, max_retries=3, retry_delay=1):
    url = "https://openrouter.ai/api/v1/chat/completions"
    data = {
        "model": self.model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 2000
    }
    
    for attempt in range(max_retries):
        try:
            # Use session instead of requests.post
            response = self.session.post(url, json=data, timeout=(10, 30))
            response.raise_for_status()
            resp_json = response.json()
            if 'usage' in resp_json:
                logger.info(f"Token usage: {resp_json['usage']}")
            return resp_json
        except requests.exceptions.RequestException as e:
            wait_time = retry_delay * (2 ** attempt)
            logger.warning(f"API call failed (attempt {attempt+1}/{max_retries}): {e}. Retrying in {wait_time}s...")
            time.sleep(wait_time)
    raise Exception("Max retries exceeded for API call.")
```

**Step 3: Cleanup (Optional)**
```python
def __del__(self):
    """Ensure session is closed when agent is destroyed."""
    if hasattr(self, 'session'):
        self.session.close()
```

**Performance Improvement:** 10-30% reduction in request latency for subsequent calls

### Advanced: Retry Configuration with HTTPAdapter

**Implementation:**
```python
from urllib3.util import Retry
from requests.adapters import HTTPAdapter

class OrchestratingAgent:
    def __init__(self, openrouter_api_key=None, model=None):
        # ... existing code ...
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,  # Wait 1s, 2s, 4s between retries
            status_forcelist=[429, 500, 502, 503, 504],  # Retry on these HTTP codes
            allowed_methods=["POST"]  # Only retry POST requests
        )
        
        # Create adapter with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy)
        
        # Mount adapter to session
        self.session = requests.Session()
        self.session.mount("https://", adapter)
        self.session.headers.update({
            "Authorization": f"Bearer {self.openrouter_api_key}",
            "Content-Type": "application/json"
        })
```

**Benefit:** Automatic retry handling at the HTTP adapter level

---

## 4. Timeout Configuration

### Current Implementation
```python
response = requests.post(url, headers=headers, json=data, timeout=(10, 30))
```

**Breakdown:**
- **Connect Timeout:** 10 seconds (time to establish TCP connection)
- **Read Timeout:** 30 seconds (time to receive response after connection)

### Rationale (from Context7 requests documentation)

**Separate Timeouts:**
- **Connect:** Should be short (3-10s) to fail fast on network issues
- **Read:** Should be longer (20-60s) to accommodate model inference time

**Current Settings Analysis:**
- ✅ **10s connect:** Appropriate for detecting network failures
- ✅ **30s read:** Reasonable for free-tier model (may queue during high demand)
- ⚠️ **Consider increasing read timeout to 60s** during peak hours

### Recommended Adjustments

**For Production:**
```python
timeout=(10, 60)  # 10s connect, 60s read
```

**For Development/Testing:**
```python
timeout=(5, 30)  # Fail faster during testing
```

---

## 5. Error Handling and Logging

### Current Implementation
```python
try:
    response = self.session.post(url, json=data, timeout=(10, 30))
    response.raise_for_status()
    resp_json = response.json()
    if 'usage' in resp_json:
        logger.info(f"Token usage: {resp_json['usage']}")
    return resp_json
except requests.exceptions.RequestException as e:
    logger.warning(f"API call failed: {e}. Retrying...")
```

### Enhanced Error Handling

**Recommended:**
```python
try:
    response = self.session.post(url, json=data, timeout=(10, 30))
    response.raise_for_status()
    resp_json = response.json()
    
    # Log token usage and response time
    if 'usage' in resp_json:
        logger.info(f"Token usage: {resp_json['usage']}")
    logger.debug(f"API response time: {response.elapsed.total_seconds():.2f}s")
    
    return resp_json
    
except requests.exceptions.Timeout as e:
    logger.error(f"Request timeout after {timeout}s: {e}")
    # Retry with longer timeout or fail
    
except requests.exceptions.HTTPError as e:
    if response.status_code == 429:
        logger.warning("Rate limit exceeded. Implementing backoff...")
    elif response.status_code == 503:
        logger.warning("Service unavailable. Model may be overloaded...")
    else:
        logger.error(f"HTTP error {response.status_code}: {e}")
    
except requests.exceptions.RequestException as e:
    logger.error(f"Request failed: {e}")
```

---

## 6. Summary of Recommendations

### Immediate Improvements (High Priority)
1. ✅ **Implement Session-based requests** (Section 3)
2. ✅ **Adjust max_tokens per agent** (Section 2, Strategy 3)
3. ✅ **Enhanced error handling** (Section 5)

### Medium Priority
4. **Optimize prompt templates** for token efficiency (Section 2, Strategy 1)
5. **Add response time logging** for performance monitoring
6. **Consider HTTPAdapter retry strategy** for cleaner code

### Low Priority (Already Implemented)
7. ✅ Exponential backoff retry logic
8. ✅ Response caching via binary hashing
9. ✅ Structured JSON output requests
10. ✅ Separate connect/read timeouts

---

## References

- [OpenRouter Documentation](https://openrouter.ai/docs)
- [requests Library - Session Objects](https://requests.readthedocs.io/en/latest/user/advanced/#session-objects)
- [urllib3 Retry Configuration](https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html#urllib3.util.Retry)
- Context7: `/psf/requests` documentation on connection pooling and timeouts

