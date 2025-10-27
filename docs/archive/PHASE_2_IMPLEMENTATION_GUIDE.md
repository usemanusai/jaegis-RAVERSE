# PHASE 2: LLM INTEGRATION WITH OPENROUTER - IMPLEMENTATION GUIDE

**Status**: READY TO START  
**Date**: October 26, 2025  
**Scope**: All 8 RAVERSE 2.0 Architecture Layer Agents

---

## OVERVIEW

Phase 2 focuses on ensuring all LLM calls are fully functional with:
- ✅ Real OpenRouter API integration
- ✅ Retry logic with exponential backoff
- ✅ Timeout handling (60 seconds default)
- ✅ Rate limiting (429 status code handling)
- ✅ Token usage tracking
- ✅ Error logging and recovery

---

## AGENTS WITH LLM CALLS

### 1. KnowledgeBaseAgent
**File**: `agents/online_knowledge_base_agent.py`  
**Status**: ✅ IMPLEMENTED

**Method**: `_call_llm(prompt, temperature=0.7, max_tokens=1000)`
- Real OpenRouter API calls
- Retry logic with exponential backoff
- Rate limit handling (429 status)
- Timeout handling (60s)
- Token usage logging

---

### 2. DocumentGeneratorAgent
**File**: `agents/online_document_generator_agent.py`  
**Status**: ✅ IMPLEMENTED

**Method**: `_call_llm(prompt, temperature=0.7, max_tokens=2000)`
- Real OpenRouter API calls
- Used in `_generate_manifest()` and `_generate_white_paper()`
- Retry logic with exponential backoff
- Rate limit handling
- Timeout handling

---

### 3. RAGOrchestratorAgent
**File**: `agents/online_rag_orchestrator_agent.py`  
**Status**: ✅ IMPLEMENTED

**Method**: `_call_llm(prompt, temperature=0.7, max_tokens=1500)`
- Real OpenRouter API calls
- Used in `_refine_query()` and `_synthesize_knowledge()`
- Retry logic with exponential backoff
- Rate limit handling
- Timeout handling

---

## OPENROUTER API CONFIGURATION

### Environment Variables
```bash
OPENROUTER_API_KEY=sk-or-...  # Your OpenRouter API key
```

### Free Models Available (2025)
```python
MODELS = {
    "fast": "google/gemini-2.0-flash-exp:free",
    "reasoning": "meta-llama/llama-3.3-70b-instruct:free",
    "complex": "anthropic/claude-3.5-sonnet:free",
    "lightweight": "mistralai/mistral-7b-instruct:free",
    "multilingual": "qwen/qwen-2.5-72b-instruct:free"
}
```

### API Endpoint
```
https://openrouter.ai/api/v1/chat/completions
```

### Request Headers
```python
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json",
    "HTTP-Referer": "https://raverse.ai",
    "X-Title": "RAVERSE"
}
```

---

## IMPLEMENTATION PATTERN

```python
def _call_llm(self, prompt: str, temperature: float = 0.7, 
              max_tokens: int = 1000) -> str:
    """Call LLM via OpenRouter with retry logic."""
    if not self.api_key:
        self.logger.error("OpenRouter API key not configured")
        return ""
    
    headers = {
        "Authorization": f"Bearer {self.api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://raverse.ai",
        "X-Title": "RAVERSE"
    }
    
    data = {
        "model": self.model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens
    }
    
    for attempt in range(self.max_retries):
        try:
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                json=data,
                timeout=60
            )
            
            # Handle rate limiting
            if response.status_code == 429:
                wait_time = self.retry_backoff ** attempt
                self.logger.warning(f"Rate limited. Retry {attempt + 1}/{self.max_retries} after {wait_time}s")
                time.sleep(wait_time)
                continue
            
            response.raise_for_status()
            result = response.json()
            
            content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
            tokens = result.get("usage", {}).get("total_tokens", "unknown")
            self.logger.info(f"LLM call successful, tokens: {tokens}")
            return content
            
        except requests.exceptions.Timeout:
            self.logger.warning(f"LLM call timeout (attempt {attempt + 1}/{self.max_retries})")
            if attempt < self.max_retries - 1:
                time.sleep(self.retry_backoff ** attempt)
                continue
            return ""
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"LLM call failed (attempt {attempt + 1}/{self.max_retries}): {e}")
            if attempt < self.max_retries - 1:
                time.sleep(self.retry_backoff ** attempt)
                continue
            return ""
    
    return ""
```

---

## TESTING STRATEGY

### Unit Tests
1. Test successful LLM call
2. Test rate limiting (429 response)
3. Test timeout handling
4. Test retry logic
5. Test missing API key
6. Test malformed response

### Integration Tests
1. Test with real OpenRouter API
2. Test with different models
3. Test with different temperatures
4. Test with different max_tokens

### End-to-End Tests
1. Test complete workflow with LLM calls
2. Test error recovery
3. Test token usage tracking

---

## VERIFICATION CHECKLIST

- [ ] All 3 agents have `_call_llm()` method
- [ ] All LLM calls use real OpenRouter API
- [ ] All LLM calls have retry logic
- [ ] All LLM calls have timeout handling
- [ ] All LLM calls have rate limit handling
- [ ] All LLM calls log token usage
- [ ] All LLM calls have proper error handling
- [ ] All tests pass
- [ ] No placeholder comments remain

---

## NEXT PHASES

**Phase 3**: Vector Embeddings & Semantic Search  
**Phase 4**: A2A Communication with Redis  
**Phase 5**: Binary Analysis Implementation  
**Phase 6**: Configuration Files & Validation  
**Phase 7**: Testing & Verification  


