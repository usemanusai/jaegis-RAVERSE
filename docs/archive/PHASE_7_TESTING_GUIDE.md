# PHASE 7: TESTING & VERIFICATION - IMPLEMENTATION GUIDE

**Status**: READY TO START  
**Date**: October 26, 2025  
**Scope**: All 8 RAVERSE 2.0 Architecture Layer Agents

---

## OVERVIEW

Phase 7 focuses on comprehensive testing and verification:
- Unit tests for all methods
- Integration tests
- End-to-end tests
- >85% code coverage
- Verification script

---

## TESTING STRATEGY

### Unit Tests
Test individual methods in isolation:
- Database operations (CRUD, retry logic)
- LLM calls (success, timeout, rate limiting)
- Vector embeddings (generation, search)
- Redis pub/sub (publish, subscribe)
- Binary analysis (format detection, disassembly)

### Integration Tests
Test component interactions:
- Database + Retry logic
- LLM + Rate limiting
- Vector embeddings + pgvector search
- Redis + Database persistence
- Binary analysis + Database storage

### End-to-End Tests
Test complete workflows:
- Knowledge base storage and retrieval
- Approval workflow creation and approval
- Binary analysis pipeline
- RAG iterative research cycle

---

## TEST STRUCTURE

```
tests/
├── unit/
│   ├── test_version_manager_agent.py
│   ├── test_knowledge_base_agent.py
│   ├── test_quality_gate_agent.py
│   ├── test_governance_agent.py
│   ├── test_document_generator_agent.py
│   ├── test_rag_orchestrator_agent.py
│   ├── test_daa_agent.py
│   └── test_lima_agent.py
├── integration/
│   ├── test_database_integration.py
│   ├── test_llm_integration.py
│   ├── test_redis_integration.py
│   └── test_binary_analysis_integration.py
├── e2e/
│   ├── test_knowledge_base_workflow.py
│   ├── test_approval_workflow.py
│   ├── test_binary_analysis_workflow.py
│   └── test_rag_workflow.py
└── conftest.py
```

---

## TEST COVERAGE TARGETS

| Component | Target Coverage |
|-----------|-----------------|
| VersionManagerAgent | >85% |
| KnowledgeBaseAgent | >85% |
| QualityGateAgent | >85% |
| GovernanceAgent | >85% |
| DocumentGeneratorAgent | >85% |
| RAGOrchestratorAgent | >85% |
| DAAAgent | >85% |
| LIMAAgent | >85% |
| **Overall** | **>85%** |

---

## TESTING TOOLS

### pytest
```bash
pip install pytest pytest-cov pytest-asyncio
```

### Mocking
```bash
pip install pytest-mock responses
```

### Database Testing
```bash
pip install pytest-postgresql
```

### Coverage
```bash
pytest --cov=agents --cov-report=html
```

---

## EXAMPLE TEST CASES

### Unit Test: Database Operations
```python
def test_store_knowledge_success(db_manager_mock):
    """Test successful knowledge storage."""
    agent = KnowledgeBaseAgent()
    result = agent._store_knowledge({
        "content": "Test content",
        "source": "test",
        "metadata": {}
    })
    assert result["status"] == "success"
    assert "knowledge_id" in result
```

### Integration Test: LLM with Retry
```python
def test_llm_call_with_retry(requests_mock):
    """Test LLM call with retry logic."""
    # Mock rate limiting then success
    requests_mock.post(
        "https://openrouter.ai/api/v1/chat/completions",
        [
            {"status_code": 429},  # Rate limited
            {"status_code": 200, "json": {"choices": [{"message": {"content": "response"}}]}}
        ]
    )
    agent = KnowledgeBaseAgent()
    result = agent._call_llm("test prompt")
    assert result == "response"
```

### End-to-End Test: Knowledge Base Workflow
```python
def test_knowledge_base_workflow(db_connection, redis_client):
    """Test complete knowledge base workflow."""
    agent = KnowledgeBaseAgent()
    
    # Store knowledge
    store_result = agent._store_knowledge({
        "content": "Test content",
        "source": "test"
    })
    assert store_result["status"] == "success"
    
    # Search knowledge
    search_result = agent._search_knowledge({
        "query": "Test",
        "limit": 5
    })
    assert search_result["status"] == "success"
    assert len(search_result["results"]) > 0
```

---

## VERIFICATION CHECKLIST

- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] All end-to-end tests pass
- [ ] Code coverage >85%
- [ ] No placeholder comments
- [ ] All imports resolve
- [ ] All database operations work
- [ ] All LLM calls work
- [ ] All Redis operations work
- [ ] All binary analysis works
- [ ] Configuration validation passes
- [ ] Logging works correctly

---

## RUNNING TESTS

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Test File
```bash
pytest tests/unit/test_knowledge_base_agent.py -v
```

### Run with Coverage
```bash
pytest tests/ --cov=agents --cov-report=html
```

### Run Integration Tests Only
```bash
pytest tests/integration/ -v
```

### Run End-to-End Tests Only
```bash
pytest tests/e2e/ -v
```

---

## EXPECTED RESULTS

✅ All tests pass  
✅ Code coverage >85%  
✅ No errors or warnings  
✅ All agents functional  
✅ All integrations working  
✅ Production ready  

---

## NEXT STEPS

1. Create test files for all agents
2. Write unit tests
3. Write integration tests
4. Write end-to-end tests
5. Run tests and achieve >85% coverage
6. Fix any failing tests
7. Final verification

**Estimated Time**: 4-5 hours


