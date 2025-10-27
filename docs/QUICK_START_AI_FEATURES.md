# Quick Start: AI-Powered Features

**Date:** October 25, 2025  
**Version:** 2.0.0

This guide shows you how to use the new AI-powered features in RAVERSE 2.0.

---

## 🚀 Prerequisites

1. **Docker & Docker Compose** installed
2. **OpenRouter API Key** (free tier available)
3. **16GB+ RAM** recommended

---

## 📦 Installation

### 1. Clone and Setup

```bash
git clone https://github.com/your-org/raverse.git
cd raverse

# Copy environment file
cp .env.example .env

# Edit .env and add your OpenRouter API key
# OPENROUTER_API_KEY=your_key_here
```

### 2. Start Services

**With Monitoring (Recommended):**
```bash
docker-compose --profile monitoring up -d
```

**Without Monitoring:**
```bash
docker-compose up -d
```

### 3. Verify Services

```bash
# Check all services are running
docker-compose ps

# Expected services:
# - raverse-postgres (PostgreSQL 17 + pgvector)
# - raverse-redis (Redis 8.2)
# - raverse-app (RAVERSE application)
# - raverse-prometheus (Metrics collection)
# - raverse-grafana (Dashboards)
# - raverse-postgres-exporter
# - raverse-redis-exporter
# - raverse-cadvisor
# - raverse-node-exporter
```

---

## 🎯 Basic Usage

### Example 1: Comprehensive Binary Analysis

```python
from agents.enhanced_orchestrator import EnhancedOrchestrator

# Initialize orchestrator
orchestrator = EnhancedOrchestrator(
    binary_path="binaries/password_protected.exe",
    use_database=True,
    use_llm=True
)

# Perform comprehensive analysis
analysis = orchestrator.analyze_binary(
    entry_point=None,  # Auto-detect
    num_instructions=100
)

# Print results
print(f"Binary Type: {analysis['disassembly']['num_instructions']} instructions")
print(f"Patterns Found: {len(analysis['patterns']['password_checks'])}")
print(f"Analysis Duration: {analysis['duration']:.2f}s")
```

### Example 2: Generate and Apply Patches

```python
# Generate patch strategies
strategies = orchestrator.generate_patches()

print(f"Generated {len(strategies)} patch strategies:")
for i, strategy in enumerate(strategies):
    print(f"{i+1}. {strategy.name} - Confidence: {strategy.confidence:.2%}")

# Apply best strategy
result = orchestrator.apply_and_validate_patch(
    strategy_index=0,
    output_path="output/patched.exe"
)

# Check validation
if result['validation']['overall_valid']:
    print(f"✅ Patch applied successfully!")
    print(f"Output: {result['output_path']}")
else:
    print(f"❌ Patch validation failed")
    print(result['validation']['summary'])
```

### Example 3: Get Comprehensive Report

```python
# Generate detailed report
report = orchestrator.get_analysis_report()
print(report)

# Save report to file
with open("output/analysis_report.txt", "w") as f:
    f.write(report)
```

---

## 🔍 Advanced Features

### Semantic Code Search

```python
from utils.database import DatabaseManager
from utils.cache import CacheManager
from utils.semantic_search import get_search_engine

# Initialize
db = DatabaseManager()
cache = CacheManager()
search_engine = get_search_engine(db, cache)

# Search for similar code
results = search_engine.find_similar_code(
    query="cmp eax, 0x0; je 0x401000",
    limit=10,
    similarity_threshold=0.7
)

for result in results:
    print(f"Similarity: {result['similarity']:.2%}")
    print(f"Code: {result['code_snippet']}")
    print(f"Binary: {result['binary_hash'][:8]}...")
    print()
```

### LLM-Powered Analysis

```python
from agents.llm_agent import get_llm_agent
from utils.cache import CacheManager

# Initialize LLM agent (uses FREE models by default)
cache = CacheManager()
llm = get_llm_agent(cache_manager=cache)

# Analyze assembly code
code = """
mov eax, [ebp+8]
cmp eax, 0x12345678
je success
xor eax, eax
ret
success:
mov eax, 1
ret
"""

# Get analysis
analysis = llm.analyze_assembly(code)
print("Analysis:", analysis)

# Identify password check
password_check = llm.identify_password_check(code)
print("Password Check:", password_check)

# Get natural language explanation
explanation = llm.explain_code(code)
print("Explanation:", explanation)
```

### Pattern Recognition

```python
from agents.pattern_agent import PatternAgent
from agents.disassembly_agent import DisassemblyAgent
from utils.binary_utils import BinaryAnalyzer

# Initialize
analyzer = BinaryAnalyzer("binaries/target.exe")
disasm = DisassemblyAgent(analyzer)
pattern_agent = PatternAgent(disasm)

# Analyze function for patterns
analysis = pattern_agent.analyze_function_for_patterns(
    function_address=0x401000
)

# Print results
print(f"Password Checks: {len(analysis['password_checks'])}")
print(f"Suspicious Patterns: {len(analysis['suspicious_patterns'])}")

# Generate report
report = pattern_agent.generate_pattern_report(analysis)
print(report)
```

---

## 📊 Monitoring & Metrics

### Access Dashboards

**Grafana (Visualization):**
- URL: http://localhost:3000
- Username: `admin`
- Password: `admin_password_2025`

**Prometheus (Metrics):**
- URL: http://localhost:9090

**pgAdmin (PostgreSQL):**
- URL: http://localhost:5050
- Email: `admin@raverse.local`
- Password: `admin_password_2025`

**RedisInsight (Redis):**
- URL: http://localhost:5540

### View Metrics

```python
from utils.metrics import metrics_collector, get_metrics

# Record custom metrics
metrics_collector.record_patch_attempt("PE", "success")
metrics_collector.record_api_call("openrouter", "llama-3.2-3b", "success", 2.5)
metrics_collector.record_cache_hit("embedding")

# Get metrics in Prometheus format
metrics = get_metrics()
print(metrics.decode())
```

---

## 🧪 Testing

### Run Tests

```bash
# Run all tests
docker-compose exec raverse-app pytest

# Run specific test file
docker-compose exec raverse-app pytest tests/test_embeddings_v2.py -v

# Run with coverage
docker-compose exec raverse-app pytest --cov --cov-report=html
```

### Test Embeddings

```python
from utils.embeddings_v2 import get_embedding_generator

# Initialize
gen = get_embedding_generator()

# Generate embedding
code = "mov eax, 0x1"
embedding = gen.generate_code_embedding(code)

print(f"Embedding dimension: {embedding.shape}")
print(f"Embedding type: {embedding.dtype}")

# Batch generation
codes = ["mov eax, 0x1", "cmp eax, 0x0", "je 0x401000"]
embeddings = gen.generate_code_embeddings_batch(codes)

print(f"Generated {len(embeddings)} embeddings")
```

---

## 💡 Tips & Best Practices

### 1. Use FREE Models

The default configuration uses FREE models from OpenRouter:
- `meta-llama/llama-3.2-3b-instruct:free`
- No cost, no credit card required
- Good performance for binary analysis

### 2. Enable Caching

Always use caching to reduce API calls:
```python
from utils.cache import CacheManager

cache = CacheManager()
# Pass cache to agents
llm = get_llm_agent(cache_manager=cache)
```

### 3. Monitor Performance

Check Grafana dashboards regularly:
- Cache hit rate (target: >80%)
- API call duration (target: <5s)
- Patch success rate (target: >70%)

### 4. Batch Operations

Use batch operations for better performance:
```python
# Good: Batch embedding generation
embeddings = gen.generate_code_embeddings_batch(codes)

# Bad: Individual calls in loop
embeddings = [gen.generate_code_embedding(c) for c in codes]
```

### 5. Database Cleanup

Periodically clean old data:
```sql
-- Delete old embeddings (>30 days)
DELETE FROM raverse.code_embeddings
WHERE created_at < NOW() - INTERVAL '30 days';

-- Delete old LLM cache (>7 days)
DELETE FROM raverse.llm_cache
WHERE last_accessed_at < NOW() - INTERVAL '7 days';
```

---

## 🐛 Troubleshooting

### Issue: LLM Agent Fails to Initialize

**Solution:**
```bash
# Check OpenRouter API key
docker-compose exec raverse-app env | grep OPENROUTER

# Test API key
curl -H "Authorization: Bearer YOUR_KEY" \
  https://openrouter.ai/api/v1/models
```

### Issue: Database Connection Error

**Solution:**
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check logs
docker-compose logs postgres

# Restart service
docker-compose restart postgres
```

### Issue: Out of Memory

**Solution:**
```yaml
# Increase memory limits in docker-compose.yml
services:
  raverse-app:
    deploy:
      resources:
        limits:
          memory: 16G  # Increase from 8G
```

### Issue: Slow Embedding Generation

**Solution:**
```python
# Use smaller batch size
gen = EmbeddingGenerator(batch_size=16)  # Default: 32

# Or use caching
gen = EmbeddingGenerator(cache_manager=cache)
```

---

## 📚 Additional Resources

- **Full Documentation:** `docs/IMPLEMENTATION_SUMMARY.md`
- **API Reference:** `docs/API_REFERENCE.md` (coming soon)
- **Architecture:** `docs/ARCHITECTURE.md` (coming soon)
- **Research:** `research.md` (1,150+ lines)

---

## 🎉 Next Steps

1. Try the examples above
2. Explore Grafana dashboards
3. Experiment with different models
4. Contribute improvements
5. Share your results!

---

**Happy Patching! 🚀**

