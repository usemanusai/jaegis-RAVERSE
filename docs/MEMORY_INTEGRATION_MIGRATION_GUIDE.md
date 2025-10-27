# Memory Integration Migration Guide

## Overview
This guide helps you migrate existing RAVERSE 2.0 code to use the new memory optimization features.

## Key Points
- ✅ **100% Backward Compatible** - Existing code works without changes
- ✅ **Opt-In** - Memory is disabled by default
- ✅ **Zero Overhead** - No performance impact when disabled
- ✅ **Easy to Enable** - Just add 2 parameters

## Migration Levels

### Level 0: No Changes Required (Default)
Your existing code continues to work exactly as before:

```python
# Existing code - works as-is
agent = VersionManagerAgent(orchestrator=my_orchestrator)
result = agent.execute(task)
```

### Level 1: Enable Memory (Recommended)
Add memory support with minimal changes:

```python
# Add memory parameters
agent = VersionManagerAgent(
    orchestrator=my_orchestrator,
    memory_strategy="sliding_window",
    memory_config={"window_size": 3}
)
result = agent.execute(task)
```

### Level 2: Use Presets (Easiest)
Use predefined configurations:

```python
from config.agent_memory_config import AGENT_MEMORY_CONFIG

# Get recommended config for agent
config = AGENT_MEMORY_CONFIG["version_manager"]

agent = VersionManagerAgent(
    orchestrator=my_orchestrator,
    memory_strategy=config["strategy"],
    memory_config=config["config"]
)
```

### Level 3: Custom Configuration (Advanced)
Fine-tune for your specific needs:

```python
agent = VersionManagerAgent(
    orchestrator=my_orchestrator,
    memory_strategy="hierarchical",
    memory_config={
        "window_size": 5,
        "k": 3,
        "summary_interval": 10
    }
)
```

## Memory Strategies Quick Reference

| Strategy | Use Case | Memory | CPU | Latency |
|----------|----------|--------|-----|---------|
| None | No memory | 0 MB | 0% | < 0.01ms |
| Sliding Window | Recent context | 5 MB | 1% | 0.3ms |
| Summarization | Compressed history | 10 MB | 2% | 1ms |
| Memory-Augmented | Critical facts | 8 MB | 1.5% | 0.8ms |
| Hierarchical | Multi-level | 20 MB | 3% | 1.2ms |
| Graph-Based | Relationships | 30 MB | 4% | 2ms |
| Compression | Extreme reduction | 3 MB | 2% | 1.5ms |
| OS-Like | Virtual memory | 50 MB | 2% | 0.7ms |
| Retrieval | Semantic search | 100 MB | 5% | 2ms |

## Preset Configurations

### Light Preset
```python
agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy="sliding_window",
    memory_config={"window_size": 5}
)
# 5 MB RAM, 1% CPU, 0.3ms latency
```

### Medium Preset (Recommended)
```python
agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy="hierarchical",
    memory_config={"window_size": 3, "k": 2}
)
# 20 MB RAM, 3% CPU, 1.2ms latency
```

### Heavy Preset
```python
agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy="retrieval",
    memory_config={"k": 5, "embedding_dim": 384}
)
# 100 MB RAM, 5% CPU, 2ms latency
```

## Migration Checklist

### Step 1: Identify Agents to Migrate
- [ ] List all agents in your application
- [ ] Determine which need memory support
- [ ] Prioritize high-value agents

### Step 2: Choose Memory Strategy
- [ ] Review strategy comparison table
- [ ] Consider your resource constraints
- [ ] Test with different strategies

### Step 3: Update Agent Initialization
- [ ] Add memory_strategy parameter
- [ ] Add memory_config parameter
- [ ] Test agent functionality

### Step 4: Verify Backward Compatibility
- [ ] Run existing tests
- [ ] Verify no performance regression
- [ ] Check memory usage

### Step 5: Monitor and Tune
- [ ] Monitor memory usage
- [ ] Monitor CPU usage
- [ ] Adjust configuration as needed

## Example: Migrating VersionManagerAgent

### Before (No Memory)
```python
from agents.online_version_manager_agent import VersionManagerAgent

agent = VersionManagerAgent(orchestrator=orchestrator)
result = agent.execute({"action": "check_version"})
```

### After (With Memory)
```python
from agents.online_version_manager_agent import VersionManagerAgent

agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy="sliding_window",
    memory_config={"window_size": 3}
)
result = agent.execute({"action": "check_version"})
```

## Troubleshooting

### Issue: Memory not working
**Solution**: Check that memory_strategy is not None
```python
if agent.has_memory_enabled():
    print("Memory is enabled")
else:
    print("Memory is disabled")
```

### Issue: High memory usage
**Solution**: Use lighter preset or smaller window size
```python
# Instead of heavy preset
memory_config={"k": 5, "embedding_dim": 384}

# Use light preset
memory_config={"window_size": 3}
```

### Issue: Slow performance
**Solution**: Use "none" or "light" preset
```python
# Disable memory
memory_strategy=None

# Or use light preset
memory_strategy="sliding_window"
memory_config={"window_size": 2}
```

## Best Practices

1. **Start with None** - Verify existing functionality
2. **Test with Light** - Minimal overhead
3. **Move to Medium** - Production recommended
4. **Use Heavy Only When Needed** - High accuracy requirements
5. **Monitor Metrics** - Track memory and CPU
6. **Tune Gradually** - Adjust based on results

## Supported Agents

All 19 agents support memory:

**Core Agents (8)**
- VersionManagerAgent
- KnowledgeBaseAgent
- QualityGateAgent
- GovernanceAgent
- DocumentGeneratorAgent
- RAGOrchestratorAgent
- DAAAgent
- LIMAAgent

**Online Analysis Agents (8)**
- ReconnaissanceAgent
- APIReverseEngineeringAgent
- JavaScriptAnalysisAgent
- WebAssemblyAnalysisAgent
- SecurityAnalysisAgent
- TrafficInterceptionAgent
- ValidationAgent
- ReportingAgent

**Deep Research Agents (3)**
- DeepResearchWebResearcherAgent
- DeepResearchContentAnalyzerAgent
- DeepResearchTopicEnhancerAgent

## Next Steps

1. Review the [Memory Strategies Documentation](./MEMORY_STRATEGIES.md)
2. Check [Configuration Guide](./MEMORY_CONFIGURATION.md)
3. Run [Verification Script](../verify_memory_integration.py)
4. Monitor with [Performance Metrics](./MEMORY_PERFORMANCE.md)

---
For questions or issues, refer to the comprehensive documentation in `/docs/memory/`

