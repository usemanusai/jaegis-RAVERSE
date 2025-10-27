# Memory Configuration Examples

## Quick Start Examples

### Example 1: Minimal Setup (No Memory)
```python
from agents.online_version_manager_agent import VersionManagerAgent

# Memory disabled by default
agent = VersionManagerAgent(orchestrator=None)
result = agent.execute({"action": "check_version"})
```

### Example 2: Light Memory (Sliding Window)
```python
from agents.online_version_manager_agent import VersionManagerAgent

agent = VersionManagerAgent(
    orchestrator=None,
    memory_strategy="sliding_window",
    memory_config={"window_size": 3}
)

# Add to memory
agent.add_to_memory("query1", "result1")
agent.add_to_memory("query2", "result2")

# Retrieve context
context = agent.get_memory_context("query1")
```

### Example 3: Medium Memory (Hierarchical)
```python
from agents.online_knowledge_base_agent import KnowledgeBaseAgent

agent = KnowledgeBaseAgent(
    orchestrator=None,
    api_key="your-api-key",
    model="your-model",
    memory_strategy="hierarchical",
    memory_config={
        "window_size": 3,
        "k": 2
    }
)

result = agent.execute({"query": "search term"})
```

### Example 4: Heavy Memory (Retrieval/RAG)
```python
from agents.online_knowledge_base_agent import KnowledgeBaseAgent

agent = KnowledgeBaseAgent(
    orchestrator=None,
    api_key="your-api-key",
    model="your-model",
    memory_strategy="retrieval",
    memory_config={
        "k": 5,
        "embedding_dim": 384
    }
)

result = agent.execute({"query": "complex search"})
```

## Agent-Specific Examples

### VersionManagerAgent
```python
from agents.online_version_manager_agent import VersionManagerAgent

# Recommended: Medium preset
agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy="hierarchical",
    memory_config={"window_size": 3, "k": 2}
)
```

### KnowledgeBaseAgent
```python
from agents.online_knowledge_base_agent import KnowledgeBaseAgent

# Recommended: Heavy preset (RAG)
agent = KnowledgeBaseAgent(
    orchestrator=orchestrator,
    api_key=api_key,
    model=model,
    memory_strategy="retrieval",
    memory_config={"k": 5, "embedding_dim": 384}
)
```

### QualityGateAgent
```python
from agents.online_quality_gate_agent import QualityGateAgent

# Recommended: Memory-augmented
agent = QualityGateAgent(
    orchestrator=orchestrator,
    memory_strategy="memory_augmented",
    memory_config={"window_size": 2}
)
```

### ReconnaissanceAgent
```python
from agents.online_reconnaissance_agent import ReconnaissanceAgent

# Recommended: Retrieval
agent = ReconnaissanceAgent(
    orchestrator=orchestrator,
    memory_strategy="retrieval",
    memory_config={"k": 5, "embedding_dim": 384}
)
```

### ValidationAgent
```python
from agents.online_validation_agent import ValidationAgent

# Recommended: Sliding window
agent = ValidationAgent(
    orchestrator=orchestrator,
    memory_strategy="sliding_window",
    memory_config={"window_size": 5}
)
```

### ReportingAgent
```python
from agents.online_reporting_agent import ReportingAgent

# Recommended: Summarization
agent = ReportingAgent(
    orchestrator=orchestrator,
    memory_strategy="summarization",
    memory_config={"summary_interval": 5}
)
```

## Orchestrator Integration

### Using OnlineOrchestrationAgent
```python
from agents.online_orchestrator import OnlineOrchestrationAgent

orchestrator = OnlineOrchestrationAgent(api_key=api_key, model=model)

# All agents initialized with memory support
# Access agents with memory enabled
agent = orchestrator.agents['VERSION_MANAGER']
```

### Custom Orchestrator with Memory
```python
from agents.online_version_manager_agent import VersionManagerAgent
from agents.online_knowledge_base_agent import KnowledgeBaseAgent

class CustomOrchestrator:
    def __init__(self):
        self.agents = {
            'VERSION_MANAGER': VersionManagerAgent(
                orchestrator=self,
                memory_strategy="hierarchical",
                memory_config={"window_size": 3, "k": 2}
            ),
            'KNOWLEDGE_BASE': KnowledgeBaseAgent(
                orchestrator=self,
                api_key=api_key,
                model=model,
                memory_strategy="retrieval",
                memory_config={"k": 5, "embedding_dim": 384}
            )
        }
```

## Configuration Patterns

### Pattern 1: Preset-Based
```python
from config.agent_memory_config import AGENT_MEMORY_CONFIG

config = AGENT_MEMORY_CONFIG["version_manager"]
agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy=config["strategy"],
    memory_config=config["config"]
)
```

### Pattern 2: Environment-Based
```python
import os

memory_strategy = os.getenv("MEMORY_STRATEGY", "sliding_window")
memory_config = {
    "window_size": int(os.getenv("MEMORY_WINDOW_SIZE", "3"))
}

agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy=memory_strategy,
    memory_config=memory_config
)
```

### Pattern 3: Config File-Based
```python
import json

with open("memory_config.json") as f:
    config = json.load(f)

agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy=config["strategy"],
    memory_config=config["config"]
)
```

### Pattern 4: Conditional
```python
# Enable memory only in production
import os

memory_strategy = "hierarchical" if os.getenv("ENV") == "production" else None

agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy=memory_strategy,
    memory_config={"window_size": 3, "k": 2} if memory_strategy else {}
)
```

## Advanced Configurations

### High-Performance Setup
```python
# Minimal memory overhead
agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy="sliding_window",
    memory_config={"window_size": 2}  # Small window
)
```

### High-Accuracy Setup
```python
# Maximum accuracy
agent = KnowledgeBaseAgent(
    orchestrator=orchestrator,
    api_key=api_key,
    model=model,
    memory_strategy="retrieval",
    memory_config={
        "k": 10,  # More neighbors
        "embedding_dim": 768  # Higher dimension
    }
)
```

### Balanced Setup
```python
# Good balance of performance and accuracy
agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy="hierarchical",
    memory_config={
        "window_size": 3,
        "k": 2
    }
)
```

### Extreme Compression Setup
```python
# Minimal memory usage
agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy="compression",
    memory_config={"compression_ratio": 0.3}
)
```

## Testing Configurations

### Unit Test Setup
```python
# No memory for fast tests
agent = VersionManagerAgent(
    orchestrator=None,
    memory_strategy=None
)
```

### Integration Test Setup
```python
# Light memory for realistic tests
agent = VersionManagerAgent(
    orchestrator=None,
    memory_strategy="sliding_window",
    memory_config={"window_size": 2}
)
```

### Performance Test Setup
```python
# All strategies for benchmarking
strategies = [
    ("none", None),
    ("light", {"window_size": 3}),
    ("medium", {"window_size": 3, "k": 2}),
    ("heavy", {"k": 5, "embedding_dim": 384})
]

for name, config in strategies:
    agent = VersionManagerAgent(
        orchestrator=None,
        memory_strategy=name if name != "none" else None,
        memory_config=config or {}
    )
    # Run benchmarks
```

## Troubleshooting Configurations

### Issue: Memory not persisting
```python
# Verify memory is enabled
if not agent.has_memory_enabled():
    agent = VersionManagerAgent(
        orchestrator=orchestrator,
        memory_strategy="sliding_window",
        memory_config={"window_size": 3}
    )
```

### Issue: Out of memory
```python
# Use compression strategy
agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy="compression",
    memory_config={"compression_ratio": 0.5}
)
```

### Issue: Slow performance
```python
# Disable memory or use light preset
agent = VersionManagerAgent(
    orchestrator=orchestrator,
    memory_strategy="sliding_window",
    memory_config={"window_size": 2}
)
```

---
For more information, see [Migration Guide](./MEMORY_INTEGRATION_MIGRATION_GUIDE.md)

