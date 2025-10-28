# AI Agent Pipeline System - Complete Guide

## Overview

The AI Agent Pipeline System is a comprehensive framework for orchestrating multi-agent workflows in RAVERSE. It provides:

- **Agent Orchestration**: Coordinate multiple agents with dependency management
- **Tool Integration**: Seamless integration with MCP tools and external services
- **Memory Management**: Multi-layer memory system with caching and TTL
- **Error Handling**: Comprehensive error recovery with circuit breakers and retries
- **State Management**: Context persistence and state recovery
- **MCP Integration**: Full integration with Model Context Protocol

## Architecture

### Core Components

1. **AgentRegistry**: Manages agent registration and discovery
2. **TaskQueue**: Priority-based task queuing with dependency tracking
3. **PipelineExecutor**: Executes tasks with timeout and error handling
4. **PipelineOrchestrator**: Main orchestrator for workflow execution
5. **ToolRegistry**: Manages tool registration and execution
6. **PipelineMemory**: Multi-layer memory system (L1, L2, L3)
7. **ErrorHandler**: Centralized error handling and recovery
8. **MCPPipelineIntegration**: Bridges pipeline with MCP protocol

## Quick Start

### 1. Setup Pipeline

```python
from src.agents import PipelineOrchestrator, PipelineConfig

config = PipelineConfig(
    max_concurrent_tasks=5,
    enable_caching=True,
    enable_recovery=True
)
orchestrator = PipelineOrchestrator(config)
```

### 2. Register Agents

```python
class MyAgent:
    async def execute(self, parameters):
        return {"result": "success"}

agent = MyAgent()
orchestrator.register_agent("MY_AGENT", agent)
```

### 3. Register Tools

```python
def my_tool(data):
    return {"processed": data}

orchestrator.register_tool("my_tool", my_tool)
```

### 4. Execute Workflow

```python
tasks = [
    {
        "agent_type": "MY_AGENT",
        "agent_name": "My Agent",
        "action": "process",
        "parameters": {"input": "data"}
    }
]

execution = await orchestrator.execute_workflow("my_workflow", tasks)
```

## Features

### Agent Orchestration

- Sequential and parallel execution
- Priority-based task scheduling
- Dependency management
- Timeout handling
- Automatic retry with exponential backoff

### Memory System

Three-layer memory architecture:

- **L1**: Fast access, 100 entries, 5-minute TTL
- **L2**: Medium access, 1000 entries, 1-hour TTL
- **L3**: Slow access, 10000 entries, 24-hour TTL

```python
memory = PipelineMemory()
memory.set("key", "value", layer=1)
value = memory.get("key")
```

### Error Handling

- Automatic error classification
- Retry policies with exponential backoff
- Circuit breaker pattern
- Fallback handlers
- Error callbacks

```python
error_handler = ErrorHandler()
error = error_handler.handle_error(
    error_type="TIMEOUT",
    message="Task timeout",
    source_agent="AGENT_1",
    source_task="task_1"
)
```

### Tool Integration

- Tool registry with metadata
- Async and sync tool support
- Result caching
- Tool chaining
- Execution history

```python
tool_registry = ToolRegistry()
tool = ToolDefinition(
    name="my_tool",
    description="My tool",
    category="processing",
    handler=my_handler,
    input_schema={...}
)
tool_registry.register_tool(tool)
```

### MCP Integration

Exposes pipeline as MCP tools:

- `execute_workflow`: Execute workflow
- `get_execution_status`: Get workflow status
- `list_agents`: List registered agents
- `list_tools`: List registered tools
- `call_tool`: Call a tool
- `store_state`: Store state
- `get_state`: Retrieve state

## Advanced Usage

### Parallel Execution

```python
execution = await orchestrator.execute_workflow(
    "parallel_workflow",
    tasks,
    parallel=True
)
```

### Context Management

```python
context_manager = ContextManager()
context = context_manager.create_context("ctx1")
context_manager.set_variable("ctx1", "key", "value")
```

### State Recovery

```python
recovery = StateRecovery()
recovery.create_checkpoint("cp1", state_dict)
restored = recovery.restore_checkpoint("cp1")
```

### Tool Chaining

```python
chain = ToolChain(executor)
chain.add_step("tool1", {"param": "value"})
chain.add_step("tool2", {"param": "$tool1"})
result = await chain.execute()
```

## Configuration

### PipelineConfig Options

- `max_concurrent_tasks`: Maximum parallel tasks (default: 5)
- `enable_caching`: Enable result caching (default: True)
- `enable_recovery`: Enable error recovery (default: True)
- `log_level`: Logging level (default: "INFO")
- `timeout_seconds`: Default task timeout (default: 300)

## Monitoring

### Execution Status

```python
status = orchestrator.get_execution_status(execution_id)
```

### Error Statistics

```python
stats = error_handler.get_error_stats()
```

### Tool Statistics

```python
tool_stats = executor.get_tool_stats("tool_name")
```

### Memory Statistics

```python
memory_stats = memory.get_stats()
```

## Best Practices

1. **Use appropriate memory layers** based on access frequency
2. **Register error callbacks** for monitoring
3. **Set reasonable timeouts** for tasks
4. **Use tool caching** for expensive operations
5. **Monitor circuit breaker states** for system health
6. **Create checkpoints** for long-running workflows
7. **Use context managers** for state isolation

## Examples

See `examples/pipeline_integration_example.py` for complete working examples.

## API Reference

### PipelineOrchestrator

- `register_agent(agent_type, agent_instance, metadata)`
- `register_tool(tool_name, tool_func)`
- `execute_workflow(workflow_name, tasks, parallel)`
- `get_execution_status(execution_id)`
- `list_agents()`
- `list_tools()`
- `store_state(key, value)`
- `get_state(key)`

### ErrorHandler

- `handle_error(...)`
- `should_retry(error, attempt)`
- `get_retry_delay(attempt)`
- `get_errors(severity)`
- `get_error_stats()`

### PipelineMemory

- `set(key, value, layer, ttl_seconds)`
- `get(key)`
- `delete(key)`
- `clear()`
- `get_stats()`

### ToolRegistry

- `register_tool(tool_def)`
- `get_tool(tool_name)`
- `list_tools(category)`
- `get_tool_schema(tool_name)`
- `get_all_tool_schemas()`

