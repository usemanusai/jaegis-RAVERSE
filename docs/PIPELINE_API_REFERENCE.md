# AI Agent Pipeline System - Complete API Reference

## Core Classes

### PipelineOrchestrator

Main orchestration engine for the pipeline system.

```python
class PipelineOrchestrator:
    def __init__(self, config: PipelineConfig = None)
    def register_agent(self, agent_type: str, agent_instance: Any, metadata: Dict = None)
    def register_tool(self, tool_name: str, tool_func: Callable)
    def list_agents(self) -> List[str]
    def list_tools(self) -> List[str]
    async def execute_workflow(self, workflow_name: str, tasks: List[Dict], parallel: bool = False) -> PipelineExecution
    def get_execution_status(self, execution_id: str) -> Optional[Dict]
    def store_state(self, key: str, value: Any)
    def get_state(self, key: str) -> Optional[Any]
    def store_memory(self, key: str, value: Any)
    def get_memory(self, key: str) -> Optional[Any]
    def call_tool(self, tool_name: str, **kwargs) -> Any
```

### PipelineMemory

Multi-layer memory system with L1, L2, L3 caching.

```python
class PipelineMemory:
    def set(self, key: str, value: Any, layer: int = 1, ttl_seconds: Optional[int] = None)
    def get(self, key: str) -> Optional[Any]
    def delete(self, key: str)
    def clear(self)
    def get_stats(self) -> Dict[str, Any]
```

### ContextManager

Manages execution contexts and variables.

```python
class ContextManager:
    def create_context(self, context_id: str, initial_state: Dict = None) -> Dict
    def get_context(self, context_id: str) -> Optional[Dict]
    def set_variable(self, context_id: str, key: str, value: Any)
    def get_variable(self, context_id: str, key: str) -> Optional[Any]
    def add_artifact(self, context_id: str, artifact: Dict)
    def get_artifacts(self, context_id: str) -> List[Dict]
    def delete_context(self, context_id: str)
```

### ErrorHandler

Centralized error management and recovery.

```python
class ErrorHandler:
    def handle_error(self, error_type: str, message: str, source_agent: str, 
                    source_task: str, severity: ErrorSeverity = ErrorSeverity.ERROR,
                    context: Dict = None, exc: Exception = None) -> PipelineError
    def should_retry(self, error: PipelineError, attempt: int) -> bool
    def get_retry_delay(self, attempt: int) -> float
    def get_errors(self, severity: Optional[ErrorSeverity] = None) -> List[PipelineError]
    def get_error_stats(self) -> Dict[str, Any]
    def clear_errors()
    def register_error_callback(self, callback: Callable)
```

### CircuitBreaker

Implements circuit breaker pattern for fault tolerance.

```python
class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, timeout_seconds: int = 60)
    def record_success()
    def record_failure()
    def can_execute(self) -> bool
    def get_state(self) -> str  # "closed", "open", "half-open"
```

### ToolRegistry

Manages tool registration and discovery.

```python
class ToolRegistry:
    def register_tool(self, tool_def: ToolDefinition)
    def get_tool(self, tool_name: str) -> Optional[ToolDefinition]
    def list_tools(self, category: Optional[str] = None) -> List[ToolDefinition]
    def get_tool_schema(self, tool_name: str) -> Optional[Dict]
    def get_all_tool_schemas(self) -> List[Dict]
```

### ToolExecutor

Executes tools with caching and error handling.

```python
class ToolExecutor:
    def __init__(self, registry: ToolRegistry)
    async def execute_tool(self, tool_name: str, parameters: Dict, 
                          use_cache: bool = True) -> ToolExecutionResult
    def get_execution_history(self) -> List[ToolExecutionResult]
    def get_tool_stats(self, tool_name: str) -> Dict[str, Any]
```

### ToolChain

Chains multiple tools together.

```python
class ToolChain:
    def __init__(self, executor: ToolExecutor)
    def add_step(self, tool_name: str, parameters: Dict, output_key: str = None)
    async def execute(self) -> Dict[str, Any]
```

### MCPPipelineIntegration

Bridges pipeline with MCP protocol.

```python
class MCPPipelineIntegration:
    def __init__(self, orchestrator: PipelineOrchestrator)
    def get_mcp_tools(self) -> List[Dict]
    async def handle_mcp_tool_call(self, tool_name: str, arguments: Dict) -> Dict
```

## Data Classes

### AgentTask

Represents a task for an agent.

```python
@dataclass
class AgentTask:
    task_id: str
    agent_name: str
    agent_type: str
    action: str
    parameters: Dict[str, Any]
    priority: int = 0
    timeout: int = 300
    retry_count: int = 0
    max_retries: int = 3
    dependencies: List[str] = None
    created_at: datetime = None
```

### ExecutionResult

Result from agent execution.

```python
@dataclass
class ExecutionResult:
    task_id: str
    agent_name: str
    agent_type: str
    state: AgentState
    success: bool
    data: Optional[Dict] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    artifacts: List[str] = None
    metrics: Dict = None
    start_time: datetime = None
    end_time: datetime = None
    duration_seconds: float = 0.0
```

### PipelineExecution

Represents a complete pipeline execution.

```python
@dataclass
class PipelineExecution:
    execution_id: str
    workflow_name: str
    status: str  # "queued", "running", "completed", "failed"
    phase: PipelinePhase
    tasks: List[AgentTask]
    results: List[ExecutionResult]
    start_time: datetime
    end_time: Optional[datetime] = None
    total_duration: float = 0.0
    success_count: int = 0
    failure_count: int = 0
    error: Optional[str] = None
```

### ToolDefinition

Tool metadata and configuration.

```python
@dataclass
class ToolDefinition:
    name: str
    description: str
    category: str
    handler: Callable
    input_schema: Dict[str, Any]
    output_schema: Dict = None
    timeout: int = 30
    retry_on_failure: bool = True
    cache_results: bool = False
```

## Enumerations

### AgentState
- IDLE
- QUEUED
- RUNNING
- SUCCEEDED
- FAILED
- CANCELLED
- SKIPPED

### PipelinePhase
- INITIALIZATION
- VALIDATION
- EXECUTION
- AGGREGATION
- FINALIZATION

### ErrorSeverity
- INFO
- WARNING
- ERROR
- CRITICAL

### ErrorRecoveryStrategy
- RETRY
- FALLBACK
- SKIP
- ABORT
- CUSTOM

## Configuration

### PipelineConfig

```python
@dataclass
class PipelineConfig:
    max_concurrent_tasks: int = 5
    enable_caching: bool = True
    enable_recovery: bool = True
    log_level: str = "INFO"
    timeout_seconds: int = 300
```

## MCP Tools

### execute_workflow
Execute a complete workflow.

**Input Schema:**
```json
{
  "workflow_name": "string",
  "tasks": [
    {
      "agent_type": "string",
      "agent_name": "string",
      "action": "string",
      "parameters": "object"
    }
  ],
  "parallel": "boolean"
}
```

### get_execution_status
Get status of a pipeline execution.

**Input Schema:**
```json
{
  "execution_id": "string"
}
```

### list_agents
List all registered agents.

### list_tools
List all registered tools.

### call_tool
Call a registered tool.

**Input Schema:**
```json
{
  "tool_name": "string",
  "parameters": "object"
}
```

### store_state
Store state in the pipeline.

**Input Schema:**
```json
{
  "key": "string",
  "value": "object"
}
```

### get_state
Retrieve state from the pipeline.

**Input Schema:**
```json
{
  "key": "string"
}
```

## Error Handling

### RetryPolicy

```python
class RetryPolicy:
    def __init__(self, max_retries: int = 3, initial_delay: float = 1.0,
                 max_delay: float = 60.0, backoff_multiplier: float = 2.0,
                 jitter: bool = True)
    def get_delay(self, attempt: int) -> float
```

### FallbackHandler

```python
class FallbackHandler:
    def register_fallback(self, error_type: str, handler: Callable)
    def handle_fallback(self, error: PipelineError) -> Optional[Any]
```

## Memory Layers

### L1 Memory
- Capacity: 100 entries
- TTL: 5 minutes
- Use case: Fast access, frequently used data

### L2 Memory
- Capacity: 1000 entries
- TTL: 1 hour
- Use case: Medium-term storage

### L3 Memory
- Capacity: 10000 entries
- TTL: 24 hours
- Use case: Long-term storage

## Best Practices

1. Use L1 for frequently accessed data
2. Set appropriate timeouts for tasks
3. Register error callbacks for monitoring
4. Use tool caching for expensive operations
5. Monitor circuit breaker states
6. Create checkpoints for long workflows
7. Use context managers for state isolation

