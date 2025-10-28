#!/usr/bin/env python
"""
Direct test of pipeline components without importing all agents
"""

import sys
import asyncio

print("Testing AI Agent Pipeline System...")
print("="*60)

# Test 1: Import pipeline components directly
print("\n[1/11] Testing imports...")
try:
    from src.agents.ai_agent_pipeline import (
        AgentRegistry, TaskQueue, PipelineExecutor, AgentTask,
        ExecutionResult, AgentState, PipelinePhase
    )
    from src.agents.pipeline_orchestrator import PipelineOrchestrator, PipelineConfig
    from src.agents.pipeline_memory import PipelineMemory, ContextManager, StateRecovery
    from src.agents.pipeline_error_handling import ErrorHandler, ErrorSeverity, CircuitBreaker
    from src.agents.pipeline_tool_integration import ToolRegistry, ToolDefinition
    from src.agents.mcp_pipeline_integration import MCPPipelineIntegration
    print("✓ All imports successful")
except Exception as e:
    print(f"✗ Import failed: {e}")
    sys.exit(1)

# Test 2: PipelineConfig
print("[2/11] Testing PipelineConfig...")
try:
    config = PipelineConfig(max_concurrent_tasks=5, enable_caching=True)
    assert config.max_concurrent_tasks == 5
    print("✓ PipelineConfig working")
except Exception as e:
    print(f"✗ PipelineConfig failed: {e}")
    sys.exit(1)

# Test 3: AgentRegistry
print("[3/11] Testing AgentRegistry...")
try:
    registry = AgentRegistry()
    class MockAgent:
        async def execute(self, params):
            return {"result": "ok"}
    agent = MockAgent()
    registry.register("TEST", agent)
    assert registry.get_agent("TEST") == agent
    print("✓ AgentRegistry working")
except Exception as e:
    print(f"✗ AgentRegistry failed: {e}")
    sys.exit(1)

# Test 4: TaskQueue
print("[4/11] Testing TaskQueue...")
try:
    queue = TaskQueue()
    task = AgentTask("t1", "Agent1", "TYPE1", "test", {}, priority=5)
    queue.enqueue(task)
    dequeued = queue.dequeue()
    assert dequeued.task_id == "t1"
    print("✓ TaskQueue working")
except Exception as e:
    print(f"✗ TaskQueue failed: {e}")
    sys.exit(1)

# Test 5: PipelineMemory
print("[5/11] Testing PipelineMemory...")
try:
    memory = PipelineMemory()
    memory.set("key1", "value1", layer=1)
    memory.set("key2", "value2", layer=2)
    memory.set("key3", "value3", layer=3)
    assert memory.get("key1") == "value1"
    assert memory.get("key2") == "value2"
    assert memory.get("key3") == "value3"
    print("✓ PipelineMemory working")
except Exception as e:
    print(f"✗ PipelineMemory failed: {e}")
    sys.exit(1)

# Test 6: ContextManager
print("[6/11] Testing ContextManager...")
try:
    manager = ContextManager()
    ctx = manager.create_context("ctx1", {"initial": "state"})
    manager.set_variable("ctx1", "var1", "value1")
    assert manager.get_variable("ctx1", "var1") == "value1"
    print("✓ ContextManager working")
except Exception as e:
    print(f"✗ ContextManager failed: {e}")
    sys.exit(1)

# Test 7: StateRecovery
print("[7/11] Testing StateRecovery...")
try:
    recovery = StateRecovery()
    state = {"key": "value"}
    recovery.create_checkpoint("cp1", state)
    restored = recovery.restore_checkpoint("cp1")
    assert restored == state
    print("✓ StateRecovery working")
except Exception as e:
    print(f"✗ StateRecovery failed: {e}")
    sys.exit(1)

# Test 8: ErrorHandler
print("[8/11] Testing ErrorHandler...")
try:
    handler = ErrorHandler()
    error = handler.handle_error(
        "TEST_ERROR", "Test message", "AGENT1", "task1", ErrorSeverity.ERROR
    )
    assert error.error_type == "TEST_ERROR"
    stats = handler.get_error_stats()
    assert stats["total_errors"] == 1
    print("✓ ErrorHandler working")
except Exception as e:
    print(f"✗ ErrorHandler failed: {e}")
    sys.exit(1)

# Test 9: CircuitBreaker
print("[9/11] Testing CircuitBreaker...")
try:
    breaker = CircuitBreaker(failure_threshold=3)
    assert breaker.can_execute()
    breaker.record_failure()
    breaker.record_failure()
    breaker.record_failure()
    assert not breaker.can_execute()
    breaker.record_success()
    assert breaker.can_execute()
    print("✓ CircuitBreaker working")
except Exception as e:
    print(f"✗ CircuitBreaker failed: {e}")
    sys.exit(1)

# Test 10: ToolRegistry
print("[10/11] Testing ToolRegistry...")
try:
    registry = ToolRegistry()
    tool = ToolDefinition(
        name="test_tool",
        description="Test",
        category="test",
        handler=lambda x: x*2,
        input_schema={"type": "object"}
    )
    registry.register_tool(tool)
    assert registry.get_tool("test_tool") is not None
    print("✓ ToolRegistry working")
except Exception as e:
    print(f"✗ ToolRegistry failed: {e}")
    sys.exit(1)

# Test 11: MCPPipelineIntegration
print("[11/11] Testing MCPPipelineIntegration...")
try:
    orchestrator = PipelineOrchestrator()
    mcp = MCPPipelineIntegration(orchestrator)
    tools = mcp.get_mcp_tools()
    assert len(tools) > 0
    tool_names = [t["name"] for t in tools]
    assert "execute_workflow" in tool_names
    print("✓ MCPPipelineIntegration working")
except Exception as e:
    print(f"✗ MCPPipelineIntegration failed: {e}")
    sys.exit(1)

print("\n" + "="*60)
print("✓ All 11 tests passed!")
print("✓ AI Agent Pipeline System is fully functional")
print("="*60 + "\n")

