#!/usr/bin/env python
"""
Simple validation script for AI Agent Pipeline System
Tests core pipeline components directly
"""

import sys
import asyncio

# Import only the pipeline components, not all agents
from src.agents.ai_agent_pipeline import (
    AgentRegistry, TaskQueue, PipelineExecutor, AgentTask,
    ExecutionResult, AgentState, PipelinePhase
)
from src.agents.pipeline_orchestrator import PipelineOrchestrator, PipelineConfig
from src.agents.pipeline_memory import PipelineMemory, ContextManager, StateRecovery
from src.agents.pipeline_error_handling import ErrorHandler, ErrorSeverity, CircuitBreaker
from src.agents.pipeline_tool_integration import ToolRegistry, ToolDefinition
from src.agents.mcp_pipeline_integration import MCPPipelineIntegration

def test_imports():
    """Test all imports"""
    print("✓ All imports successful")
    return True

def test_pipeline_config():
    """Test pipeline configuration"""
    config = PipelineConfig(
        max_concurrent_tasks=5,
        enable_caching=True,
        enable_recovery=True
    )
    assert config.max_concurrent_tasks == 5
    print("✓ PipelineConfig working")
    return True

def test_pipeline_orchestrator():
    """Test pipeline orchestrator"""
    orchestrator = PipelineOrchestrator()
    assert orchestrator is not None
    assert len(orchestrator.list_agents()) == 0
    assert len(orchestrator.list_tools()) == 0
    print("✓ PipelineOrchestrator working")
    return True

def test_tool_registry():
    """Test tool registry"""
    registry = ToolRegistry()
    
    def test_handler(x):
        return x * 2
    
    tool = ToolDefinition(
        name="test_tool",
        description="Test tool",
        category="test",
        handler=test_handler,
        input_schema={"type": "object"}
    )
    
    registry.register_tool(tool)
    assert registry.get_tool("test_tool") is not None
    print("✓ ToolRegistry working")
    return True

def test_pipeline_memory():
    """Test pipeline memory"""
    memory = PipelineMemory()
    
    memory.set("key1", "value1", layer=1)
    assert memory.get("key1") == "value1"
    
    memory.set("key2", "value2", layer=2)
    assert memory.get("key2") == "value2"
    
    memory.set("key3", "value3", layer=3)
    assert memory.get("key3") == "value3"
    
    stats = memory.get_stats()
    assert stats["total_entries"] == 3
    print("✓ PipelineMemory working")
    return True

def test_context_manager():
    """Test context manager"""
    manager = ContextManager()
    
    context = manager.create_context("ctx1", {"initial": "state"})
    assert context["id"] == "ctx1"
    
    manager.set_variable("ctx1", "var1", "value1")
    assert manager.get_variable("ctx1", "var1") == "value1"
    print("✓ ContextManager working")
    return True

def test_state_recovery():
    """Test state recovery"""
    recovery = StateRecovery()
    
    state = {"key": "value", "data": [1, 2, 3]}
    recovery.create_checkpoint("cp1", state)
    
    restored = recovery.restore_checkpoint("cp1")
    assert restored == state
    print("✓ StateRecovery working")
    return True

def test_error_handler():
    """Test error handler"""
    handler = ErrorHandler()
    
    error = handler.handle_error(
        error_type="TEST_ERROR",
        message="Test error",
        source_agent="TEST_AGENT",
        source_task="task1",
        severity=ErrorSeverity.ERROR
    )
    
    assert error.error_type == "TEST_ERROR"
    assert len(handler.get_errors()) == 1
    
    stats = handler.get_error_stats()
    assert stats["total_errors"] == 1
    print("✓ ErrorHandler working")
    return True

def test_circuit_breaker():
    """Test circuit breaker"""
    breaker = CircuitBreaker(failure_threshold=3)
    
    assert breaker.can_execute()
    assert breaker.get_state() == "closed"
    
    breaker.record_failure()
    breaker.record_failure()
    breaker.record_failure()
    
    assert not breaker.can_execute()
    assert breaker.get_state() == "open"
    
    breaker.record_success()
    assert breaker.can_execute()
    assert breaker.get_state() == "closed"
    print("✓ CircuitBreaker working")
    return True

def test_mcp_integration():
    """Test MCP integration"""
    orchestrator = PipelineOrchestrator()
    mcp_integration = MCPPipelineIntegration(orchestrator)
    
    tools = mcp_integration.get_mcp_tools()
    assert len(tools) > 0
    
    tool_names = [t["name"] for t in tools]
    assert "execute_workflow" in tool_names
    assert "list_agents" in tool_names
    print("✓ MCPPipelineIntegration working")
    return True

async def test_async_operations():
    """Test async operations"""
    orchestrator = PipelineOrchestrator()
    
    class TestAgent:
        async def execute(self, parameters):
            await asyncio.sleep(0.01)
            return {"result": "success"}
    
    agent = TestAgent()
    orchestrator.register_agent("TEST", agent)
    
    tasks = [
        {
            "agent_type": "TEST",
            "agent_name": "Test Agent",
            "action": "test",
            "parameters": {}
        }
    ]
    
    execution = await orchestrator.execute_workflow("test", tasks)
    assert execution.status in ["completed", "partial"]
    print("✓ Async operations working")
    return True

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("AI Agent Pipeline System - Validation (Core Components)")
    print("="*60 + "\n")
    
    tests = [
        ("Imports", test_imports),
        ("PipelineConfig", test_pipeline_config),
        ("PipelineOrchestrator", test_pipeline_orchestrator),
        ("ToolRegistry", test_tool_registry),
        ("PipelineMemory", test_pipeline_memory),
        ("ContextManager", test_context_manager),
        ("StateRecovery", test_state_recovery),
        ("ErrorHandler", test_error_handler),
        ("CircuitBreaker", test_circuit_breaker),
        ("MCPIntegration", test_mcp_integration),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"✗ {test_name} failed: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    # Run async test
    try:
        asyncio.run(test_async_operations())
        passed += 1
    except Exception as e:
        print(f"✗ Async operations failed: {e}")
        import traceback
        traceback.print_exc()
        failed += 1
    
    print("\n" + "="*60)
    print(f"Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    if failed == 0:
        print("✓ All tests passed! Pipeline system is working correctly.")
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())

