"""
Tests for AI Agent Pipeline System
"""

import pytest
import asyncio
from datetime import datetime
from src.agents.ai_agent_pipeline import (
    AgentRegistry, TaskQueue, PipelineExecutor, AgentTask,
    ExecutionResult, AgentState, PipelinePhase
)
from src.agents.pipeline_orchestrator import PipelineOrchestrator, PipelineConfig
from src.agents.pipeline_memory import PipelineMemory, ContextManager, StateRecovery
from src.agents.pipeline_error_handling import ErrorHandler, ErrorSeverity, CircuitBreaker
from src.agents.pipeline_tool_integration import ToolRegistry, ToolExecutor, ToolDefinition


class MockAgent:
    """Mock agent for testing"""
    
    def __init__(self, name: str, should_fail: bool = False):
        self.name = name
        self.should_fail = should_fail
        self.executed = False
    
    async def execute(self, parameters):
        self.executed = True
        if self.should_fail:
            raise Exception(f"Mock agent {self.name} failed")
        return {"result": f"Executed {self.name}", "parameters": parameters}


class TestAgentRegistry:
    """Test agent registry"""
    
    def test_register_agent(self):
        registry = AgentRegistry()
        agent = MockAgent("test_agent")
        
        registry.register("TEST", agent, {"name": "Test Agent"})
        
        assert registry.get_agent("TEST") == agent
        assert "TEST" in registry.list_agents()
    
    def test_get_nonexistent_agent(self):
        registry = AgentRegistry()
        assert registry.get_agent("NONEXISTENT") is None


class TestTaskQueue:
    """Test task queue"""
    
    def test_enqueue_dequeue(self):
        queue = TaskQueue()
        task = AgentTask(
            task_id="task1",
            agent_name="Agent1",
            agent_type="TYPE1",
            action="test",
            parameters={}
        )
        
        queue.enqueue(task)
        dequeued = queue.dequeue()
        
        assert dequeued.task_id == "task1"
    
    def test_priority_ordering(self):
        queue = TaskQueue()
        
        task1 = AgentTask("t1", "A1", "T1", "test", {}, priority=1)
        task2 = AgentTask("t2", "A2", "T2", "test", {}, priority=10)
        task3 = AgentTask("t3", "A3", "T3", "test", {}, priority=5)
        
        queue.enqueue(task1)
        queue.enqueue(task2)
        queue.enqueue(task3)
        
        assert queue.dequeue().task_id == "t2"  # priority 10
        assert queue.dequeue().task_id == "t3"  # priority 5
        assert queue.dequeue().task_id == "t1"  # priority 1


class TestPipelineExecutor:
    """Test pipeline executor"""
    
    @pytest.mark.asyncio
    async def test_execute_task_success(self):
        registry = AgentRegistry()
        queue = TaskQueue()
        executor = PipelineExecutor(registry, queue)
        
        agent = MockAgent("test_agent")
        registry.register("TEST", agent)
        
        task = AgentTask(
            task_id="task1",
            agent_name="Test Agent",
            agent_type="TEST",
            action="test",
            parameters={"key": "value"}
        )
        
        result = await executor.execute_task(task)
        
        assert result.success
        assert result.state == AgentState.SUCCEEDED
        assert agent.executed
    
    @pytest.mark.asyncio
    async def test_execute_task_failure(self):
        registry = AgentRegistry()
        queue = TaskQueue()
        executor = PipelineExecutor(registry, queue)
        
        agent = MockAgent("test_agent", should_fail=True)
        registry.register("TEST", agent)
        
        task = AgentTask(
            task_id="task1",
            agent_name="Test Agent",
            agent_type="TEST",
            action="test",
            parameters={}
        )
        
        result = await executor.execute_task(task)
        
        assert not result.success
        assert result.state == AgentState.FAILED


class TestPipelineOrchestrator:
    """Test pipeline orchestrator"""
    
    @pytest.mark.asyncio
    async def test_execute_workflow(self):
        config = PipelineConfig(max_concurrent_tasks=2)
        orchestrator = PipelineOrchestrator(config)
        
        agent = MockAgent("test_agent")
        orchestrator.register_agent("TEST", agent)
        
        tasks = [
            {
                "agent_type": "TEST",
                "agent_name": "Test Agent",
                "action": "test",
                "parameters": {"key": "value"}
            }
        ]
        
        execution = await orchestrator.execute_workflow("test_workflow", tasks)
        
        assert execution.status in ["completed", "partial"]
        assert execution.success_count > 0
    
    def test_register_tool(self):
        orchestrator = PipelineOrchestrator()
        
        def test_tool(x):
            return x * 2
        
        orchestrator.register_tool("test_tool", test_tool)
        
        assert "test_tool" in orchestrator.list_tools()
        assert orchestrator.call_tool("test_tool", x=5) == 10


class TestPipelineMemory:
    """Test pipeline memory"""
    
    def test_memory_layers(self):
        memory = PipelineMemory()
        
        memory.set("key1", "value1", layer=1)
        memory.set("key2", "value2", layer=2)
        memory.set("key3", "value3", layer=3)
        
        assert memory.get("key1") == "value1"
        assert memory.get("key2") == "value2"
        assert memory.get("key3") == "value3"
    
    def test_memory_stats(self):
        memory = PipelineMemory()
        memory.set("key1", "value1")
        
        stats = memory.get_stats()
        assert stats["total_entries"] > 0


class TestContextManager:
    """Test context manager"""
    
    def test_create_context(self):
        manager = ContextManager()
        
        context = manager.create_context("ctx1", {"initial": "state"})
        
        assert context["id"] == "ctx1"
        assert context["state"]["initial"] == "state"
    
    def test_set_get_variable(self):
        manager = ContextManager()
        manager.create_context("ctx1")
        
        manager.set_variable("ctx1", "var1", "value1")
        
        assert manager.get_variable("ctx1", "var1") == "value1"


class TestErrorHandler:
    """Test error handler"""
    
    def test_handle_error(self):
        handler = ErrorHandler()
        
        error = handler.handle_error(
            error_type="TEST_ERROR",
            message="Test error message",
            source_agent="TEST_AGENT",
            source_task="task1",
            severity=ErrorSeverity.ERROR
        )
        
        assert error.error_type == "TEST_ERROR"
        assert error.message == "Test error message"
        assert len(handler.get_errors()) == 1
    
    def test_error_stats(self):
        handler = ErrorHandler()
        
        handler.handle_error("ERROR1", "msg1", "agent1", "task1", ErrorSeverity.ERROR)
        handler.handle_error("ERROR2", "msg2", "agent2", "task2", ErrorSeverity.WARNING)
        
        stats = handler.get_error_stats()
        assert stats["total_errors"] == 2


class TestCircuitBreaker:
    """Test circuit breaker"""
    
    def test_circuit_breaker_states(self):
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


class TestToolRegistry:
    """Test tool registry"""
    
    def test_register_tool(self):
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
        
        assert registry.get_tool("test_tool") == tool
    
    def test_get_tool_schema(self):
        registry = ToolRegistry()
        
        tool = ToolDefinition(
            name="test_tool",
            description="Test tool",
            category="test",
            handler=lambda x: x,
            input_schema={"type": "object", "properties": {"x": {"type": "number"}}}
        )
        
        registry.register_tool(tool)
        schema = registry.get_tool_schema("test_tool")
        
        assert schema["name"] == "test_tool"
        assert schema["description"] == "Test tool"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

