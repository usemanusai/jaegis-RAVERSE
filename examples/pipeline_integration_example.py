"""
AI Agent Pipeline Integration Example
Demonstrates complete usage of the pipeline system with agents, tools, and MCP integration.
"""

import asyncio
import logging
from src.agents import (
    PipelineOrchestrator, PipelineConfig, ToolRegistry, ToolDefinition,
    ToolExecutor, MCPPipelineIntegration, PipelineMemory, ContextManager,
    ErrorHandler, ErrorSeverity
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ExampleAgent:
    """Example agent for demonstration"""
    
    def __init__(self, name: str):
        self.name = name
    
    async def execute(self, parameters):
        """Execute agent task"""
        logger.info(f"[{self.name}] Executing with parameters: {parameters}")
        await asyncio.sleep(0.5)  # Simulate work
        return {
            "agent": self.name,
            "status": "completed",
            "result": f"Processed {parameters.get('input', 'data')}"
        }


async def setup_pipeline():
    """Setup and configure the pipeline"""
    
    # Create pipeline with configuration
    config = PipelineConfig(
        max_concurrent_tasks=5,
        enable_caching=True,
        enable_recovery=True,
        timeout_seconds=300
    )
    orchestrator = PipelineOrchestrator(config)
    
    # Register agents
    agent1 = ExampleAgent("Agent-1")
    agent2 = ExampleAgent("Agent-2")
    agent3 = ExampleAgent("Agent-3")
    
    orchestrator.register_agent("AGENT_1", agent1, {"name": "Agent 1", "version": "1.0"})
    orchestrator.register_agent("AGENT_2", agent2, {"name": "Agent 2", "version": "1.0"})
    orchestrator.register_agent("AGENT_3", agent3, {"name": "Agent 3", "version": "1.0"})
    
    logger.info(f"Registered agents: {orchestrator.list_agents()}")
    
    # Setup tool registry
    tool_registry = ToolRegistry()
    
    # Define and register tools
    def process_data(data: str) -> dict:
        """Example tool: process data"""
        return {"processed": data.upper(), "length": len(data)}
    
    async def async_analyze(text: str) -> dict:
        """Example async tool: analyze text"""
        await asyncio.sleep(0.1)
        return {"analysis": f"Analyzed: {text}", "words": len(text.split())}
    
    tool1 = ToolDefinition(
        name="process_data",
        description="Process and transform data",
        category="data_processing",
        handler=process_data,
        input_schema={
            "type": "object",
            "properties": {"data": {"type": "string"}},
            "required": ["data"]
        },
        cache_results=True
    )
    
    tool2 = ToolDefinition(
        name="analyze_text",
        description="Analyze text content",
        category="analysis",
        handler=async_analyze,
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"]
        }
    )
    
    tool_registry.register_tool(tool1)
    tool_registry.register_tool(tool2)
    
    # Register tools with orchestrator
    orchestrator.register_tool("process_data", process_data)
    orchestrator.register_tool("analyze_text", async_analyze)
    
    logger.info(f"Registered tools: {orchestrator.list_tools()}")
    
    # Setup MCP integration
    mcp_integration = MCPPipelineIntegration(orchestrator)
    logger.info(f"MCP tools available: {len(mcp_integration.get_mcp_tools())}")
    
    # Setup memory system
    memory = PipelineMemory()
    memory.set("config", {"version": "1.0", "mode": "production"}, layer=1)
    
    # Setup context manager
    context_manager = ContextManager()
    context_manager.create_context("main", {"workflow": "example"})
    
    # Setup error handling
    error_handler = ErrorHandler()
    
    return {
        "orchestrator": orchestrator,
        "tool_registry": tool_registry,
        "mcp_integration": mcp_integration,
        "memory": memory,
        "context_manager": context_manager,
        "error_handler": error_handler
    }


async def execute_sequential_workflow(pipeline_components):
    """Execute tasks sequentially"""
    orchestrator = pipeline_components["orchestrator"]
    
    logger.info("\n=== Sequential Workflow Execution ===")
    
    tasks = [
        {
            "agent_type": "AGENT_1",
            "agent_name": "Agent 1",
            "action": "process",
            "parameters": {"input": "task1"}
        },
        {
            "agent_type": "AGENT_2",
            "agent_name": "Agent 2",
            "action": "analyze",
            "parameters": {"input": "task2"}
        },
        {
            "agent_type": "AGENT_3",
            "agent_name": "Agent 3",
            "action": "validate",
            "parameters": {"input": "task3"}
        }
    ]
    
    execution = await orchestrator.execute_workflow(
        "sequential_workflow",
        tasks,
        parallel=False
    )
    
    logger.info(f"Workflow Status: {execution.status}")
    logger.info(f"Success: {execution.success_count}, Failed: {execution.failure_count}")
    logger.info(f"Duration: {execution.total_duration:.2f}s")
    
    return execution


async def execute_parallel_workflow(pipeline_components):
    """Execute tasks in parallel"""
    orchestrator = pipeline_components["orchestrator"]
    
    logger.info("\n=== Parallel Workflow Execution ===")
    
    tasks = [
        {
            "agent_type": "AGENT_1",
            "agent_name": "Agent 1",
            "action": "process",
            "parameters": {"input": f"parallel_task_{i}"}
        }
        for i in range(5)
    ]
    
    execution = await orchestrator.execute_workflow(
        "parallel_workflow",
        tasks,
        parallel=True
    )
    
    logger.info(f"Workflow Status: {execution.status}")
    logger.info(f"Success: {execution.success_count}, Failed: {execution.failure_count}")
    logger.info(f"Duration: {execution.total_duration:.2f}s")
    
    return execution


async def demonstrate_mcp_integration(pipeline_components):
    """Demonstrate MCP integration"""
    mcp_integration = pipeline_components["mcp_integration"]
    
    logger.info("\n=== MCP Integration Demo ===")
    
    # List agents via MCP
    result = await mcp_integration.handle_mcp_tool_call("list_agents", {})
    logger.info(f"MCP list_agents: {result}")
    
    # List tools via MCP
    result = await mcp_integration.handle_mcp_tool_call("list_tools", {})
    logger.info(f"MCP list_tools: {result}")
    
    # Store state via MCP
    result = await mcp_integration.handle_mcp_tool_call(
        "store_state",
        {"key": "test_state", "value": {"data": "example"}}
    )
    logger.info(f"MCP store_state: {result}")
    
    # Get state via MCP
    result = await mcp_integration.handle_mcp_tool_call(
        "get_state",
        {"key": "test_state"}
    )
    logger.info(f"MCP get_state: {result}")


async def demonstrate_memory_system(pipeline_components):
    """Demonstrate memory system"""
    memory = pipeline_components["memory"]
    context_manager = pipeline_components["context_manager"]
    
    logger.info("\n=== Memory System Demo ===")
    
    # Store in different layers
    memory.set("fast_data", {"type": "L1"}, layer=1)
    memory.set("medium_data", {"type": "L2"}, layer=2)
    memory.set("slow_data", {"type": "L3"}, layer=3)
    
    # Retrieve data
    logger.info(f"L1 Data: {memory.get('fast_data')}")
    logger.info(f"L2 Data: {memory.get('medium_data')}")
    logger.info(f"L3 Data: {memory.get('slow_data')}")
    
    # Memory stats
    stats = memory.get_stats()
    logger.info(f"Memory Stats: {stats}")
    
    # Context management
    context_manager.set_variable("main", "workflow_status", "running")
    status = context_manager.get_variable("main", "workflow_status")
    logger.info(f"Context Variable: {status}")


async def main():
    """Main execution"""
    logger.info("Starting AI Agent Pipeline Integration Example\n")
    
    # Setup pipeline
    pipeline_components = await setup_pipeline()
    
    # Execute workflows
    await execute_sequential_workflow(pipeline_components)
    await execute_parallel_workflow(pipeline_components)
    
    # Demonstrate features
    await demonstrate_mcp_integration(pipeline_components)
    await demonstrate_memory_system(pipeline_components)
    
    logger.info("\n=== Example Complete ===")


if __name__ == "__main__":
    asyncio.run(main())

