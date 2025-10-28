"""
Pipeline Orchestrator - Manages complete AI Agent Pipeline workflows.
Handles agent coordination, tool integration, state management, and result aggregation.
"""

import asyncio
import logging
import json
from typing import Any, Dict, List, Optional, Callable
from datetime import datetime
from dataclasses import dataclass, asdict
import uuid

from .ai_agent_pipeline import (
    AgentRegistry, TaskQueue, PipelineExecutor, AgentTask, 
    ExecutionResult, AgentState, PipelinePhase
)

logger = logging.getLogger("RAVERSE.ORCHESTRATOR")


@dataclass
class PipelineConfig:
    """Configuration for pipeline execution"""
    max_concurrent_tasks: int = 5
    enable_caching: bool = True
    enable_recovery: bool = True
    log_level: str = "INFO"
    timeout_seconds: int = 300


@dataclass
class PipelineExecution:
    """Represents a complete pipeline execution"""
    execution_id: str
    workflow_name: str
    status: str  # queued, running, completed, failed
    phase: PipelinePhase
    tasks: List[AgentTask]
    results: List[ExecutionResult]
    start_time: datetime
    end_time: Optional[datetime] = None
    total_duration: float = 0.0
    success_count: int = 0
    failure_count: int = 0
    error: Optional[str] = None


class PipelineOrchestrator:
    """Main orchestrator for AI Agent Pipeline"""
    
    def __init__(self, config: PipelineConfig = None):
        self.config = config or PipelineConfig()
        self.registry = AgentRegistry()
        self.queue = TaskQueue()
        self.executor = PipelineExecutor(self.registry, self.queue)
        self.executions: Dict[str, PipelineExecution] = {}
        self.tool_registry: Dict[str, Callable] = {}
        self.state_store: Dict[str, Any] = {}
        self.memory: Dict[str, Any] = {}
    
    def register_agent(self, agent_type: str, agent_instance: Any, metadata: Dict[str, Any] = None):
        """Register an agent with the pipeline"""
        self.registry.register(agent_type, agent_instance, metadata)
        logger.info(f"Agent registered: {agent_type}")
    
    def register_tool(self, tool_name: str, tool_func: Callable):
        """Register a tool for agent use"""
        self.tool_registry[tool_name] = tool_func
        logger.info(f"Tool registered: {tool_name}")
    
    def list_agents(self) -> List[str]:
        """List all registered agents"""
        return self.registry.list_agents()
    
    def list_tools(self) -> List[str]:
        """List all registered tools"""
        return list(self.tool_registry.keys())
    
    async def execute_workflow(
        self,
        workflow_name: str,
        tasks: List[Dict[str, Any]],
        parallel: bool = False
    ) -> PipelineExecution:
        """Execute a complete workflow"""
        execution_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        logger.info(f"Starting workflow: {workflow_name} (ID: {execution_id})")
        
        execution = PipelineExecution(
            execution_id=execution_id,
            workflow_name=workflow_name,
            status="running",
            phase=PipelinePhase.INITIALIZATION,
            tasks=[],
            results=[],
            start_time=start_time
        )
        
        self.executions[execution_id] = execution
        
        try:
            # Convert task dicts to AgentTask objects
            agent_tasks = []
            for task_dict in tasks:
                task = AgentTask(
                    task_id=task_dict.get("task_id", str(uuid.uuid4())),
                    agent_name=task_dict.get("agent_name", ""),
                    agent_type=task_dict.get("agent_type", ""),
                    action=task_dict.get("action", ""),
                    parameters=task_dict.get("parameters", {}),
                    priority=task_dict.get("priority", 0),
                    timeout=task_dict.get("timeout", self.config.timeout_seconds),
                    dependencies=task_dict.get("dependencies", [])
                )
                agent_tasks.append(task)
                self.queue.enqueue(task)
            
            execution.tasks = agent_tasks
            execution.phase = PipelinePhase.VALIDATION
            
            # Execute tasks
            if parallel:
                results = await self._execute_parallel(agent_tasks)
            else:
                results = await self._execute_sequential(agent_tasks)
            
            execution.results = results
            execution.phase = PipelinePhase.AGGREGATION
            
            # Aggregate results
            execution.success_count = sum(1 for r in results if r.success)
            execution.failure_count = sum(1 for r in results if not r.success)
            
            execution.phase = PipelinePhase.FINALIZATION
            execution.status = "completed" if execution.failure_count == 0 else "partial"
            execution.end_time = datetime.now()
            execution.total_duration = (execution.end_time - execution.start_time).total_seconds()
            
            logger.info(f"Workflow {workflow_name} completed: {execution.success_count} succeeded, {execution.failure_count} failed")
            
            return execution
            
        except Exception as e:
            execution.status = "failed"
            execution.error = str(e)
            execution.end_time = datetime.now()
            execution.total_duration = (execution.end_time - execution.start_time).total_seconds()
            logger.error(f"Workflow {workflow_name} failed: {e}")
            return execution
    
    async def _execute_sequential(self, tasks: List[AgentTask]) -> List[ExecutionResult]:
        """Execute tasks sequentially"""
        results = []
        for task in tasks:
            result = await self.executor.execute_task(task)
            results.append(result)
        return results
    
    async def _execute_parallel(self, tasks: List[AgentTask]) -> List[ExecutionResult]:
        """Execute tasks in parallel with concurrency limit"""
        semaphore = asyncio.Semaphore(self.config.max_concurrent_tasks)
        
        async def execute_with_semaphore(task):
            async with semaphore:
                return await self.executor.execute_task(task)
        
        results = await asyncio.gather(
            *[execute_with_semaphore(task) for task in tasks],
            return_exceptions=False
        )
        return results
    
    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a pipeline execution"""
        execution = self.executions.get(execution_id)
        if not execution:
            return None
        
        return {
            "execution_id": execution.execution_id,
            "workflow_name": execution.workflow_name,
            "status": execution.status,
            "phase": execution.phase.value,
            "start_time": execution.start_time.isoformat(),
            "end_time": execution.end_time.isoformat() if execution.end_time else None,
            "total_duration": execution.total_duration,
            "success_count": execution.success_count,
            "failure_count": execution.failure_count,
            "total_tasks": len(execution.tasks),
            "results": [asdict(r) for r in execution.results]
        }
    
    def store_state(self, key: str, value: Any):
        """Store state in pipeline"""
        self.state_store[key] = value
    
    def get_state(self, key: str) -> Optional[Any]:
        """Retrieve state from pipeline"""
        return self.state_store.get(key)
    
    def store_memory(self, key: str, value: Any):
        """Store in agent memory"""
        self.memory[key] = value
    
    def get_memory(self, key: str) -> Optional[Any]:
        """Retrieve from agent memory"""
        return self.memory.get(key)
    
    def call_tool(self, tool_name: str, **kwargs) -> Any:
        """Call a registered tool"""
        tool = self.tool_registry.get(tool_name)
        if not tool:
            raise ValueError(f"Tool not found: {tool_name}")
        return tool(**kwargs)

