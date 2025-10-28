"""
AI Agent Pipeline System - Core orchestration and routing for RAVERSE agents.
Provides unified interface for agent execution, tool integration, and state management.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable
from enum import Enum
from dataclasses import dataclass, asdict
import hashlib

logger = logging.getLogger("RAVERSE.PIPELINE")


class AgentState(Enum):
    """Agent execution states"""
    IDLE = "idle"
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class PipelinePhase(Enum):
    """Pipeline execution phases"""
    INITIALIZATION = "initialization"
    VALIDATION = "validation"
    EXECUTION = "execution"
    AGGREGATION = "aggregation"
    FINALIZATION = "finalization"


@dataclass
class AgentTask:
    """Represents a task for an agent to execute"""
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
    
    def __post_init__(self):
        if self.task_id is None:
            self.task_id = str(uuid.uuid4())
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.dependencies is None:
            self.dependencies = []


@dataclass
class ExecutionResult:
    """Result from agent execution"""
    task_id: str
    agent_name: str
    agent_type: str
    state: AgentState
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    artifacts: List[str] = None
    metrics: Dict[str, Any] = None
    start_time: datetime = None
    end_time: datetime = None
    duration_seconds: float = 0.0
    
    def __post_init__(self):
        if self.artifacts is None:
            self.artifacts = []
        if self.metrics is None:
            self.metrics = {}
        if self.start_time is None:
            self.start_time = datetime.now()
        if self.end_time is None:
            self.end_time = datetime.now()
        self.duration_seconds = (self.end_time - self.start_time).total_seconds()


class AgentRegistry:
    """Registry for managing available agents"""
    
    def __init__(self):
        self.agents: Dict[str, Any] = {}
        self.agent_metadata: Dict[str, Dict[str, Any]] = {}
    
    def register(self, agent_type: str, agent_instance: Any, metadata: Dict[str, Any] = None):
        """Register an agent"""
        self.agents[agent_type] = agent_instance
        self.agent_metadata[agent_type] = metadata or {
            "name": agent_type,
            "description": f"Agent {agent_type}",
            "capabilities": [],
            "version": "1.0.0"
        }
        logger.info(f"Registered agent: {agent_type}")
    
    def get_agent(self, agent_type: str) -> Optional[Any]:
        """Get agent by type"""
        return self.agents.get(agent_type)
    
    def list_agents(self) -> List[str]:
        """List all registered agents"""
        return list(self.agents.keys())
    
    def get_metadata(self, agent_type: str) -> Optional[Dict[str, Any]]:
        """Get agent metadata"""
        return self.agent_metadata.get(agent_type)


class TaskQueue:
    """Priority queue for managing agent tasks"""
    
    def __init__(self):
        self.queue: List[AgentTask] = []
        self.completed: Dict[str, ExecutionResult] = {}
        self.failed: Dict[str, ExecutionResult] = {}
    
    def enqueue(self, task: AgentTask):
        """Add task to queue"""
        self.queue.append(task)
        self.queue.sort(key=lambda t: (-t.priority, t.created_at))
        logger.debug(f"Enqueued task: {task.task_id} for agent {task.agent_type}")
    
    def dequeue(self) -> Optional[AgentTask]:
        """Get next task from queue"""
        if self.queue:
            return self.queue.pop(0)
        return None
    
    def mark_completed(self, result: ExecutionResult):
        """Mark task as completed"""
        self.completed[result.task_id] = result
    
    def mark_failed(self, result: ExecutionResult):
        """Mark task as failed"""
        self.failed[result.task_id] = result
    
    def get_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task status"""
        if task_id in self.completed:
            return {"status": "completed", "result": asdict(self.completed[task_id])}
        if task_id in self.failed:
            return {"status": "failed", "result": asdict(self.failed[task_id])}
        for task in self.queue:
            if task.task_id == task_id:
                return {"status": "queued", "task": asdict(task)}
        return None


class PipelineExecutor:
    """Executes agent tasks with error handling and recovery"""
    
    def __init__(self, registry: AgentRegistry, queue: TaskQueue):
        self.registry = registry
        self.queue = queue
        self.execution_history: List[ExecutionResult] = []
        self.current_phase = PipelinePhase.INITIALIZATION
    
    async def execute_task(self, task: AgentTask) -> ExecutionResult:
        """Execute a single task"""
        start_time = datetime.now()
        
        try:
            agent = self.registry.get_agent(task.agent_type)
            if not agent:
                raise ValueError(f"Agent not found: {task.agent_type}")
            
            logger.info(f"Executing task {task.task_id} on agent {task.agent_type}")
            
            # Execute with timeout
            result_data = await asyncio.wait_for(
                self._call_agent(agent, task),
                timeout=task.timeout
            )
            
            result = ExecutionResult(
                task_id=task.task_id,
                agent_name=task.agent_name,
                agent_type=task.agent_type,
                state=AgentState.SUCCEEDED,
                success=True,
                data=result_data,
                start_time=start_time,
                end_time=datetime.now()
            )
            
            self.queue.mark_completed(result)
            self.execution_history.append(result)
            logger.info(f"Task {task.task_id} completed successfully")
            
            return result
            
        except asyncio.TimeoutError:
            result = ExecutionResult(
                task_id=task.task_id,
                agent_name=task.agent_name,
                agent_type=task.agent_type,
                state=AgentState.FAILED,
                success=False,
                error=f"Task timeout after {task.timeout}s",
                error_code="TIMEOUT",
                start_time=start_time,
                end_time=datetime.now()
            )
            self.queue.mark_failed(result)
            self.execution_history.append(result)
            return result
            
        except Exception as e:
            result = ExecutionResult(
                task_id=task.task_id,
                agent_name=task.agent_name,
                agent_type=task.agent_type,
                state=AgentState.FAILED,
                success=False,
                error=str(e),
                error_code="EXECUTION_ERROR",
                start_time=start_time,
                end_time=datetime.now()
            )
            self.queue.mark_failed(result)
            self.execution_history.append(result)
            logger.error(f"Task {task.task_id} failed: {e}")
            return result
    
    async def _call_agent(self, agent: Any, task: AgentTask) -> Dict[str, Any]:
        """Call agent method"""
        if hasattr(agent, 'execute'):
            if asyncio.iscoroutinefunction(agent.execute):
                return await agent.execute(task.parameters)
            else:
                return agent.execute(task.parameters)
        raise ValueError(f"Agent {task.agent_type} does not have execute method")
    
    def get_execution_history(self) -> List[ExecutionResult]:
        """Get execution history"""
        return self.execution_history

