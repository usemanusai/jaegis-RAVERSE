"""
Memory-Enabled Base Agent for RAVERSE 2.0
Extends OnlineBaseAgent with optional memory strategy support.
Provides memory context management for all agents.
"""

import logging
from typing import Dict, Any, Optional
from .online_base_agent import OnlineBaseAgent

logger = logging.getLogger(__name__)


class BaseMemoryAgent(OnlineBaseAgent):
    """
    Extended base class for RAVERSE agents with optional memory support.
    
    Memory is completely optional and disabled by default.
    When memory is disabled, all memory operations are no-ops with zero overhead.
    
    Attributes:
        memory_strategy: Name of memory strategy (e.g., "hierarchical", "retrieval")
        memory_config: Configuration dictionary for the memory strategy
        memory: Instance of the memory strategy (None if disabled)
    """

    def __init__(
        self,
        name: str,
        agent_type: str,
        orchestrator=None,
        memory_strategy: Optional[str] = None,
        memory_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize memory-enabled agent.

        Args:
            name: Agent name (e.g., "Reconnaissance Agent")
            agent_type: Agent type code (e.g., "RECON")
            orchestrator: Reference to orchestration agent
            memory_strategy: Optional memory strategy name (e.g., "hierarchical", "retrieval")
                           If None, memory is disabled (default behavior)
            memory_config: Optional configuration dictionary for memory strategy
                          Example: {"window_size": 3, "k": 2}
        """
        # Initialize parent class
        super().__init__(name=name, agent_type=agent_type, orchestrator=orchestrator)

        # Memory configuration
        self.memory_strategy_name = memory_strategy
        self.memory_config = memory_config or {}
        self.memory = None

        # Initialize memory if strategy is specified
        if memory_strategy:
            self._initialize_memory(memory_strategy, memory_config)
        else:
            self.logger.debug(f"{name} initialized with memory DISABLED (default)")

    def _initialize_memory(self, strategy_name: str, config: Optional[Dict[str, Any]] = None):
        """
        Initialize memory strategy.

        Args:
            strategy_name: Name of memory strategy to use
            config: Configuration dictionary for the strategy
        """
        try:
            from config.memory_strategies import get_memory_strategy

            config = config or {}
            self.memory = get_memory_strategy(strategy_name, **config)
            self.logger.info(f"Memory strategy '{strategy_name}' initialized for {self.name}")

        except ImportError as e:
            self.logger.error(f"Failed to import memory strategies: {e}")
            self.memory = None
        except ValueError as e:
            self.logger.error(f"Invalid memory strategy '{strategy_name}': {e}")
            self.memory = None
        except Exception as e:
            self.logger.error(f"Failed to initialize memory strategy: {e}")
            self.memory = None

    def has_memory_enabled(self) -> bool:
        """
        Check if memory is enabled for this agent.

        Returns:
            True if memory is enabled and initialized, False otherwise
        """
        return self.memory is not None

    def add_to_memory(self, user_input: str, ai_response: str) -> None:
        """
        Add interaction to memory.

        Args:
            user_input: User input or task description
            ai_response: Agent response or result

        Note:
            This is a no-op if memory is disabled (zero overhead).
        """
        if not self.has_memory_enabled():
            return

        try:
            self.memory.add_message(user_input, ai_response)
            self.logger.debug(f"Added to memory: {user_input[:50]}...")
        except Exception as e:
            self.logger.warning(f"Failed to add to memory: {e}")

    def get_memory_context(self, query: str) -> str:
        """
        Retrieve context from memory based on query.

        Args:
            query: Query to search memory for

        Returns:
            Context string from memory, or empty string if memory is disabled

        Note:
            Returns empty string if memory is disabled (zero overhead).
        """
        if not self.has_memory_enabled():
            return ""

        try:
            context = self.memory.get_context(query)
            self.logger.debug(f"Retrieved memory context for query: {query[:50]}...")
            return context
        except Exception as e:
            self.logger.warning(f"Failed to retrieve memory context: {e}")
            return ""

    def clear_memory(self) -> None:
        """
        Clear all memory.

        Note:
            This is a no-op if memory is disabled.
        """
        if not self.has_memory_enabled():
            return

        try:
            self.memory.clear()
            self.logger.info(f"Memory cleared for {self.name}")
        except Exception as e:
            self.logger.warning(f"Failed to clear memory: {e}")

    def get_memory_status(self) -> Dict[str, Any]:
        """
        Get memory status information.

        Returns:
            Dictionary with memory status information
        """
        return {
            "memory_enabled": self.has_memory_enabled(),
            "memory_strategy": self.memory_strategy_name,
            "memory_config": self.memory_config,
            "memory_type": type(self.memory).__name__ if self.memory else "None"
        }

    def _execute_impl(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Implementation of agent-specific logic.
        Must be overridden by subclasses.

        Args:
            task: Task configuration dictionary

        Returns:
            Dictionary with execution results
        """
        raise NotImplementedError("Subclasses must implement _execute_impl()")

