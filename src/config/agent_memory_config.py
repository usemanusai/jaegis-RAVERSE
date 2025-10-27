"""
RAVERSE 2.0 - Agent Memory Configuration
Defines memory strategy recommendations for each agent type.
Provides presets (light/medium/heavy) for different use cases.
"""

from typing import Dict, Any, Optional

# ============================================================================
# MEMORY PRESETS
# ============================================================================
# Three tiers of memory configuration for different resource constraints

MEMORY_PRESETS = {
    "none": {
        "description": "No memory (default, zero overhead)",
        "strategy": None,
        "config": {},
        "use_case": "Default behavior, no memory overhead",
        "ram_mb": 0,
        "cpu_percent": 0
    },
    "light": {
        "description": "Minimal memory overhead",
        "strategy": "sliding_window",
        "config": {"window_size": 2},
        "use_case": "Short conversations, minimal resource usage",
        "ram_mb": 5,
        "cpu_percent": 1
    },
    "medium": {
        "description": "Balanced memory and performance",
        "strategy": "hierarchical",
        "config": {"window_size": 3, "k": 2},
        "use_case": "Medium conversations, balanced approach",
        "ram_mb": 20,
        "cpu_percent": 3
    },
    "heavy": {
        "description": "Maximum memory capability",
        "strategy": "retrieval",
        "config": {"k": 5, "embedding_dim": 384},
        "use_case": "Long conversations, semantic search, knowledge retrieval",
        "ram_mb": 100,
        "cpu_percent": 5
    }
}

# ============================================================================
# AGENT-SPECIFIC MEMORY CONFIGURATIONS
# ============================================================================
# Recommended memory strategy for each agent type
# Default: None (memory disabled)

AGENT_MEMORY_CONFIG = {
    # Core Architecture Agents
    "version_manager": {
        "strategy": "hierarchical",
        "config": {"window_size": 3, "k": 2},
        "preset": "medium",
        "reason": "Critical version info must be retained long-term"
    },
    "knowledge_base": {
        "strategy": "retrieval",
        "config": {"k": 5, "embedding_dim": 384},
        "preset": "heavy",
        "reason": "Semantic search for knowledge retrieval"
    },
    "quality_gate": {
        "strategy": "memory_augmented",
        "config": {"window_size": 2},
        "preset": "medium",
        "reason": "Critical metrics + recent context"
    },
    "governance": {
        "strategy": "hierarchical",
        "config": {"window_size": 2, "k": 3},
        "preset": "medium",
        "reason": "Approval rules + historical context"
    },
    "document_generator": {
        "strategy": "summarization",
        "config": {"summary_threshold": 4},
        "preset": "medium",
        "reason": "Long documents + token efficiency"
    },
    "rag_orchestrator": {
        "strategy": "retrieval",
        "config": {"k": 4, "embedding_dim": 384},
        "preset": "heavy",
        "reason": "Semantic search + knowledge relationships"
    },
    "daa": {
        "strategy": "os_like",
        "config": {"ram_size": 3},
        "preset": "heavy",
        "reason": "Large binaries + virtual memory"
    },
    "lima": {
        "strategy": "os_like",
        "config": {"ram_size": 2},
        "preset": "heavy",
        "reason": "Large analysis + relationship tracking"
    },

    # Online Analysis Agents
    "reconnaissance": {
        "strategy": "sliding_window",
        "config": {"window_size": 2},
        "preset": "light",
        "reason": "Recent reconnaissance data only"
    },
    "api_reverse_engineering": {
        "strategy": "hierarchical",
        "config": {"window_size": 2, "k": 2},
        "preset": "medium",
        "reason": "API patterns + recent calls"
    },
    "javascript_analysis": {
        "strategy": "graph",
        "config": {},
        "preset": "heavy",
        "reason": "Code relationships and dependencies"
    },
    "wasm_analysis": {
        "strategy": "os_like",
        "config": {"ram_size": 2},
        "preset": "heavy",
        "reason": "Large WASM modules"
    },
    "security_analysis": {
        "strategy": "hierarchical",
        "config": {"window_size": 2, "k": 3},
        "preset": "medium",
        "reason": "Security findings + recent threats"
    },
    "traffic_interception": {
        "strategy": "sliding_window",
        "config": {"window_size": 3},
        "preset": "light",
        "reason": "Recent traffic patterns"
    },
    "validation": {
        "strategy": "memory_augmented",
        "config": {"window_size": 2},
        "preset": "medium",
        "reason": "Critical validation rules"
    },
    "reporting": {
        "strategy": "summarization",
        "config": {"summary_threshold": 5},
        "preset": "medium",
        "reason": "Report generation + token efficiency"
    },

    # Deep Research Agents
    "web_researcher": {
        "strategy": "retrieval",
        "config": {"k": 5, "embedding_dim": 384},
        "preset": "heavy",
        "reason": "Web research + semantic search"
    },
    "content_analyzer": {
        "strategy": "summarization",
        "config": {"summary_threshold": 4},
        "preset": "medium",
        "reason": "Content analysis + summarization"
    },
    "topic_enhancer": {
        "strategy": "graph",
        "config": {},
        "preset": "heavy",
        "reason": "Topic relationships and connections"
    },

    # Orchestrators
    "orchestrator": {
        "strategy": "hierarchical",
        "config": {"window_size": 2, "k": 3},
        "preset": "medium",
        "reason": "Orchestration state + agent coordination"
    },
    "ai_copilot": {
        "strategy": "hierarchical",
        "config": {"window_size": 3, "k": 2},
        "preset": "medium",
        "reason": "User interaction history + context"
    }
}

# ============================================================================
# MEMORY HARDWARE REQUIREMENTS
# ============================================================================

MEMORY_HARDWARE_REQUIREMENTS = {
    "sequential": {
        "ram_mb": 50,
        "cpu_percent": 2,
        "description": "Simple list storage, grows with conversation"
    },
    "sliding_window": {
        "ram_mb": 5,
        "cpu_percent": 1,
        "description": "Fixed-size deque, constant memory"
    },
    "summarization": {
        "ram_mb": 10,
        "cpu_percent": 3,
        "description": "Buffer + summary, requires LLM calls"
    },
    "retrieval": {
        "ram_mb": 100,
        "cpu_percent": 5,
        "description": "FAISS index, requires embeddings"
    },
    "memory_augmented": {
        "ram_mb": 15,
        "cpu_percent": 3,
        "description": "Sliding window + fact extraction"
    },
    "hierarchical": {
        "ram_mb": 30,
        "cpu_percent": 3,
        "description": "Working + long-term memory"
    },
    "graph": {
        "ram_mb": 50,
        "cpu_percent": 4,
        "description": "NetworkX graph, requires triple extraction"
    },
    "compression": {
        "ram_mb": 5,
        "cpu_percent": 2,
        "description": "Compressed facts, minimal storage"
    },
    "os_like": {
        "ram_mb": 20,
        "cpu_percent": 2,
        "description": "Active + passive memory, paging logic"
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def get_agent_memory_config(
    agent_type: str,
    preset: str = "none"
) -> Dict[str, Any]:
    """
    Get memory configuration for an agent.

    Args:
        agent_type: Type of agent (e.g., "version_manager", "knowledge_base")
        preset: Memory preset to use ("none", "light", "medium", "heavy")
                If "none", memory is disabled (default)

    Returns:
        Dictionary with memory configuration
    """
    # If preset is specified, use it
    if preset != "none" and preset in MEMORY_PRESETS:
        preset_config = MEMORY_PRESETS[preset]
        return {
            "strategy": preset_config["strategy"],
            "config": preset_config["config"],
            "preset": preset,
            "reason": preset_config["use_case"]
        }

    # Otherwise, use agent-specific config if available
    if agent_type in AGENT_MEMORY_CONFIG:
        return AGENT_MEMORY_CONFIG[agent_type]

    # Default: no memory
    return {
        "strategy": None,
        "config": {},
        "preset": "none",
        "reason": "Default behavior, no memory"
    }


def get_memory_hardware_requirements(strategy: str) -> Dict[str, Any]:
    """
    Get hardware requirements for a memory strategy.

    Args:
        strategy: Memory strategy name

    Returns:
        Dictionary with RAM and CPU requirements
    """
    if strategy in MEMORY_HARDWARE_REQUIREMENTS:
        return MEMORY_HARDWARE_REQUIREMENTS[strategy]

    return {
        "ram_mb": 0,
        "cpu_percent": 0,
        "description": "Unknown strategy"
    }


def list_available_presets() -> Dict[str, Dict[str, Any]]:
    """
    List all available memory presets.

    Returns:
        Dictionary of presets with descriptions
    """
    return MEMORY_PRESETS


def list_agent_configs() -> Dict[str, Dict[str, Any]]:
    """
    List all agent memory configurations.

    Returns:
        Dictionary of agent configurations
    """
    return AGENT_MEMORY_CONFIG


# ============================================================================
# DEFAULT CONFIGURATION
# ============================================================================
# By default, all agents have memory DISABLED (strategy: None)
# Users can opt-in by specifying memory_strategy parameter when creating agents
# This ensures 100% backward compatibility and zero overhead by default

