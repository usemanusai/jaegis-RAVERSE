"""
Pipeline Memory & State Management - Handles context persistence and state tracking.
Provides memory layers, context management, and state recovery.
"""

import json
import logging
from typing import Any, Dict, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import hashlib

logger = logging.getLogger("RAVERSE.MEMORY")


@dataclass
class MemoryEntry:
    """Single memory entry"""
    key: str
    value: Any
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    ttl_seconds: Optional[int] = None
    access_count: int = 0
    
    def is_expired(self) -> bool:
        """Check if entry has expired"""
        if self.ttl_seconds is None:
            return False
        expiry_time = self.updated_at + timedelta(seconds=self.ttl_seconds)
        return datetime.now() > expiry_time


class MemoryLayer:
    """Single layer of memory (L1, L2, L3)"""
    
    def __init__(self, name: str, capacity: int = 1000, ttl_seconds: Optional[int] = None):
        self.name = name
        self.capacity = capacity
        self.ttl_seconds = ttl_seconds
        self.entries: Dict[str, MemoryEntry] = {}
    
    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None):
        """Store value in memory"""
        if len(self.entries) >= self.capacity:
            self._evict_lru()
        
        self.entries[key] = MemoryEntry(
            key=key,
            value=value,
            ttl_seconds=ttl_seconds or self.ttl_seconds
        )
        logger.debug(f"[{self.name}] Stored: {key}")
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve value from memory"""
        entry = self.entries.get(key)
        if not entry:
            return None
        
        if entry.is_expired():
            del self.entries[key]
            return None
        
        entry.access_count += 1
        entry.updated_at = datetime.now()
        return entry.value
    
    def delete(self, key: str):
        """Delete value from memory"""
        if key in self.entries:
            del self.entries[key]
            logger.debug(f"[{self.name}] Deleted: {key}")
    
    def clear(self):
        """Clear all entries"""
        self.entries.clear()
    
    def _evict_lru(self):
        """Evict least recently used entry"""
        if not self.entries:
            return
        
        lru_key = min(
            self.entries.keys(),
            key=lambda k: (self.entries[k].access_count, self.entries[k].updated_at)
        )
        del self.entries[lru_key]
        logger.debug(f"[{self.name}] Evicted LRU: {lru_key}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics"""
        return {
            "name": self.name,
            "entries": len(self.entries),
            "capacity": self.capacity,
            "utilization": len(self.entries) / self.capacity
        }


class PipelineMemory:
    """Multi-layer memory system for pipeline"""
    
    def __init__(self):
        # L1: Fast access, small capacity, short TTL
        self.l1 = MemoryLayer("L1", capacity=100, ttl_seconds=300)
        # L2: Medium access, medium capacity, medium TTL
        self.l2 = MemoryLayer("L2", capacity=1000, ttl_seconds=3600)
        # L3: Slow access, large capacity, long TTL
        self.l3 = MemoryLayer("L3", capacity=10000, ttl_seconds=86400)
        
        self.layers = [self.l1, self.l2, self.l3]
        self.access_log: List[Dict[str, Any]] = []
    
    def set(self, key: str, value: Any, layer: int = 1, ttl_seconds: Optional[int] = None):
        """Store value in specified layer"""
        if layer < 1 or layer > 3:
            raise ValueError("Layer must be 1, 2, or 3")
        
        self.layers[layer - 1].set(key, value, ttl_seconds)
        self.access_log.append({
            "operation": "set",
            "key": key,
            "layer": layer,
            "timestamp": datetime.now().isoformat()
        })
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve value from any layer (L1 -> L2 -> L3)"""
        for layer in self.layers:
            value = layer.get(key)
            if value is not None:
                self.access_log.append({
                    "operation": "get",
                    "key": key,
                    "layer": layer.name,
                    "timestamp": datetime.now().isoformat()
                })
                return value
        return None
    
    def delete(self, key: str):
        """Delete from all layers"""
        for layer in self.layers:
            layer.delete(key)
    
    def clear(self):
        """Clear all layers"""
        for layer in self.layers:
            layer.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics"""
        return {
            "layers": [layer.get_stats() for layer in self.layers],
            "total_entries": sum(len(layer.entries) for layer in self.layers),
            "access_log_size": len(self.access_log)
        }


class ContextManager:
    """Manages execution context and state"""
    
    def __init__(self):
        self.contexts: Dict[str, Dict[str, Any]] = {}
        self.current_context_id: Optional[str] = None
    
    def create_context(self, context_id: str, initial_state: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create new execution context"""
        self.contexts[context_id] = {
            "id": context_id,
            "created_at": datetime.now().isoformat(),
            "state": initial_state or {},
            "variables": {},
            "artifacts": []
        }
        self.current_context_id = context_id
        logger.info(f"Created context: {context_id}")
        return self.contexts[context_id]
    
    def get_context(self, context_id: str) -> Optional[Dict[str, Any]]:
        """Get context by ID"""
        return self.contexts.get(context_id)
    
    def set_variable(self, context_id: str, key: str, value: Any):
        """Set variable in context"""
        context = self.contexts.get(context_id)
        if context:
            context["variables"][key] = value
    
    def get_variable(self, context_id: str, key: str) -> Optional[Any]:
        """Get variable from context"""
        context = self.contexts.get(context_id)
        if context:
            return context["variables"].get(key)
        return None
    
    def add_artifact(self, context_id: str, artifact: Dict[str, Any]):
        """Add artifact to context"""
        context = self.contexts.get(context_id)
        if context:
            context["artifacts"].append(artifact)
    
    def get_artifacts(self, context_id: str) -> List[Dict[str, Any]]:
        """Get all artifacts from context"""
        context = self.contexts.get(context_id)
        if context:
            return context["artifacts"]
        return []
    
    def delete_context(self, context_id: str):
        """Delete context"""
        if context_id in self.contexts:
            del self.contexts[context_id]
            if self.current_context_id == context_id:
                self.current_context_id = None
            logger.info(f"Deleted context: {context_id}")


class StateRecovery:
    """Handles state persistence and recovery"""
    
    def __init__(self):
        self.checkpoints: Dict[str, Dict[str, Any]] = {}
    
    def create_checkpoint(self, checkpoint_id: str, state: Dict[str, Any]):
        """Create state checkpoint"""
        self.checkpoints[checkpoint_id] = {
            "id": checkpoint_id,
            "state": state,
            "created_at": datetime.now().isoformat()
        }
        logger.info(f"Created checkpoint: {checkpoint_id}")
    
    def restore_checkpoint(self, checkpoint_id: str) -> Optional[Dict[str, Any]]:
        """Restore state from checkpoint"""
        checkpoint = self.checkpoints.get(checkpoint_id)
        if checkpoint:
            logger.info(f"Restored checkpoint: {checkpoint_id}")
            return checkpoint["state"]
        return None
    
    def list_checkpoints(self) -> List[str]:
        """List all checkpoints"""
        return list(self.checkpoints.keys())
    
    def delete_checkpoint(self, checkpoint_id: str):
        """Delete checkpoint"""
        if checkpoint_id in self.checkpoints:
            del self.checkpoints[checkpoint_id]

