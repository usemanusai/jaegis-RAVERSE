"""
Multi-Level Caching Strategy for RAVERSE
Date: October 25, 2025

This module implements a multi-level caching strategy with:
- Level 1: In-memory LRU cache (fastest)
- Level 2: Redis cache (shared across instances)
- Level 3: PostgreSQL cache (persistent)
"""

import time
import hashlib
import pickle
from typing import Any, Optional, Dict
from functools import lru_cache
from collections import OrderedDict
import logging

logger = logging.getLogger(__name__)


class LRUCache:
    """
    Thread-safe LRU cache implementation.
    """
    
    def __init__(self, max_size: int = 1000):
        """
        Initialize LRU cache.
        
        Args:
            max_size: Maximum number of items to cache
        """
        self.max_size = max_size
        self.cache = OrderedDict()
        self.hits = 0
        self.misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if key in self.cache:
            # Move to end (most recently used)
            self.cache.move_to_end(key)
            self.hits += 1
            return self.cache[key]
        
        self.misses += 1
        return None
    
    def set(self, key: str, value: Any):
        """Set value in cache."""
        if key in self.cache:
            # Update existing
            self.cache.move_to_end(key)
        else:
            # Add new
            if len(self.cache) >= self.max_size:
                # Remove least recently used
                self.cache.popitem(last=False)
        
        self.cache[key] = value
    
    def clear(self):
        """Clear all cache entries."""
        self.cache.clear()
        self.hits = 0
        self.misses = 0
    
    def get_stats(self) -> Dict:
        """Get cache statistics."""
        total = self.hits + self.misses
        hit_rate = self.hits / total if total > 0 else 0
        
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate
        }


class MultiLevelCache:
    """
    Multi-level caching with L1 (memory), L2 (Redis), L3 (PostgreSQL).
    """
    
    def __init__(
        self,
        redis_manager=None,
        db_manager=None,
        l1_size: int = 1000,
        l2_ttl: int = 3600,
        l3_ttl: int = 86400
    ):
        """
        Initialize multi-level cache.
        
        Args:
            redis_manager: Redis cache manager (L2)
            db_manager: Database manager (L3)
            l1_size: L1 cache size
            l2_ttl: L2 TTL in seconds (default: 1 hour)
            l3_ttl: L3 TTL in seconds (default: 24 hours)
        """
        self.l1 = LRUCache(max_size=l1_size)
        self.l2 = redis_manager
        self.l3 = db_manager
        self.l2_ttl = l2_ttl
        self.l3_ttl = l3_ttl
        
        # Statistics
        self.stats = {
            "l1_hits": 0,
            "l2_hits": 0,
            "l3_hits": 0,
            "misses": 0
        }
    
    def _make_key(self, namespace: str, key: str) -> str:
        """Create namespaced cache key."""
        return f"{namespace}:{key}"
    
    def get(self, namespace: str, key: str) -> Optional[Any]:
        """
        Get value from cache (checks L1 -> L2 -> L3).
        
        Args:
            namespace: Cache namespace
            key: Cache key
            
        Returns:
            Cached value or None
        """
        cache_key = self._make_key(namespace, key)
        
        # L1: In-memory cache
        value = self.l1.get(cache_key)
        if value is not None:
            self.stats["l1_hits"] += 1
            logger.debug(f"L1 cache hit: {cache_key}")
            return value
        
        # L2: Redis cache
        if self.l2:
            try:
                value = self.l2.get(cache_key)
                if value is not None:
                    # Promote to L1
                    self.l1.set(cache_key, value)
                    self.stats["l2_hits"] += 1
                    logger.debug(f"L2 cache hit: {cache_key}")
                    return value
            except Exception as e:
                logger.warning(f"L2 cache error: {e}")
        
        # L3: PostgreSQL cache
        if self.l3:
            try:
                value = self._get_from_db(namespace, key)
                if value is not None:
                    # Promote to L1 and L2
                    self.l1.set(cache_key, value)
                    if self.l2:
                        self.l2.set(cache_key, value, ttl=self.l2_ttl)
                    self.stats["l3_hits"] += 1
                    logger.debug(f"L3 cache hit: {cache_key}")
                    return value
            except Exception as e:
                logger.warning(f"L3 cache error: {e}")
        
        # Cache miss
        self.stats["misses"] += 1
        logger.debug(f"Cache miss: {cache_key}")
        return None
    
    def set(
        self,
        namespace: str,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ):
        """
        Set value in all cache levels.
        
        Args:
            namespace: Cache namespace
            key: Cache key
            value: Value to cache
            ttl: Optional TTL override
        """
        cache_key = self._make_key(namespace, key)
        
        # L1: Always cache
        self.l1.set(cache_key, value)
        
        # L2: Redis cache
        if self.l2:
            try:
                self.l2.set(cache_key, value, ttl=ttl or self.l2_ttl)
            except Exception as e:
                logger.warning(f"L2 cache set error: {e}")
        
        # L3: PostgreSQL cache
        if self.l3:
            try:
                self._set_in_db(namespace, key, value, ttl or self.l3_ttl)
            except Exception as e:
                logger.warning(f"L3 cache set error: {e}")
    
    def delete(self, namespace: str, key: str):
        """Delete value from all cache levels."""
        cache_key = self._make_key(namespace, key)
        
        # L1
        if cache_key in self.l1.cache:
            del self.l1.cache[cache_key]
        
        # L2
        if self.l2:
            try:
                self.l2.delete(cache_key)
            except Exception as e:
                logger.warning(f"L2 cache delete error: {e}")
        
        # L3
        if self.l3:
            try:
                self._delete_from_db(namespace, key)
            except Exception as e:
                logger.warning(f"L3 cache delete error: {e}")
    
    def clear(self, namespace: Optional[str] = None):
        """Clear cache (all levels)."""
        if namespace:
            # Clear specific namespace
            prefix = f"{namespace}:"

            # L1
            keys_to_delete = [k for k in self.l1.cache.keys() if k.startswith(prefix)]
            for key in keys_to_delete:
                del self.l1.cache[key]

            # L2
            if self.l2:
                try:
                    # Redis pattern delete
                    self.l2.delete_pattern(f"{prefix}*")
                except Exception as e:
                    logger.warning(f"L2 cache clear error: {e}")

            # L3
            if self.l3:
                try:
                    self._clear_db_namespace(namespace)
                except Exception as e:
                    logger.warning(f"L3 cache clear error: {e}")
        else:
            # Clear all
            self.l1.clear()
            if self.l2:
                try:
                    self.l2.clear()
                except (ConnectionError, TimeoutError, Exception) as e:
                    logger.warning("failed_to_clear_l2_cache",
                                  error=str(e),
                                  error_type=type(e).__name__)
                    from utils.metrics import metrics_collector
                    metrics_collector.increment_counter("cache_l2_clear_failures")

    def clear_all(self):
        """Convenience method to clear all cache levels."""
        self.clear(namespace=None)

    def clear_namespace(self, namespace: str):
        """Convenience method to clear a specific namespace."""
        self.clear(namespace=namespace)
    
    def _get_from_db(self, namespace: str, key: str) -> Optional[Any]:
        """Get value from PostgreSQL cache."""
        query = """
            SELECT value, expires_at
            FROM raverse.cache_entries
            WHERE namespace = %s AND key = %s
            AND (expires_at IS NULL OR expires_at > NOW())
        """
        
        result = self.l3.execute_query(query, (namespace, key))
        if result and len(result) > 0:
            # Deserialize value
            return pickle.loads(result[0]['value'])
        
        return None
    
    def _set_in_db(self, namespace: str, key: str, value: Any, ttl: int):
        """Set value in PostgreSQL cache."""
        query = """
            INSERT INTO raverse.cache_entries
            (namespace, key, value, expires_at)
            VALUES (%s, %s, %s, NOW() + INTERVAL '%s seconds')
            ON CONFLICT (namespace, key) DO UPDATE
            SET value = EXCLUDED.value,
                expires_at = EXCLUDED.expires_at,
                updated_at = NOW()
        """
        
        # Serialize value
        serialized = pickle.dumps(value)
        self.l3.execute_query(query, (namespace, key, serialized, ttl))
    
    def _delete_from_db(self, namespace: str, key: str):
        """Delete value from PostgreSQL cache."""
        query = "DELETE FROM raverse.cache_entries WHERE namespace = %s AND key = %s"
        self.l3.execute_query(query, (namespace, key))
    
    def _clear_db_namespace(self, namespace: str):
        """Clear namespace from PostgreSQL cache."""
        query = "DELETE FROM raverse.cache_entries WHERE namespace = %s"
        self.l3.execute_query(query, (namespace,))
    
    def _clear_db_all(self):
        """Clear all from PostgreSQL cache."""
        query = "DELETE FROM raverse.cache_entries"
        self.l3.execute_query(query)
    
    def get_stats(self) -> Dict:
        """Get comprehensive cache statistics."""
        total_requests = sum(self.stats.values())
        
        return {
            "l1": self.l1.get_stats(),
            "l2": {
                "hits": self.stats["l2_hits"],
                "hit_rate": self.stats["l2_hits"] / total_requests if total_requests > 0 else 0
            },
            "l3": {
                "hits": self.stats["l3_hits"],
                "hit_rate": self.stats["l3_hits"] / total_requests if total_requests > 0 else 0
            },
            "overall": {
                "total_requests": total_requests,
                "total_hits": self.stats["l1_hits"] + self.stats["l2_hits"] + self.stats["l3_hits"],
                "misses": self.stats["misses"],
                "hit_rate": (self.stats["l1_hits"] + self.stats["l2_hits"] + self.stats["l3_hits"]) / total_requests if total_requests > 0 else 0
            }
        }
    
    def warm_cache(self, namespace: str, items: Dict[str, Any]):
        """
        Warm cache with pre-computed values.
        
        Args:
            namespace: Cache namespace
            items: Dictionary of key-value pairs to cache
        """
        logger.info(f"Warming cache for namespace '{namespace}' with {len(items)} items")
        
        for key, value in items.items():
            self.set(namespace, key, value)
        
        logger.info(f"Cache warming complete")


# Global instance
_multi_level_cache = None


def get_multi_level_cache(
    redis_manager=None,
    db_manager=None
) -> MultiLevelCache:
    """Get or create global multi-level cache instance."""
    global _multi_level_cache
    
    if _multi_level_cache is None:
        _multi_level_cache = MultiLevelCache(
            redis_manager=redis_manager,
            db_manager=db_manager
        )
    
    return _multi_level_cache

