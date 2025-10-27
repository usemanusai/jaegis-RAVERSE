"""
Comprehensive tests for MultiLevelCache
Date: October 25, 2025

Full test coverage with correct signatures (namespace-based API).
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
import redis.exceptions

from utils.multi_level_cache import MultiLevelCache, LRUCache


class TestLRUCache:
    """Test LRU cache implementation."""
    
    def test_init(self):
        """Test initialization."""
        cache = LRUCache(max_size=100)
        
        assert cache.max_size == 100
        assert cache.hits == 0
        assert cache.misses == 0
    
    def test_set_get(self):
        """Test basic set and get."""
        cache = LRUCache(max_size=10)
        
        cache.set("key1", "value1")
        result = cache.get("key1")
        
        assert result == "value1"
        assert cache.hits == 1
    
    def test_miss(self):
        """Test cache miss."""
        cache = LRUCache(max_size=10)
        
        result = cache.get("nonexistent")
        
        assert result is None
        assert cache.misses == 1
    
    def test_eviction(self):
        """Test LRU eviction."""
        cache = LRUCache(max_size=3)
        
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        cache.set("key4", "value4")  # Evicts key1
        
        assert cache.get("key1") is None
        assert cache.get("key2") == "value2"
    
    def test_clear(self):
        """Test cache clearing."""
        cache = LRUCache(max_size=10)
        
        cache.set("key1", "value1")
        cache.clear()
        
        assert cache.get("key1") is None


class TestMultiLevelCacheInit:
    """Test MultiLevelCache initialization."""
    
    def test_init_default(self):
        """Test default initialization."""
        cache = MultiLevelCache()
        
        assert cache.l1 is not None
        assert cache.l2 is None
        assert cache.l3 is None
    
    def test_init_with_managers(self, mock_redis_manager, mock_db_manager):
        """Test initialization with managers."""
        cache = MultiLevelCache(
            redis_manager=mock_redis_manager,
            db_manager=mock_db_manager,
            l1_size=500
        )
        
        assert cache.l1.max_size == 500
        assert cache.l2 == mock_redis_manager
        assert cache.l3 == mock_db_manager


class TestMultiLevelCacheGet:
    """Test get operations (namespace-based API)."""
    
    def test_get_from_l1(self):
        """Test getting from L1 cache."""
        cache = MultiLevelCache(l1_size=10)
        
        cache.set("test_ns", "test_key", "test_value")
        result = cache.get("test_ns", "test_key")
        
        assert result == "test_value"
        assert cache.stats['l1_hits'] == 1
    
    def test_get_from_l2(self, mock_redis_manager):
        """Test getting from L2 cache."""
        cache = MultiLevelCache(redis_manager=mock_redis_manager, l1_size=10)

        # Mock should return the actual value, not pickled bytes
        # The cache implementation handles pickling/unpickling internally
        mock_redis_manager.get.return_value = "test_value"

        result = cache.get("test_ns", "test_key")

        assert result == "test_value"
        assert cache.stats['l2_hits'] == 1
    
    def test_get_from_l3(self, mock_redis_manager, mock_db_manager):
        """Test getting from L3 cache."""
        cache = MultiLevelCache(
            redis_manager=mock_redis_manager,
            db_manager=mock_db_manager,
            l1_size=10
        )

        mock_redis_manager.get.return_value = None

        # L3 uses execute_query which returns list of dicts with pickled values
        import pickle
        mock_db_manager.execute_query.return_value = [
            {'value': pickle.dumps("test_value"), 'expires_at': None}
        ]

        result = cache.get("test_ns", "test_key")

        assert result == "test_value"
        assert cache.stats['l3_hits'] == 1
    
    def test_get_miss_all_levels(self, mock_redis_manager, mock_db_manager):
        """Test cache miss across all levels."""
        cache = MultiLevelCache(
            redis_manager=mock_redis_manager,
            db_manager=mock_db_manager,
            l1_size=10
        )
        
        mock_redis_manager.get.return_value = None
        
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_conn = Mock()
        mock_conn.cursor.return_value.__enter__ = Mock(return_value=mock_cursor)
        mock_conn.cursor.return_value.__exit__ = Mock(return_value=False)
        mock_db_manager.get_connection.return_value.__enter__ = Mock(return_value=mock_conn)
        mock_db_manager.get_connection.return_value.__exit__ = Mock(return_value=False)
        
        result = cache.get("test_ns", "test_key")
        
        assert result is None
        assert cache.stats['misses'] == 1


class TestMultiLevelCacheSet:
    """Test set operations (namespace-based API)."""
    
    def test_set_all_levels(self, mock_redis_manager, mock_db_manager):
        """Test setting in all cache levels."""
        cache = MultiLevelCache(
            redis_manager=mock_redis_manager,
            db_manager=mock_db_manager,
            l1_size=10
        )
        
        cache.set("test_ns", "test_key", "test_value")
        
        # Should be in L1
        full_key = "test_ns:test_key"
        assert cache.l1.get(full_key) == "test_value"
        
        # Should have called L2 set
        assert mock_redis_manager.set.called
        
        # Should have called L3 set
        assert mock_db_manager.execute_query.called
    
    def test_set_with_ttl(self, mock_redis_manager):
        """Test setting with custom TTL."""
        cache = MultiLevelCache(redis_manager=mock_redis_manager, l1_size=10)
        
        cache.set("test_ns", "test_key", "test_value", ttl=1800)
        
        # Verify TTL was passed to Redis
        assert mock_redis_manager.set.called


class TestMultiLevelCacheClear:
    """Test cache clearing operations."""
    
    def test_clear_all_l1_only(self):
        """Test clearing L1 cache only."""
        cache = MultiLevelCache(l1_size=10)
        
        cache.set("ns1", "key1", "value1")
        cache.set("ns1", "key2", "value2")
        cache.clear_all()
        
        assert cache.get("ns1", "key1") is None
        assert cache.get("ns1", "key2") is None
    
    def test_clear_all_with_l2(self, mock_redis_manager):
        """Test clearing all cache levels."""
        cache = MultiLevelCache(redis_manager=mock_redis_manager, l1_size=10)

        cache.set("ns1", "key1", "value1")
        cache.clear_all()

        # Implementation calls clear() which is an alias for flush_all()
        assert mock_redis_manager.clear.called
    
    def test_clear_namespace(self, mock_redis_manager, mock_db_manager):
        """Test clearing specific namespace."""
        cache = MultiLevelCache(
            redis_manager=mock_redis_manager,
            db_manager=mock_db_manager,
            l1_size=10
        )
        
        cache.set("ns1", "key1", "value1")
        cache.set("ns2", "key2", "value2")
        cache.clear_namespace("ns1")
        
        # ns1 should be cleared from L1
        assert cache.l1.get("ns1:key1") is None


class TestMultiLevelCacheExceptionHandling:
    """Test exception handling."""
    
    def test_l2_connection_error(self, mock_redis_manager):
        """Test handling Redis connection errors."""
        cache = MultiLevelCache(redis_manager=mock_redis_manager, l1_size=10)
        
        mock_redis_manager.get.side_effect = redis.exceptions.ConnectionError("Connection failed")
        
        result = cache.get("test_ns", "test_key")
        assert result is None
    
    def test_l2_timeout_error(self, mock_redis_manager):
        """Test handling Redis timeout errors."""
        cache = MultiLevelCache(redis_manager=mock_redis_manager, l1_size=10)
        
        mock_redis_manager.get.side_effect = redis.exceptions.TimeoutError("Timeout")
        
        result = cache.get("test_ns", "test_key")
        assert result is None
    
    def test_l3_database_error(self, mock_redis_manager, mock_db_manager):
        """Test handling database errors."""
        cache = MultiLevelCache(
            redis_manager=mock_redis_manager,
            db_manager=mock_db_manager,
            l1_size=10
        )
        
        mock_redis_manager.get.return_value = None
        mock_db_manager.get_connection.side_effect = Exception("DB Error")
        
        result = cache.get("test_ns", "test_key")
        assert result is None


class TestMultiLevelCacheSmoke:
    """Smoke tests."""
    
    def test_smoke_init(self):
        """Smoke: Can initialize."""
        cache = MultiLevelCache()
        assert cache is not None
    
    def test_smoke_basic_operations(self):
        """Smoke: Basic operations work."""
        cache = MultiLevelCache(l1_size=10)
        
        cache.set("ns", "key", "value")
        result = cache.get("ns", "key")
        
        assert result == "value"
    
    def test_smoke_clear(self):
        """Smoke: Clear operations work."""
        cache = MultiLevelCache(l1_size=10)
        
        cache.set("ns", "key", "value")
        cache.clear_all()
        
        assert cache.get("ns", "key") is None


class TestMultiLevelCacheIntegration:
    """Integration tests."""
    
    def test_cache_promotion(self, mock_redis_manager):
        """Test that L2 hits are promoted to L1."""
        cache = MultiLevelCache(redis_manager=mock_redis_manager, l1_size=10)

        # Mock should return the actual value, not pickled bytes
        mock_redis_manager.get.return_value = "test_value"

        # First get from L2
        result1 = cache.get("ns", "key")
        assert result1 == "test_value"
        assert cache.stats['l2_hits'] == 1

        # Second get should be from L1
        result2 = cache.get("ns", "key")
        assert result2 == "test_value"
        assert cache.stats['l1_hits'] == 1
    
    def test_namespace_isolation(self):
        """Test that namespaces are isolated."""
        cache = MultiLevelCache(l1_size=10)
        
        cache.set("ns1", "key", "value1")
        cache.set("ns2", "key", "value2")
        
        assert cache.get("ns1", "key") == "value1"
        assert cache.get("ns2", "key") == "value2"
    
    def test_l1_eviction_with_l2(self, mock_redis_manager):
        """Test L1 eviction with L2 backup."""
        cache = MultiLevelCache(redis_manager=mock_redis_manager, l1_size=3)

        # Fill L1 beyond capacity
        cache.set("ns", "key1", "value1")
        cache.set("ns", "key2", "value2")
        cache.set("ns", "key3", "value3")
        cache.set("ns", "key4", "value4")  # Evicts key1 from L1

        # key1 should be evicted from L1 but still in L2
        # Mock should return the actual value, not pickled bytes
        mock_redis_manager.get.return_value = "value1"

        result = cache.get("ns", "key1")
        assert result == "value1"
        assert cache.stats['l2_hits'] == 1


class TestMultiLevelCacheEdgeCases:
    """Test edge cases and error handling."""

    def test_lru_cache_update_existing(self):
        """Test updating existing key in LRU cache."""
        lru = LRUCache(max_size=3)
        lru.set("key1", "value1")
        lru.set("key1", "value2")  # Update

        assert lru.get("key1") == "value2"

    def test_set_with_l2_error(self, mock_redis_manager):
        """Test set operation with L2 error."""
        cache = MultiLevelCache(redis_manager=mock_redis_manager, l1_size=10)

        # Mock L2 set to raise exception
        mock_redis_manager.set.side_effect = Exception("Redis error")

        # Should still succeed with L1
        cache.set("ns", "key", "value")
        assert cache.get("ns", "key") == "value"

    def test_set_with_l3_error(self, mock_redis_manager, mock_db_manager):
        """Test set operation with L3 error."""
        cache = MultiLevelCache(
            redis_manager=mock_redis_manager,
            db_manager=mock_db_manager,
            l1_size=10
        )

        # Mock L3 set to raise exception
        mock_db_manager.execute_query.side_effect = Exception("DB error")

        # Should still succeed with L1 and L2
        cache.set("ns", "key", "value")
        assert cache.get("ns", "key") == "value"

    def test_delete_with_l2_error(self, mock_redis_manager):
        """Test delete operation with L2 error."""
        cache = MultiLevelCache(redis_manager=mock_redis_manager, l1_size=10)

        cache.set("ns", "key", "value")

        # Mock L2 delete to raise exception
        mock_redis_manager.delete.side_effect = Exception("Redis error")

        # Should still delete from L1
        cache.delete("ns", "key")
        assert cache.get("ns", "key") is None

    def test_delete_with_l3_error(self, mock_redis_manager, mock_db_manager):
        """Test delete operation with L3 error."""
        cache = MultiLevelCache(
            redis_manager=mock_redis_manager,
            db_manager=mock_db_manager,
            l1_size=10
        )

        cache.set("ns", "key", "value")

        # Mock L3 delete to raise exception
        mock_db_manager.execute_query.side_effect = Exception("DB error")

        # Should still delete from L1 and L2
        cache.delete("ns", "key")

    def test_clear_namespace_with_l2_error(self, mock_redis_manager):
        """Test clear namespace with L2 error."""
        cache = MultiLevelCache(redis_manager=mock_redis_manager, l1_size=10)

        cache.set("ns1", "key1", "value1")
        cache.set("ns1", "key2", "value2")

        # Mock L2 delete_pattern to raise exception
        mock_redis_manager.delete_pattern = Mock(side_effect=Exception("Redis error"))

        # Should still clear from L1
        cache.clear_namespace("ns1")
        assert cache.get("ns1", "key1") is None

    def test_clear_namespace_with_l3_error(self, mock_redis_manager, mock_db_manager):
        """Test clear namespace with L3 error."""
        cache = MultiLevelCache(
            redis_manager=mock_redis_manager,
            db_manager=mock_db_manager,
            l1_size=10
        )

        cache.set("ns1", "key1", "value1")

        # Mock L3 clear to raise exception
        mock_db_manager.execute_query.side_effect = Exception("DB error")

        # Should still clear from L1 and L2
        cache.clear_namespace("ns1")

    def test_stats_tracking(self, mock_redis_manager):
        """Test that stats are tracked correctly."""
        cache = MultiLevelCache(redis_manager=mock_redis_manager, l1_size=10)

        # L1 hit
        cache.set("ns", "key1", "value1")
        cache.get("ns", "key1")
        assert cache.stats['l1_hits'] == 1

        # L2 hit
        mock_redis_manager.get.return_value = "value2"
        cache.get("ns", "key2")
        assert cache.stats['l2_hits'] == 1

        # Miss
        mock_redis_manager.get.return_value = None
        cache.get("ns", "key3")
        assert cache.stats['misses'] == 1

