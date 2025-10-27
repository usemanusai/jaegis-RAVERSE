"""
Redis Cache Manager for RAVERSE
Handles caching, session management, and rate limiting
Date: October 25, 2025
"""

import os
import logging
import json
import hashlib
from typing import Optional, Any, Dict, List
import redis
from redis.connection import ConnectionPool


logger = logging.getLogger(__name__)


class CacheManager:
    """
    Manages Redis connections and caching operations for RAVERSE
    Uses connection pooling for optimal performance
    """
    
    def __init__(self):
        """Initialize Redis connection pool"""
        self.host = os.getenv('REDIS_HOST', 'localhost')
        self.port = int(os.getenv('REDIS_PORT', 6379))
        self.password = os.getenv('REDIS_PASSWORD', 'raverse_redis_password_2025')
        self.db = int(os.getenv('REDIS_DB', 0))
        
        # Create connection pool
        self.pool = ConnectionPool(
            host=self.host,
            port=self.port,
            password=self.password,
            db=self.db,
            decode_responses=True,
            max_connections=50,
            socket_timeout=5,
            socket_connect_timeout=5,
            socket_keepalive=True,
            health_check_interval=30
        )
        
        # Create Redis client
        self.client = redis.Redis(connection_pool=self.pool)
        
        # Test connection
        try:
            self.client.ping()
            logger.info(f"Redis connection established: {self.host}:{self.port}")
        except redis.ConnectionError as e:
            logger.error(f"Redis connection failed: {e}")
            raise
        
        # Cache key prefixes
        self.PREFIX_SESSION = "session:"
        self.PREFIX_ANALYSIS = "analysis:"
        self.PREFIX_DISASM = "disasm:"
        self.PREFIX_LLM = "llm:"
        self.PREFIX_RATE_LIMIT = "ratelimit:"
        self.PREFIX_BINARY = "binary:"
    
    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """
        Set a cache value with optional TTL (time-to-live in seconds)
        Automatically serializes complex objects to JSON
        """
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            
            if ttl:
                return self.client.setex(key, ttl, value)
            else:
                return self.client.set(key, value)
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False
    
    def get(self, key: str, deserialize: bool = True) -> Optional[Any]:
        """
        Get a cache value
        Automatically deserializes JSON if deserialize=True
        """
        try:
            value = self.client.get(key)
            if value is None:
                return None
            
            if deserialize:
                try:
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    return value
            return value
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            return None
    
    def delete(self, key: str) -> bool:
        """Delete a cache key"""
        try:
            return bool(self.client.delete(key))
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if a key exists"""
        try:
            return bool(self.client.exists(key))
        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False
    
    def expire(self, key: str, ttl: int) -> bool:
        """Set TTL on an existing key"""
        try:
            return bool(self.client.expire(key, ttl))
        except Exception as e:
            logger.error(f"Cache expire error for key {key}: {e}")
            return False
    
    def increment(self, key: str, amount: int = 1) -> int:
        """Increment a counter"""
        try:
            return self.client.incr(key, amount)
        except Exception as e:
            logger.error(f"Cache increment error for key {key}: {e}")
            return 0
    
    def decrement(self, key: str, amount: int = 1) -> int:
        """Decrement a counter"""
        try:
            return self.client.decr(key, amount)
        except Exception as e:
            logger.error(f"Cache decrement error for key {key}: {e}")
            return 0
    
    # Session management
    
    def create_session(self, session_id: str, data: Dict, ttl: int = 3600) -> bool:
        """Create a session with TTL (default 1 hour)"""
        key = f"{self.PREFIX_SESSION}{session_id}"
        return self.set(key, data, ttl)
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session data"""
        key = f"{self.PREFIX_SESSION}{session_id}"
        return self.get(key)
    
    def update_session(self, session_id: str, data: Dict, ttl: int = 3600) -> bool:
        """Update session data and refresh TTL"""
        key = f"{self.PREFIX_SESSION}{session_id}"
        return self.set(key, data, ttl)
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session"""
        key = f"{self.PREFIX_SESSION}{session_id}"
        return self.delete(key)
    
    # Analysis caching
    
    def cache_analysis(self, binary_hash: str, agent_name: str, 
                      result: Dict, ttl: int = 86400) -> bool:
        """Cache analysis result (default 24 hours)"""
        key = f"{self.PREFIX_ANALYSIS}{binary_hash}:{agent_name}"
        return self.set(key, result, ttl)
    
    def get_cached_analysis(self, binary_hash: str, 
                           agent_name: str) -> Optional[Dict]:
        """Get cached analysis result"""
        key = f"{self.PREFIX_ANALYSIS}{binary_hash}:{agent_name}"
        return self.get(key)
    
    # Disassembly caching
    
    def cache_disassembly(self, binary_hash: str, disassembly: str, 
                         ttl: int = 86400) -> bool:
        """Cache disassembly output (default 24 hours)"""
        key = f"{self.PREFIX_DISASM}{binary_hash}"
        return self.set(key, disassembly, ttl)
    
    def get_cached_disassembly(self, binary_hash: str) -> Optional[str]:
        """Get cached disassembly"""
        key = f"{self.PREFIX_DISASM}{binary_hash}"
        return self.get(key, deserialize=False)
    
    # LLM response caching
    
    def cache_llm_response(self, prompt: str, response: str, 
                          model: str, ttl: int = 604800) -> bool:
        """Cache LLM response (default 7 days)"""
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
        key = f"{self.PREFIX_LLM}{model}:{prompt_hash}"
        data = {
            'prompt': prompt,
            'response': response,
            'model': model
        }
        return self.set(key, data, ttl)
    
    def get_cached_llm_response(self, prompt: str, model: str) -> Optional[str]:
        """Get cached LLM response"""
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
        key = f"{self.PREFIX_LLM}{model}:{prompt_hash}"
        data = self.get(key)
        return data['response'] if data else None
    
    # Rate limiting
    
    def check_rate_limit(self, identifier: str, max_requests: int, 
                        window_seconds: int) -> bool:
        """
        Check if rate limit is exceeded
        Returns True if request is allowed, False if rate limit exceeded
        """
        key = f"{self.PREFIX_RATE_LIMIT}{identifier}"
        try:
            current = self.client.get(key)
            if current is None:
                # First request in window
                self.client.setex(key, window_seconds, 1)
                return True
            
            current = int(current)
            if current >= max_requests:
                return False
            
            # Increment counter
            self.client.incr(key)
            return True
        except Exception as e:
            logger.error(f"Rate limit check error: {e}")
            return True  # Allow on error
    
    def get_rate_limit_remaining(self, identifier: str, 
                                 max_requests: int) -> int:
        """Get remaining requests in current window"""
        key = f"{self.PREFIX_RATE_LIMIT}{identifier}"
        try:
            current = self.client.get(key)
            if current is None:
                return max_requests
            return max(0, max_requests - int(current))
        except Exception as e:
            logger.error(f"Rate limit remaining error: {e}")
            return max_requests
    
    # Binary metadata caching
    
    def cache_binary_metadata(self, binary_hash: str, metadata: Dict, 
                             ttl: int = 86400) -> bool:
        """Cache binary metadata (default 24 hours)"""
        key = f"{self.PREFIX_BINARY}{binary_hash}"
        return self.set(key, metadata, ttl)
    
    def get_cached_binary_metadata(self, binary_hash: str) -> Optional[Dict]:
        """Get cached binary metadata"""
        key = f"{self.PREFIX_BINARY}{binary_hash}"
        return self.get(key)
    
    # Utility methods
    
    def flush_all(self) -> bool:
        """Flush all cache (use with caution)"""
        try:
            self.client.flushdb()
            logger.warning("Redis cache flushed")
            return True
        except Exception as e:
            logger.error(f"Cache flush error: {e}")
            return False

    def clear(self) -> bool:
        """Alias for flush_all() for compatibility."""
        return self.flush_all()
    
    def get_stats(self) -> Dict:
        """Get Redis statistics"""
        try:
            info = self.client.info()
            return {
                'used_memory': info.get('used_memory_human'),
                'connected_clients': info.get('connected_clients'),
                'total_commands_processed': info.get('total_commands_processed'),
                'keyspace_hits': info.get('keyspace_hits'),
                'keyspace_misses': info.get('keyspace_misses'),
                'uptime_in_seconds': info.get('uptime_in_seconds')
            }
        except Exception as e:
            logger.error(f"Stats error: {e}")
            return {}
    
    def close(self):
        """Close Redis connection"""
        try:
            self.client.close()
            logger.info("Redis connection closed")
        except Exception as e:
            logger.error(f"Redis close error: {e}")

