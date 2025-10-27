"""Cache utilities for RAVERSE MCP Server"""

import json
import redis
from typing import Optional, Any, Dict
from .config import MCPServerConfig
from .errors import CacheError
from .logging_config import get_logger

logger = get_logger(__name__)


class CacheManager:
    """Manages Redis cache operations"""
    
    def __init__(self, config: MCPServerConfig):
        self.config = config
        self.client: Optional[redis.Redis] = None
        self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize Redis client"""
        try:
            self.client = redis.from_url(
                self.config.redis_url,
                socket_timeout=self.config.redis_timeout,
                decode_responses=True,
            )
            self.client.ping()
            logger.info("Redis cache initialized")
        except redis.ConnectionError as e:
            raise CacheError(f"Failed to connect to Redis: {str(e)}")
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if not self.client:
            raise CacheError("Cache client not initialized")
        try:
            value = self.client.get(key)
            if value:
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
            return None
        except redis.RedisError as e:
            logger.warning(f"Cache get failed: {str(e)}", key=key)
            return None
    
    def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
    ) -> bool:
        """Set value in cache"""
        if not self.client:
            raise CacheError("Cache client not initialized")
        try:
            ttl = ttl or self.config.cache_ttl_seconds
            serialized = json.dumps(value) if not isinstance(value, str) else value
            self.client.setex(key, ttl, serialized)
            return True
        except redis.RedisError as e:
            logger.warning(f"Cache set failed: {str(e)}", key=key)
            return False
    
    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        if not self.client:
            raise CacheError("Cache client not initialized")
        try:
            self.client.delete(key)
            return True
        except redis.RedisError as e:
            logger.warning(f"Cache delete failed: {str(e)}", key=key)
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        if not self.client:
            raise CacheError("Cache client not initialized")
        try:
            return bool(self.client.exists(key))
        except redis.RedisError as e:
            logger.warning(f"Cache exists check failed: {str(e)}", key=key)
            return False
    
    def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching pattern"""
        if not self.client:
            raise CacheError("Cache client not initialized")
        try:
            keys = self.client.keys(pattern)
            if keys:
                return self.client.delete(*keys)
            return 0
        except redis.RedisError as e:
            logger.warning(f"Cache pattern clear failed: {str(e)}", pattern=pattern)
            return 0
    
    def publish(self, channel: str, message: Dict[str, Any]) -> int:
        """Publish message to channel"""
        if not self.client:
            raise CacheError("Cache client not initialized")
        try:
            return self.client.publish(channel, json.dumps(message))
        except redis.RedisError as e:
            raise CacheError(f"Failed to publish message: {str(e)}")
    
    def close(self) -> None:
        """Close Redis connection"""
        if self.client:
            self.client.close()
            logger.info("Redis cache connection closed")

