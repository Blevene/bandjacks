"""LLM response caching for improved performance."""

import hashlib
import json
import logging
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional
from threading import Lock

logger = logging.getLogger(__name__)


class LLMCache:
    """Thread-safe LLM response cache with optional Redis L2 layer.

    L1: In-memory LRU cache (fast, per-worker)
    L2: Redis cache (shared across workers) - enabled when redis_client is provided
    """

    def __init__(self, ttl_seconds: int = 900, max_size: int = 10000, redis_client=None):
        self.cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self.ttl = ttl_seconds
        self.max_size = max_size
        self.lock = Lock()
        self.redis_client = redis_client
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "l2_hits": 0,
        }

    def _generate_key(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Generate cache key from messages and parameters."""
        # Create stable hash from messages and params
        content = {
            "messages": messages,
            "params": kwargs
        }
        content_str = json.dumps(content, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()

    def _redis_key(self, key: str) -> str:
        """Build the Redis key for L2 storage."""
        return f"llm_cache:{key}"

    def _get_from_redis(self, key: str) -> Optional[Dict[str, Any]]:
        """Try to fetch a response from Redis L2. Returns None on miss or error."""
        if self.redis_client is None:
            return None
        try:
            raw = self.redis_client.get(self._redis_key(key))
            if raw is not None:
                return json.loads(raw)
        except Exception as e:
            logger.debug(f"Redis L2 read error: {e}")
        return None

    def _set_in_redis(self, key: str, response: Dict[str, Any]) -> None:
        """Write a response to Redis L2. Errors are silently logged."""
        if self.redis_client is None:
            return
        try:
            self.redis_client.setex(
                self._redis_key(key),
                self.ttl,
                json.dumps(response),
            )
        except Exception as e:
            logger.debug(f"Redis L2 write error: {e}")

    def get(self, messages: List[Dict[str, str]], **kwargs) -> Optional[Dict[str, Any]]:
        """Get cached response if available and not expired."""
        key = self._generate_key(messages, **kwargs)

        with self.lock:
            if key in self.cache:
                entry = self.cache[key]

                # Check if expired
                if time.time() - entry["timestamp"] > self.ttl:
                    del self.cache[key]
                    self.stats["evictions"] += 1
                    self.stats["misses"] += 1
                    # Fall through to L2 check below
                else:
                    self.cache.move_to_end(key)  # LRU: mark as recently used
                    self.stats["hits"] += 1
                    return entry["response"]

        # L1 miss - check Redis L2
        response = self._get_from_redis(key)
        if response is not None:
            # Promote to L1
            with self.lock:
                self.cache[key] = {
                    "response": response,
                    "timestamp": time.time(),
                }
                self.cache.move_to_end(key)
                while len(self.cache) > self.max_size:
                    oldest_key = next(iter(self.cache))
                    del self.cache[oldest_key]
                    self.stats["evictions"] += 1
                self.stats["hits"] += 1
                self.stats["l2_hits"] += 1
            return response

        with self.lock:
            self.stats["misses"] += 1
        return None

    def set(self, messages: List[Dict[str, str]], response: Dict[str, Any], **kwargs) -> None:
        """Cache a response."""
        key = self._generate_key(messages, **kwargs)

        with self.lock:
            self.cache[key] = {
                "response": response,
                "timestamp": time.time()
            }
            # Evict oldest entries if over max_size
            while len(self.cache) > self.max_size:
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
                self.stats["evictions"] += 1

        # Write-through to Redis L2
        self._set_in_redis(key, response)
    
    def clear_expired(self) -> int:
        """Remove expired entries and return count."""
        current_time = time.time()
        expired_keys = []
        
        with self.lock:
            for key, entry in self.cache.items():
                if current_time - entry["timestamp"] > self.ttl:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.cache[key]
                self.stats["evictions"] += 1
            
            return len(expired_keys)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            total = self.stats["hits"] + self.stats["misses"]
            hit_rate = (self.stats["hits"] / total * 100) if total > 0 else 0

            return {
                "hits": self.stats["hits"],
                "misses": self.stats["misses"],
                "evictions": self.stats["evictions"],
                "l2_hits": self.stats["l2_hits"],
                "l2_enabled": self.redis_client is not None,
                "hit_rate": f"{hit_rate:.1f}%",
                "size": len(self.cache)
            }
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self.lock:
            self.cache.clear()
            self.stats = {
                "hits": 0,
                "misses": 0,
                "evictions": 0,
                "l2_hits": 0,
            }
        # Clear Redis L2 keys
        if self.redis_client is not None:
            try:
                cursor = 0
                while True:
                    cursor, keys = self.redis_client.scan(cursor, match="llm_cache:*", count=100)
                    if keys:
                        self.redis_client.delete(*keys)
                    if cursor == 0:
                        break
            except Exception as e:
                logger.debug(f"Failed to clear Redis L2 cache: {e}")


# Global cache instance
_global_cache = None
_cache_lock = Lock()


def get_cache() -> LLMCache:
    """Get or create global cache instance."""
    global _global_cache
    
    with _cache_lock:
        if _global_cache is None:
            _global_cache = LLMCache()
        return _global_cache


def clear_cache() -> None:
    """Clear the global cache."""
    cache = get_cache()
    cache.clear()


def get_cache_stats() -> Dict[str, Any]:
    """Get global cache statistics."""
    cache = get_cache()
    return cache.get_stats()