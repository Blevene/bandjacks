"""Two-tier vector search cache for performance optimization."""

import hashlib
import json
import logging
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

import redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)


class VectorSearchCache:
    """Two-tier cache for vector search results.
    
    L1: In-memory LRU cache (fast, per-worker)
    L2: Redis cache (shared across workers, persistent)
    """
    
    def __init__(
        self,
        max_size: int = 5000,
        ttl: int = 3600,
        redis_enabled: bool = True,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 1,  # Use DB 1 for cache (DB 0 for jobs)
    ):
        """Initialize the vector search cache.
        
        Args:
            max_size: Maximum number of entries in L1 cache
            ttl: Time-to-live for cache entries in seconds
            redis_enabled: Whether to use Redis for L2 cache
            redis_host: Redis host
            redis_port: Redis port
            redis_db: Redis database number
        """
        self.max_size = max_size
        self.ttl = ttl
        self.redis_enabled = redis_enabled
        
        # L1: In-memory LRU cache
        self.l1_cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self.l1_hits = 0
        self.l1_misses = 0
        
        # L2: Redis cache
        self.redis_client = None
        self.l2_hits = 0
        self.l2_misses = 0
        
        if redis_enabled:
            try:
                self.redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=redis_db,
                    decode_responses=False,
                    socket_connect_timeout=2,
                    socket_timeout=2,
                )
                self.redis_client.ping()
                logger.info(f"Redis cache connected: {redis_host}:{redis_port}/db{redis_db}")
            except (RedisError, ConnectionError) as e:
                logger.warning(f"Redis not available for vector cache: {e}")
                self.redis_client = None
                self.redis_enabled = False
    
    def _make_key(self, text: str, top_k: int, cache_type: str = "result") -> str:
        """Generate cache key from text and parameters.
        
        Args:
            text: The search text
            top_k: Number of results requested
            cache_type: Type of cache entry ("embedding" or "result")
            
        Returns:
            Cache key string
        """
        # Create a hash of the text for the key
        text_hash = hashlib.sha256(text.encode('utf-8')).hexdigest()
        return f"vector_cache:{cache_type}:{text_hash}:{top_k}"
    
    def _is_expired(self, timestamp: float) -> bool:
        """Check if a cache entry has expired.
        
        Args:
            timestamp: Timestamp when entry was created
            
        Returns:
            True if expired, False otherwise
        """
        return time.time() - timestamp > self.ttl
    
    def _evict_lru(self) -> None:
        """Evict least recently used item from L1 cache."""
        if self.l1_cache:
            evicted_key = next(iter(self.l1_cache))
            del self.l1_cache[evicted_key]
            logger.debug(f"Evicted LRU entry from L1 cache: {evicted_key}")
    
    def get_embedding(self, text: str) -> Optional[List[float]]:
        """Get cached embedding for text.
        
        Args:
            text: Text to get embedding for
            
        Returns:
            Cached embedding vector or None if not found
        """
        cache_key = self._make_key(text, 0, "embedding")
        
        # Check L1 cache
        if cache_key in self.l1_cache:
            value, timestamp = self.l1_cache[cache_key]
            if not self._is_expired(timestamp):
                # Move to end (most recently used)
                self.l1_cache.move_to_end(cache_key)
                self.l1_hits += 1
                return value
            else:
                # Expired, remove it
                del self.l1_cache[cache_key]
        
        self.l1_misses += 1
        
        # Check L2 cache (Redis)
        if self.redis_client:
            try:
                cached = self.redis_client.get(cache_key)
                if cached:
                    value = json.loads(cached)
                    # Add to L1 cache
                    self._add_to_l1(cache_key, value)
                    self.l2_hits += 1
                    return value
            except (RedisError, json.JSONDecodeError) as e:
                logger.debug(f"Redis cache read error: {e}")
        
        self.l2_misses += 1
        return None
    
    def get_candidates(self, text: str, top_k: int) -> Optional[List[Dict[str, Any]]]:
        """Get cached search results for text.
        
        Args:
            text: Search text
            top_k: Number of results requested
            
        Returns:
            Cached candidate list or None if not found
        """
        cache_key = self._make_key(text, top_k, "result")
        
        # Check L1 cache
        if cache_key in self.l1_cache:
            value, timestamp = self.l1_cache[cache_key]
            if not self._is_expired(timestamp):
                # Move to end (most recently used)
                self.l1_cache.move_to_end(cache_key)
                self.l1_hits += 1
                logger.debug(f"L1 cache hit for: {cache_key}")
                return value
            else:
                # Expired, remove it
                del self.l1_cache[cache_key]
        
        self.l1_misses += 1
        
        # Check L2 cache (Redis)
        if self.redis_client:
            try:
                cached = self.redis_client.get(cache_key)
                if cached:
                    value = json.loads(cached)
                    # Add to L1 cache
                    self._add_to_l1(cache_key, value)
                    self.l2_hits += 1
                    logger.debug(f"L2 cache hit for: {cache_key}")
                    return value
            except (RedisError, json.JSONDecodeError) as e:
                logger.debug(f"Redis cache read error: {e}")
        
        self.l2_misses += 1
        return None
    
    def set_embedding(self, text: str, embedding: List[float]) -> None:
        """Cache an embedding vector.
        
        Args:
            text: Text that was embedded
            embedding: The embedding vector
        """
        cache_key = self._make_key(text, 0, "embedding")
        
        # Add to L1 cache
        self._add_to_l1(cache_key, embedding)
        
        # Add to L2 cache (Redis)
        if self.redis_client:
            try:
                self.redis_client.setex(
                    cache_key,
                    self.ttl,
                    json.dumps(embedding)
                )
            except (RedisError, json.JSONDecodeError) as e:
                logger.debug(f"Redis cache write error: {e}")
    
    def set_candidates(self, text: str, top_k: int, candidates: List[Dict[str, Any]]) -> None:
        """Cache search results.
        
        Args:
            text: Search text
            top_k: Number of results requested
            candidates: The search results to cache
        """
        cache_key = self._make_key(text, top_k, "result")
        
        # Add to L1 cache
        self._add_to_l1(cache_key, candidates)
        
        # Add to L2 cache (Redis)
        if self.redis_client:
            try:
                self.redis_client.setex(
                    cache_key,
                    self.ttl,
                    json.dumps(candidates)
                )
            except (RedisError, json.JSONDecodeError) as e:
                logger.debug(f"Redis cache write error: {e}")
    
    def _add_to_l1(self, key: str, value: Any) -> None:
        """Add entry to L1 cache with LRU eviction.
        
        Args:
            key: Cache key
            value: Value to cache
        """
        # Evict if at capacity
        if len(self.l1_cache) >= self.max_size:
            self._evict_lru()
        
        # Add new entry (or update existing)
        self.l1_cache[key] = (value, time.time())
        # Move to end (most recently used)
        self.l1_cache.move_to_end(key)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        total_hits = self.l1_hits + self.l2_hits
        total_misses = self.l1_misses + self.l2_misses
        hit_rate = total_hits / (total_hits + total_misses) if (total_hits + total_misses) > 0 else 0
        
        return {
            "l1_size": len(self.l1_cache),
            "l1_hits": self.l1_hits,
            "l1_misses": self.l1_misses,
            "l1_hit_rate": self.l1_hits / (self.l1_hits + self.l1_misses) if (self.l1_hits + self.l1_misses) > 0 else 0,
            "l2_hits": self.l2_hits,
            "l2_misses": self.l2_misses,
            "l2_enabled": self.redis_enabled,
            "total_hits": total_hits,
            "total_misses": total_misses,
            "overall_hit_rate": hit_rate,
        }
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self.l1_cache.clear()
        if self.redis_client:
            try:
                # Clear all vector cache keys
                pattern = "vector_cache:*"
                cursor = 0
                while True:
                    cursor, keys = self.redis_client.scan(cursor, match=pattern, count=100)
                    if keys:
                        self.redis_client.delete(*keys)
                    if cursor == 0:
                        break
            except RedisError as e:
                logger.warning(f"Failed to clear Redis cache: {e}")
        
        # Reset stats
        self.l1_hits = 0
        self.l1_misses = 0
        self.l2_hits = 0
        self.l2_misses = 0
        
        logger.info("Vector search cache cleared")


# Global cache instance (singleton per worker)
_global_cache: Optional[VectorSearchCache] = None


def get_vector_cache() -> VectorSearchCache:
    """Get the global vector search cache instance.
    
    Returns:
        The global VectorSearchCache instance
    """
    global _global_cache
    
    if _global_cache is None:
        from bandjacks.services.api.settings import settings
        
        _global_cache = VectorSearchCache(
            max_size=settings.vector_cache_max_size,
            ttl=settings.vector_cache_ttl,
            redis_enabled=settings.vector_cache_redis_enabled,
            redis_host=settings.redis_host,
            redis_port=settings.redis_port,
            redis_db=1,  # Use DB 1 for cache
        )
    
    return _global_cache