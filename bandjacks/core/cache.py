"""Redis caching layer for performance optimization."""

import json
import hashlib
from typing import Any, Optional, Dict, List
from datetime import timedelta
import redis
from redis.exceptions import RedisError
import pickle


class CacheManager:
    """Manages caching for expensive operations."""
    
    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        default_ttl: int = 3600,
        enable_cache: bool = True
    ):
        """
        Initialize cache manager.
        
        Args:
            redis_url: Redis connection URL
            default_ttl: Default TTL in seconds (1 hour)
            enable_cache: Whether caching is enabled
        """
        self.enable_cache = enable_cache
        self.default_ttl = default_ttl
        self.client = None
        
        if enable_cache:
            try:
                self.client = redis.from_url(redis_url, decode_responses=False)
                self.client.ping()
                print(f"Redis cache connected: {redis_url}")
            except (RedisError, ConnectionError) as e:
                print(f"Redis not available, caching disabled: {e}")
                self.enable_cache = False
    
    def _make_key(self, prefix: str, params: Dict[str, Any]) -> str:
        """
        Generate cache key from prefix and parameters.
        
        Args:
            prefix: Key prefix (e.g., "query", "graph")
            params: Parameters to include in key
            
        Returns:
            Cache key string
        """
        # Sort params for consistent keys
        sorted_params = json.dumps(params, sort_keys=True)
        param_hash = hashlib.md5(sorted_params.encode()).hexdigest()
        return f"bandjacks:{prefix}:{param_hash}"
    
    def get(self, prefix: str, params: Dict[str, Any]) -> Optional[Any]:
        """
        Get cached value.
        
        Args:
            prefix: Key prefix
            params: Parameters
            
        Returns:
            Cached value or None
        """
        if not self.enable_cache or not self.client:
            return None
        
        try:
            key = self._make_key(prefix, params)
            data = self.client.get(key)
            
            if data:
                return pickle.loads(data)
            
        except Exception as e:
            print(f"Cache get error: {e}")
        
        return None
    
    def set(
        self,
        prefix: str,
        params: Dict[str, Any],
        value: Any,
        ttl: Optional[int] = None
    ) -> bool:
        """
        Set cached value.
        
        Args:
            prefix: Key prefix
            params: Parameters
            value: Value to cache
            ttl: TTL in seconds (uses default if None)
            
        Returns:
            Success boolean
        """
        if not self.enable_cache or not self.client:
            return False
        
        try:
            key = self._make_key(prefix, params)
            data = pickle.dumps(value)
            ttl = ttl or self.default_ttl
            
            self.client.setex(key, ttl, data)
            return True
            
        except Exception as e:
            print(f"Cache set error: {e}")
            return False
    
    def invalidate(self, prefix: str, pattern: Optional[str] = None) -> int:
        """
        Invalidate cached entries.
        
        Args:
            prefix: Key prefix to invalidate
            pattern: Optional pattern to match
            
        Returns:
            Number of keys deleted
        """
        if not self.enable_cache or not self.client:
            return 0
        
        try:
            if pattern:
                keys = self.client.keys(f"bandjacks:{prefix}:*{pattern}*")
            else:
                keys = self.client.keys(f"bandjacks:{prefix}:*")
            
            if keys:
                return self.client.delete(*keys)
            
        except Exception as e:
            print(f"Cache invalidate error: {e}")
        
        return 0
    
    def get_or_compute(
        self,
        prefix: str,
        params: Dict[str, Any],
        compute_fn,
        ttl: Optional[int] = None
    ) -> Any:
        """
        Get from cache or compute and cache.
        
        Args:
            prefix: Key prefix
            params: Parameters
            compute_fn: Function to compute value if not cached
            ttl: TTL in seconds
            
        Returns:
            Cached or computed value
        """
        # Try cache first
        cached = self.get(prefix, params)
        if cached is not None:
            return cached
        
        # Compute value
        value = compute_fn()
        
        # Cache result
        self.set(prefix, params, value, ttl)
        
        return value
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Statistics dictionary
        """
        if not self.enable_cache or not self.client:
            return {"enabled": False}
        
        try:
            info = self.client.info("stats")
            memory = self.client.info("memory")
            
            return {
                "enabled": True,
                "connected": True,
                "total_connections": info.get("total_connections_received", 0),
                "commands_processed": info.get("total_commands_processed", 0),
                "hits": info.get("keyspace_hits", 0),
                "misses": info.get("keyspace_misses", 0),
                "hit_rate": (
                    info.get("keyspace_hits", 0) / 
                    max(1, info.get("keyspace_hits", 0) + info.get("keyspace_misses", 0))
                ),
                "memory_used": memory.get("used_memory_human", "0"),
                "memory_peak": memory.get("used_memory_peak_human", "0")
            }
            
        except Exception as e:
            return {
                "enabled": True,
                "connected": False,
                "error": str(e)
            }
    
    def close(self):
        """Close Redis connection."""
        if self.client:
            self.client.close()


class QueryCache:
    """Specialized cache for query results."""
    
    def __init__(self, cache_manager: CacheManager):
        """
        Initialize query cache.
        
        Args:
            cache_manager: Base cache manager
        """
        self.cache = cache_manager
        self.ttl_map = {
            "search": 1800,      # 30 minutes
            "graph": 3600,       # 1 hour
            "suggestions": 7200, # 2 hours
            "stats": 300         # 5 minutes
        }
    
    def get_search_results(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        top_k: int = 20
    ) -> Optional[List[Dict[str, Any]]]:
        """Get cached search results."""
        params = {
            "query": query,
            "filters": filters or {},
            "top_k": top_k
        }
        return self.cache.get("search", params)
    
    def set_search_results(
        self,
        query: str,
        results: List[Dict[str, Any]],
        filters: Optional[Dict[str, Any]] = None,
        top_k: int = 20
    ) -> bool:
        """Cache search results."""
        params = {
            "query": query,
            "filters": filters or {},
            "top_k": top_k
        }
        return self.cache.set(
            "search",
            params,
            results,
            self.ttl_map["search"]
        )
    
    def get_graph_traversal(
        self,
        center_id: str,
        depth: int,
        relationships: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Get cached graph traversal."""
        params = {
            "center_id": center_id,
            "depth": depth,
            "relationships": sorted(relationships)
        }
        return self.cache.get("graph", params)
    
    def set_graph_traversal(
        self,
        center_id: str,
        depth: int,
        relationships: List[str],
        result: Dict[str, Any]
    ) -> bool:
        """Cache graph traversal."""
        params = {
            "center_id": center_id,
            "depth": depth,
            "relationships": sorted(relationships)
        }
        return self.cache.set(
            "graph",
            params,
            result,
            self.ttl_map["graph"]
        )
    
    def invalidate_search(self, query_pattern: Optional[str] = None):
        """Invalidate search cache."""
        return self.cache.invalidate("search", query_pattern)
    
    def invalidate_graph(self, node_id: Optional[str] = None):
        """Invalidate graph cache."""
        return self.cache.invalidate("graph", node_id)


# Global cache instance
_cache_manager = None
_query_cache = None


def get_cache_manager(
    redis_url: Optional[str] = None,
    force_new: bool = False
) -> CacheManager:
    """
    Get global cache manager instance.
    
    Args:
        redis_url: Optional Redis URL
        force_new: Force new instance
        
    Returns:
        Cache manager instance
    """
    global _cache_manager
    
    if force_new or _cache_manager is None:
        url = redis_url or "redis://localhost:6379"
        _cache_manager = CacheManager(url)
    
    return _cache_manager


def get_query_cache(
    redis_url: Optional[str] = None,
    force_new: bool = False
) -> QueryCache:
    """
    Get global query cache instance.
    
    Args:
        redis_url: Optional Redis URL
        force_new: Force new instance
        
    Returns:
        Query cache instance
    """
    global _query_cache
    
    if force_new or _query_cache is None:
        manager = get_cache_manager(redis_url, force_new)
        _query_cache = QueryCache(manager)
    
    return _query_cache