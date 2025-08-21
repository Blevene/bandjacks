"""Cache management for embeddings and LLM responses."""

import logging
import time
from typing import Dict, Any, Optional, Set
from datetime import datetime, timedelta
import hashlib
import json
from collections import OrderedDict
import threading

logger = logging.getLogger(__name__)


class CacheManager:
    """Manages TTL-based caching with invalidation support."""
    
    def __init__(
        self,
        max_size: int = 10000,
        default_ttl: int = 3600,
        cleanup_interval: int = 300
    ):
        """
        Initialize cache manager.
        
        Args:
            max_size: Maximum cache entries
            default_ttl: Default TTL in seconds
            cleanup_interval: Cleanup interval in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cleanup_interval = cleanup_interval
        
        # Use OrderedDict for LRU behavior
        self._cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._lock = threading.RLock()
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "invalidations": 0
        }
        
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None
        """
        with self._lock:
            entry = self._cache.get(key)
            
            if entry:
                # Check TTL
                if time.time() < entry["expires_at"]:
                    # Move to end (LRU)
                    self._cache.move_to_end(key)
                    self._stats["hits"] += 1
                    return entry["value"]
                else:
                    # Expired
                    del self._cache[key]
            
            self._stats["misses"] += 1
            return None
    
    def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ):
        """
        Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: TTL in seconds (optional)
        """
        with self._lock:
            # Evict if at max size
            if len(self._cache) >= self.max_size and key not in self._cache:
                # Remove oldest (first) item
                self._cache.popitem(last=False)
                self._stats["evictions"] += 1
            
            # Set entry
            self._cache[key] = {
                "value": value,
                "expires_at": time.time() + (ttl or self.default_ttl),
                "created_at": time.time()
            }
            
            # Move to end (most recently used)
            self._cache.move_to_end(key)
    
    def invalidate(self, key: str) -> bool:
        """
        Invalidate cache entry.
        
        Args:
            key: Cache key
            
        Returns:
            True if entry was invalidated
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                self._stats["invalidations"] += 1
                return True
            return False
    
    def invalidate_pattern(self, pattern: str) -> int:
        """
        Invalidate entries matching pattern.
        
        Args:
            pattern: Key pattern (prefix match)
            
        Returns:
            Number of entries invalidated
        """
        with self._lock:
            keys_to_remove = [
                key for key in self._cache.keys()
                if key.startswith(pattern)
            ]
            
            for key in keys_to_remove:
                del self._cache[key]
                self._stats["invalidations"] += 1
            
            return len(keys_to_remove)
    
    def clear(self):
        """Clear all cache entries."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._stats["invalidations"] += count
            logger.info(f"Cleared {count} cache entries")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_requests = self._stats["hits"] + self._stats["misses"]
            hit_rate = (
                self._stats["hits"] / total_requests
                if total_requests > 0
                else 0
            )
            
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._stats["hits"],
                "misses": self._stats["misses"],
                "evictions": self._stats["evictions"],
                "invalidations": self._stats["invalidations"],
                "hit_rate": round(hit_rate, 3),
                "total_requests": total_requests
            }
    
    def _cleanup_loop(self):
        """Background thread to clean up expired entries."""
        while True:
            time.sleep(self.cleanup_interval)
            self._cleanup_expired()
    
    def _cleanup_expired(self):
        """Remove expired entries."""
        with self._lock:
            current_time = time.time()
            expired_keys = [
                key for key, entry in self._cache.items()
                if current_time >= entry["expires_at"]
            ]
            
            for key in expired_keys:
                del self._cache[key]
            
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")


class EmbeddingCache(CacheManager):
    """Specialized cache for embedding vectors."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.embedding_dimension = 768  # Default for sentence transformers
    
    def get_embedding(self, text: str) -> Optional[list]:
        """Get cached embedding for text."""
        key = self._generate_key(text)
        return self.get(key)
    
    def set_embedding(self, text: str, embedding: list, ttl: Optional[int] = None):
        """Cache embedding for text."""
        if len(embedding) != self.embedding_dimension:
            logger.warning(f"Embedding dimension mismatch: {len(embedding)} != {self.embedding_dimension}")
        
        key = self._generate_key(text)
        self.set(key, embedding, ttl)
    
    def invalidate_embedding(self, text: str) -> bool:
        """Invalidate cached embedding for text."""
        key = self._generate_key(text)
        return self.invalidate(key)
    
    def _generate_key(self, text: str) -> str:
        """Generate cache key for text."""
        hash_obj = hashlib.md5(text.encode())
        return f"emb:{hash_obj.hexdigest()}"


class LLMResponseCache(CacheManager):
    """Specialized cache for LLM responses."""
    
    def get_response(
        self,
        prompt: str,
        model: str = "default",
        params: Optional[Dict] = None
    ) -> Optional[str]:
        """Get cached LLM response."""
        key = self._generate_key(prompt, model, params)
        return self.get(key)
    
    def set_response(
        self,
        prompt: str,
        response: str,
        model: str = "default",
        params: Optional[Dict] = None,
        ttl: Optional[int] = None
    ):
        """Cache LLM response."""
        key = self._generate_key(prompt, model, params)
        self.set(key, response, ttl)
    
    def invalidate_response(
        self,
        prompt: str,
        model: str = "default",
        params: Optional[Dict] = None
    ) -> bool:
        """Invalidate cached LLM response."""
        key = self._generate_key(prompt, model, params)
        return self.invalidate(key)
    
    def _generate_key(
        self,
        prompt: str,
        model: str,
        params: Optional[Dict]
    ) -> str:
        """Generate cache key for LLM request."""
        cache_data = {
            "prompt": prompt,
            "model": model,
            "params": params or {}
        }
        
        cache_str = json.dumps(cache_data, sort_keys=True)
        hash_obj = hashlib.md5(cache_str.encode())
        return f"llm:{model}:{hash_obj.hexdigest()}"


# Global cache instances
_embedding_cache: Optional[EmbeddingCache] = None
_llm_cache: Optional[LLMResponseCache] = None


def get_embedding_cache() -> EmbeddingCache:
    """Get or create embedding cache singleton."""
    global _embedding_cache
    if _embedding_cache is None:
        _embedding_cache = EmbeddingCache(
            max_size=50000,
            default_ttl=86400,  # 24 hours
            cleanup_interval=600  # 10 minutes
        )
    return _embedding_cache


def get_llm_cache() -> LLMResponseCache:
    """Get or create LLM response cache singleton."""
    global _llm_cache
    if _llm_cache is None:
        _llm_cache = LLMResponseCache(
            max_size=10000,
            default_ttl=3600,  # 1 hour
            cleanup_interval=300  # 5 minutes
        )
    return _llm_cache


def invalidate_caches_for_item(item_id: str):
    """
    Invalidate all caches for a specific item.
    
    Args:
        item_id: Item ID to invalidate
    """
    # Invalidate embedding cache
    embedding_cache = get_embedding_cache()
    count = embedding_cache.invalidate_pattern(item_id)
    
    # Invalidate LLM cache
    llm_cache = get_llm_cache()
    count += llm_cache.invalidate_pattern(item_id)
    
    logger.info(f"Invalidated {count} cache entries for item {item_id}")