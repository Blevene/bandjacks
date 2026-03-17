"""LLM response caching for improved performance."""

import hashlib
import json
import time
from typing import Any, Dict, List, Optional
from threading import Lock


class LLMCache:
    """Thread-safe in-memory cache for LLM responses with TTL support."""
    
    def __init__(self, ttl_seconds: int = 900, max_size: int = 10000):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.ttl = ttl_seconds
        self.max_size = max_size
        self.lock = Lock()
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0
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
                    return None
                
                self.stats["hits"] += 1
                return entry["response"]
            
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
                "evictions": 0
            }


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