"""Tests for LLMCache max_size LRU eviction."""

from bandjacks.llm.cache import LLMCache


def test_cache_evicts_at_max_size():
    cache = LLMCache(ttl_seconds=900, max_size=3)
    for i in range(5):
        msgs = [{"role": "user", "content": f"msg-{i}"}]
        cache.set(msgs, {"content": f"resp-{i}"})
    assert cache.get_stats()["size"] <= 3


def test_cache_evicts_oldest():
    cache = LLMCache(ttl_seconds=900, max_size=2)
    msgs_a = [{"role": "user", "content": "a"}]
    msgs_b = [{"role": "user", "content": "b"}]
    msgs_c = [{"role": "user", "content": "c"}]
    cache.set(msgs_a, {"content": "resp-a"})
    cache.set(msgs_b, {"content": "resp-b"})
    cache.set(msgs_c, {"content": "resp-c"})  # should evict 'a'
    assert cache.get(msgs_a) is None
    assert cache.get(msgs_c) is not None


def test_cache_default_max_size():
    cache = LLMCache()
    assert cache.max_size == 10000


def test_cache_eviction_stats():
    cache = LLMCache(ttl_seconds=900, max_size=2)
    for i in range(5):
        msgs = [{"role": "user", "content": f"msg-{i}"}]
        cache.set(msgs, {"content": f"resp-{i}"})
    stats = cache.get_stats()
    assert stats["evictions"] == 3  # 5 inserts - 2 max_size = 3 evictions


def test_cache_lru_access_refreshes_position():
    """Accessing an entry should move it to most-recently-used, protecting from eviction."""
    cache = LLMCache(ttl_seconds=900, max_size=2)
    msgs_a = [{"role": "user", "content": "a"}]
    msgs_b = [{"role": "user", "content": "b"}]
    msgs_c = [{"role": "user", "content": "c"}]
    cache.set(msgs_a, {"content": "resp-a"})
    cache.set(msgs_b, {"content": "resp-b"})
    # Access 'a' to refresh it — now 'b' is the least recently used
    assert cache.get(msgs_a) is not None
    # Insert 'c' — should evict 'b' (LRU), not 'a' (recently accessed)
    cache.set(msgs_c, {"content": "resp-c"})
    assert cache.get(msgs_a) is not None, "LRU: 'a' was accessed recently, should survive"
    assert cache.get(msgs_b) is None, "LRU: 'b' was least recently used, should be evicted"
