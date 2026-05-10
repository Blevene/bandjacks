"""Pin the vector-cache namespace version.

Bumping the namespace invalidates entries cached before a filter-semantics
change (e.g., the May 2026 BatchRetriever revoked-TID filter). Pre-existing
entries simply can't be read by post-fix code; they expire via TTL with no
migration needed.

Tests both that v2 is the current namespace AND that a v1-shaped key won't
match what _make_key now produces.
"""

import hashlib

from bandjacks.llm.vector_cache import VectorSearchCache


def _v1_key(text: str, top_k: int, cache_type: str = "result") -> str:
    """The pre-fix key shape, hardcoded so this test is self-contained."""
    text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"vector_cache:{cache_type}:{text_hash}:{top_k}"


def test_namespace_is_v2():
    cache = VectorSearchCache.__new__(VectorSearchCache)  # bypass __init__
    assert cache._CACHE_NAMESPACE == "v2"


def test_make_key_includes_namespace():
    cache = VectorSearchCache.__new__(VectorSearchCache)
    key = cache._make_key("powershell", top_k=5, cache_type="result")
    assert key.startswith("vector_cache:v2:result:")


def test_v2_key_does_not_match_v1_key():
    """The whole point of the bump: post-fix lookups must miss pre-fix entries."""
    cache = VectorSearchCache.__new__(VectorSearchCache)
    text = "credential dumping"
    v2 = cache._make_key(text, top_k=10, cache_type="result")
    v1 = _v1_key(text, top_k=10, cache_type="result")
    assert v1 != v2, (
        "v1 and v2 keys must differ — otherwise the namespace bump is a no-op "
        "and pre-fix cache entries will continue to be served"
    )


def test_namespace_applies_to_embedding_keys_too():
    cache = VectorSearchCache.__new__(VectorSearchCache)
    embed_key = cache._make_key("x", top_k=1, cache_type="embedding")
    assert "v2" in embed_key
