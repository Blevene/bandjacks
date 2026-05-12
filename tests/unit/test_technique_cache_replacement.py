"""Tests for TechniqueCache.replacement_for() chain walking."""

import pytest

from bandjacks.services.technique_cache import TechniqueCache


@pytest.fixture
def cache():
    c = TechniqueCache()
    original = dict(c._cache)
    original_loaded = c._loaded
    yield c
    c._cache.clear()
    c._cache.update(original)
    c._loaded = original_loaded


def _seed(cache, entries):
    """entries: list of dicts with at minimum external_id, revoked, replacement."""
    cache._cache.clear()
    for e in entries:
        tid = e["external_id"]
        cache._cache[tid] = {
            "external_id": tid,
            "name": tid,
            "description": "",
            "is_subtechnique": False,
            "platforms": [],
            "tactics": [],
            "tactic": None,
            "revoked": e.get("revoked", False),
            "deprecated": e.get("deprecated", False),
            "replacement": e.get("replacement"),
        }
    cache._loaded = True


def test_revoked_with_active_replacement_returns_replacement(cache):
    _seed(
        cache,
        [
            {"external_id": "T1128", "revoked": True, "replacement": "T1546.007"},
            {"external_id": "T1546.007", "revoked": False},
        ],
    )
    assert cache.replacement_for("T1128") == "T1546.007"


def test_active_input_returns_none(cache):
    """Active TIDs don't need a replacement; return None so callers know."""
    _seed(cache, [{"external_id": "T1059", "revoked": False}])
    assert cache.replacement_for("T1059") is None


def test_unknown_input_returns_none(cache):
    _seed(cache, [])
    assert cache.replacement_for("T9999") is None


def test_revoked_no_replacement_returns_none(cache):
    """Revoked but no successor edge → drop, don't remap."""
    _seed(cache, [{"external_id": "T1024", "revoked": True, "replacement": None}])
    assert cache.replacement_for("T1024") is None


def test_chain_walks_to_first_active(cache):
    """Multi-hop revocation: T1 → T2 (revoked) → T3 (active)."""
    _seed(
        cache,
        [
            {"external_id": "T1", "revoked": True, "replacement": "T2"},
            {"external_id": "T2", "revoked": True, "replacement": "T3"},
            {"external_id": "T3", "revoked": False},
        ],
    )
    assert cache.replacement_for("T1") == "T3"


def test_chain_dead_ends_in_revoked_with_no_replacement(cache):
    """T1 → T2 (revoked, no successor) → return None, don't return T2."""
    _seed(
        cache,
        [
            {"external_id": "T1", "revoked": True, "replacement": "T2"},
            {"external_id": "T2", "revoked": True, "replacement": None},
        ],
    )
    assert cache.replacement_for("T1") is None


def test_cycle_protection(cache):
    """Pathological: T1 → T2 → T1 (revoked-by cycle). Must not loop forever."""
    _seed(
        cache,
        [
            {"external_id": "T1", "revoked": True, "replacement": "T2"},
            {"external_id": "T2", "revoked": True, "replacement": "T1"},
        ],
    )
    assert cache.replacement_for("T1") is None


def test_chain_dead_ends_at_unknown(cache):
    """T1 → T2 (not in cache) → return None, don't crash."""
    _seed(cache, [{"external_id": "T1", "revoked": True, "replacement": "T_UNLOADED"}])
    assert cache.replacement_for("T1") is None


def test_deprecated_treated_like_revoked(cache):
    """Deprecated TIDs should also walk to their replacement if present."""
    _seed(
        cache,
        [
            {"external_id": "Tdep", "deprecated": True, "replacement": "Tnew"},
            {"external_id": "Tnew", "revoked": False},
        ],
    )
    assert cache.replacement_for("Tdep") == "Tnew"
