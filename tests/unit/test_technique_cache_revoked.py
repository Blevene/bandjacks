"""Tests for TechniqueCache revoked/deprecated helper methods."""

import pytest

from bandjacks.services.technique_cache import TechniqueCache


@pytest.fixture
def cache():
    """Yield the singleton, then reset it on teardown."""
    c = TechniqueCache()
    original = dict(c._cache)
    original_loaded = c._loaded
    yield c
    c._cache.clear()
    c._cache.update(original)
    c._loaded = original_loaded


def _seed(cache, entries):
    """entries: list[(tid, revoked, deprecated)]"""
    cache._cache.clear()
    for tid, revoked, deprecated in entries:
        cache._cache[tid] = {
            "external_id": tid,
            "name": tid,
            "description": "",
            "is_subtechnique": False,
            "platforms": [],
            "tactics": [],
            "tactic": None,
            "revoked": revoked,
            "deprecated": deprecated,
        }
    cache._loaded = True


def test_is_revoked_true_for_revoked(cache):
    _seed(cache, [("T1128", True, False)])
    assert cache.is_revoked("T1128") is True


def test_is_revoked_true_for_deprecated(cache):
    _seed(cache, [("T1024", False, True)])
    assert cache.is_revoked("T1024") is True


def test_is_revoked_false_for_active(cache):
    _seed(cache, [("T1059", False, False)])
    assert cache.is_revoked("T1059") is False


def test_is_revoked_false_for_unknown_tid(cache):
    # Unknown TID: helper returns False so callers don't filter
    # techniques the cache simply hasn't seen yet.
    _seed(cache, [])
    assert cache.is_revoked("T9999") is False


def test_is_active_inverse_of_is_revoked(cache):
    _seed(cache, [("T1059", False, False), ("T1128", True, False)])
    assert cache.is_active("T1059") is True
    assert cache.is_active("T1128") is False
    # Unknown TID is not active (cache miss != confirmed valid)
    assert cache.is_active("T9999") is False


def test_revoked_ids_returns_set(cache):
    _seed(
        cache,
        [("T1059", False, False), ("T1128", True, False), ("T1024", False, True)],
    )
    assert cache.revoked_ids() == {"T1128", "T1024"}
