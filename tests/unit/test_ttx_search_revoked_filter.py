"""Tests for the revoked-TID `must_not` filter in ttx_search_kb."""

from unittest.mock import patch

from bandjacks.loaders.search_nodes import ttx_search_kb


class _FakeClient:
    """Captures the body sent to OpenSearch and returns an empty hit list."""

    def __init__(self):
        self.last_body = None

    def search(self, index, body):
        self.last_body = body
        return {"hits": {"hits": []}}


@patch("bandjacks.loaders.search_nodes.encode", return_value=[0.0] * 768)
def test_default_excludes_revoked(_):
    fc = _FakeClient()
    ttx_search_kb("http://x", "attack_nodes", "credential dumping", top_k=5, client=fc)
    must_not = fc.last_body["query"]["bool"]["must_not"]
    assert {"term": {"revoked": True}} in must_not


@patch("bandjacks.loaders.search_nodes.encode", return_value=[0.0] * 768)
def test_explicit_include_revoked(_):
    fc = _FakeClient()
    ttx_search_kb(
        "http://x", "attack_nodes", "x", top_k=5, client=fc, exclude_revoked=False
    )
    bool_q = fc.last_body["query"]["bool"]
    assert bool_q.get("must_not", []) == []


@patch("bandjacks.loaders.search_nodes.encode", return_value=[0.0] * 768)
def test_knn_query_preserved(_):
    fc = _FakeClient()
    ttx_search_kb("http://x", "attack_nodes", "x", top_k=5, client=fc)
    must = fc.last_body["query"]["bool"]["must"]
    assert any("knn" in clause for clause in must)


@patch("bandjacks.loaders.search_nodes.encode", return_value=None)
def test_empty_when_no_embedding(_):
    fc = _FakeClient()
    out = ttx_search_kb("http://x", "attack_nodes", "x", top_k=5, client=fc)
    assert out == []


@patch("bandjacks.loaders.search_nodes.encode", return_value=[0.0] * 768)
def test_kb_type_filter_still_applied(_):
    """Bool wrapper must not break the existing kb_types post-filter behavior."""
    fc = _FakeClient()
    ttx_search_kb(
        "http://x",
        "attack_nodes",
        "x",
        top_k=5,
        kb_types=["AttackPattern"],
        client=fc,
    )
    # The size should be larger when kb_types is set (existing pre-filter behavior)
    assert fc.last_body["size"] >= 30
