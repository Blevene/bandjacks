"""Pin the must_not revoked filter in BatchRetrieverAgent's msearch query.

The production extraction pipeline goes through BatchRetriever — not
ttx_search_kb — so the KNN must_not filter has to be applied here too,
otherwise revoked TIDs reach mem.candidates and the LLM is asked to
verify them.
"""

from unittest.mock import patch

from bandjacks.llm.batch_retriever import BatchRetrieverAgent
from bandjacks.llm.memory import WorkingMemory


class _FakeOSClient:
    """Captures the body sent to msearch and returns an empty response set."""

    def __init__(self):
        self.last_body = None

    def msearch(self, body):
        self.last_body = body
        # Two entries per search: one index spec + one query body.
        # Half of body is queries; respond with one empty result per query.
        n_queries = len(body) // 2
        return {"responses": [{"hits": {"hits": []}} for _ in range(n_queries)]}


@patch("bandjacks.llm.batch_retriever.batch_encode")
def test_msearch_body_excludes_revoked(mock_batch_encode):
    """Each msearch query body must contain `must_not: [{term: revoked: true}]`."""
    mock_batch_encode.return_value = [[0.0] * 768]

    fake = _FakeOSClient()
    agent = BatchRetrieverAgent(os_client=fake)

    mem = WorkingMemory()
    mem.spans = [{"text": "powershell -enc ...", "line_refs": []}]
    mem.candidates = {}

    agent.run(mem, {"top_k": 5, "use_embedding_cache": False})

    assert fake.last_body is not None, "msearch should have been called"
    # The body alternates: [{"index": ...}, {query body}, {"index": ...}, ...].
    # Inspect every odd-indexed entry (the actual query bodies).
    query_bodies = [fake.last_body[i] for i in range(1, len(fake.last_body), 2)]
    assert query_bodies, "expected at least one query body"
    for qb in query_bodies:
        bool_q = qb["query"]["bool"]
        must = bool_q["must"]
        must_not = bool_q["must_not"]
        assert any("knn" in clause for clause in must), "knn clause must be preserved"
        assert {"term": {"revoked": True}} in must_not, (
            "must_not should exclude revoked: True at the index layer"
        )


@patch("bandjacks.llm.batch_retriever.batch_encode")
def test_msearch_size_unchanged(mock_batch_encode):
    """The bool wrapper must not regress the size or fetch_size logic."""
    mock_batch_encode.return_value = [[0.0] * 768]

    fake = _FakeOSClient()
    agent = BatchRetrieverAgent(os_client=fake)

    mem = WorkingMemory()
    mem.spans = [{"text": "anything", "line_refs": []}]
    mem.candidates = {}

    agent.run(mem, {"top_k": 5, "use_embedding_cache": False})

    query_bodies = [fake.last_body[i] for i in range(1, len(fake.last_body), 2)]
    # Existing behavior: max(top_k, 20)
    assert query_bodies[0]["size"] == 20
