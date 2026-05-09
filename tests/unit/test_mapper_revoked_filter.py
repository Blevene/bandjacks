"""Tests that BatchMapperAgent and DiscoveryAgent drop revoked TIDs.

Defense-in-depth: even with the KNN must_not filter (Patch 1), the LLM
can emit revoked TIDs from training-data memorization. The output-side
filter ensures none reach mem.claims or mem.candidates.
"""

import json
from unittest.mock import MagicMock, patch

from bandjacks.llm.mapper_optimized import BatchMapperAgent
from bandjacks.llm.memory import WorkingMemory
from bandjacks.services.technique_cache import technique_cache


def _stub_cache(active=(), revoked=()):
    technique_cache._cache.clear()
    for tid in active:
        technique_cache._cache[tid] = {
            "external_id": tid, "name": tid, "description": "",
            "is_subtechnique": False, "platforms": [], "tactics": [],
            "tactic": None, "revoked": False, "deprecated": False,
        }
    for tid in revoked:
        technique_cache._cache[tid] = {
            "external_id": tid, "name": tid, "description": "",
            "is_subtechnique": False, "platforms": [], "tactics": [],
            "tactic": None, "revoked": True, "deprecated": False,
        }
    technique_cache._loaded = True


def _llm_response(items):
    return {
        "content": json.dumps({"techniques": items}),
        "usage": {"prompt_tokens": 0, "completion_tokens": 0},
    }


@patch("bandjacks.llm.mapper_optimized.get_llm_client")
def test_revoked_tid_dropped(mock_get_client):
    _stub_cache(active=["T1059"], revoked=["T1128"])
    client = MagicMock()
    client.call.return_value = _llm_response(
        [
            {"span": 0, "tid": "T1128", "conf": 80},
            {"span": 0, "tid": "T1059", "conf": 80},
        ]
    )
    mock_get_client.return_value = client

    mem = WorkingMemory()
    mem.spans = [{"text": "powershell -enc ...", "line_refs": []}]
    mem.candidates = {0: []}
    mem.line_index = []

    BatchMapperAgent().run(
        mem, {"mapper_batch_size": 8, "enable_dynamic_batching": False}
    )

    tids = [c["external_id"] for c in mem.claims]
    assert "T1059" in tids
    assert "T1128" not in tids


@patch("bandjacks.llm.mapper_optimized.get_llm_client")
def test_active_tid_kept_when_unknown_to_cache(mock_get_client):
    """An LLM-emitted TID not in the cache (e.g., very new) must NOT be dropped."""
    _stub_cache(active=["T1059"], revoked=["T1128"])  # T9999 not in cache
    client = MagicMock()
    client.call.return_value = _llm_response(
        [
            {"span": 0, "tid": "T9999", "conf": 80},
            {"span": 0, "tid": "T1128", "conf": 80},
        ]
    )
    mock_get_client.return_value = client

    mem = WorkingMemory()
    mem.spans = [{"text": "x", "line_refs": []}]
    mem.candidates = {0: []}
    mem.line_index = []

    BatchMapperAgent().run(
        mem, {"mapper_batch_size": 8, "enable_dynamic_batching": False}
    )

    tids = [c["external_id"] for c in mem.claims]
    assert "T9999" in tids       # unknown stays
    assert "T1128" not in tids   # revoked dropped


@patch("bandjacks.llm.mapper_optimized.get_llm_client")
def test_truncation_logged_and_counted(mock_get_client, caplog):
    """finish_reason=length triggers a warning + tracker counter increment."""
    _stub_cache(active=["T1059"], revoked=[])
    client = MagicMock()
    client.call.return_value = {
        "content": '{"techniques": [{"span": 0, "tid": "T1059", "conf": 80}]}',
        "usage": {"prompt_tokens": 0, "completion_tokens": 0},
        "finish_reason": "length",
    }
    mock_get_client.return_value = client

    from bandjacks.llm.tracker import ExtractionTracker
    tracker = ExtractionTracker()

    mem = WorkingMemory()
    mem.spans = [{"text": "x", "line_refs": []}]
    mem.candidates = {0: []}
    mem.line_index = []

    with caplog.at_level("WARNING"):
        BatchMapperAgent().run(
            mem,
            {
                "mapper_batch_size": 8,
                "enable_dynamic_batching": False,
                "_tracker": tracker,
            },
        )

    assert any("truncated by token limit" in r.message for r in caplog.records)
    assert tracker.counters.get("batchmapper_truncated") == 1


@patch("bandjacks.llm.mapper_optimized.get_llm_client")
def test_parse_failure_counted(mock_get_client):
    """An unparseable response increments the parse-failed counter."""
    _stub_cache(active=["T1059"], revoked=[])
    client = MagicMock()
    client.call.return_value = {
        "content": '{"techniques": [{"span": 0, "tid": "T1059", "conf": 80',  # truncated, no closing
        "usage": {"prompt_tokens": 0, "completion_tokens": 0},
    }
    mock_get_client.return_value = client

    from bandjacks.llm.tracker import ExtractionTracker
    tracker = ExtractionTracker()

    mem = WorkingMemory()
    mem.spans = [{"text": "x", "line_refs": []}]
    mem.candidates = {0: []}
    mem.line_index = []

    BatchMapperAgent().run(
        mem,
        {
            "mapper_batch_size": 8,
            "enable_dynamic_batching": False,
            "_tracker": tracker,
        },
    )

    assert tracker.counters.get("batchmapper_parse_failed") == 1


@patch("bandjacks.llm.mapper_optimized.get_llm_client")
def test_max_batch_cap_clamps_actual_batch_size(mock_get_client, monkeypatch):
    """End-to-end: with 25 spans and MAX_MAPPER_BATCH_SIZE unset, the LLM
    must receive batches of at most 10 spans (the new default cap)."""
    monkeypatch.delenv("MAX_MAPPER_BATCH_SIZE", raising=False)
    _stub_cache(active=["T1059"], revoked=[])

    captured_batch_sizes = []

    def _capture(messages, **kwargs):
        # Parse the user message to count spans in this batch
        user_msg = next(m for m in messages if m["role"] == "user")
        # The body is "Process these N spans:\n\n[..." — extract N
        first_line = user_msg["content"].split("\n", 1)[0]
        # "Process these 10 spans:" -> 10
        n = int(first_line.split()[2])
        captured_batch_sizes.append(n)
        return _llm_response([])

    client = MagicMock()
    client.call.side_effect = _capture
    mock_get_client.return_value = client

    mem = WorkingMemory()
    mem.spans = [{"text": f"span {i}", "line_refs": []} for i in range(25)]
    mem.candidates = {i: [] for i in range(25)}
    mem.line_index = []

    BatchMapperAgent().run(
        mem,
        # Request batch_size=20 to ensure the cap (not the request) governs.
        {"mapper_batch_size": 20, "enable_dynamic_batching": False},
    )

    assert captured_batch_sizes, "BatchMapper should have called the LLM"
    assert max(captured_batch_sizes) <= 10, (
        f"All batches must be <=10 (got {captured_batch_sizes}); "
        f"the MAX_MAPPER_BATCH_SIZE cap is not being enforced."
    )


@patch("bandjacks.llm.tools.resolve_technique_by_external_id")
@patch("bandjacks.llm.client.get_llm_client")
def test_discovery_agent_drops_revoked(mock_get_client, mock_resolve):
    """DiscoveryAgent.run() must not append revoked TIDs to mem.candidates.

    Drives the real production path: stubs the LLM to emit one revoked + one
    active TID, runs DiscoveryAgent, asserts only the active one ends up in
    mem.candidates and that resolve_technique_by_external_id is NOT called
    for the revoked TID (it should be filtered before resolution).
    """
    from bandjacks.llm.agents_v2 import DiscoveryAgent

    _stub_cache(active=["T1059"], revoked=["T1128"])

    client = MagicMock()
    client.call.return_value = {
        "content": json.dumps(
            {"discoveries": [{"span": 0, "techniques": ["T1128", "T1059"]}]}
        ),
        "usage": {"prompt_tokens": 0, "completion_tokens": 0},
        "finish_reason": "stop",
    }
    mock_get_client.return_value = client
    mock_resolve.return_value = {"name": "Active Technique", "tactic": "execution"}

    mem = WorkingMemory()
    mem.spans = [{"text": "powershell -enc ...", "line_refs": []}]
    # Empty candidates so the span qualifies for discovery (line 316-317
    # of agents_v2.py skips spans that already have >=5 candidates with
    # any score >0.7).
    mem.candidates = {}

    DiscoveryAgent().run(mem, {"max_discovery_per_span": 3})

    cand_ids = [c["external_id"] for c in mem.candidates.get(0, [])]
    assert "T1059" in cand_ids, f"active T1059 should be appended; got {cand_ids}"
    assert "T1128" not in cand_ids, (
        f"revoked T1128 should be filtered before resolution; got {cand_ids}"
    )
    # The resolver should only be called for the active TID — proves the
    # filter runs *before* resolution.
    resolved_tids = [call.args[0] for call in mock_resolve.call_args_list]
    assert "T1128" not in resolved_tids, (
        "resolve_technique_by_external_id was called for a revoked TID; "
        "the filter should short-circuit before resolution"
    )
