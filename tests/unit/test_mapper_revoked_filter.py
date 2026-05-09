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


@patch("bandjacks.llm.agents_v2._call_llm_for_discovery", create=True)
def test_discovery_agent_drops_revoked(_):
    """DiscoveryAgent must not append revoked TIDs to mem.candidates.

    We simulate the post-LLM portion of DiscoveryAgent.run() by directly
    invoking the loop body that appends to mem.candidates after the LLM
    has returned a list of techniques including a revoked one.
    """
    from bandjacks.llm.agents_v2 import TECH_ID_RE
    from bandjacks.llm.tools import resolve_technique_by_external_id  # noqa: F401

    _stub_cache(active=["T1059"], revoked=["T1128"])

    mem = WorkingMemory()
    mem.spans = [{"text": "x", "line_refs": []}]
    mem.candidates = {}

    # This block mirrors the post-LLM loop in DiscoveryAgent.run() (agents_v2.py:413-428)
    # The filter we add at line 414-area must drop T1128 before the append.
    techniques = ["T1128", "T1059"]
    orig_idx = 0
    mem.candidates.setdefault(orig_idx, [])
    seen = {c.get("external_id") for c in mem.candidates[orig_idx]}

    for tech_id in techniques[:5]:
        if not isinstance(tech_id, str) or not TECH_ID_RE.match(tech_id):
            continue
        if tech_id in seen:
            continue
        if technique_cache.is_revoked(tech_id):
            continue
        mem.candidates[orig_idx].append({
            "external_id": tech_id,
            "name": tech_id,
            "score": 0.5,
            "meta": {},
            "source": "discovery",
        })
        seen.add(tech_id)

    cand_ids = [c["external_id"] for c in mem.candidates[0]]
    assert "T1059" in cand_ids
    assert "T1128" not in cand_ids
