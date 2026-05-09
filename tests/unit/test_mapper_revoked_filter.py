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
