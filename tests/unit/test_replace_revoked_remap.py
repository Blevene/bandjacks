"""Tests that BatchMapperAgent and DiscoveryAgent remap revoked TIDs
to their replacement when `replace_revoked=True`, and drop otherwise."""

import json
from unittest.mock import MagicMock, patch

from bandjacks.llm.mapper_optimized import BatchMapperAgent
from bandjacks.llm.memory import WorkingMemory
from bandjacks.services.technique_cache import technique_cache


def _stub_cache(active=(), revoked_with_replacement=()):
    technique_cache._cache.clear()
    for tid in active:
        technique_cache._cache[tid] = {
            "external_id": tid, "name": tid, "description": "",
            "is_subtechnique": False, "platforms": [], "tactics": [],
            "tactic": None, "revoked": False, "deprecated": False,
            "replacement": None,
        }
    for revoked_tid, replacement_tid in revoked_with_replacement:
        technique_cache._cache[revoked_tid] = {
            "external_id": revoked_tid, "name": revoked_tid, "description": "",
            "is_subtechnique": False, "platforms": [], "tactics": [],
            "tactic": None, "revoked": True, "deprecated": False,
            "replacement": replacement_tid,
        }
    technique_cache._loaded = True


def _llm_response(items):
    return {
        "content": json.dumps({"techniques": items}),
        "usage": {"prompt_tokens": 0, "completion_tokens": 0},
        "finish_reason": "stop",
    }


@patch("bandjacks.llm.mapper_optimized.get_llm_client")
def test_mapper_remaps_revoked_when_flag_on(mock_get_client):
    """T1128 (revoked) → T1546.007 (active) when replace_revoked=True."""
    _stub_cache(
        active=["T1546.007"],
        revoked_with_replacement=[("T1128", "T1546.007")],
    )
    client = MagicMock()
    client.call.return_value = _llm_response(
        [{"span": 0, "tid": "T1128", "conf": 80}]
    )
    mock_get_client.return_value = client

    mem = WorkingMemory()
    mem.spans = [{"text": "netsh helper dll", "line_refs": []}]
    mem.candidates = {0: []}
    mem.line_index = []

    BatchMapperAgent().run(
        mem,
        {
            "mapper_batch_size": 8,
            "enable_dynamic_batching": False,
            "replace_revoked": True,
        },
    )

    tids = [c["external_id"] for c in mem.claims]
    assert tids == ["T1546.007"], f"expected remap to T1546.007; got {tids}"


@patch("bandjacks.llm.mapper_optimized.get_llm_client")
def test_mapper_drops_revoked_when_flag_off(mock_get_client):
    """Default behavior unchanged: revoked TIDs dropped, replacement ignored."""
    _stub_cache(
        active=["T1546.007"],
        revoked_with_replacement=[("T1128", "T1546.007")],
    )
    client = MagicMock()
    client.call.return_value = _llm_response(
        [{"span": 0, "tid": "T1128", "conf": 80}]
    )
    mock_get_client.return_value = client

    mem = WorkingMemory()
    mem.spans = [{"text": "x", "line_refs": []}]
    mem.candidates = {0: []}
    mem.line_index = []

    BatchMapperAgent().run(
        mem,
        {
            "mapper_batch_size": 8,
            "enable_dynamic_batching": False,
            # replace_revoked omitted -> default False
        },
    )

    assert mem.claims == [], f"expected empty claims; got {[c['external_id'] for c in mem.claims]}"


@patch("bandjacks.llm.mapper_optimized.get_llm_client")
def test_mapper_drops_when_no_replacement_even_with_flag(mock_get_client):
    """T1024 revoked with no successor -> drop, even with replace_revoked=True."""
    technique_cache._cache.clear()
    technique_cache._cache["T1024"] = {
        "external_id": "T1024", "name": "T1024", "description": "",
        "is_subtechnique": False, "platforms": [], "tactics": [],
        "tactic": None, "revoked": True, "deprecated": False,
        "replacement": None,  # No successor
    }
    technique_cache._loaded = True

    client = MagicMock()
    client.call.return_value = _llm_response(
        [{"span": 0, "tid": "T1024", "conf": 80}]
    )
    mock_get_client.return_value = client

    mem = WorkingMemory()
    mem.spans = [{"text": "x", "line_refs": []}]
    mem.candidates = {0: []}
    mem.line_index = []

    BatchMapperAgent().run(
        mem,
        {
            "mapper_batch_size": 8,
            "enable_dynamic_batching": False,
            "replace_revoked": True,
        },
    )

    assert mem.claims == [], "revoked TID with no replacement must still drop"


@patch("bandjacks.llm.mapper_optimized.get_llm_client")
def test_remap_increments_counter(mock_get_client):
    """Each remap should bump tracker.counters['batchmapper_remapped']."""
    _stub_cache(
        active=["T1546.007"],
        revoked_with_replacement=[("T1128", "T1546.007")],
    )
    client = MagicMock()
    client.call.return_value = _llm_response(
        [{"span": 0, "tid": "T1128", "conf": 80}]
    )
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
            "replace_revoked": True,
            "_tracker": tracker,
        },
    )

    assert tracker.counters.get("batchmapper_remapped") == 1


@patch("bandjacks.llm.tools.resolve_technique_by_external_id")
@patch("bandjacks.llm.client.get_llm_client")
def test_discovery_remaps_revoked_when_flag_on(mock_get_client, mock_resolve):
    """DiscoveryAgent should remap revoked TIDs to their replacement before
    appending to mem.candidates when replace_revoked=True."""
    from bandjacks.llm.agents_v2 import DiscoveryAgent

    _stub_cache(
        active=["T1546.007"],
        revoked_with_replacement=[("T1128", "T1546.007")],
    )

    client = MagicMock()
    client.call.return_value = {
        "content": json.dumps(
            {"discoveries": [{"span": 0, "techniques": ["T1128"]}]}
        ),
        "usage": {"prompt_tokens": 0, "completion_tokens": 0},
        "finish_reason": "stop",
    }
    mock_get_client.return_value = client
    mock_resolve.return_value = {"name": "Replacement Technique", "tactic": "persistence"}

    mem = WorkingMemory()
    mem.spans = [{"text": "x", "line_refs": []}]
    mem.candidates = {}

    DiscoveryAgent().run(mem, {"max_discovery_per_span": 3, "replace_revoked": True})

    cand_ids = [c["external_id"] for c in mem.candidates.get(0, [])]
    assert cand_ids == ["T1546.007"], (
        f"DiscoveryAgent should have remapped T1128 -> T1546.007; got {cand_ids}"
    )
    # The resolver gets called for the REPLACEMENT, not the revoked TID
    resolved_tids = [call.args[0] for call in mock_resolve.call_args_list]
    assert resolved_tids == ["T1546.007"]


@patch("bandjacks.llm.tools.resolve_technique_by_external_id")
@patch("bandjacks.llm.client.get_llm_client")
def test_discovery_dedupes_when_replacement_already_present(
    mock_get_client, mock_resolve,
):
    """If the LLM emits both T1128 (revoked->T1546.007) and T1546.007 directly,
    the remap path must not double-add T1546.007."""
    from bandjacks.llm.agents_v2 import DiscoveryAgent

    _stub_cache(
        active=["T1546.007"],
        revoked_with_replacement=[("T1128", "T1546.007")],
    )

    client = MagicMock()
    client.call.return_value = {
        "content": json.dumps(
            {"discoveries": [{"span": 0, "techniques": ["T1546.007", "T1128"]}]}
        ),
        "usage": {"prompt_tokens": 0, "completion_tokens": 0},
        "finish_reason": "stop",
    }
    mock_get_client.return_value = client
    mock_resolve.return_value = {"name": "x", "tactic": "x"}

    mem = WorkingMemory()
    mem.spans = [{"text": "x", "line_refs": []}]
    mem.candidates = {}

    DiscoveryAgent().run(mem, {"max_discovery_per_span": 3, "replace_revoked": True})

    cand_ids = [c["external_id"] for c in mem.candidates.get(0, [])]
    assert cand_ids == ["T1546.007"], (
        f"replacement T1546.007 should appear exactly once; got {cand_ids}"
    )
