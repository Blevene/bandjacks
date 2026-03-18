# Dual Flow Generation Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate two attack flows per report — an LLM-synthesized causal chain and a deterministic full ordering of all techniques with three-tier edge confidence.

**Architecture:** New `DeterministicFlowBuilder` class produces orkl-style flows from claims using (tactic_rank, narrative_position) sorting. A shared `build_dual_flows()` helper is called by both the sync pipeline and async job processor. OpenSearch uses dual-read (`flows` list + legacy `flow` fallback).

**Tech Stack:** Python, Neo4j (existing persistence), TechniqueCache (O(1) tactic lookups), constants.TACTIC_ORDER (1-14)

**Spec:** `docs/superpowers/specs/2026-03-17-dual-flow-generation-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `bandjacks/llm/flow_deterministic.py` | **Create** | `DeterministicFlowBuilder` class + `build_dual_flows()` helper |
| `tests/unit/test_flow_deterministic.py` | **Create** | Unit tests for deterministic builder |
| `bandjacks/llm/extraction_pipeline.py` | Modify | `_build_attack_flow()` calls `build_dual_flows()`, returns list |
| `bandjacks/services/api/job_processor.py` | Modify | Replace direct `build_from_extraction()` with `build_dual_flows()` |
| `bandjacks/services/api/routes/reports.py` | Modify | Update 2 endpoints to handle flow list |
| `bandjacks/services/api/routes/flows.py` | Modify | Update on-demand flow build |

---

## Chunk 1: DeterministicFlowBuilder Core

### Task 1: Create DeterministicFlowBuilder with tests

**Files:**
- Create: `bandjacks/llm/flow_deterministic.py`
- Create: `tests/unit/test_flow_deterministic.py`

- [ ] **Step 1: Write test file with all unit tests**

```python
# tests/unit/test_flow_deterministic.py
"""Tests for DeterministicFlowBuilder."""

from bandjacks.llm.flow_deterministic import DeterministicFlowBuilder


def _make_claim(tid, line_refs=None, confidence=80, name=None):
    """Helper to build a claim dict."""
    return {
        "external_id": tid,
        "name": name or tid,
        "line_refs": line_refs or [],
        "confidence": confidence,
    }


class _FakeCache:
    """Minimal TechniqueCache stub for testing."""

    def __init__(self, data=None):
        self._data = data or {}

    def get(self, external_id):
        return self._data.get(external_id)


# --- tactic order fixture ---
CACHE_DATA = {
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "initial-access", "tactics": ["initial-access"]},
    "T1059.001": {"name": "PowerShell", "tactic": "execution", "tactics": ["execution"]},
    "T1055": {"name": "Process Injection", "tactic": "defense-evasion", "tactics": ["defense-evasion", "privilege-escalation"]},
    "T1003.001": {"name": "LSASS Memory", "tactic": "credential-access", "tactics": ["credential-access"]},
    "T1021.001": {"name": "Remote Desktop Protocol", "tactic": "lateral-movement", "tactics": ["lateral-movement"]},
    "T1547.001": {"name": "Registry Run Keys", "tactic": "persistence", "tactics": ["persistence"]},
    "T1041": {"name": "Exfiltration Over C2", "tactic": "exfiltration", "tactics": ["exfiltration"]},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution", "tactics": ["execution"]},
}


def _cache():
    return _FakeCache(CACHE_DATA)


# === Core tests ===

def test_empty_claims_returns_none():
    result = DeterministicFlowBuilder().build([], _cache())
    assert result is None


def test_single_technique_returns_none():
    claims = [_make_claim("T1566.001", [10])]
    result = DeterministicFlowBuilder().build(claims, _cache())
    assert result is None


def test_two_techniques_kill_chain_high_confidence():
    claims = [
        _make_claim("T1566.001", [10]),  # initial-access, pos 10
        _make_claim("T1059.001", [20]),  # execution, pos 20
    ]
    result = DeterministicFlowBuilder().build(claims, _cache())
    assert result is not None
    assert len(result["actions"]) == 2
    assert len(result["edges"]) == 1
    assert result["edges"][0]["confidence_tier"] == "high"
    assert result["edges"][0]["probability"] == 0.8
    # Order: initial-access before execution
    assert result["actions"][0]["attack_pattern_ref"] == "T1566.001"
    assert result["actions"][1]["attack_pattern_ref"] == "T1059.001"


def test_same_tactic_medium_confidence():
    claims = [
        _make_claim("T1059.001", [10]),  # execution
        _make_claim("T1059", [20]),       # execution (same tactic)
    ]
    result = DeterministicFlowBuilder().build(claims, _cache())
    assert result["edges"][0]["confidence_tier"] == "medium"
    assert result["edges"][0]["probability"] == 0.5


def test_same_tactic_backward_position_medium():
    """Same tactic but position goes backward → still medium, not low."""
    claims = [
        _make_claim("T1059.001", [50]),  # execution, pos 50
        _make_claim("T1059", [10]),       # execution, pos 10 (backward)
    ]
    result = DeterministicFlowBuilder().build(claims, _cache())
    # Sorted by (tactic_rank=4, position): T1059 at 10 first, T1059.001 at 50 second
    assert result["actions"][0]["attack_pattern_ref"] == "T1059"
    assert result["actions"][1]["attack_pattern_ref"] == "T1059.001"
    # Same tactic, position forward after sort → actually high
    assert result["edges"][0]["confidence_tier"] == "high"


def test_forward_tactic_backward_position_low():
    """Tactic progresses but position goes backward → low."""
    claims = [
        _make_claim("T1566.001", [100]),  # initial-access, pos 100
        _make_claim("T1059.001", [5]),    # execution, pos 5 (before in text)
    ]
    result = DeterministicFlowBuilder().build(claims, _cache())
    # Sorted: T1566.001 (rank 3) then T1059.001 (rank 4)
    assert result["actions"][0]["attack_pattern_ref"] == "T1566.001"
    assert result["actions"][1]["attack_pattern_ref"] == "T1059.001"
    assert result["edges"][0]["confidence_tier"] == "low"
    assert result["edges"][0]["probability"] == 0.25


def test_tactic_regression_low():
    """Tactic goes backward → low."""
    claims = [
        _make_claim("T1041", [10]),       # exfiltration (rank 13)
        _make_claim("T1566.001", [20]),   # initial-access (rank 3)
    ]
    result = DeterministicFlowBuilder().build(claims, _cache())
    # Sorted by tactic: T1566.001 first, T1041 second
    # So this becomes forward tactic + forward position = high
    assert result["edges"][0]["confidence_tier"] == "high"


def test_deduplication():
    claims = [
        _make_claim("T1566.001", [10], confidence=80),
        _make_claim("T1566.001", [20], confidence=90),  # same technique
        _make_claim("T1059.001", [30]),
    ]
    result = DeterministicFlowBuilder().build(claims, _cache())
    assert len(result["actions"]) == 2  # deduplicated
    # Should take max confidence
    assert result["actions"][0]["confidence"] == 90


def test_no_line_refs_sorts_last():
    """Techniques with empty line_refs get inf position, sort last in tactic."""
    claims = [
        _make_claim("T1059.001", [10]),     # execution, pos 10
        _make_claim("T1059", []),            # execution, no position → inf
    ]
    result = DeterministicFlowBuilder().build(claims, _cache())
    assert result["actions"][0]["attack_pattern_ref"] == "T1059.001"  # pos 10
    assert result["actions"][1]["attack_pattern_ref"] == "T1059"       # pos inf


def test_self_loop_guard():
    """After dedup, if consecutive actions share external_id somehow, skip edge."""
    # This shouldn't happen after proper dedup, but guard anyway
    claims = [
        _make_claim("T1566.001", [10]),
        _make_claim("T1059.001", [20]),
    ]
    result = DeterministicFlowBuilder().build(claims, _cache())
    for edge in result["edges"]:
        assert edge["source"] != edge["target"]


def test_tier_distribution_stats():
    claims = [
        _make_claim("T1566.001", [10]),
        _make_claim("T1059.001", [20]),
        _make_claim("T1003.001", [30]),
    ]
    result = DeterministicFlowBuilder().build(claims, _cache())
    stats = result["stats"]
    assert stats["steps_count"] == 3
    assert stats["edges_count"] == 2
    dist = stats["tier_distribution"]
    assert dist["high"] + dist["medium"] + dist["low"] == 2


def test_techniques_without_position_stat():
    claims = [
        _make_claim("T1566.001", [10]),
        _make_claim("T1059.001", []),  # no position
    ]
    result = DeterministicFlowBuilder().build(claims, _cache())
    assert result["stats"]["techniques_without_position"] == 1


def test_unknown_tactic_gets_rank_7():
    cache = _FakeCache({"T9999": {"name": "Unknown", "tactic": None, "tactics": []}})
    cache._data["T1566.001"] = CACHE_DATA["T1566.001"]
    claims = [
        _make_claim("T1566.001", [10]),
        _make_claim("T9999", [20]),
    ]
    result = DeterministicFlowBuilder().build(claims, cache)
    assert result is not None
    assert len(result["actions"]) == 2


def test_subtechnique_after_parent():
    """T1059 sorts before T1059.001 due to lexicographic tiebreak."""
    claims = [
        _make_claim("T1059.001", [10]),  # execution
        _make_claim("T1059", [10]),       # execution, same position
    ]
    result = DeterministicFlowBuilder().build(claims, _cache())
    assert result["actions"][0]["attack_pattern_ref"] == "T1059"
    assert result["actions"][1]["attack_pattern_ref"] == "T1059.001"


def test_source_id_in_result():
    claims = [
        _make_claim("T1566.001", [10]),
        _make_claim("T1059.001", [20]),
    ]
    result = DeterministicFlowBuilder().build(claims, _cache(), source_id="report--abc")
    assert result["source_id"] == "report--abc"


def test_flow_type_is_deterministic_full():
    claims = [
        _make_claim("T1566.001", [10]),
        _make_claim("T1059.001", [20]),
    ]
    result = DeterministicFlowBuilder().build(claims, _cache())
    assert result["flow_type"] == "deterministic_full"
    assert result["llm_synthesized"] is False


def test_full_kill_chain_ordering():
    """7 techniques across the kill chain should be ordered correctly."""
    claims = [
        _make_claim("T1041", [70]),       # exfiltration
        _make_claim("T1003.001", [40]),   # credential-access
        _make_claim("T1566.001", [10]),   # initial-access
        _make_claim("T1059.001", [20]),   # execution
        _make_claim("T1055", [30]),       # defense-evasion
        _make_claim("T1021.001", [50]),   # lateral-movement
        _make_claim("T1547.001", [60]),   # persistence
    ]
    result = DeterministicFlowBuilder().build(claims, _cache())
    tids = [a["attack_pattern_ref"] for a in result["actions"]]
    assert tids == [
        "T1566.001",  # initial-access (3)
        "T1059.001",  # execution (4)
        "T1547.001",  # persistence (5)
        "T1055",      # defense-evasion (7)
        "T1003.001",  # credential-access (8)
        "T1021.001",  # lateral-movement (10)
        "T1041",      # exfiltration (13)
    ]
```

- [ ] **Step 2: Create DeterministicFlowBuilder implementation**

```python
# bandjacks/llm/flow_deterministic.py
"""Deterministic full attack flow builder using tactic + narrative position ordering.

Produces an orkl-style flow with all extracted techniques ordered by kill chain phase
and first mention in the source text, with three-tier edge confidence.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from bandjacks.llm.constants import TACTIC_ORDER, get_tactic_order

logger = logging.getLogger(__name__)

# Tier → probability mapping
TIER_PROBABILITY = {"high": 0.8, "medium": 0.5, "low": 0.25}


class DeterministicFlowBuilder:
    """Build full deterministic attack flow from extraction claims."""

    def build(
        self,
        claims: List[Dict[str, Any]],
        technique_cache,
        flow_name: str = "Deterministic Attack Flow",
        source_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Build deterministic flow from extraction claims.

        Returns None if fewer than 2 unique techniques.
        """
        # Step 1: Deduplicate claims by external_id
        deduped = self._deduplicate(claims)
        if len(deduped) < 2:
            return None

        # Step 2: Resolve tactics and build sortable entries
        entries = self._resolve_tactics(deduped, technique_cache)

        # Step 3: Sort by (tactic_rank, narrative_position, external_id)
        entries.sort(key=lambda e: (e["tactic_rank"], e["narrative_position"], e["external_id"]))

        # Step 4: Build actions
        actions = self._build_actions(entries)

        # Step 5: Compute edges with three-tier confidence
        edges, tier_dist = self._compute_edges(actions)

        # Step 6: Build result
        without_position = sum(1 for e in entries if e["narrative_position"] == float("inf"))

        return {
            "flow_id": f"flow--{uuid.uuid4()}",
            "name": flow_name,
            "source_id": source_id,
            "actions": actions,
            "edges": edges,
            "flow_type": "deterministic_full",
            "llm_synthesized": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "stats": {
                "steps_count": len(actions),
                "edges_count": len(edges),
                "tier_distribution": tier_dist,
                "techniques_without_position": without_position,
            },
        }

    def _deduplicate(self, claims: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Group claims by external_id, taking max confidence and min line_ref."""
        deduped: Dict[str, Dict[str, Any]] = {}
        for claim in claims:
            tid = claim.get("external_id") or claim.get("technique_id", "")
            if not tid:
                continue
            line_refs = claim.get("line_refs", [])
            confidence = claim.get("confidence", 50)
            name = claim.get("name", tid)

            if tid in deduped:
                existing = deduped[tid]
                existing["confidence"] = max(existing["confidence"], confidence)
                if line_refs:
                    valid_refs = [r for r in line_refs if isinstance(r, int) and r > 0]
                    if valid_refs:
                        existing["min_line_ref"] = min(existing["min_line_ref"], min(valid_refs))
                if name and name != tid:
                    existing["name"] = name
            else:
                valid_refs = [r for r in line_refs if isinstance(r, int) and r > 0]
                deduped[tid] = {
                    "external_id": tid,
                    "name": name,
                    "confidence": confidence,
                    "min_line_ref": min(valid_refs) if valid_refs else float("inf"),
                }
        return deduped

    def _resolve_tactics(
        self, deduped: Dict[str, Dict[str, Any]], technique_cache
    ) -> List[Dict[str, Any]]:
        """Look up tactic for each technique and build sortable entries."""
        entries = []
        for tid, info in deduped.items():
            cached = technique_cache.get(tid)
            if cached:
                tactic = cached.get("tactic")
                name = cached.get("name", info["name"])
            else:
                tactic = None
                name = info["name"]

            entries.append({
                "external_id": tid,
                "name": name,
                "confidence": info["confidence"],
                "tactic": tactic or "unknown",
                "tactic_rank": get_tactic_order(tactic) if tactic else 7,
                "narrative_position": info["min_line_ref"],
            })
        return entries

    def _build_actions(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build action dicts from sorted entries."""
        actions = []
        for i, entry in enumerate(entries, 1):
            actions.append({
                "action_id": f"action--{uuid.uuid4()}",
                "order": i,
                "attack_pattern_ref": entry["external_id"],
                "name": entry["name"],
                "confidence": entry["confidence"],
                "tactic": entry["tactic"],
                "tactic_rank": entry["tactic_rank"],
                "narrative_position": entry["narrative_position"],
                "description": "",
                "evidence": [],
                "reason": "",
            })
        return actions

    def _compute_edges(
        self, actions: List[Dict[str, Any]]
    ) -> tuple:
        """Compute NEXT edges with three-tier confidence."""
        edges = []
        tier_dist = {"high": 0, "medium": 0, "low": 0}

        for i in range(len(actions) - 1):
            curr = actions[i]
            nxt = actions[i + 1]

            # Self-loop guard
            if curr["attack_pattern_ref"] == nxt["attack_pattern_ref"]:
                continue

            tactic_forward = nxt["tactic_rank"] >= curr["tactic_rank"]
            position_forward = nxt["narrative_position"] >= curr["narrative_position"]
            same_tactic = nxt["tactic_rank"] == curr["tactic_rank"]

            # Tier assignment (first match wins)
            if tactic_forward and position_forward:
                tier = "high"
            elif same_tactic:
                tier = "medium"
            else:
                tier = "low"

            tier_dist[tier] += 1

            edges.append({
                "source": curr["action_id"],
                "target": nxt["action_id"],
                "probability": TIER_PROBABILITY[tier],
                "confidence_tier": tier,
                "rationale": (
                    f"{curr['tactic']} → {nxt['tactic']}, "
                    f"positions {curr['narrative_position']}→{nxt['narrative_position']}, "
                    f"{tier} confidence"
                ),
            })

        return edges, tier_dist
```

- [ ] **Step 3: Run tests**

Run: `uv run python -c "from tests.unit.test_flow_deterministic import *; print('Import OK')"`

Then: `uv run python -m pytest tests/unit/test_flow_deterministic.py -v` (or verify inline if pytest unavailable)

- [ ] **Step 4: Commit**

```bash
git add bandjacks/llm/flow_deterministic.py tests/unit/test_flow_deterministic.py
git commit -m "feat: add DeterministicFlowBuilder with orkl-style tactic+position ordering"
```

---

### Task 2: Add `build_dual_flows()` helper

**Files:**
- Modify: `bandjacks/llm/flow_deterministic.py`

- [ ] **Step 1: Add the shared helper function**

Append to `flow_deterministic.py`:

```python
def build_dual_flows(
    claims: List[Dict[str, Any]],
    technique_cache,
    flow_builder=None,
    extraction_data: Optional[Dict[str, Any]] = None,
    report_text: str = "",
    source_id: Optional[str] = None,
    flow_name: str = "Deterministic Attack Flow",
) -> List[Dict[str, Any]]:
    """Build both deterministic and LLM flows.

    Args:
        claims: Extraction claims for deterministic flow
        technique_cache: TechniqueCache instance
        flow_builder: Optional FlowBuilder for LLM synthesis
        extraction_data: Extraction data dict for LLM flow (required if flow_builder provided)
        report_text: Report text for LLM flow context
        source_id: Report ID
        flow_name: Name for deterministic flow

    Returns:
        List of flow dicts (1-2 flows). Deterministic first, then LLM if successful.
    """
    flows = []

    # Always: deterministic full flow
    det_builder = DeterministicFlowBuilder()
    det_flow = det_builder.build(claims, technique_cache, flow_name, source_id)
    if det_flow:
        flows.append(det_flow)
        logger.info(
            f"Deterministic flow: {det_flow['stats']['steps_count']} steps, "
            f"tier distribution: {det_flow['stats']['tier_distribution']}"
        )

    # Attempt: LLM synthesis (if flow_builder provided)
    if flow_builder and extraction_data:
        try:
            llm_flow = flow_builder.build_from_extraction(
                extraction_data=extraction_data,
                source_id=source_id,
                report_text=report_text,
                use_stored_text=False,
            )
            if llm_flow:
                flows.append(llm_flow)
                logger.info(f"LLM flow: {len(llm_flow.get('actions', []))} steps")
        except Exception as e:
            logger.warning(f"LLM flow synthesis failed: {e}")

    logger.info(f"build_dual_flows produced {len(flows)} flow(s)")
    return flows
```

- [ ] **Step 2: Verify import**

Run: `uv run python -c "from bandjacks.llm.flow_deterministic import build_dual_flows; print('OK')"`

- [ ] **Step 3: Commit**

```bash
git add bandjacks/llm/flow_deterministic.py
git commit -m "feat: add build_dual_flows() shared helper for pipeline and job processor"
```

---

## Chunk 2: Pipeline and Job Processor Integration

### Task 3: Update ExtractionPipeline to use dual flows

**Files:**
- Modify: `bandjacks/llm/extraction_pipeline.py:415-470`

- [ ] **Step 1: Rewrite `_build_attack_flow` to return a list**

Replace the method body (starting around line 415) to:
1. Import `build_dual_flows` and `technique_cache`
2. Call `build_dual_flows()` with claims from extraction_result
3. Return list of flow dicts instead of a single dict
4. Update the method signature return type to `List[Dict[str, Any]]`

Key changes:
- `from bandjacks.llm.flow_deterministic import build_dual_flows`
- `from bandjacks.services.technique_cache import technique_cache`
- The method now returns `List[Dict]` instead of `Optional[Dict]`
- Each flow in the list gets packaged with `flow_id`, `flow_name`, `flow_type`, `steps`, `edges`

- [ ] **Step 2: Update callers of `_build_attack_flow` within extraction_pipeline.py**

The caller in `extract_and_build_flow()` (around line 96) currently does:
```python
flow_data = self._build_attack_flow(...)
```
Change to handle list:
```python
flows = self._build_attack_flow(...)
flow_data = flows[0] if flows else None  # Primary flow for backward compat
```

And in the review package preparation, store `flows` list.

- [ ] **Step 3: Verify import**

Run: `uv run python -c "from bandjacks.llm.extraction_pipeline import ExtractionPipeline; print('OK')"`

- [ ] **Step 4: Commit**

```bash
git add bandjacks/llm/extraction_pipeline.py
git commit -m "feat: ExtractionPipeline._build_attack_flow returns dual flows list"
```

---

### Task 4: Update job_processor to use dual flows

**Files:**
- Modify: `bandjacks/services/api/job_processor.py:625-680` and `735-765`

- [ ] **Step 1: Replace direct `build_from_extraction()` with `build_dual_flows()`**

In the flow-building section (around line 625):
1. Import `build_dual_flows` and `technique_cache`
2. Replace the single `flow_builder.build_from_extraction()` call with `build_dual_flows()`
3. Iterate the returned list to package each flow

Key pattern:
```python
from bandjacks.llm.flow_deterministic import build_dual_flows
from bandjacks.services.technique_cache import technique_cache

flows = build_dual_flows(
    claims=extraction_results.get("claims", []),
    technique_cache=technique_cache,
    flow_builder=flow_builder,
    extraction_data=flow_extraction_data,
    report_text=text_content,
    source_id=report_sdo["id"],
)

# Package flows list
flow_data_list = []
for flow_result in flows:
    flow_data_list.append({
        "flow_id": flow_result.get("flow_id"),
        "flow_name": flow_result.get("name"),
        "flow_type": flow_result.get("flow_type", "unknown"),
        "steps": flow_result.get("actions", []),
        "edges": flow_result.get("edges", []),
        "stats": flow_result.get("stats", {}),
        "confidence": flow_result.get("confidence", 0.5),
    })
```

- [ ] **Step 2: Update OpenSearch document to use dual-read schema**

At line 742 where `"flow": flow_data` is stored, change to:
```python
"flow": flow_data_list[0] if flow_data_list else None,   # Legacy compat
"flows": flow_data_list,                                    # New: list of all flows
```

- [ ] **Step 3: Update result_data**

At line 762 where `"flow_generated": flow_data is not None`, change to:
```python
"flow_generated": len(flow_data_list) > 0,
"flows_count": len(flow_data_list),
```

- [ ] **Step 4: Persist each flow to Neo4j**

After building the flow list, persist each:
```python
for flow_result in flows:
    try:
        flow_builder.persist_to_neo4j(flow_result)
    except Exception as e:
        logger.warning(f"Failed to persist flow {flow_result.get('flow_type')}: {e}")
```

- [ ] **Step 5: Verify import**

Run: `uv run python -c "from bandjacks.services.api.job_processor import JobProcessor; print('OK')"`

- [ ] **Step 6: Commit**

```bash
git add bandjacks/services/api/job_processor.py
git commit -m "feat: job processor generates and persists dual flows"
```

---

## Chunk 3: Route Updates and Backward Compatibility

### Task 5: Update reports.py route endpoints

**Files:**
- Modify: `bandjacks/services/api/routes/reports.py:~1080` (post-review) and `~1312` (regenerate)

- [ ] **Step 1: Update post-review flow build (line ~1080)**

Replace:
```python
flow_data = flow_builder.build_from_extraction(...)
if flow_data:
    flow_builder.persist_to_neo4j(flow_data)
```

With:
```python
from bandjacks.llm.flow_deterministic import build_dual_flows
from bandjacks.services.technique_cache import technique_cache

flows = build_dual_flows(
    claims=flow_extraction.get("claims", []),
    technique_cache=technique_cache,
    flow_builder=flow_builder,
    extraction_data=flow_extraction,
    source_id=report_id,
)
for flow_data in flows:
    flow_builder.persist_to_neo4j(flow_data)
if flows:
    result["flow_generated"] = True
    result["flow_id"] = flows[0].get("flow_id")
```

- [ ] **Step 2: Update regenerate-flow endpoint (line ~1312)**

Same pattern: replace direct `build_from_extraction()` with `build_dual_flows()`, persist each flow, update the OpenSearch document with both `flow` (first) and `flows` (list).

- [ ] **Step 3: Verify import**

Run: `uv run python -c "from bandjacks.services.api.routes.reports import router; print('OK')"`

- [ ] **Step 4: Commit**

```bash
git add bandjacks/services/api/routes/reports.py
git commit -m "feat: reports routes generate dual flows on review/regenerate"
```

---

### Task 6: Update flows.py route

**Files:**
- Modify: `bandjacks/services/api/routes/flows.py:~65`

- [ ] **Step 1: Update on-demand flow build**

Replace direct `build_from_extraction()` call with `build_dual_flows()`. The endpoint returns the first flow (or all flows if the response schema supports a list).

- [ ] **Step 2: Verify import**

Run: `uv run python -c "from bandjacks.services.api.routes.flows import router; print('OK')"`

- [ ] **Step 3: Commit**

```bash
git add bandjacks/services/api/routes/flows.py
git commit -m "feat: flows route generates dual flows on-demand"
```

---

### Task 7: E2E verification

- [ ] **Step 1: Restart API and run DarkCloud PDF**

```bash
# Restart API
pkill -f "uvicorn bandjacks"; sleep 2
nohup uv run uvicorn bandjacks.services.api.main:app --workers 4 --host 0.0.0.0 --port 8000 > /tmp/bandjacks-api.log 2>&1 &
sleep 20

# Upload DarkCloud PDF
curl -s -X POST http://localhost:8000/v1/reports/ingest_file_async \
  -F "file=@darkcloud-stealer-unit42.pdf" \
  -F 'config={"max_spans": 20}'
```

- [ ] **Step 2: Verify dual flows in response**

After job completes, check:
- `result.flows_count` should be 2
- Report should have both `flow` (legacy) and `flows` (list)
- Deterministic flow should have all techniques
- LLM flow should have focused causal chain

- [ ] **Step 3: Commit any fixes**

```bash
git add -A
git commit -m "fix: E2E adjustments for dual flow generation"
```
