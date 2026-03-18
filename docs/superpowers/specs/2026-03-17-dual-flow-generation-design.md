# Dual Flow Generation: LLM Synthesis + Deterministic Full Ordering

## Goal

Generate two attack flows per report: a focused LLM-synthesized causal chain and a comprehensive deterministic ordering of all extracted techniques using tactic position and narrative position signals with three-tier edge confidence.

## Problem

The LLM synthesizer produces high-quality 5-15 step flows capturing the core narrative, but leaves 80%+ of extracted techniques unsequenced. Analysts need visibility into the full technique set ordered as an attack path, even at lower confidence.

## Solution

Every report produces two independent `AttackEpisode` nodes:

1. **LLM Flow** (`flow_type: "llm_synthesized"`) — Existing behavior unchanged. Focused causal chain with narrative reasoning.

2. **Deterministic Flow** (`flow_type: "deterministic_full"`) — All extracted techniques ordered by `(tactic_rank, min_line_ref)` with orkl-style three-tier edge confidence.

Both attach to the Report via `HAS_FLOW` relationships. No Neo4j schema changes required.

> **Note on existing `flow_type: "deterministic"`**: The old deterministic fallback (in `FlowBuilder._build_deterministic()`) used this value. It is superseded by `"deterministic_full"`. The old `_build_deterministic` method is deprecated but left in place for backward compatibility; it will not be called in the new flow.

## Architecture

### New module: `bandjacks/llm/flow_deterministic.py`

Single class with one public method. No Neo4j dependency, no LLM calls. Pure deterministic computation using `TechniqueCache` for O(1) tactic lookups.

```python
class DeterministicFlowBuilder:
    """Build full deterministic attack flow from extraction claims.

    Uses orkl-style two-signal ordering: tactic phase + narrative position.
    Assigns three-tier edge confidence based on signal agreement.
    """

    def build(
        self,
        claims: List[Dict[str, Any]],
        technique_cache: TechniqueCache,
        flow_name: str = "Deterministic Attack Flow",
        source_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Build deterministic flow from extraction claims.

        Args:
            claims: Extraction claims with external_id, line_refs, confidence.
                    Claims use external_id field (e.g. "T1566.001") matching
                    TechniqueCache keys.
            technique_cache: Loaded TechniqueCache for tactic lookups.
                    Access: cache.get(external_id)["tactic"] returns primary
                    tactic shortname, cache.get(external_id)["tactics"] returns
                    full list. Returns None for unknown techniques.
            flow_name: Name for the generated flow
            source_id: Optional report ID for attribution

        Returns:
            Flow dict with actions, edges (tier + probability), and stats.
            Returns None if fewer than 2 techniques after deduplication.
        """
```

### Algorithm

```
Input: claims[] (each has external_id, line_refs, confidence)

Step 1: Deduplicate
  - Group claims by external_id
  - For each technique: max(confidence), min(line_refs) as narrative_position
  - If line_refs is empty: assign narrative_position = float('inf')
    (technique sorts last within its tactic bucket, NOT dropped)
  - Skip self-loop: if consecutive actions after sort share the same
    external_id, skip the duplicate edge (don't create A→A)

Step 2: Resolve tactics
  - For each technique, look up via TechniqueCache:
      entry = technique_cache.get(external_id)
      tactic = entry["tactic"] if entry else None
  - Use primary tactic shortname for ordering
  - Map tactic shortname to rank via constants.TACTIC_ORDER (1-14, 1-based)
  - Techniques with unknown tactic get rank 7 (defense-evasion, middle)

Step 3: Sort
  - Primary key: tactic_rank (ascending, kill chain order)
  - Secondary key: narrative_position (ascending, first mention in text)
  - Tertiary key: external_id (lexicographic — ensures parent T1059 before
    sub-technique T1059.001 when tactic and position are equal)
  - Stable sort preserves extraction order as final tiebreaker

Step 4: Build actions
  - One action per technique
  - Return None if fewer than 2 techniques

  Action object:
  {
      "action_id": "action--{uuid4}",
      "order": int,                    # 1-based sequential
      "attack_pattern_ref": str,       # external_id (e.g., "T1566.001")
      "name": str,                     # technique name from cache
      "confidence": float,             # max confidence from extraction (0-100)
      "tactic": str,                   # resolved tactic shortname
      "tactic_rank": int,              # 1-14 from TACTIC_ORDER
      "narrative_position": int|float, # min line_ref or float('inf')
      "description": str,              # empty for deterministic flow
      "evidence": [],                  # empty — evidence is on the claims
      "reason": ""                     # empty — no causal reasoning
  }

Step 5: Compute edges with three-tier confidence

  First action: no incoming edge. Actions are not edges, so no tier needed.

  For each consecutive pair (action_i, action_i+1):
    # Skip self-loops
    if action_i.attack_pattern_ref == action_i+1.attack_pattern_ref:
        continue

    tactic_forward = action_i+1.tactic_rank >= action_i.tactic_rank
    position_forward = action_i+1.narrative_position >= action_i.narrative_position
    same_tactic = action_i+1.tactic_rank == action_i.tactic_rank

    Tier assignment (evaluated in order, first match wins):
      if tactic_forward AND position_forward:       → high   (both signals agree)
      elif same_tactic:                              → medium (within same phase)
      else:                                          → low    (signals disagree OR regression)

    This covers all cases:
    | tactic_forward | same_tactic | position_forward | Tier   |
    |----------------|-------------|------------------|--------|
    | True           | False       | True             | high   |
    | True           | True        | True             | high   |
    | True           | False       | False            | low    |
    | True           | True        | False            | medium |
    | False          | False       | True             | low    |
    | False          | False       | False            | low    |

    Note: same_tactic=True implies tactic_forward=True (rank equal → >=),
    so rows where same_tactic=True AND tactic_forward=False cannot occur.

    Probability mapping:
      high   → 0.8
      medium → 0.5
      low    → 0.25

    Rationale: "{tactic1} → {tactic2}, positions {pos1}→{pos2}, {tier} confidence"

Step 6: Build flow result
  Return dict:
  {
      "flow_id": "flow--{uuid4}",
      "name": flow_name,
      "source_id": source_id,
      "actions": [action objects from Step 4],
      "edges": [edge objects from Step 5],
      "flow_type": "deterministic_full",
      "llm_synthesized": False,
      "created_at": ISO timestamp,
      "stats": {
          "steps_count": int,
          "edges_count": int,
          "tier_distribution": {"high": N, "medium": N, "low": N},
          "techniques_without_position": int  # count with narrative_position=inf
      }
  }

  Note: flow_id is the only ID. No separate episode_id — the flow_id serves
  as the episode identifier when persisted to Neo4j.
```

### Pipeline integration

There are **two flow-building code paths** that both need updating:

**Path 1: `ExtractionPipeline._build_attack_flow()`** — used for sync processing and small documents.

**Path 2: `job_processor.py` (lines 635-680)** — used for async/chunked processing of large documents (PDFs). This path directly instantiates `FlowBuilder` and calls `build_from_extraction()` independently.

To avoid duplicating dual-flow logic, extract a shared helper:

```python
# In flow_deterministic.py or a new shared module:
def build_dual_flows(
    claims: List[Dict],
    technique_cache: TechniqueCache,
    flow_builder: FlowBuilder,
    extraction_data: Dict,
    report_text: str = "",
    source_id: Optional[str] = None,
    flow_name: str = "Deterministic Attack Flow",
) -> List[Dict[str, Any]]:
    """Build both deterministic and LLM flows. Returns list of flows."""
    flows = []

    # Always: deterministic full flow
    det_builder = DeterministicFlowBuilder()
    det_flow = det_builder.build(claims, technique_cache, flow_name, source_id)
    if det_flow:
        flows.append(det_flow)

    # Attempt: LLM synthesis
    try:
        llm_flow = flow_builder.build_from_extraction(
            extraction_data, source_id, report_text, use_stored_text=False
        )
        if llm_flow:
            flows.append(llm_flow)
    except Exception as e:
        logger.warning(f"LLM flow synthesis failed: {e}")

    return flows
```

Both `ExtractionPipeline._build_attack_flow()` and `job_processor.py` call `build_dual_flows()`.

### Caller migration

All callers of `build_from_extraction` or `_build_attack_flow` must be updated:

| Caller | File | Current | Change |
|--------|------|---------|--------|
| `_build_attack_flow()` | `extraction_pipeline.py:430` | Returns single dict | Call `build_dual_flows()`, return list |
| Job processor flow build | `job_processor.py:651` | Calls `build_from_extraction()` directly | Call `build_dual_flows()`, iterate list |
| Post-review flow rebuild | `routes/reports.py:~1080` | Calls `build_from_extraction()` | Call `build_dual_flows()`, persist each |
| Regenerate-flow endpoint | `routes/reports.py:~1312` | Calls `build_from_extraction()` | Call `build_dual_flows()`, persist each |
| On-demand flow build | `routes/flows.py:~65` | Calls `build_from_extraction()` | Call `build_dual_flows()`, persist each |

### Backward compatibility and OpenSearch schema

The OpenSearch report document currently stores `extraction.flow` (single dict). This changes:

**Strategy: dual-read with migration**

1. **Write path**: New reports store `extraction.flows` (list of flow dicts). Also write `extraction.flow` as the first flow for backward compat.

2. **Read path**: Check `extraction.flows` first. If absent, fall back to `extraction.flow` (wrap in list). This handles existing documents without migration.

3. **Job result**: `result.flow_generated` becomes `result.flows_generated: int` (count of flows). Existing consumers checking truthiness still work since `int > 0` is truthy.

4. **Report summary**: `has_flow` computed from `bool(extraction.get("flows") or extraction.get("flow"))`.

No OpenSearch index schema change needed (the `flows` field is just a different key in the JSON document).

### Edge data model

```python
# Deterministic flow edge:
{
    "source": "action--uuid",
    "target": "action--uuid",
    "probability": 0.8,
    "confidence_tier": "high",
    "rationale": "initial-access → execution, positions 142→289, high confidence"
}

# LLM flow edge (unchanged):
{
    "source": "action--uuid",
    "target": "action--uuid",
    "probability": 0.6,
    "rationale": "moderate confidence, tactic progression"
    # Note: no confidence_tier field on LLM edges
}
```

Callers iterating edges across both flow types should use `edge.get("confidence_tier")` defensively.

### What doesn't change

- FlowSynthesizer (unchanged)
- Neo4j schema (AttackEpisode, AttackAction, NEXT edges all reused)
- `_compute_next_edges` (still used by LLM flow path)
- `_convert_to_episode` (still used by LLM flow path)
- Graph persistence via FlowPersistence (called once per flow)
- `FlowBuilder._build_deterministic()` (deprecated, left in place, no longer called as fallback)

### Files to create or modify

| File | Action | Description |
|------|--------|-------------|
| `bandjacks/llm/flow_deterministic.py` | **Create** | `DeterministicFlowBuilder` class + `build_dual_flows()` helper |
| `bandjacks/llm/extraction_pipeline.py` | Modify | `_build_attack_flow()` calls `build_dual_flows()`, returns list |
| `bandjacks/services/api/job_processor.py` | Modify | Replace direct `build_from_extraction()` with `build_dual_flows()`, persist each flow, update result schema |
| `bandjacks/services/api/routes/reports.py` | Modify | Update post-review and regenerate-flow endpoints to handle list |
| `bandjacks/services/api/routes/flows.py` | Modify | Update on-demand flow build to handle list |
| `bandjacks/llm/flow_builder.py` | Modify | Minor: ensure LLM path returns consistent structure |
| `tests/unit/test_flow_deterministic.py` | **Create** | Tests for deterministic builder |

### Test strategy

Unit tests for `DeterministicFlowBuilder`:
- Empty claims → returns None
- Single technique → returns None (need ≥2 for edges)
- Two techniques, kill chain progression → one high-confidence edge
- Multiple techniques same tactic → medium confidence edges
- Same tactic, backward position → medium (not low)
- Kill chain progression with forward position → high confidence edges
- Narrative position disagreement (forward tactic, backward position) → low confidence edges
- Tactic regression (backward tactic) → low confidence edges
- Deduplication of claims with same external_id
- Techniques with no line_refs → sorted last within tactic (not dropped)
- Self-loop guard: consecutive same technique → no edge
- Tier distribution stats correct
- `techniques_without_position` stat counts inf-position entries
- All unknown tactics → all get rank 7, all edges medium
- Sub-technique ordering: T1059 before T1059.001 (lexicographic tiebreak)
- Source_id=None → flow still returned

Integration tests:
- `build_dual_flows` returns list of 1-2 flows
- Job processor persists both flows to Neo4j
- OpenSearch dual-read: new `flows` field + legacy `flow` fallback

### Success criteria

- Both flows generated for the DarkCloud report
- Deterministic flow includes all 48 techniques (none dropped)
- Edge tier distribution roughly matches orkl benchmarks (~85%+ high)
- LLM flow unchanged from current behavior
- No increase in LLM calls (deterministic flow uses zero)
- Processing time increase < 500ms (pure computation, no I/O)
- Existing reports with single `flow` field still readable
