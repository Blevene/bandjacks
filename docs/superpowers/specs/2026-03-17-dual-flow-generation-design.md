# Dual Flow Generation: LLM Synthesis + Deterministic Full Ordering

## Goal

Generate two attack flows per report: a focused LLM-synthesized causal chain and a comprehensive deterministic ordering of all extracted techniques using tactic position and narrative position signals with three-tier edge confidence.

## Problem

The LLM synthesizer produces high-quality 5-15 step flows capturing the core narrative, but leaves 80%+ of extracted techniques unsequenced. Analysts need visibility into the full technique set ordered as an attack path, even at lower confidence.

## Solution

Every report produces two independent `AttackEpisode` nodes:

1. **LLM Flow** (`flow_type: "llm_synthesized"`) — Existing behavior unchanged. Focused causal chain with narrative reasoning.

2. **Deterministic Flow** (`flow_type: "deterministic_full"`) — All extracted techniques ordered by `(tactic_rank, min_line_ref)` with orkl-style three-tier edge confidence.

Both attach to the Report via `HAS_FLOW` relationships. No schema changes required.

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
    ) -> Dict[str, Any]:
        """Build deterministic flow from extraction claims.

        Args:
            claims: Extraction claims with external_id, line_refs, confidence
            technique_cache: Loaded TechniqueCache for tactic lookups
            flow_name: Name for the generated flow
            source_id: Optional report ID for attribution

        Returns:
            Flow dict with actions, edges (tier + probability), and stats
        """
```

### Algorithm

```
Input: claims[] (each has external_id, line_refs, confidence)

Step 1: Deduplicate
  - Group claims by external_id
  - For each technique: max(confidence), min(line_refs) as narrative_position
  - Skip techniques with no line_refs (position unknown)

Step 2: Resolve tactics
  - For each technique, look up tactic(s) via TechniqueCache
  - Use primary tactic (first in kill chain) for ordering
  - Map tactic shortname to rank via constants.TACTIC_ORDER (1-14)
  - Techniques with unknown tactic get rank 7 (defense-evasion, middle)

Step 3: Sort
  - Primary key: tactic_rank (ascending, kill chain order)
  - Secondary key: narrative_position (ascending, first mention in text)
  - Stable sort preserves extraction order as tiebreaker

Step 4: Build actions
  - One AttackAction per technique
  - action_id: "action--{uuid}"
  - order: 1-based sequential
  - attack_pattern_ref: technique external_id (e.g., "T1566.001")
  - name: technique name from cache
  - confidence: from extraction (0-100)
  - tactic: resolved tactic shortname
  - narrative_position: min line_ref

Step 5: Compute edges with three-tier confidence
  For each consecutive pair (action_i, action_i+1):
    tactic_forward = action_i+1.tactic_rank >= action_i.tactic_rank
    position_forward = action_i+1.narrative_position >= action_i.narrative_position
    same_tactic = action_i+1.tactic_rank == action_i.tactic_rank

    Tier assignment:
      high:   tactic_forward AND position_forward (both signals agree)
      medium: same_tactic (within same phase, order uncertain)
      low:    tactic_forward BUT NOT position_forward (signals disagree)

    Probability mapping:
      high   → 0.8
      medium → 0.5
      low    → 0.25

    Rationale: "{tactic1} → {tactic2}, positions {pos1}→{pos2}, {tier} confidence"

Step 6: Build flow result
  Return dict matching existing flow structure:
    flow_id, episode_id, name, source_id, actions, edges,
    flow_type: "deterministic_full",
    llm_synthesized: False,
    stats: {steps_count, edges_count, tier_distribution: {high: N, medium: N, low: N}}
```

### Pipeline integration

Modify `ExtractionPipeline._build_attack_flow()`:

```
Current flow:
  LLM synthesis → success? → convert to episode
                → failure? → deterministic fallback

New flow:
  1. Always: DeterministicFlowBuilder.build(claims, technique_cache)
     → deterministic_flow (flow_type: "deterministic_full")
  2. Attempt: FlowSynthesizer.synthesize(extraction_data, report_text)
     → llm_flow (flow_type: "llm_synthesized") or None
  3. Return both (or just deterministic if LLM fails)
```

The LLM flow and deterministic flow are independent. LLM failure does not prevent deterministic flow generation.

### Return value change

`_build_attack_flow()` currently returns a single flow dict or None. Change to return a list of flows:

```python
def _build_attack_flow(...) -> List[Dict[str, Any]]:
    flows = []

    # Always generate deterministic flow
    det_flow = deterministic_builder.build(claims, technique_cache, ...)
    if det_flow:
        flows.append(det_flow)

    # Attempt LLM synthesis
    llm_flow = self.flow_builder.build_from_extraction(...)
    if llm_flow:
        flows.append(llm_flow)

    return flows
```

Callers updated to handle list. Report stores multiple flows.

### Edge data model

```python
{
    "source": "action--uuid",
    "target": "action--uuid",
    "probability": 0.8,
    "confidence_tier": "high",
    "rationale": "initial-access → execution, positions 142→289, high confidence"
}
```

The `confidence_tier` field is new. Existing edges from LLM flows won't have it (they use continuous probability from `_compute_next_edges`).

### Report response

The extraction result includes a `flows` list instead of a single `flow`:

```python
{
    "flows": [
        {
            "flow_id": "flow--abc",
            "flow_name": "Deterministic Attack Flow",
            "flow_type": "deterministic_full",
            "steps": [...],  # All 48 techniques
            "edges": [...],  # 47 edges with tier + probability
            "stats": {"steps_count": 48, "tier_distribution": {"high": 35, "medium": 8, "low": 4}}
        },
        {
            "flow_id": "flow--def",
            "flow_name": "DarkCloud Stealer Infection Chain via AutoIt",
            "flow_type": "llm_synthesized",
            "steps": [...],  # 5 focused steps
            "edges": [...],  # 4 edges with continuous probability
        }
    ]
}
```

### What doesn't change

- FlowSynthesizer (unchanged)
- Neo4j schema (AttackEpisode, AttackAction, NEXT edges all reused)
- `_compute_next_edges` (still used by LLM flow path)
- `_convert_to_episode` (still used by LLM flow path)
- Graph persistence via FlowPersistence (called per flow)

### Files to create or modify

| File | Action | Description |
|------|--------|-------------|
| `bandjacks/llm/flow_deterministic.py` | **Create** | `DeterministicFlowBuilder` class |
| `bandjacks/llm/extraction_pipeline.py` | Modify | Call both builders, return list of flows |
| `bandjacks/llm/flow_builder.py` | Modify | Minor: ensure LLM path returns consistent structure |
| `bandjacks/services/api/job_processor.py` | Modify | Handle list of flows, persist each |
| `tests/unit/test_flow_deterministic.py` | **Create** | Tests for deterministic builder |

### Test strategy

Unit tests for `DeterministicFlowBuilder`:
- Empty claims → empty flow
- Single technique → one action, no edges
- Multiple techniques same tactic → medium confidence edges
- Kill chain progression → high confidence edges
- Narrative position disagreement → low confidence edges
- Deduplication of claims with same technique
- Techniques with no line_refs handled gracefully
- Tier distribution stats correct

### Success criteria

- Both flows generated for the DarkCloud report
- Deterministic flow includes all 48 techniques
- Edge tier distribution roughly matches orkl benchmarks (~85%+ high)
- LLM flow unchanged from current behavior
- No increase in LLM calls (deterministic flow uses zero)
- Processing time increase < 500ms (pure computation, no I/O)
