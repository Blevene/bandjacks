Let’s bridge standalone_tdo output to bandjacks ATT&CK graph with a clear, staged plan.

### Phase 0 — Inputs and mode selection
- Decide inputs per run:
  - Prefer the markdown report if present: parse Technique Context, Nodes table, Relationships table, and embedded Attack Flow JSON.
  - Fallback to raw JSON (`*_extracted.json`) when MD is unavailable.
- Implement a “strict ATT&CK export” mode (only ATT&CK nodes/edges) and a “full export” mode (retain extra entities/edges as extensions).

### Phase 1 — Parser
- Build a small parser module (e.g., `bandjacks/loaders/tdo_bridge.py`):
  - Extract “Technique Context” block lines per technique.
  - Parse the Nodes and Relationships tables into arrays of dicts.
  - Detect and parse the “Attack Flow JSON” fenced block.
  - Fallback: if MD not available, load `nodes` and `relationships` from `*_extracted.json`; skip flow unless separately provided.

### Phase 2 — Node normalization (map to bandjacks schema)
- Map node labels:
  - Technique → AttackPattern
    - Set `external_id = pk` when `pk` matches ^T\d{4}(\.\d{3})?$
    - Preserve `name`, `description`
    - Set `x_mitre_is_subtechnique = true` when external_id contains a dot or if `SUBTECHNIQUE_OF` exists
    - Store report-specific text in `x_bj_provenance` (single string) and/or `x_bj_sources` (list)
  - ThreatActor → IntrusionSet
  - Tool and Malware → Software
  - Source → Report (map filename, extension, size, title; optional `extraction_model`/`extraction_method`)
- Handle non-ATT&CK types:
  - Identity, Infrastructure, Vulnerability: exclude in “strict” mode; include unchanged in “full” mode or map a subset to `Indicator` only if you have a reliable pattern/value.

### Phase 3 — Relationship normalization
- Unify and rename:
  - `USES_TECHNIQUE` | `USES_TOOL` | `USES_MALWARE` → USES
  - `SOURCED_FROM` (entity → Source) → `EXTRACTED_FROM` (AttackPattern/Indicator → Report) and flip direction
  - Preserve `SUBTECHNIQUE_OF`
- Populate `EXTRACTED_FROM.properties`:
  - `evidence`: from Technique Context and any short quotes in the MD (or detection opportunity source/evidence if present)
  - `confidence`: default (e.g., 70–80) or derive from related opportunity confidence where available
- Optionally enrich:
  - If you have an ATT&CK dataset locally, build `HAS_TACTIC` edges for `AttackPattern` → `Tactic`

### Phase 4 — Technique Context incorporation
- Build a technique_id → context string map from the “Technique Context” section.
- For each normalized `AttackPattern`:
  - Set `x_bj_provenance` to the technique’s context line(s)
  - Add/merge an `EXTRACTED_FROM` edge to the `Report` node with `evidence` set to the context
- If a context item references a technique by name (not an ID):
  - Resolve by:
    - Prefer an exact Technique node with matching `name`
    - Else, use `SUBTECHNIQUE_OF` rows to anchor to the parent technique id in the same doc
    - Else, store as an alias-only note in `x_bj_sources` and skip creating a new AttackPattern

### Phase 5 — AttackFlow graph conversion
- From Attack Flow JSON block:
  - Create an `AttackFlow` node with `flow_id` (from `pk`), `name`, `description`, `created`, `llm_synthesized=true`
  - Create one `AttackEpisode` per flow, link via `CONTAINS_EPISODE`
  - For each step:
    - Create an `AttackAction` with `action_id` (UUID), `description`, `rationale`, `order`
    - Link `AttackEpisode` `CONTAINS` `AttackAction` with `order`
    - Add `NEXT` edges between consecutive actions; set `rationale` (leave `p` unset)
    - If the step entity is a Technique/AttackPattern, add `OF_TECHNIQUE` from the action to the corresponding `AttackPattern`
- Attribution:
  - If an `IntrusionSet` (from ThreatActor) is present, add `AttackEpisode` `ATTRIBUTED_TO` `IntrusionSet`
- Edge cases:
  - If step entity uses tool/malware/infrastructure labels, still create actions but only add `OF_TECHNIQUE` where the entity maps to an AttackPattern
  - If the Flow JSON already uses normalized ids like `attack-pattern--t1557-002`, use those to resolve the target `AttackPattern.external_id = T1557.002`

### Phase 6 — Validation
- Structural checks:
  - Every `AttackPattern` has `external_id`
  - Every `EXTRACTED_FROM` targets a `Report`
  - Flow contains 1 episode, ≥1 actions, proper `CONTAINS` order, and `NEXT` edges chain
- Optional schema conformance:
  - Lightweight validator that asserts present fields match types from `bandjacks/docs/schema.json` (don’t overfit to counts)

### Phase 7 — Export and integration
- Output format:
  - Emit a dict with top-level `nodes` and `relationships` arrays conforming to bandjacks expectations (labels, pks, properties)
- Placement:
  - Implement exporter in `bandjacks/loaders/tdo_bridge.py` with a CLI entry (e.g., `python -m bandjacks.loaders.tdo_bridge --input <md|json> --mode strict|full --out <file>`)
  - Optionally expose an API hook in `bandjacks/services/api/routes/reports.py` to accept a TDO MD/JSON upload and return the normalized ATT&CK graph
- Storage:
  - Write results to `batch_results/` for traceability; include a provenance summary

### Phase 8 — Tests
- Unit tests:
  - Parse `wizards_20250607_164239.md` end-to-end
  - Assert AttackPattern count equals techniques with T-ids
  - Assert `EXTRACTED_FROM` created per technique with evidence
  - Assert flow objects: 1 AttackFlow, 1 AttackEpisode, N `AttackAction`, N-1 `NEXT`, and `OF_TECHNIQUE` for technique steps
- Edge tests:
  - Techniques present by name only (resolve or alias)
  - Missing Flow JSON (skip flow, still export nodes/edges)
  - Multiple sources (aggregate evidence)

### Timeline and deliverables
- Day 1: Parser + node/relationship normalization (strict mode)
- Day 2: Technique Context incorporation + flow conversion
- Day 3: Validation, tests, and CLI; optional API hook
- Day 4 (optional): Tactic enrichment via ATT&CK dataset and “full export” extras

- We’ll parse the MD first, normalize nodes/edges to ATT&CK (`AttackPattern`, `IntrusionSet`, `Software`, `Report`), convert the flow JSON into `AttackFlow`/`AttackEpisode`/`AttackAction` with `NEXT` and `OF_TECHNIQUE`, and attach “Technique Context” as evidence and provenance to `AttackPattern` and `EXTRACTED_FROM`.