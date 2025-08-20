

---

# Sprint 6 — Agentic Extractor v2, Transparency, and Novel TTPs

**Duration:** 2–3 weeks

**Goal:** Ship the retrieval-first, evidence-anchored agentic extraction with live status monitoring and safe handling of net-new techniques/entities without colliding with MITRE content.

## Scope

- Agentic v2 orchestrator (SpanFinder → Retriever → Discovery → Mapper → Verifier → Consolidator → Suggestions → Assembler)
- Transparency and status monitoring (async run management + progress snapshot)
- Novel TTP namespace & collision avoidance with MITRE ATT&CK
- Deterministic STIX ID policy and provenance for extracted objects

## Functional Requirements

1. Async extraction runs

   - POST `/v1/extract/runs`
     - Body: `{ method:"agentic_v2", content:string, title?:string, source_type?:string, config?:object }`
     - Response: `{ run_id, accepted:true }`
   - GET `/v1/extract/runs/{run_id}/status`
     - Response: `{ run_id, stage, percent, spans_total, spans_processed, counters:{ llm_calls, candidates, verified_claims, techniques, spans_found }, cost_usd, dur_sec, events_tail[], state: running|finished }`
   - GET `/v1/extract/runs/{run_id}/result`
     - Response: same shape as current extract result (`bundle`, `flow`, `techniques`) plus `metrics` snapshot.

2. Evidence-first extraction policy

   - Each accepted technique mapping MUST include ≥1 direct quote; default policy requires ≥2 quotes unless evidence score is high.
   - Line refs MUST be provided and verified with a ±2 line window.
   - Technique external_id MUST resolve to a real ATT&CK technique when present; otherwise treat as novel (see 3).

3. Novel TTPs and collision avoidance

   - For net-new techniques/entities:
     - DO NOT use `external_references.source_name="mitre-attack"` or T-style external IDs unless mapped to an official ATT&CK technique.
     - Use Bandjacks namespace for external references: `{ "source_name": "bandjacks", "external_id": "BJ-TECH-{fingerprint}" }` (fingerprint from evidence/report).
     - STIX `id`: `attack-pattern--uuid5(namespace_bj, "BJ-TECH-{fingerprint}")` to ensure uniqueness and avoid collisions.
     - Tag provenance: `x_bj_origin:"novel"`, include `x_bj_provenance` with report id, quotes, line refs.
     - Optional alignment: `x_bj_candidate_for:["Txxxx[.xxx]"]` when we believe it aligns to ATT&CK.
   - For novel intrusion-sets/software: same Bandjacks external reference pattern; deterministic STIX id with Bandjacks namespace.

4. STIX & graph compatibility

   - All SDO/SROs MUST include `"spec_version":"2.1"`.
   - Preserve ATT&CK conventions for official objects (tactics, kill_chain_phases, `HAS_TACTIC`, `SUBTECHNIQUE_OF`).
   - Ingest policy:
     - Merge by `stix_id` only; official content carries `{collection, version, domain}` provenance.
     - Bandjacks novel content goes into collection `"extracted"`; indices/queries can filter by collection and `x_bj_origin`.

## Data Contracts (Status/Result)

```json
{
  "run_id": "ex-...",
  "stage": "Mapper",
  "percent": 62,
  "spans_total": 38,
  "spans_processed": 22,
  "counters": {
    "llm_calls": 0,
    "candidates": 0,
    "verified_claims": 15,
    "techniques": 12,
    "spans_found": 38
  },
  "cost_usd": 0.0,
  "dur_sec": 486,
  "events_tail": [],
  "state": "running"
}
```

Result adds: `bundle`, `flow`, `techniques`, `metrics`.

## Acceptance Criteria

- Async run can be started and polled to completion; status reflects steady progress through stages.
- Evidence verification rejects hallucinated quotes/lines; accepted techniques include verified quotes and line refs.
- Novel techniques do not collide with ATT&CK: no T-IDs used; Bandjacks external references and deterministic STIX ids present; provenance indicates `x_bj_origin:"novel"`.
- Final STIX bundle validates (spec 2.1), and Attack Flow builds successfully from the bundle.

## Test Plan

- Unit: verify status snapshot shape; stage transitions; percent computation; counters increment.
- Unit: evidence verifier windowed check accepts valid anchors and rejects mismatched lines.
- Unit: STIX id policy for novel objects generates stable uuid5 ids and Bandjacks external refs.
- Integration: run async extraction on sample PDFs; poll `/status` → `/result`; assert `bundle` + `flow` non-empty; techniques include quotes/line refs.
- Integration: ingest result into graph + OpenSearch; verify no duplicate collisions with official ATT&CK nodes.

## Metrics

- `extract_runs_started`, `extract_runs_completed`, `extract_runs_failed`
- `avg_extract_duration_sec`, `p95_extract_duration_sec`
- `avg_verified_claims_per_run`, `avg_techniques_per_run`
- `novel_techniques_created_total`, `alignment_candidates_tagged_total`

## Performance Targets (dev)

- Small reports: 3–8 min; medium: 8–20 min; large: ≤30 min with caps (top_k=5, discovery off, max spans ~30).
- Status polling latency ≤ 200 ms; server handles concurrent 5–10 runs in dev.
