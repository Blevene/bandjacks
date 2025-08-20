

---

## 9. Agentic Extractor v2, Transparency, and Novel TTP Handling (Sprint 6)

This section aligns the PRD to the latest functional spec updates for Sprint 6.

### 9.1 Objectives
- Deliver a retrieval-first, evidence-anchored agentic extraction pipeline that produces STIX 2.1 objects and Attack Flows.
- Provide live transparency of long-running extractions via async run management and status polling.
- Safely handle net-new techniques/entities without colliding with MITRE ATT&CK content.

### 9.2 Extractor v2 Architecture (High Level)
- Orchestrator stages: SpanFinder → Retriever → Discovery (optional) → Mapper → Evidence Verifier → Consolidator → KillChain Suggestions → Assembler (STIX + Flow).
- Evidence-first policy: accepted mappings must include direct quotes and line refs (±2 line window verification).
- Retrieval-first policy: LLM maps spans to ATT&CK candidates; free proposals allowed but must be verified.
- Deterministic assembly: outputs valid STIX 2.1 `attack-pattern` SDOs and Attack Flow episodes.

### 9.3 Transparency & Async Runs
APIs:
- POST `/v1/extract/runs` → start async extraction
  - Body: `{ method:"agentic_v2", content:string, title?:string, source_type?:string, config?:object }`
  - Response: `{ run_id, accepted:true }`
- GET `/v1/extract/runs/{run_id}/status` → poll progress
  - Response: `{ run_id, stage, percent, spans_total, spans_processed, counters:{ llm_calls, candidates, verified_claims, techniques, spans_found }, cost_usd, dur_sec, events_tail[], state }`
- GET `/v1/extract/runs/{run_id}/result` → final bundle/flow/techniques + `metrics` snapshot

Status payload (example):
```json
{
  "run_id": "ex-...",
  "stage": "Mapper",
  "percent": 62,
  "spans_total": 38,
  "spans_processed": 22,
  "counters": { "llm_calls": 0, "candidates": 0, "verified_claims": 15, "techniques": 12, "spans_found": 38 },
  "cost_usd": 0.0,
  "dur_sec": 486,
  "events_tail": [],
  "state": "running"
}
```

### 9.4 Novel TTP Namespace & Collision Avoidance
- Do not assign ATT&CK T-IDs or `external_references.source_name="mitre-attack"` to net-new techniques/entities.
- Use Bandjacks namespace for novel objects:
  - `external_references`: `{ "source_name": "bandjacks", "external_id": "BJ-TECH-{fingerprint}" }` (fingerprint from evidence/report).
  - STIX id: deterministic `attack-pattern--uuid5(namespace_bj, "BJ-TECH-{fingerprint}")`.
  - Provenance: `x_bj_origin:"novel"`, `x_bj_provenance` includes report id, quotes, line refs.
  - Optional: `x_bj_candidate_for:["Txxxx[.xxx]"]` for anticipated ATT&CK alignment.
- For novel Intrusion Sets / Software: same Bandjacks namespace pattern; deterministic ids; no ATT&CK external refs unless resolvable.
- Ingest policy:
  - Merge by `stix_id` only.
  - Official ATT&CK objects retain `{collection, version, domain}`; novel objects use `collection:"extracted"` and `x_bj_origin:"novel"`.

### 9.5 STIX & Flow Compatibility
- All emitted/ingested SDO/SROs must include `"spec_version":"2.1"`.
- Preserve standard ATT&CK relationships and fields (`kill_chain_phases`, `HAS_TACTIC`, `SUBTECHNIQUE_OF`).
- `Assembler` builds STIX `attack-pattern` objects with `external_references` and provenance (`x_bj_*`) and constructs an Attack Flow episode.

### 9.6 Acceptance Criteria
- Async run start/status/result works end-to-end; status percent advances through stages.
- Evidence verification rejects hallucinated quotes/lines; accepted techniques include verified quotes and line refs.
- Novel techniques/entities do not collide with ATT&CK: Bandjacks namespace external refs and deterministic STIX ids; provenance indicates `x_bj_origin:"novel"`.
- Final STIX bundle validates (2.1) and Attack Flow builds successfully.

### 9.7 Test Plan
- Unit: status snapshot shape, stage transitions, percent, counters.
- Unit: evidence verifier (±2 lines) accepts valid anchors; rejects mismatch.
- Unit: STIX id policy for novel objects (uuid5 stability; correct external refs).
- Integration: async extraction on sample PDFs; poll `/status` then `/result`; bundle & flow non-empty; techniques include quotes/line refs.
- Integration: ingest result to graph + OpenSearch; verify no collisions with official ATT&CK nodes.

### 9.8 Metrics & Performance Targets
- Metrics: `extract_runs_started`, `extract_runs_completed`, `extract_runs_failed`, `avg_extract_duration_sec`, `p95_extract_duration_sec`, `avg_verified_claims_per_run`, `avg_techniques_per_run`, `novel_techniques_created_total`, `alignment_candidates_tagged_total`.
- Targets (dev): small 3–8 min; medium 8–20 min; large ≤30 min (caps: top_k=5, discovery off, max spans ~30). Status polling ≤200 ms; support 5–10 concurrent runs in dev.
