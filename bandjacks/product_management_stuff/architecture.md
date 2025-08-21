

---

# 23) Sprint 6 Alignment — Agentic Extractor v2, Transparency, Novel TTPs

This section aligns the architecture with the updated PRD and functional spec for Sprint 6.

## Agentic Extractor v2 (Retrieval-first, Evidence-anchored)

Flow (orchestrated in-process):
- SpanFinder → Retriever → (optional) Discovery → Mapper → Evidence Verifier → Consolidator → KillChain Suggestions → Assembler (STIX + Flow)
- Evidence-first policy:
  - Accepted mappings must include direct quotes and line refs
  - Line refs verified with a ±2 line window
  - Technique external_id must resolve to ATT&CK when provided; otherwise treated as novel (see below)
- Retrieval-first policy:
  - LLM chooses from grounded candidates; free proposals allowed but accepted only after verification
- Deterministic assembly:
  - Emits valid STIX 2.1 `attack-pattern` SDOs with `external_references`, `x_bj_*` provenance
  - Builds an Attack Flow episode from the resulting techniques

## Transparency & Async Runs

New API surface (status polling for long extractions):
- POST `/v1/extract/runs` → start async extraction
  - Body: `{ method:"agentic_v2", content:string, title?:string, source_type?:string, config?:object }`
  - Response: `{ run_id, accepted:true }`
- GET `/v1/extract/runs/{run_id}/status` → poll progress
  - Response: `{ run_id, stage, percent, spans_total, spans_processed, counters:{ llm_calls, candidates, verified_claims, techniques, spans_found }, cost_usd, dur_sec, events_tail[], state }`
- GET `/v1/extract/runs/{run_id}/result` → final bundle/flow/techniques + `metrics`

Tracker fields surfaced in `metrics` and status:
- Stage, percent (derived), spans_total, spans_processed
- Counters: llm_calls, candidates, verified_claims, techniques, spans_found
- dur_sec, cost_usd (optional), events_tail

## Novel TTP Namespace & Collision Avoidance

- Do not assign ATT&CK T-IDs or `external_references.source_name="mitre-attack"` to net-new techniques/entities
- Bandjacks namespace for novel objects:
  - `external_references`: `{ "source_name": "bandjacks", "external_id": "BJ-TECH-{fingerprint}" }` (fingerprint from evidence/report)
  - STIX id: deterministic `attack-pattern--uuid5(namespace_bj, "BJ-TECH-{fingerprint}")`
  - Provenance: `x_bj_origin:"novel"`, `x_bj_provenance` (report id, quotes, line refs)
  - Optional `x_bj_candidate_for:["Txxxx[.xxx]"]` when likely aligned to ATT&CK
- Novel intrusion sets/software:
  - Same Bandjacks namespace pattern; deterministic ids; do not set ATT&CK external refs unless resolved
- Ingest policy:
  - Merge by `stix_id` only
  - Official ATT&CK content retains `{collection, version, domain}`; novel content uses `collection:"extracted"` and `x_bj_origin:"novel"`

## Observability & Performance (Targets in dev)

- Metrics: `extract_runs_started`, `extract_runs_completed`, `extract_runs_failed`, `avg_extract_duration_sec`, `p95_extract_duration_sec`, `avg_verified_claims_per_run`, `avg_techniques_per_run`, `novel_techniques_created_total`, `alignment_candidates_tagged_total`
- Targets: small 3–8 min; medium 8–20 min; large ≤30 min (caps: top_k=5, discovery off, max spans ~30); status polling ≤200 ms; support 5–10 concurrent runs in dev
