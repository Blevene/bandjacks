Awesome — here’s a detailed **functional spec** organized into logical, feature-based sprints that align with the updated architecture. Each sprint ships a vertical slice with clear scope, APIs, data contracts, acceptance criteria, and test plans. Focus stays squarely on **TTPs** (techniques, sub-techniques, tactics, groups, software, mitigations), **Attack Flows**, and **D3FEND** overlays.

---

# Functional Specification (Feature-Based Sprints)

## Product Summary (context)

A TTP-centric world model system that:

* Loads version-pinned **ATT\&CK STIX 2.1** content.
* Validates via **ATT\&CK Data Model (ADM)**.
* Stores dual **RDF/OWL ↔ Property-Graph** projections.
* Adds **vector retrieval** for node/edge/flow semantics.
* Builds **Attack Flows** from processed intel.
* Overlays **D3FEND** countermeasures and artifacts.
* Learns via **analyst feedback** and **active learning**.

Non-goals (v1): IOC lifecycle, blocking/enforcement, full SOC console.

---

## EPICS (persistent across sprints)

* **E1. Catalog & Loader** (ATT\&CK release pinning, ADM-gated ingest)
* **E2. Mapper** (report → STIX bundles → graph + vectors)
* **E3. Vectors** (embeddings + KNN search)
* **E4. Flows** (episode assembler, sequencer, flow embeddings)
* **E5. Defense Overlay** (ATT\&CK Mitigations → D3FEND + artifacts)
* **E6. Feedback/AL** (review APIs, uncertainty queues, retraining hooks)
* **E7. Simulation & Coverage** (next-step, minimal-cut sets, gaps)
* **E8. Ops** (authz/markings, observability, provenance/versioning)

---

# Sprint 1 — Foundations: Catalog, Loader, ADM Validation, TTP Search

**Duration:** 2 weeks
**Goal:** Ship the “parse → validate (ADM) → upsert → search (TTP)” happy path.

### Scope

* **E1**: Catalog & Loader (ATT\&CK `index.json`; release pinning; provenance).
* **E2**: Bundle ingest endpoint (user bundles; TTP-only SDO/SRO).
* **E3**: Node embeddings + `/search/ttx`.

### Functional Requirements

1. **GET /v1/catalog/attack/releases**

   * Returns collections (`enterprise-attack`, `mobile-attack`, `ics-attack`) with available versions and bundle URLs.
2. **POST /v1/stix/load/attack?collection=\&version=\&adm\_strict=true**

   * Fetch bundle via catalog; **ADM-validate**; upsert to Neo4j; generate embeddings for `AttackPattern`, `Tactic`, `IntrusionSet`, `Software`, `Mitigation`; index in OpenSearch.
   * Persist raw bundle to blob store; stamp provenance on all nodes/edges.
3. **POST /v1/stix/bundles?strict=true**

   * Accept a user bundle (TTP objects only). Validate via ADM; upsert + embed.
   * Response includes `rejected[]` for invalid objects.
4. **POST /v1/search/ttx { text, top\_k }**

   * KNN search returning ATT\&CK technique/sub-technique candidates.

### Data Contracts (responses – concise)

```json
// UpsertResult
{
  "inserted": 1342,
  "updated": 17,
  "rejected": [{"id":"relationship--...","type":"relationship","reason":"missing target_ref"}],
  "provenance": {
    "collection": "enterprise-attack",
    "version": "17.1",
    "modified": "2025-05-06T00:00:00Z",
    "url": "https://raw.githubusercontent.com/...json",
    "adm_spec": "3.3.0",
    "adm_sha": "abc1234"
  },
  "trace_id": "..."
}
```

### Acceptance Criteria

* Load **enterprise-attack latest** → ≥ 1000 techniques/sub-techniques present; no downgrades unless `force=true`.
* `/stix/bundles?strict=true` rejects malformed objects with clear ADM-driven reasons.
* `/search/ttx` returns top-k techniques with P95 ≤ 300ms (dev) for `top_k ≤ 10`.

### Test Plan

* Contract tests (OpenAPI) with **schemathesis**.
* Pos/neg fixtures: valid Technique; invalid Relationship (missing `target_ref`).
* Integration: `load → graph readback → embeddings → /search/ttx`.

### Metrics

* `bundles_ingested`, `objects_rejected`, `search_latency_ms_p95`, `objects_by_type`.

---

# Sprint 2 — Mapper MVP & Review Hooks

**Duration:** 2 weeks
**Goal:** Upload reports (text blocks) → system proposes ATT\&CK mappings; analyst can record decisions.

### Scope

* **E2**: Mapper entrypoint for user bundles produced by IE/linker.
* **E6**: Minimal feedback endpoint for accept/edit/reject decisions.

### Functional Requirements

1. **POST /v1/stix/bundles?strict=true** (reuse S1)

   * Ensure we accept bundles derived from report parsing containing:

     * `AttackPattern`, `IntrusionSet`, `Software`, `Mitigation`, and `relationship: uses/mitigates/implies`.
2. **POST /v1/review/mapping**

   * Body: `{ object_id, decision: accept|edit|reject, note? }`
   * Persist decisions (auditable). Emit to queue for AL later.
3. **GET /v1/stix/objects/{id}**

   * Return object, its provenance, and inbound/outbound relationships.

### Acceptance Criteria

* Analyst can upload a small bundle → validated → upserted → visible via `GET /stix/objects/{id}`.
* Decision recorded; subsequent GET shows latest state and retains provenance.

### Test Plan

* Golden bundles from sample intel paragraphs (technique + uses).
* Negative tests: invalid `relationship_type`, revoked objects.

### Metrics

* `review_decisions_total`, breakdown by `accept/edit/reject`.

---

# Sprint 3 — Attack Flow Builder v1 + Flow Search

**Duration:** 3 weeks
**Goal:** Convert observations/relations into **Attack Flows**; search for similar flows.

### Scope

* **E4**: Episode assembler, deterministic sequencer, STIX Attack Flow generation, PG projection.
* **E3**: Flow embeddings + `/search/flows`.

### Functional Requirements

1. **POST /v1/flows/build?source\_id=**

   * Input `source_id` can be a processed bundle id, incident id, or a query token selecting observations & relations.
   * Steps:

     * Assemble **episode** by time window + entity overlap.
     * Order steps; merge near duplicates; compute `NEXT { p }` scores using temporal proximity + historical transition counts.
     * Emit **Attack Flow** (STIX extension) + upsert `(:AttackEpisode)-[:CONTAINS]->(:AttackAction)` and `(:AttackAction)-[:NEXT {p}]->(:AttackAction)`.
     * Build flow embedding; index.
   * Response: `{ flow_id, steps[], edges[] }`.
2. **GET /v1/flows/{flow\_id}**

   * Return steps (with `attack_pattern_ref`, confidence) and `NEXT` edges (probabilities).
3. **POST /v1/search/flows { flow\_id | text, top\_k }**

   * Return similar flows by flow-level embeddings.

### Data Contract (flow excerpt)

```json
{
  "id": "flow--123",
  "name": "Credential theft → PrivEsc → Lateral",
  "steps": [
    {"id":"action--a1","attack_pattern_ref":"attack-pattern--T1528","confidence":80},
    {"id":"action--a2","attack_pattern_ref":"attack-pattern--T1068","confidence":70}
  ],
  "edges": [
    {"source":"action--a1","target":"action--a2","p":0.62,"rationale":"temporal+freq"}
  ]
}
```

### Acceptance Criteria

* Build a flow from a small curated bundle; graph contains `AttackEpisode`, `AttackAction`, `NEXT` edges with `p ∈ [0,1]`.
* `/search/flows` returns ≥ 1 similar flow for a known scenario.

### Test Plan

* Synthetic bundle → deterministic ordering checks.
* Verify `p` calculation; ensure cycles handled or pruned per policy.

### Metrics

* `flows_built_total`, `flow_build_success_rate`, `avg_steps_per_flow`.

---

# Sprint 4 — D3FEND Overlay & Defense Recommendations

**Duration:** 2 weeks
**Goal:** Augment flows with **D3FEND** techniques and artifacts; compute defensive choke points.

### Scope

* **E5**: Ingest D3FEND ontology; materialize `COUNTERS`; artifact hints.
* **E7** (partial): Minimal-cut recommendation (greedy/baseline) over flow graph.

### Functional Requirements

1. **D3FEND ingest (internal job)**

   * Import ontology via n10s; project `D3fendTechnique`, `DigitalArtifact`.
   * Import ATT\&CK Mitigation ↔ D3FEND mapping; derive and persist:

     * `(:D3fendTechnique)-[:COUNTERS]->(:AttackPattern)`
2. **GET /v1/defense/overlay/{flow\_id}**

   * For each `AttackAction`, list mapped `D3fendTechnique`(s), rationale, and candidate **DigitalArtifact** anchors.
3. **POST /v1/defense/mincut { flow\_id, budget? }**

   * Return recommended set of D3FEND techniques that minimizes path success probability (greedy baseline; exact minimal cut optional later).

### Acceptance Criteria

* For a flow with T1059/T1110 steps, overlay returns non-empty `COUNTERS` with associated artifacts.
* `mincut` returns a ranked defensive set; includes expected impact narrative.

### Test Plan

* Known ATT\&CK→Mitigation→D3FEND mappings; spot-check `COUNTERS` edges.
* Unit test greedy minimal-cut on small DAG flows.

### Metrics

* `overlay_calls_total`, `avg_counters_per_step`, `mincut_coverage_delta`.

---

# Sprint 5 — Feedback → Active Learning & Coverage Analytics

**Duration:** 3 weeks
**Goal:** Close the loop: uncertainty queues, retraining hooks, basic coverage gap views.

### Scope

* **E6**: Uncertainty queue + weekly retrain (linker/sequencer); re-embed updated nodes/flows.
* **E7**: Coverage & gap analytics (by tactic, platform, data component).

### Functional Requirements

1. **POST /v1/review/flowedge**

   * Body: `{ flow_id, source, target, decision: accept|edit|reject, note? }`
   * Persist and enqueue for AL.
2. **GET /v1/analytics/coverage?tactic=TA0003\&platform=windows**

   * Returns technique coverage summary (e.g., % techniques with `ObservedData`/`Sighting` in last N days, presence of D3FEND counters).
3. **Jobs (internal)**

   * **AL sampler**: select lowest-confidence mappings/edges → notify reviewers (or queue).
   * **Retrain**: light weekly updates for linker/sequencer; invalidate & refresh embeddings for impacted nodes/flows.

### Acceptance Criteria

* Review decisions update internal labels; retrain job picks them up and reduces uncertainty week-over-week on sampled set.
* Coverage endpoint returns stable aggregates and filters by tactic/platform.

### Test Plan

* Seed fake low-confidence edges; ensure they appear in uncertainty queue.
* Snapshot coverage metrics; verify reproducibility across runs.

### Metrics

* `uncertainty_queue_size`, `al_processed_total`, `mapping_precision/recall` (sampled), `flow_edge_approval_rate`, `coverage_gap_rate`.

---

# Cross-cutting Specifications

## APIs (OpenAPI alignment)

* Versioned under `/v1`; explicit `trace_id` in responses & errors.
* Query params for `adm_strict`, `force`, `top_k`.
* Common error schema: `{ trace_id, code, message, hints? }`.

## Security & Markings

* OIDC/JWT for all write routes.
* RBAC roles: `analyst`, `engineer`, `admin`.
* STIX markings (e.g., TLP) honored on reads; markings propagate to derived objects/flows/overlays.

## Observability (per sprint)

* Counters and histograms for each new feature.
* Structured logs with `{trace_id, route, duration_ms, status}`.
* Basic dashboards: ingestion health, search latency, flow build success, overlay usage.

## Data & Storage

* **Neo4j**: constraints on `stix_id` unique; edges typed; properties include `source` (provenance).
* **OpenSearch**: indices `attack_nodes-v1`, `attack_flows-v1`; filterable fields (`kb_type`, `attack_version`, `revoked=false`).
* **Blob**: raw bundles, generated flow bundles, import manifests (with sha256 + counts).

## Performance Targets (dev)

* `/search/ttx` P95 ≤ 300ms (top\_k ≤ 10).
* Initial ATT\&CK load ≤ 5 min.
* Flow build for small episode (≤ 10 actions) ≤ 2s.

## Risks & Mitigations

* **Schema drift:** pin ADM spec; nightly check; fail-fast on mismatch.
* **Release churn:** store provenance; delta re-embed only changed nodes.
* **Ambiguity in mapping:** retrieval-assisted linking; analyst review; AL retrain.
* **Confidence inflation:** calibrated scoring; require review for high-impact graph changes.

---

# Deliverables by Sprint (DoD Recap)

* **S1:** Catalog + Loader (ADM-strict), Bundle ingest, TTP search, provenance persisted.
* **S2:** Mapper ingest for report-derived bundles, Review decisions API.
* **S3:** Flow build + storage + flow search.
* **S4:** D3FEND overlay + minimal-cut recommendations.
* **S5:** Feedback → AL loop, Coverage analytics.

---

# Engineering Readiness (what to implement next)

* Generate OpenAPI stubs for S1/S2 routes (FastAPI), plus uv tasks.
* Create Neo4j constraints and OpenSearch index templates.
* Implement loader caching for `index.json` and bundle blobs.
* Build ADM validator path (sidecar **or** schema export) and gate both ingest endpoints.
