# Co-occurrence Analytics – Precomputation & Responsiveness Plan

This is a phased, pragmatic plan to make co-occurrence analytics (especially Actor Insights) fast, reliable, and scalable. Each phase lists logically sequenced tasks, deliverables, and acceptance criteria.

## Phase 0 – Stabilize current behavior (now)
- Tasks
  - [ ] Ensure CORS and base URL correctness across environments
  - [ ] Add robust fallbacks in UI (done for actor name search → reports attribution search)
  - [ ] Improve error handling and user messaging on timeouts
  - [ ] Verify `/v1/analytics/statistics` drives landing KPIs
- Deliverables
  - Working UI for Pairs, Conditional, Actor (with fallback), Bundles, Bridging
- Acceptance
  - Landing KPIs populate; Conditional/Actor pages are usable without hard errors

## Phase 1 – API route hygiene & lookup ergonomics
- Tasks
  - [ ] Finalize `actors` router: `GET /actors/{id}`, `GET /actors/search?query=`
  - [ ] Move remaining cross-entity lookups out of `reports.py` to domain routers (`actors`, `techniques`, `software`)
  - [ ] Update UI clients to prefer domain routers; keep legacy fallbacks 1 sprint
  - [ ] Add typed responses and basic pagination
- Deliverables
  - Clean lookup/search architecture; stable UI autocomplete flows
- Acceptance
  - Actor Insights resolves by name or STIX id with no 5xx; routes documented

## Phase 2 – Precomputed data model (Neo4j)
- Tasks
  - [ ] Define schema:
    - `(:ActorCooccurrenceStats { actor_id, episode_count, last_updated })`
    - `(:ActorTechniqueSupport { actor_id, technique_id, support })`
    - `(:ActorPair { actor_id, t1, t2, pair_count, support_a, support_b, episode_count, lift, pmi, npmi, jaccard, updated_at })`
  - [ ] Enforce canonical ordering `t1 < t2`
  - [ ] Indexes/constraints:
    - Unique `(actor_id, t1, t2)` for `ActorPair`
    - Index `(actor_id, technique_id)` for `ActorTechniqueSupport`
  - [ ] Document metric formulas (same as pairs) & thresholds
- Deliverables
  - DDL Cypher script with constraints and index creation
- Acceptance
  - DDL runs idempotently; validates on empty and seeded DBs

## Phase 3 – Backfill job (batch)
- Tasks
  - [ ] For each actor: aggregate episodes → distinct technique sets
  - [ ] Compute per-technique support and per-pair counts
  - [ ] Persist `ActorTechniqueSupport`, `ActorPair`, and `ActorCooccurrenceStats`
  - [ ] Compute and store metrics (lift, pmi, npmi, jaccard)
  - [ ] Use `apoc.periodic.iterate` for chunked execution and logging
  - [ ] Add CLI/admin endpoint to trigger full backfill
- Deliverables
  - Backfill script + logs; runbook for re-running
- Acceptance
  - Backfill completes on a representative dataset within SLO; spot checks match on-demand results

## Phase 4 – Incremental updater (near real-time)
- Tasks
  - [ ] Hook report approval/upsert path to queue “episode updated” jobs (actor_id, episode_id)
  - [ ] For an updated episode:
    - Recompute episode technique set
    - Increment/decrement `ActorTechniqueSupport` supports
    - Increment/decrement `ActorPair` pair_count for all combinations
    - Update `ActorCooccurrenceStats.episode_count`
    - Recalculate metrics for impacted pairs (cheap, local)
  - [ ] Concurrency control (apoc lock or per-actor batching)
  - [ ] Thresholding: skip persisting pairs below `(min_support, min_pair_count)`
- Deliverables
  - Deterministic, idempotent updater
- Acceptance
  - New/edited episodes reflect in Actor Insights within seconds; duplicates do not inflate counts

## Phase 5 – API v2 (read from precomputed)
- Tasks
  - [ ] Add `GET /actors/{id}/cooccurrence?sort=npmi&limit=…&min_support=…` that reads only from precomputed stores
  - [ ] Add freshness metadata (`last_updated`, `is_stale`)
  - [ ] Feature flag to switch UI to v2 endpoint; keep old path as fallback
- Deliverables
  - Fast Actor Insights API (no timeouts)
- Acceptance
  - P95 response < 200 ms for typical queries; UI fully migrated to v2

## Phase 6 – Frontend integration & UX polish
- Tasks
  - [ ] Switch Actor Insights to v2 endpoint under a feature flag
  - [ ] Add freshness badge (e.g., “updated 2m ago”) and fallback notice if stale
  - [ ] Persist and expose thresholds in the UI (min_support, min_pair_count)
  - [ ] Improve tables (tooltips for metrics; copy-to-clipboard for ids)
- Deliverables
  - Polished Actor Insights with clear state and fast results
- Acceptance
  - No “loading forever/timeouts”; users can filter and sort with immediate feedback

## Phase 7 – Performance & Ops
- Tasks
  - [ ] Monitor sizes of `ActorPair` and hot actors; prune low-signal pairs
  - [ ] Add Redis cache for API responses keyed by `(actor, sort, limit, thresholds)` with short TTL
  - [ ] Expose Prometheus metrics (update latency, job queue depth, pair counts)
- Deliverables
  - Operational visibility and guardrails
- Acceptance
  - SLOs tracked; cache hit rate > 80% for repeated queries

## Phase 8 – Advanced analytics (optional)
- Tasks
  - [ ] Rolling time windows per actor (monthly/quarterly) for trend detection
  - [ ] Statistical significance (Fisher’s exact + BH correction) flags on pairs
  - [ ] Community detection over co-occurrence graph (Louvain) for bundle surfacing
  - [ ] Platform segmentation (post platform enrichment)
- Deliverables
  - Enriched insights with reduced false positives
- Acceptance
  - Users can filter by time and trust significance indicators

## Phase 9 – Documentation & runbooks
- Tasks
  - [ ] Update `docs/cooccurrence/*` with v2 API details and data model
  - [ ] Add runbooks: backfill, repairing counters, thresholds, capacity planning
  - [ ] ADR on precomputation decision and trade-offs
- Deliverables
  - Clear docs; operational playbooks
- Acceptance
  - On-call engineers can diagnose and repair within runbook guidance

## Phase 10 – Rollout & cleanup
- Tasks
  - [ ] Dark launch v2 API; monitor errors/latency
  - [ ] Gradually flip feature flag for all users
  - [ ] Remove on-demand fallback code after one release window
- Deliverables
  - Clean final architecture; reduced complexity
- Acceptance
  - No regressions; timeouts eliminated for Actor Insights

---

## Risks & Mitigations
- Data skew (very prolific actors) → prune below thresholds, keep top-N by NPMI
- Concurrency updates → per-actor batch queue; apoc locks when needed
- Storage growth → compress metrics, avoid storing edges below thresholds
- Consistency drift → periodic reconciliation job comparing precomputed vs on-demand for samples

## Dependencies
- Neo4j APOC procedures enabled
- Background job runner (existing job processor or Celery/RQ alternative)
- Redis (optional, recommended for response caching)

## Success Criteria
- Actor Insights P95 latency < 200 ms (precomputed API)
- No timeouts on typical loads; 0 unhandled 5xx due to timeouts
- Backfill completes within maintenance window and is rerunnable

