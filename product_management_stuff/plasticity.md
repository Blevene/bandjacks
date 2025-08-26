# Sprint Execution Plan — Edge Weighting & Plasticity (Hebbian + optional GNN Priors)

**Duration:** 2 weeks (10 working days)
**Goal:** Produce stable, evidence‑weighted technique edges that resist recency bias and improve simulation accuracy using Hebbian updates, slow decay, consolidation floors, tactic proximity, defense reduction, and (optionally) GNN priors.
**Scope:**

* Relationship types & props:

  * `(:AttackPattern)-[r:NEXT {w_hebb, w_recent, w_long, w_imputed, w_gnn?, w_final, updated_at}]->(:AttackPattern)`
  * `(:AttackPattern)-[r:CO_OCCURS {w_hebb, w_recent, w_long, w_imputed, w_gnn?, w_final, updated_at}]->(:AttackPattern)` (unordered pairs)
* Jobs:

  * Nightly plasticity job (co‑occurrence → Hebbian EMA updates → decay/floor → tactic bonus → defense reduction → `w_final`)
  * Weekly optional GNN prior (edge regression) and blend into `w_final`
* Consumers:

  * **Simulator**: prefer `w_final` for transitions; fallback to historical `avg(n.p)`
  * **Flow builder**: boost probability when `w_final` is high
* APIs:

  * Read‑only weight inspection endpoints for observability/UI
* **Non‑goals (this sprint):** full temporal KGE, prod‑grade GNN retraining pipelines, UI viz beyond inspection

---

## 1) Workstreams & Trackable Tickets

**EPIC: PLAS‑0 — Hebbian Plasticity & Edge Weighting**

### WS1 — Data model, indices & one‑off migration

* **Story PLAS‑10:** Add relationship default props & constraints

  * *Tasks*

    * Add defaults on create: `w_hebb=0, w_recent=0, w_long=0, w_imputed=0, w_final=0, updated_at=timestamp()`
    * Indices/constraints:

      * `(:AttackPattern {stix_id})` unique
      * Indexes to speed read paths: `:NEXT(w_final)`, `:CO_OCCURS(w_final)` (and `updated_at` if supported)
    * Filter revoked/deprecated techniques by default via label/prop (`revoked=true` or `deprecated=true`)
  * *Acceptance*

    * Queries for top‑K successors/co‑occurs run ≤ 50ms on dev set
    * Revoked/deprecated excluded by default

* **Story PLAS‑11:** One‑off migration & backfill

  * *Tasks*

    * Backfill `NEXT` relationship properties (zeros) where missing
    * Initialize `CO_OCCURS` edges via MERGE from episodes (unordered)
    * Verify idempotency (safe re‑run)
  * *Acceptance*

    * Backfill completes on target sample in ≤ 2 minutes
    * Repeat run yields 0 changes

### WS2 — Plasticity job (Hebbian + decay + bonuses + defense)

* **Story PLAS‑20:** Implement Hebbian EMA updates for `CO_OCCURS`

  * *Tasks*

    * Extract unordered pairs per episode
    * EMA updates: `w_recent = (1−αr)*w_recent + αr*1.0`, `w_long = (1−αl)*w_long + αl*1.0`
    * Metaplastic blend: `w_hebb = m*w_recent + (1−m)*w_long`
    * Consolidation floor: `w_hebb = max(floor, w_hebb)`
  * *Acceptance*

    * After ingest, `CO_OCCURS` edges have non‑zero `w_hebb` & `w_final`

* **Story PLAS‑21:** Implement Hebbian updates for `NEXT` (transition signal)

  * *Tasks*

    * Use observed `AttackAction -[:NEXT]-> AttackAction` with `avg(probability)` as signal
    * Same EMA + floor pattern as above
  * *Acceptance*

    * `NEXT` edges updated with non‑zero weights on sample flows

* **Story PLAS‑22:** Tactic proximity, defense reduction & `w_final`

  * *Tasks*

    * Tactic proximity bonus → `w_imputed` (same tactic / adjacent tactics)
    * Defense reduction using `(:D3fendTechnique)-[:COUNTERS]->(:AttackPattern)` with cap
    * Compute `w_final = clamp(w_hebb + w_imputed − defense_reduction, 0, 1)`
  * *Acceptance*

    * Defense reduces but never < 0; floor respected; clamps stay in \[0,1]

* **Story PLAS‑23:** Performance & scheduling

  * *Tasks*

    * Batch updates; parameterized Cypher; periodic commits
    * Cron config & CLI: `scripts/plasticity_run.py` with `--since`, `--dry-run`
    * Target perf: complete ≤ 5 minutes for 100k actions / 10k episodes
  * *Acceptance*

    * P95 job run ≤ 5 min in perf tests

### WS3 — Consumers (Simulator & Flow Builder)

* **Story PLAS‑30:** Simulator reads `w_final`

  * *Tasks*

    * Update `AttackSimulator._get_next_techniques` to prefer `w_final`, fallback to `avg(n.p)`
    * Feature flag to revert to historical
  * *Acceptance*

    * No accuracy regression on baseline dataset; improved stability in noisy recent data

* **Story PLAS‑31:** Flow Builder probability boost

  * *Tasks*

    * In `_calculate_probability`, apply boost when `w_final` high
    * Calibrate boost curve; add unit tests
  * *Acceptance*

    * Probabilities monotonic w\.r.t. `w_final` and bounded

### WS4 — Read‑only APIs

* **Story PLAS‑40:** `GET /v1/analytics/weights/next/{technique_id}`

  * *Tasks*

    * Returns top successors with `w_final` and components (`w_hebb`, `w_imputed`, `defense_reduction`)
    * P95 < 200ms for top 20

* **Story PLAS‑41:** `GET /v1/analytics/weights/cooccurs/{technique_id}`

  * *Tasks*

    * Returns top co‑occurs with the same component breakdown
  * *Acceptance*

    * P95 < 200ms for top 20

### WS5 — Testing & QA

* **Story PLAS‑50:** Unit tests

  * EMA update, metaplastic blend, floor/clamp
  * Tactic proximity bonus; defense reduction (cap & per‑counter)
  * Revoked/deprecated filtering behavior

* **Story PLAS‑51:** Integration tests (Neo4j)

  * Tiny episode set → run job → assert `w_recent`, `w_long`, `w_hebb`, `w_final`
  * Add D3FEND counters → verify reduced `w_final`
  * Revoked technique present → excluded by default

* **Story PLAS‑52:** Simulator & API tests

  * Simulator prefers `w_final` when present
  * API snapshot tests; latency budget checks

### WS6 — Optional GNN prior (weekly)

* **Story PLAS‑60:** Baseline model & data pipeline

  * Lightweight GraphSAGE/edge‑regressor on `AttackPattern` projection
  * Positives: `NEXT` & `CO_OCCURS`; negatives: sampled non‑edges
  * Features: text embedding, tactic one‑hot, platform flags, degree, age

* **Story PLAS‑61:** Blend & scheduling

  * Predict `w_gnn` for sparse/isolated pairs
  * Blend: `w_final = clamp((1−α)*w_final + α*w_gnn, 0, 1)`
  * Weekly cron; cache `w_gnn` on edges; feature flag `plasticity.enable_gnn`

### WS7 — Observability & Ops

* **Story PLAS‑70:** Metrics, logs, alerts

  * Metrics: `plasticity_edges_updated`, `avg_w_final`, `defense_reduction_avg`, `job_duration_ms`, `gnn_enabled`
  * Logs with `trace_id` and counts by edge type
  * Alert if job > 10 min or `avg_w_final` shifts > 25% d/d

* **Story PLAS‑71:** Runbook & rollback

  * Rollback plan: keep `w_*` additive; simulator fallback to `avg(n.p)`
  * Toggle via config flags; pause jobs safely

### WS8 — Docs & Handover

* **Story PLAS‑80:** Docs & examples

  * `docs/SPRINT6_PLASTICITY.md`: overview, configs, API examples, Cypher appendix
  * Pasteable queries for analysts

---

## 2) Configuration (defaults)

```yaml
# configs/plasticity.yaml
plasticity:
  consolidation_floor: 0.05       # floor
  recent_alpha: 0.3               # αr
  long_alpha: 0.01                # αl
  metaplastic_m: 0.6              # blend recent vs long
  tactic_bonus_same: 0.08
  tactic_bonus_adjacent: 0.05
  defense_reduction_per_counter: 0.15
  defense_reduction_cap: 0.75
  enable_gnn: false
  alpha_gnn: 0.4                  # blend weight if GNN enabled
  exclude_revoked_by_default: true
  job_batch_size: 2000
  job_txn_pause_ms: 25
  log_level: INFO
```

**Env vars**

* `PLASTICITY_CONFIG=/etc/app/plasticity.yaml`
* `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`

---

## 3) CLI & Scheduling

```bash
# nightly
python -m scripts.plasticity_run --since=1d --apply

# weekly (optional GNN)
python -m scripts.gnn_prior_run --since=7d --apply
```

**Cron examples**

```cron
# Nightly UTC 02:15\ n15 2 * * * /usr/bin/python -m scripts.plasticity_run --since=1d --apply >> /var/log/plasticity.log 2>&1
# Weekly UTC Sun 03:00
0 3 * * 0 /usr/bin/python -m scripts.gnn_prior_run --since=7d --apply >> /var/log/gnn_prior.log 2>&1
```

---

## 4) Algorithmic Steps (job core)

1. **Gather evidence**

   * For each episode, extract unordered technique pairs → `CO_OCCURS` signals (1.0)
   * For each observed `AttackAction -[:NEXT]-> AttackAction`, compute `s = avg(probability)`
2. **EMA updates**

   * `w_recent = (1−αr)*w_recent + αr*signal`
   * `w_long   = (1−αl)*w_long   + αl*signal`
   * `w_hebb   = m*w_recent + (1−m)*w_long`
   * `w_hebb   = max(floor, w_hebb)`
3. **Tactic proximity bonus**

   * `w_imputed += tactic_bonus_same | tactic_bonus_adjacent`
4. **Defense reduction**

   * `defense_reduction = min(per_counter * num_counters, cap)`
5. **Finalize**

   * `w_final = clamp(w_hebb + w_imputed − defense_reduction, 0, 1)`
6. **Optional weekly GNN**

   * Predict `w_gnn` for sparse pairs; blend with weight `alpha_gnn`

---

## 5) Cypher Building Blocks (trimmed for clarity)

**Maintain CO\_OCCURS from episodes (unordered)**

```cypher
MATCH (e:AttackEpisode)
WITH e
MATCH (e)-[:CONTAINS]->(a:AttackAction)
WITH e, collect(DISTINCT a.attack_pattern_ref) AS techs
WHERE size(techs) >= 2
UNWIND techs AS tA
UNWIND techs AS tB
WITH tA, tB WHERE tA < tB
MATCH (i:AttackPattern {stix_id: tA})
MATCH (j:AttackPattern {stix_id: tB})
MERGE (i)-[r:CO_OCCURS]->(j)
ON CREATE SET r.w_hebb=0.0, r.w_recent=0.0, r.w_long=0.0, r.w_imputed=0.0, r.w_final=0.0, r.updated_at=timestamp()
WITH r
SET r.w_recent = 0.7*r.w_recent + 0.3*1.0,
    r.w_long   = 0.99*r.w_long   + 0.01*1.0,
    r.w_hebb   = 0.6*r.w_recent + 0.4*r.w_long,
    r.w_hebb   = CASE WHEN r.w_hebb < 0.05 THEN 0.05 ELSE r.w_hebb END,
    r.updated_at = timestamp();
```

**Update NEXT edges using observed transitions**

```cypher
MATCH (a1:AttackAction)-[n:NEXT]->(a2:AttackAction)
WITH a1.attack_pattern_ref AS i, a2.attack_pattern_ref AS j,
     avg(coalesce(n.probability, n.p, 0.5)) AS s
MATCH (ti:AttackPattern {stix_id: i})
MATCH (tj:AttackPattern {stix_id: j})
MERGE (ti)-[r:NEXT]->(tj)
ON CREATE SET r.w_hebb=0.0, r.w_recent=0.0, r.w_long=0.0, r.w_imputed=0.0, r.w_final=0.0
WITH r, s
SET r.w_recent = 0.7*r.w_recent + 0.3*s,
    r.w_long   = 0.995*r.w_long + 0.005*s,
    r.w_hebb   = 0.6*r.w_recent + 0.4*r.w_long;
```

**Impute tactic bonus & defense reduction; compute w\_final**

```cypher
MATCH (i:AttackPattern)-[:HAS_TACTIC]->(ti:Tactic),
      (j:AttackPattern)-[:HAS_TACTIC]->(tj:Tactic),
      (i)-[r:NEXT]->(j)
WITH r, ti.shortname AS t1, tj.shortname AS t2
WITH r,
  CASE WHEN t1 = t2 THEN $cfg.tactic_bonus_same
       WHEN t1 IN ['initial-access','execution'] AND t2 IN ['persistence','privilege-escalation'] THEN $cfg.tactic_bonus_adjacent
       ELSE 0.0 END AS tactic_bonus
OPTIONAL MATCH (i)<-[:COUNTERS]-(d1:D3fendTechnique)
OPTIONAL MATCH (j)<-[:COUNTERS]-(d2:D3fendTechnique)
WITH r, tactic_bonus, coalesce(count(d1),0)+coalesce(count(d2),0) AS dcount
WITH r, tactic_bonus,
  apoc.number.min($cfg.defense_reduction_per_counter * dcount, $cfg.defense_reduction_cap) AS dred
SET r.w_imputed = coalesce(r.w_imputed, 0.0) + tactic_bonus,
    r.w_final   = apoc.number.clamp(r.w_hebb + r.w_imputed - dred, 0.0, 1.0);
```

**Exclude revoked/deprecated by default**

```cypher
MATCH (i:AttackPattern)-[r]->(j:AttackPattern)
WHERE coalesce(i.revoked,false)=false AND coalesce(i.deprecated,false)=false
  AND coalesce(j.revoked,false)=false AND coalesce(j.deprecated,false)=false
WITH r
/* further updates here */
```

---

## 6) API Specs (read‑only)

**`GET /v1/analytics/weights/next/{technique_id}`**

* **Query params:** `limit` (default 20), `include_revoked=false`
* **Response (200):**

```json
{
  "technique_id": "T1059",
  "successors": [
    {
      "technique_id": "T1106",
      "w_final": 0.78,
      "components": {"w_hebb": 0.66, "w_imputed": 0.20, "defense_reduction": 0.08, "w_gnn": 0.00},
      "updated_at": 1723959237000
    }
  ]
}
```

* **Errors:** 404 unknown technique; 400 invalid id

**`GET /v1/analytics/weights/cooccurs/{technique_id}`**

* Same shape as above; key `cooccurs` instead of `successors`

**Perf budgets:** P95 < 200ms for top‑20 on prod‑like dataset

---

## 7) Tests — Traceability Matrix

| Req/Acceptance                | Test ID       | Type        | Description                           |
| ----------------------------- | ------------- | ----------- | ------------------------------------- |
| EMA updates compute correctly | UT‑EMA‑01     | Unit        | Verify recent/long EMA & blend `m`    |
| Consolidation floor applied   | UT‑FLOOR‑01   | Unit        | `w_hebb ≥ floor` when evidence exists |
| Clamp bounds \[0,1]           | UT‑CLAMP‑01   | Unit        | Clamp function tests                  |
| Tactic bonus applied          | UT‑TACTIC‑01  | Unit        | Same/adjacent tactic bonuses          |
| Defense reduction capped      | UT‑DEF‑01     | Unit        | Per‑counter & cap logic               |
| Revoked excluded by default   | IT‑REV‑01     | Integration | Graph with revoked nodes excluded     |
| CO\_OCCURS populated          | IT‑COO‑01     | Integration | Tiny episode set creates pairs        |
| NEXT updated from flows       | IT‑NEXT‑01    | Integration | Transition signals reflected          |
| w\_final computed             | IT‑FINAL‑01   | Integration | Components → final weight             |
| API latency within budget     | AT‑API‑LAT‑01 | API         | P95 < 200ms for top‑20                |
| Simulator prefers w\_final    | ST‑SIM‑01     | System      | Selection logic honors weights        |

---

## 8) Performance Plan

* Batch updates (e.g., 2k rels/chunk) with periodic commits
* Ensure indexes on `AttackPattern(stix_id)` and relationship lookups
* Avoid cross‑product pair explosions with early `WHERE tA < tB`
* Use projections for tactic joins (pre‑materialize tactic shortnames if needed)
* Perf target: **≤ 5 minutes** for **100k actions / 10k episodes**

---

## 9) Observability

* **Metrics (Prometheus/OpenTelemetry):**

  * `plasticity_edges_updated{type="NEXT|CO_OCCURS"}` counter
  * `plasticity_avg_w_final` gauge
  * `plasticity_defense_reduction_avg` gauge
  * `plasticity_job_duration_ms` histogram
  * `plasticity_gnn_enabled` gauge
* **Logs:** per run `trace_id`, counts updated per type, warnings on skips
* **Alerts:** job duration > 10m; `avg_w_final` day‑over‑day shift > 25%

---

## 10) Risk Log & Mitigations

| Risk                             | Impact | Likelihood | Mitigation                                  |
| -------------------------------- | ------ | ---------- | ------------------------------------------- |
| Pair explosion on large episodes | High   | Med        | Cap episode size; sample; windowing         |
| Over‑penalizing via defense      | Med    | Med        | Cap at 0.75; add per‑domain override        |
| Tactic bonus mis‑calibration     | Med    | Med        | A/B on dev; config‑driven; add unit tests   |
| GNN false positives              | Med    | Low        | Keep opt‑in; blend weight `alpha_gnn ≤ 0.4` |
| API latency regressions          | Med    | Low        | Add indexes; response caching; top‑K only   |

---

## 11) RACI & Resourcing

* **DRI (Engineering):** @owner‑eng
* **Data/ML (GNN):** @owner‑ml
* **Product Acceptance:** @owner‑pm
* **QA:** @owner‑qa

---

## 12) Definition of Ready / Done

**DoR**

* Sample episodes & actions available; D3FEND mappings present
* Config approved; flags defined; perf environment ready

**DoD**

* All acceptance tests green; perf budgets met
* Runbook complete; metrics/alerts live
* Simulator/FlowBuilder reading `w_final` behind feature flag
* Docs published (`docs/SPRINT6_PLASTICITY.md`)

---

## 13) Timeline (suggested)

**Week 1**

* **Days 1–2:** WS1 (data model, indices, migration backfill); WS2 (CO\_OCCURS EMA)
* **Days 3–4:** WS2 (NEXT updates, bonuses, defense, final); WS3 (Simulator + FlowBuilder integration)
* **Day 5:** WS4 (APIs) + WS5 (unit tests); initial perf pass

**Week 2**

* **Days 6–7:** WS5 (integration/system tests), tuning & flags; WS7 (metrics/alerts)
* **Days 8–9:** WS6 (optional GNN baseline & blend)
* **Day 10:** WS8 (docs), bake, QA sign‑off, toggle ready

---

## 14) Rollout & Rollback

* **Rollout:** enable nightly job in dry‑run → verify metrics → flip `--apply`; keep simulator on fallback for 24h; then enable `w_final` read path
* **Rollback:** disable jobs; flip simulator/flowbuilder flags to fallback; weights remain on edges but unused

---

## 15) Attachments / Artifacts to Deliver

* `scripts/plasticity_run.py` (CLI + job), cron examples
* `scripts/gnn_prior_run.py` (optional)
* Updated Simulator & Flow Builder modules
* API routes (`/v1/analytics/weights/...`)
* Tests (unit + integration + API)
* `docs/SPRINT6_PLASTICITY.md`
* Config file `configs/plasticity.yaml`

---

### TL;DR

Use Hebbian EMA (recent + long) with a consolidation floor to maintain evidence‑weighted edges for `NEXT` and `CO_OCCURS`. Add tactic proximity bonus and D3FEND‑based defense reduction; optionally blend a weekly GNN prior for sparse pairs. Consumers (Simulator/Flow Builder) prefer `w_final`. APIs provide observable breakdowns of `w_final` and components.
