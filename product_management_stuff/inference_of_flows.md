Awesome — here’s a single, cohesive execution plan that merges **(A) sequence inference from co-occurrence flows** and **(B) LLM-judge reasoning**, with concrete stubs, APIs, tasks, and acceptance checks you can track in Sprint/Issue tooling.

---

# Bandjacks — Cohesive Execution Plan (Sequences + LLM Judge)

## Objectives

1. Build a **Probabilistic Temporal Graph (PTG)** over ATT\&CK techniques per intrusion set.
2. Use the PTG to **simulate** likely progressions, quantify **choke points**, and plan **interdictions**.
3. Integrate an **LLM Judge** (via LiteLLM) to adjudicate ambiguous pair directions using grounded evidence from our KG + OpenSearch.
4. Keep full **provenance** and **safety rails** (constraints, costs, tests).

---

## Architecture Additions (minimal)

### Data Artifacts

* `:SequenceModel` (node) — `{ scope: "intrusion-set"|"global", version, created_at, params, evidence_hashes[] }`
* `(:AttackPattern)-[:NEXT_P {p, features, judge?, observed?}]->(:AttackPattern)` — **normalized** transition probabilities.
* `JudgeVerdict` (doc in OpenSearch or Postgres) — `{ti, tj, verdict, confidence, evidence_ids[], rationale, model, ts, retrieval_hash}`

### APIs (OpenAPI-ready)

* `POST /v1/sequence/infer` — build/refresh PTG; optional `use_judge=true`.
* `GET /v1/sequence/model/{scope_id}` — fetch transitions and params.
* `POST /v1/simulate/rollout` — Monte Carlo path sampling.
* `POST /v1/simulate/mdp` — attacker adaptation policy.
* `POST /v1/analyze/chokepoints` — betweenness, dominators, min-cut, interdiction.
* `POST /v1/sequence/judge` — run LLM judge for (ti,tj) pairs; returns verdicts.
* `GET /v1/sequence/provenance/{ti}/{tj}` — evidence pack + judge history.

---

## Execution Plan by Workstream

### EPIC 1 — Pairwise Statistics & PTG

**Goal:** Turn 165 AttackFlows into per-intrusion-set transition probabilities.

**Stories & Tasks**

1. **Flow normalizer**

   * T1: Extract technique sets per flow → `{flow_id, intrusion_set_id, techniques[]}`.
   * T2: Optional: ingest any existing `NEXT` edges as `observed=true`.

2. **Pair counters & conditionals**

   * T3: Compute counts `c_ij`, Laplace-smoothed `p(j|i)`, asymmetry.
   * T4: Persist per intrusion set + global.

3. **Priors & constraints**

   * T5: Map techniques → primary tactics; define `tactic_prior(i,j) ∈ [0,1]`.
   * T6: Enforce sub-tech hierarchy & domain constraints (hard rules).

4. **PTG assembly**

   * T7: Feature fusion (stats + priors + software bias + observed).
   * T8: Softmax normalization → `NEXT_P` edges with `{p,features}`.
   * T9: Store `:SequenceModel` node (scope, params, evidence set).

**Acceptance**

* A1: For a chosen intrusion set, `GET /v1/sequence/model/{id}` returns ≤K outgoing edges per node, `Σ p = 1 ± 1e-6`.
* A2: Held-out flows have higher average path likelihood under PTG than a uniform baseline.

**Code stub (T7/T8)**

```python
def build_ptg(flow_sets, priors, soft_bias, observed_next, kmax=5, params=None):
    pairs, tech_counts = pair_counts(flow_sets)
    edges = {}
    for i in pairs:
        scores = []
        for j, c in pairs[i].items():
            pcond = (c+1) / (tech_counts[i] + len(tech_counts))
            w = (params.alpha*logit(pcond)
               + params.beta*priors.tactic(i,j)
               + params.delta*soft_bias(i,j)
               + params.epsilon*(1 if observed_next(i,j) else 0))
            scores.append((j, w, {"pcond":pcond}))
        # normalize with softmax and keep top-k
        probs = softmax(scores)[:kmax]
        edges[i] = [{"to":j, "p":p, "features":feat} for (j,p,feat) in probs]
    return edges
```

---

### EPIC 2 — LLM Judge Integration (LiteLLM)

**Goal:** Resolve ambiguous directions with grounded, citable verdicts.

**Stories & Tasks**

1. **Evidence retrieval**

   * T10: Build evidence pack per pair *(ti,tj)*: stats, priors, graph hints, top-k OpenSearch snippets (IDs + text + sources).

2. **Judge service**

   * T11: LiteLLM router config (primary + fallback models).
   * T12: Strict schema output (`verdict`, `confidence`, `evidence_ids[]`, `rationale_summary`).
   * T13: Guardrails: reject outputs with missing citations; retry once; else `unknown`.

3. **Fusion layer**

   * T14: Replace `entail` feature with judge score `J_ij ∈ [-1,1]`.
   * T15: Ensemble option (N calls / multiple models) → average + entropy.
   * T16: Cache `(ti,tj,retrieval_hash)` verdicts.

4. **Triage**

   * T17: Only judge pairs with `|p(j|i)-p(i|j)| < τ` and `c_ij ≥ c_min`.

**Acceptance**

* A3: `/v1/sequence/judge` over 100 ambiguous pairs returns JSON-valid verdicts with ≥90% having ≥1 evidence ID.
* A4: PTG AUROC vs. analyst labels improves over stats-only baseline (tracked on a 20–50 pair gold set).

**Code stub (T12/T14)**

```python
def judge_pair(ti, tj, pack, client):
    prompt = {"system": SYSTEM_PROMPT, "user": json.dumps(pack)}
    out = client.chat(prompt, response_format="json")
    v = parse_and_validate(out)
    if not v["evidence_ids"] and v["verdict"] != "unknown":
        v["verdict"], v["confidence"] = "unknown", 0.0
    return v

def judge_to_score(v):
    if v["verdict"] == "i->j": return +v["confidence"]
    if v["verdict"] == "j->i": return -v["confidence"]
    return 0.0
```

---

### EPIC 3 — Simulation & Interdiction

**Goal:** Use PTG for rollouts, attacker adaptation, and choke-point analysis.

**Stories & Tasks**

1. **Monte Carlo rollouts**

   * T18: Sample paths with depth cap; compute success probability to terminals (tactics/techniques).

2. **MDP policy**

   * T19: Value iteration over PTG; include mitigation transforms (remove/penalize node or incoming edges).

3. **Choke points**

   * T20: Betweenness centrality (node/edge) on top-K path union.
   * T21: Dominator analysis S→T; min-cut (node/edge).
   * T22: Budgeted interdiction (greedy max-impact).

4. **APIs**

   * T23: `/v1/simulate/rollout`, `/v1/simulate/mdp`.
   * T24: `/v1/analyze/chokepoints` (returns betweenness, dominators, min-cut, recommendations).

**Acceptance**

* A5: Rollout results are stable across seeds (±2% on success prob with n≥5k).
* A6: Turning on mitigation **reduces** success probability; top paths shift (measurable delta).
* A7: Dominators/min-cut return non-empty sets on synthetic graphs; results verified against a known toy.

**Code stub (T18/T20)**

```python
def simulate_rollouts(G, starts, terminals, n=5000, depth=8):
    succ = 0; paths = Counter()
    for _ in range(n):
        node = random.choice(starts); path=[node]
        for _ in range(depth):
            if node in terminals: break
            nxt = sample(G, node)  # by P(j|i)
            if not nxt: break
            path.append(nxt); node=nxt
        if node in terminals: succ += 1; paths[tuple(path)] += 1
    return succ/n, paths

def choke_points(G, S, T, k_paths=50):
    H = union_of_top_k_paths(G, S, T, k=k_paths)
    return betweenness(H), dominators(H, S), min_node_cut(H, S, T)
```

---

### EPIC 4 — Provenance, Governance, Cost Controls

**Goal:** Make everything auditable and affordable.

**Stories & Tasks**

* T25: Store exact **evidence pack hash** used for each judged pair; `/v1/sequence/provenance/{ti}/{tj}` returns snippet IDs + sources.
* T26: Rate limits + budget caps for judge calls per job; caching; batch mode.
* T27: Flags: `include_revoked`, `include_provisional`, depth caps, top-K caps per node.
* T28: Metrics: cost per 100 pairs, latency, cache hit rate, verdict entropy.

**Acceptance**

* A8: Provenance endpoint shows evidence IDs and model meta.
* A9: Cost ceiling respected (rejects job with clear error if projected cost > budget).

---

## Backlog (stretch)

* B1: **Analyst constraints** UI: mark “Ti never precedes Tj” → add to rules.
* B2: **Platform-aware PTGs** (Windows/Linux/macOS).
* B3: **Time-sliced PTGs** (by year/quarter) to detect drift.

---

## Tracking (suggested tickets)

* **SEQ-01** Flow normalizer (T1–T2)
* **SEQ-02** Pair stats + priors (T3–T6)
* **SEQ-03** PTG build + store (T7–T9)
* **JDG-01** Retrieval pack builder (T10)
* **JDG-02** Judge service via LiteLLM (T11–T13)
* **JDG-03** Fusion + cache + triage (T14–T17)
* **SIM-01** Rollouts (T18)
* **SIM-02** MDP + mitigations (T19)
* **SIM-03** Choke points + interdiction (T20–T22)
* **API-01** Sequence endpoints (T23–T24)
* **GOV-01** Provenance + budgets + metrics (T25–T28)

---

## Test Matrix (CI)

* **Unit**: pair counts, priors, softmax normalization, cache keys, JSON schema for judge outputs.
* **Integration**: build PTG on a 10-flow fixture; confirm probabilities; judge improves AUROC vs. baseline.
* **Simulation**: success prob decreases with mitigation; top path set changes.
* **Governance**: provenance returns evidence; cost cap enforced.

---

## Defaults & Guardrails

* `kmax_outgoing=5`, `depth_max=8`, `cooccur_min=3`, `ambiguity_tau=0.15`.
* Judge only on ambiguous pairs; **must cite evidence IDs** or return `unknown`.
* Enforce hard constraints (hierarchy, invalid SRO types); run cycle breaker if needed.
* Version everything: `{sequence_model_version, created_at, flow_ids_used, params}`.
