## Co-occurrence (Pairs) — Methodology, Filters, Metrics, and UI Reference

This document describes how Bandjacks computes technique co‑occurrence (pairs), what each filter means, how metrics are derived, and how the UI maps to API endpoints.

---

### 1) Graph data model (source of truth)
- Episodes: `AttackEpisode`
- Actions: `AttackAction` with property `attack_pattern_ref` (technique STIX ID)
- Techniques: `AttackPattern` with `stix_id`, `name`, and `external_id` (ATT&CK T‑code like T1007)
- Tactics: `(:AttackPattern)-[:HAS_TACTIC]->(:Tactic)`
- Core linkage: `(:AttackEpisode)-[:CONTAINS]->(:AttackAction)`

Important schema properties we leverage:
- Distinct techniques per episode: within a single `AttackEpisode`, repeated actions for the same technique are de‑duplicated.
- Time fields (available for future filtering): `AttackAction.timestamp`, `AttackEpisode.created`.

---

### 2) Pair formation and counting
For each episode:
1. Collect the set of distinct technique IDs present (from `attack_pattern_ref`).
2. Generate all unordered 2‑combinations (A,B) with a canonical order (A < B) to avoid duplicates.
3. Maintain global counters across episodes:
   - `support_A`: episodes containing A
   - `support_B`: episodes containing B
   - `count_AB`: episodes containing both A and B (co‑occurrence)
4. `N`: total episodes considered in the scope of the query

Notes:
- Counting is episode‑level (not action‑level). Multiple actions of the same technique in one episode still count once.
- Technique names and T‑codes are looked up from `AttackPattern` for display (`name`, `external_id`).

---

### 3) Filters (Global co‑occurrence endpoint)
- `min_support` (per‑technique):
  - Minimum number of episodes where each technique (A and B) appears individually.
  - Purpose: remove ultra‑rare techniques that can produce unstable metrics.
- `min_episodes_per_pair` (pair co‑occurrence):
  - Minimum number of episodes where A and B co‑occur together.
  - Purpose: filter out weakly supported pairs.
- `limit`:
  - Maximum number of pairs returned after computing metrics and formatting.

Top pairs (frequency view) supports additional filters:
- `tactic` (optional): Only count pairs where at least one technique maps to the selected tactic.
- `min_episode_size` (optional): Ignore episodes with fewer than this many distinct techniques (helps avoid trivial or low‑signal episodes).

Interpretation tips:
- Increasing `min_support` improves metric stability by excluding rare techniques.
- Increasing `min_episodes_per_pair` reduces spurious associations with low evidence.

---

### 4) Metrics (definitions and properties)
Let:
- `N` = total episodes considered
- `support_A` = episodes containing technique A
- `support_B` = episodes containing technique B
- `count_AB` = episodes containing both A and B
- `p(A)` = `support_A / N`
- `p(B)` = `support_B / N`
- `p(A,B)` = `count_AB / N`

Derived metrics:
- Confidence: `P(B|A) = count_AB / support_A`
  - Asymmetric; measures conditional probability of B given A.
- Lift: `lift(A,B) = p(A,B) / (p(A) * p(B)) = (count_AB * N) / (support_A * support_B)`
  - > 1 indicates positive association beyond chance; < 1 indicates negative association.
- PMI (Pointwise Mutual Information): `PMI(A,B) = log2( p(A,B) / (p(A) * p(B)) )`
  - Unbounded above; inflates with very small probabilities; use alongside supports.
- NPMI (Normalized PMI): `NPMI = PMI / ( -log2( p(A,B) ) )`
  - Range [-1, 1]; robust across popularity; recommended primary rank metric.
- Jaccard: `count_AB / (support_A + support_B - count_AB)`
  - Measures overlap of supports.

Considerations:
- Global endpoint uses raw counts (no smoothing). Actor‑scoped analysis applies Laplace‑style adjustments for small sample sizes (see below).
- Always sanity‑check `count_AB` and supports when interpreting large lift/PMI values.

---

### 5) Actor‑scoped co‑occurrence (how it differs)
When scoped to a single `IntrusionSet`, we compute the same counts but apply small‑sample stabilizers:
- Confidence with pseudocounts: `(count_AB + 0.5) / (support_A + 1)`
- Lift with Laplace smoothing: expected probabilities use `(support + 1)` and `(N + 2)`
- PMI with additive smoothing: `p(A) = (support_A + 0.5) / (N + 1)` etc.

Why: smaller `N` per actor can make raw estimates unstable; pseudocounts reduce variance and avoid zero‑division.

---

### 6) UI: Pairs Explorer (columns and controls)
Columns:
- Technique A / B
  - Name (`AttackPattern.name`)
  - T‑code (`AttackPattern.external_id`, e.g., T1007)
  - STIX ID (`AttackPattern.stix_id`)
- Count (`count_AB`)
- Lift, PMI, NPMI, Jaccard

Controls:
- `min_support`, `min_episodes_per_pair`, `limit` (fetch‑time filters)
- Sorting (client): by NPMI (recommended), Lift, Count

---

### 7) UI: Conditional Explorer (P(B|A))
- Input A: Technique via STIX ID or name (autocomplete backed by `/v1/search/ttx`)
- Output table for co‑techniques B with:
  - Name, T‑code, STIX ID
  - Episodes with A, co‑occurrence count
  - `P(B|A)`
- Client‑side filters: `limit`, `min_count`, `min_p`, sort (probability/count/name), text search
- Backend: `GET /v1/analytics/cooccurrence/conditional?technique_id=A&limit=L` (returns external IDs)

---

### 8) UI: Actor Insights (overview)
- Inputs: `intrusion_set_id`, `min_support`, metric (`npmi|lift|confidence`)
- Top pairs for the actor (with Name, T‑code, STIX ID, Count, Conf A→B, Conf B→A, Lift, PMI, NPMI, Jaccard)
- Signature bundles: technique chips, support, confidence, lift, tactic tags
- Backend: `POST /v1/analytics/cooccurrence/actor`

---

### 9) UI: Bundles Explorer (overview)
- Inputs: optional `intrusion_set_id`, `min_support`, `min_size`, `max_size`
- Output: bundles with technique chips (names), size, support, confidence, lift, tactics, D3FEND coverage% and gap count
- Backend: `POST /v1/analytics/cooccurrence/bundles`
  - Coverage currently uses `(:D3fendTechnique)-[:COUNTERS]->(:AttackPattern)`; `DETECTS` relationships are not required.

---

### 10) UI: Bridging Techniques (overview)
- Input: `min_actors` (default 3)
- Output: techniques sorted by number of distinct actors using them, with tactics and a sample of actors
- Backend: `GET /v1/analytics/cooccurrence/bridging`

---

### 11) API quick reference (Pairs)
- Global pairs: `POST /v1/analytics/cooccurrence/global`
  - Body:
    ```json
    { "min_support": 2, "min_episodes_per_pair": 2, "limit": 100 }
    ```
  - Returns for each pair:
    ```json
    {
      "technique_a": "attack-pattern--…",
      "technique_b": "attack-pattern--…",
      "name_a": "PowerShell",
      "name_b": "Ingress Tool Transfer",
      "external_id_a": "T1059.001",
      "external_id_b": "T1105",
      "count": 44,
      "support_a": 120,
      "support_b": 80,
      "lift": 1.72,
      "pmi": 0.83,
      "npmi": 0.41,
      "jaccard": 0.15
    }
    ```

---

### 12) Known limitations and best practices
- Popularity bias: Count favors popular techniques; use NPMI or Lift to mitigate.
- Small sample sizes: For actors with few episodes, prefer actor endpoint (uses smoothing) or raise supports.
- Tactic filter semantics: a pair is included if either technique has the selected tactic.
- Episode size filter: set `min_episode_size` > 2 to focus on richer episodes.
- Time‑windowing: timestamps exist, but time filters are not wired into endpoints yet (planned).

---

### 13) Performance and scalability
- Current endpoints compute aggregates on the fly in Neo4j for the requested scope; keep reasonable limits.
- For very large graphs, consider caching common queries and precomputing popular scopes.

---

### 14) Roadmap
- Add time filters (`start`, `end`) to endpoints
- Significance testing (Fisher’s exact test + Benjamini–Hochberg correction)
- Community detection on co‑occurrence graph; surfacing cluster labels
- Platform segmentation once platform attributes/edges are available



