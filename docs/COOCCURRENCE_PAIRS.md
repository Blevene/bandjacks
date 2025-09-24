## Co-occurrence (Pairs) — Method and UI Reference

This document explains how Bandjacks computes technique co-occurrence pairs, the meaning of filters, and the UI columns shown in the Pairs Explorer.

### Data model (source of truth)
- Episodes: `AttackEpisode` nodes
- Actions: `AttackAction` nodes with `attack_pattern_ref` → technique STIX ID
- Technique: `AttackPattern` nodes (name, `stix_id`, `external_id` a.k.a. T-code)
- Linkage: `(:AttackEpisode)-[:CONTAINS]->(:AttackAction)`; tactics via `(:AttackPattern)-[:HAS_TACTIC]->(:Tactic)`

During computation, each episode contributes a set of distinct techniques (deduplicated within an episode).

### How pairs are formed
1. For every episode, collect the distinct technique IDs used in that episode.
2. Generate unordered pairs (A,B) with A < B to avoid duplicates.
3. Count how many episodes contain A, how many contain B, and how many contain both together.

### Filters (Global co-occurrence endpoint)
- min_support: Minimum number of episodes where each technique appears individually.
  - Both A and B must satisfy support ≥ min_support.
- min_episodes (min_episodes_per_pair): Minimum number of episodes where A and B co-occur together.
- limit: Maximum number of returned pairs after sorting by the primary metric (NPMI in backend, additional UI sorting available).

Top co-occurrence (aggregate pair frequency) endpoint also supports:
- tactic (optional): Only consider pairs where at least one technique maps to the selected tactic.
- min_episode_size (optional): Minimum number of distinct techniques in an episode to be counted.

### Metrics (how they are calculated)
Let:
- N = total number of episodes considered
- support_A = episodes containing technique A
- support_B = episodes containing technique B
- count_AB = episodes containing both A and B
- p(A) = support_A / N
- p(B) = support_B / N
- p(A,B) = count_AB / N

- Confidence P(B|A) = count_AB / support_A (not shown in the pairs table by default; available in API)
- Lift = p(A,B) / (p(A)*p(B)) = (count_AB * N) / (support_A * support_B)
- PMI (Pointwise Mutual Information) = log2( p(A,B) / (p(A)*p(B)) )
- NPMI (Normalized PMI) = PMI / ( -log2( p(A,B) ) ), range [-1, 1]
- Jaccard = count_AB / (support_A + support_B - count_AB)

Notes:
- Pairs are computed over distinct techniques per episode (duplicate actions in the same episode do not inflate counts).
- Global endpoint uses raw counts (no smoothing). Actor-scoped endpoint applies Laplace-type smoothing for small-N; that is documented separately.

### UI columns (Pairs Explorer)
- Technique A / Technique B
  - Name
  - T-code (external_id) — e.g., T1007
  - STIX ID — e.g., attack-pattern--…
- Count — number of episodes where A and B appear together
- Lift — higher than 1 indicates positive association beyond chance
- PMI / NPMI — PMI strength, with NPMI normalized to [-1, 1]
- Jaccard — overlap ratio of A and B supports

### Interpreting filters
- Increasing min_support removes rarely observed techniques (reducing noise, improving stability of metrics)
- Increasing min_episodes removes weakly supported pairs (reduces spurious associations)
- Sorting:
  - NPMI: emphasizes de-biased association strength (recommended)
  - Lift: emphasizes multiplicative association; can be large with low supports
  - Count: emphasizes frequent pairs; may bias towards popular techniques

### API endpoints used by the UI
- Global metrics (Pairs Explorer): `POST /v1/analytics/cooccurrence/global`
  - Body: `{ min_support?: number, min_episodes_per_pair?: number, limit?: number }`
  - Returns each pair with: `technique_a/b`, `name_a/b`, `external_id_a/b`, `count`, `support_a/b`, `lift`, `pmi`, `npmi`, `jaccard`, plus totals
- Top pairs (frequency, optional tactic): `GET /v1/analytics/cooccurrence/top`
  - Params: `limit`, `min_episode_size`, `tactic`

### Caveats and best practices
- Use NPMI as the primary ranking to avoid popularity bias; review Count to ensure adequate evidence.
- Apply reasonable minimums (e.g., min_support ≥ 2, min_episodes ≥ 2) to avoid unstable pairs.
- For tactic-specific work, use the tactic filter or pre-filter the set by tactic.

### Future extensions (not yet in this document)
- Actor-scoped co-occurrence with small-sample smoothing
- Bundle (itemset) mining with coverage overlays
- Time-windowed co-occurrence and trending pairs
- Statistical significance tests (e.g., Fisher’s exact with multiple-testing correction)


