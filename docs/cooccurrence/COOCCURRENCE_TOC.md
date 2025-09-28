# Co-occurrence Analytics — Table of Contents

Bandjacks provides several co-occurrence analytics to understand how ATT&CK techniques relate across episodes and actors. Start here and jump to the detailed guides.

- Overview and Pairs (global)
  - See: `COOCCURRENCE_PAIRS.md` — methodology, filters (`min_support`, `min_episodes_per_pair`), metrics (Lift, PMI, NPMI, Jaccard), UI mapping
- Conditional co-occurrence P(B|A)
  - See: `COOCCURRENCE_CONDITIONAL.md` — conditioning on a technique A to rank B by P(B|A), client filters, autocomplete
- Actor co-occurrence
  - See: `COOCCURRENCE_ACTOR.md` — actor-scoped pairs with small-sample smoothing (Laplace), signature bundles
- Bundles (frequent itemsets)
  - See: `COOCCURRENCE_BUNDLES.md` — bundle mining, metrics (support, confidence, lift), D3FEND coverage overlay
- Bridging techniques
  - See: `COOCCURRENCE_BRIDGING.md` — techniques used by many actors; actor_count and average importance

Frontend routes
- `/analytics/cooccurrence` (landing)
- `/analytics/cooccurrence/pairs`
- `/analytics/cooccurrence/conditional`
- `/analytics/cooccurrence/actors`
- `/analytics/cooccurrence/bundles`
- `/analytics/cooccurrence/bridging`

Backend endpoints (prefix `/v1`)
- `POST /analytics/cooccurrence/global`
- `GET /analytics/cooccurrence/conditional`
- `POST /analytics/cooccurrence/actor`
- `POST /analytics/cooccurrence/bundles`
- `GET /analytics/cooccurrence/bridging`

Shared best practices
- Prefer NPMI to mitigate popularity bias; verify evidence with counts
- Raise `min_support` and `min_episodes_per_pair` to improve stability
- Use tactic filter or episode size constraints to focus on high-signal subsets
- For actors with few episodes, prefer the actor endpoint (smoothing enabled)

Planned enhancements
- Time-filtered variants across endpoints
- Significance testing and multiple-testing correction
- Community detection on the co-occurrence graph
