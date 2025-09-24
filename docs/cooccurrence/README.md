# Co-occurrence Analytics

This section documents Bandjacks co-occurrence analytics. Start with the overview below and drill into each analysis.

- Pairs (global): `COOCCURRENCE_PAIRS.md`
- Conditional P(B|A): `COOCCURRENCE_CONDITIONAL.md`
- Actor co-occurrence: `COOCCURRENCE_ACTOR.md`
- Bundles (frequent itemsets): `COOCCURRENCE_BUNDLES.md`
- Bridging techniques: `COOCCURRENCE_BRIDGING.md`
- Table of contents: `COOCCURRENCE_TOC.md`

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
