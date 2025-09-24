# Co-occurrence Bundles (Frequent Itemsets)

This document explains how Bandjacks extracts frequently co-occurring technique bundles and how to interpret the metrics and coverage.

## Data and scope
- From each `AttackEpisode`, use the set of distinct techniques present
- Generate itemsets of size `k` (`min_size <= k <= max_size`) and count their supports across episodes
- Optionally scope to an `IntrusionSet` to get actor-specific bundles

## Metrics
- Support: number of episodes containing all techniques in the bundle
- Confidence: `support(bundle) / min_individual_support` (least frequent technique in the bundle)
- Lift: compares observed joint occurrence to expectation from individual probabilities
- Tactics: union of tactic shortnames for the techniques in the bundle

## Coverage (D3FEND overlay)
- For techniques in a bundle, compute coverage using `(:D3fendTechnique)-[:COUNTERS]->(:AttackPattern)`
- Coverage% = covered techniques / total techniques in bundle (and aggregated across bundles)
- Note: `DETECTS` edges are not required; D3FEND is used as a proxy for defensive coverage

## Endpoint
- `POST /v1/analytics/cooccurrence/bundles`
  - Body: `intrusion_set_id?`, `min_support`, `min_size`, `max_size`
  - Returns: bundles with `technique_names`, `size`, `support`, `confidence`, `lift`, `tactics`, `detection_coverage`, `gap_count`; plus aggregate coverage stats

## UI (Bundles Explorer)
- Inputs: optional actor, min_support, min_size, max_size
- Table shows technique chips, size, support/confidence/lift, tactics, D3FEND coverage and gaps

## Interpretation
- High lift suggests unexpectedly frequent co-usage beyond chance
- Confidence captures bundle reliability; ensure support is adequate
- Use tactic diversity to infer multi-stage patterns (e.g., initial-access + execution)

## Caveats
- Combinatorial growth: high `max_size` can be expensive; keep ranges modest
- Coverage via D3FEND differs from detection coverage; treat as guidance, not ground truth

## Roadmap
- Time-windowed bundle mining
- Statistical validation of itemsets
- Coverage overlays via `DETECTS` when available
