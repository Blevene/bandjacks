# Actor Co-occurrence

This document explains actor-scoped co-occurrence in Bandjacks: pairs and bundles restricted to a specific `IntrusionSet`, with small-sample smoothing.

## Data and scope
- Actor: `IntrusionSet` (`stix_id`)
- Episodes attributed to the actor: `(:AttackEpisode)-[:ATTRIBUTED_TO]->(:IntrusionSet)`
- From these episodes, collect distinct techniques by episode and compute pair counts as in global pairs

## Smoothing and metrics
Given small N per actor, we apply stabilizers:
- Confidence (P(B|A)): `(count_AB + 0.5) / (support_A + 1)`
- Lift: expected uses `(support + 1)` and `(N + 2)`
- PMI/NPMI: probabilities use `(+0.5)` numerator and `(N + 1)` denominator
- Jaccard: unchanged (set overlap)

Reasons:
- Avoid zero-probabilities
- Reduce variance with limited samples

## Endpoint
- `POST /v1/analytics/cooccurrence/actor`
  - Body: `intrusion_set_id`, `min_support` (per-technique), `metric_filter` (`npmi|lift|confidence`)
  - Returns:
    - `top_pairs`: technique A/B with Name, T-code, STIX, Count, Conf A→B, Conf B→A, Lift, PMI, NPMI, Jaccard
    - `signature_bundles`: frequent itemsets with names, support, confidence, lift, tactics
    - `total_episodes`, `total_techniques`

## UI (Actor Insights)
- Inputs: actor STIX ID, min_support, sort metric
- Sections: Top pairs table; Signature bundles table

## Interpretation
- Use NPMI/Lift to identify actor-specific hallmark combinations
- Bundles highlight playbook-like sets; check tactic tags for diversity
- Validate evidence (counts) before operationalizing detections

## Caveats
- Smoothing introduces slight bias at very large N (negligible in practice)
- Attribution completeness and accuracy impact results

## Roadmap
- Actor similarity view (TF-IDF cosine) is already available via `POST /v1/analytics/similarity/actors` (separate doc)
- Time segmentation by campaign or period
- Drill-through to episodes list for selected pairs
