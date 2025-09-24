# Conditional Co-occurrence P(B|A)

This document explains the conditional co-occurrence view in Bandjacks: given technique A, list co-techniques B with P(B|A) and evidence, aligned with the global pairs methodology.

## Data and scope
- Uses the same graph entities as pairs: `AttackEpisode`, `AttackAction`, `AttackPattern`
- For a given technique A (by `stix_id`), build the set of episodes containing A
- Within those episodes, enumerate other techniques B and count co-occurrence

## Computation
Let:
- `episodes_A` = episodes containing A
- `totalA` = |episodes_A|
- For each B != A:
  - `co_count` = number of episodes in `episodes_A` that also contain B
  - `P(B|A) = co_count / totalA` (0 if `totalA = 0`)

Notes:
- Co-occurrence counts are per episode (deduplicated within episode)
- No smoothing is applied in the conditional endpoint (direct ratio)

## Endpoint
- `GET /v1/analytics/cooccurrence/conditional`
  - Params: `technique_id` (A), `limit`
  - Returns: for each B
    - `co_technique`, `co_technique_name`, `co_technique_external_id`
    - `episodes_with_given` (= totalA)
    - `co_occurrence_count` (= co_count)
    - `probability` (= P(B|A))

## UI (Conditional Explorer)
- Inputs:
  - Technique A: STIX ID or name via autocomplete (backed by `/v1/search/ttx`)
  - Filters (client-side): `limit`, `min_count`, `min_p` (probability), `sort` (probability/count/name), free-text search
- Table columns:
  - Co-technique: Name, T-code (external_id), STIX ID
  - Episodes with A (totalA)
  - Co-occurrence (co_count)
  - P(B|A)

## Interpretation
- Higher P(B|A) suggests B commonly appears when A appears
- Check `co_occurrence_count` to ensure sufficient evidence
- Use in hunting pivots: given an A sighting, prioritize high P(B|A) techniques to investigate next

## Caveats
- Asymmetric: P(B|A) != P(A|B)
- Sensitive to `totalA`: if A is rare, P(B|A) can be unstable; consider raising evidence thresholds (min_count) or using the global pairs view

## Roadmap
- Optional time window filters (by episode or action timestamps)
- Significance testing (e.g., confidence intervals or Bayesian posteriors)
- Batch mode: compute P(B|A) for a set of A techniques
