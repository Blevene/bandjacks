# Bridging Techniques

This document explains the bridging techniques view: techniques used by many actors, which are strong candidates for prioritized detection and monitoring.

## Definition
- A technique is considered “bridging” if it appears across multiple distinct `IntrusionSet` actors
- We count distinct actors and episodes using each technique
- Average importance = episodes per actor (proxy for typical usage intensity)

## Endpoint
- `GET /v1/analytics/cooccurrence/bridging?min_actors=K`
  - Returns: for each technique
    - `technique_id`, `technique_name`
    - `actor_count`, `avg_importance`
    - `tactics` (shortnames)
    - `actors_sample` (small list of actor ids/names)

## UI (Bridging Techniques)
- Input: `min_actors` (default 3)
- Table columns: Technique (name + STIX), Actor Count, Avg Importance, Tactics, Actors (sample)

## Interpretation
- Higher actor_count implies broader adversary adoption
- Higher avg_importance suggests more consistent usage per actor
- Use to prioritize “must-have” detections and hunting coverage

## Caveats
- Actor attribution completeness impacts actor_count
- Average importance may be skewed by a few large campaigns; treat as directional

## Roadmap
- Time-trend analysis for emerging bridging techniques
- Drill-through to per-actor usage breakdown
