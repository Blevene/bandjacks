# AttackFlow Generation Guide

Complete reference for generating and working with AttackFlow co-occurrence models in Bandjacks.

## Overview

AttackFlow models in Bandjacks represent how threat actors use MITRE ATT&CK techniques together. Unlike sequential attack flows, these use a **co-occurrence model** that shows technique relationships without implying false temporal ordering.

### Why Co-occurrence Models?

Traditional attack flows assume sequence (A → B → C), but intrusion set data from MITRE ATT&CK only tells us which techniques a group uses, not in what order. Co-occurrence models solve this by:

1. **Respecting data limitations**: We model what we know (techniques used) vs. what we don't (sequences)
2. **Avoiding false patterns**: No artificial sequencing that could mislead analysts
3. **Showing real relationships**: Techniques that cluster within tactics or span adjacent tactics
4. **Enabling analysis**: Still allows for threat hunting, gap analysis, and pattern recognition

## Architecture

### Graph Schema

AttackFlow models use a three-level hierarchy:

```
AttackFlow (flow--uuid)
├── CONTAINS_EPISODE
└── AttackEpisode (episode--uuid)
    ├── CONTAINS (with order property)
    └── AttackAction (action--uuid)
        ├── OF_TECHNIQUE
        └── AttackPattern (attack-pattern--uuid)

AttackAction -[NEXT {probability, rationale, edge_type}]-> AttackAction
```

### Node Properties

**AttackFlow**:
- `flow_id`: Unique flow identifier
- `name`: Human-readable name (e.g., "Techniques used by APT29")
- `flow_type`: "co-occurrence" 
- `attributed_group_id`: Source IntrusionSet STIX ID
- `attributed_group_name`: Threat actor name
- `source_id`: Original data source
- `sequence_inferred`: false (no artificial sequencing)
- `created`, `modified`: Timestamps

**AttackAction**:
- `action_id`: Unique action identifier
- `order`: Display order (arbitrary for co-occurrence)
- `attack_pattern_ref`: Links to MITRE ATT&CK technique
- `confidence`: 60.0 (default for intrusion set data)
- `description`: Technique description excerpt

### Edge Properties

**NEXT edges** (co-occurrence relationships):
- `probability`: Likelihood of co-occurrence (0.1-1.0)
- `rationale`: Human-readable explanation
- `edge_type`: "co-occurrence"

**Edge Types**:
1. **Intra-tactic**: Between techniques in same kill chain tactic
   - Probability: 0.3 (same-tactic baseline)
   - Rationale: "co-occurrence within [tactic]"
   
2. **Cross-tactic**: Between techniques in adjacent tactics
   - Probability: 0.4 (cross-tactic pattern)
   - Rationale: "cross-tactic pattern: [tactic1] → [tactic2]"

### Connectivity Patterns

**Small Groups** (≤5 techniques per tactic): Full mesh connectivity
```
T1566.001 ←→ T1566.002 ←→ T1566.003
    ↑              ↑              ↑
    └──────────────┴──────────────┘
```

**Large Groups** (>5 techniques per tactic): Hub-and-spoke pattern
```
       T1059.001 (hub)
      ↙    ↓    ↘
T1059.003  T1059.004  T1059.005
     ↓       ↓       ↓
T1059.006  T1059.007  T1059.008
```

## API Reference

### Generate Single Flow

**Endpoint**: `POST /v1/flows/build`

**Request Body**:
```json
{
  "intrusion_set_id": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542"
}
```

**Response**:
```json
{
  "flow_id": "flow--abc123...",
  "episode_id": "episode--def456...",
  "name": "Techniques used by APT29",
  "source_id": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
  "steps": [
    {
      "order": 1,
      "action_id": "action--ghi789...",
      "attack_pattern_ref": "attack-pattern--a028ed90-6d9b-5f9b-95f0-ed61173717d2",
      "name": "Spearphishing Attachment",
      "description": "Conducting spearphishing attacks with malicious attachments",
      "confidence": 60.0
    }
  ],
  "edges": [
    {
      "source": "action--ghi789...",
      "target": "action--jkl012...",
      "probability": 0.3,
      "rationale": "co-occurrence within initial-access"
    }
  ],
  "stats": {
    "steps_count": 67,
    "edges_count": 84,
    "avg_confidence": 60.0
  },
  "llm_synthesized": false,
  "flow_type": "co-occurrence",
  "attributed_group_name": "APT29"
}
```

### Retrieve Flow Details

**Endpoint**: `GET /v1/flows/{flow_id}`

Returns detailed flow information including all actions and edges.

### Search Similar Flows

**Endpoint**: `POST /v1/flows/search`

Find flows with similar technique patterns.

## Bulk Generation

### Using the Script

```bash
# Generate flows for all intrusion sets
uv run python scripts/build_intrusion_flows_simple.py

# Optional parameters
uv run python scripts/build_intrusion_flows_simple.py \
  --limit 10          # Process only first 10
  --force             # Regenerate existing flows
```

### Script Features

- **Automatic rate limiting**: 25-second pauses every 20 requests
- **Progress tracking**: Real-time status updates
- **Error handling**: Continues on individual failures
- **Deduplication**: Skips existing flows by default
- **Logging**: Saves detailed results to JSON

### Performance Characteristics

| Metric | Value |
|--------|-------|
| Processing speed | ~1-3 seconds per intrusion set |
| Total intrusion sets | 165 (with techniques) |
| Total runtime | ~10-15 minutes (with rate limiting) |
| Database queries per flow | 1 (optimized from N+1 problem) |
| Memory usage | Low (streaming processing) |

## Database Implementation

### Efficient Query Pattern

The system uses a single optimized query per intrusion set:

```cypher
MATCH (g:IntrusionSet {stix_id: $group_id})
OPTIONAL MATCH (g)-[:USES]->(t:AttackPattern)
OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
WITH g, t, collect(DISTINCT tac.shortname) as tactics
RETURN g.name as group_name,
       collect(DISTINCT {
           technique_id: t.stix_id,
           name: t.name,
           description: coalesce(t.description, ""),
           tactics: tactics
       }) as techniques
```

This replaces the previous N+1 pattern that made separate queries for each technique.

### Edge Generation Algorithm

```python
def _create_cooccurrence_edges(self, actions):
    edges = []
    
    # Group by primary tactic
    tactic_groups = {}
    for action in actions:
        primary_tactic = action.get("tactics", ["unknown"])[0]
        tactic_groups.setdefault(primary_tactic, []).append(action)
    
    # Create intra-tactic edges
    for tactic, group_actions in tactic_groups.items():
        if len(group_actions) <= 5:
            # Small group: full mesh
            for i, action1 in enumerate(group_actions):
                for action2 in group_actions[i+1:]:
                    edges.append({
                        "source": action1["action_id"],
                        "target": action2["action_id"],
                        "probability": 0.3,
                        "rationale": f"co-occurrence within {tactic}",
                        "edge_type": "co-occurrence"
                    })
        else:
            # Large group: hub-spoke
            hub = group_actions[0]
            for action in group_actions[1:]:
                edges.append({
                    "source": hub["action_id"],
                    "target": action["action_id"],
                    "probability": 0.25,
                    "rationale": f"co-occurrence within {tactic}",
                    "edge_type": "co-occurrence"
                })
    
    # Create cross-tactic edges
    tactic_sequence = ["initial-access", "execution", "persistence", ...]
    for i, tactic1 in enumerate(tactic_sequence[:-1]):
        tactic2 = tactic_sequence[i + 1]
        if tactic1 in tactic_groups and tactic2 in tactic_groups:
            source = tactic_groups[tactic1][0]
            target = tactic_groups[tactic2][0]
            edges.append({
                "source": source["action_id"],
                "target": target["action_id"],
                "probability": 0.4,
                "rationale": f"cross-tactic pattern: {tactic1} → {tactic2}",
                "edge_type": "co-occurrence"
            })
    
    return edges
```

## Analysis Patterns

### Common Queries

**Count flows by threat actor type**:
```cypher
MATCH (f:AttackFlow)
RETURN f.attributed_group_name as group, 
       size((f)-[:CONTAINS_EPISODE]->()-[:CONTAINS]->()) as technique_count
ORDER BY technique_count DESC
```

**Find most connected techniques**:
```cypher
MATCH (a:AttackAction)-[n:NEXT]->(b:AttackAction)
WITH a.attack_pattern_ref as technique, count(n) as connections
RETURN technique, connections
ORDER BY connections DESC LIMIT 10
```

**Analyze tactic co-occurrence patterns**:
```cypher
MATCH (a1:AttackAction)-[n:NEXT {edge_type: "co-occurrence"}]->(a2:AttackAction)
MATCH (a1)-[:OF_TECHNIQUE]->()-[:HAS_TACTIC]->(t1:Tactic)
MATCH (a2)-[:OF_TECHNIQUE]->()-[:HAS_TACTIC]->(t2:Tactic)
WITH t1.shortname as tactic1, t2.shortname as tactic2, count(n) as co_occurrences
WHERE tactic1 <> tactic2
RETURN tactic1, tactic2, co_occurrences
ORDER BY co_occurrences DESC
```

### Threat Hunting Applications

**Find groups using similar technique combinations**:
```cypher
MATCH (f1:AttackFlow)-[:CONTAINS_EPISODE]->()-[:CONTAINS]->(a1:AttackAction)
MATCH (f2:AttackFlow)-[:CONTAINS_EPISODE]->()-[:CONTAINS]->(a2:AttackAction)
WHERE f1 <> f2 AND a1.attack_pattern_ref = a2.attack_pattern_ref
WITH f1, f2, count(*) as shared_techniques
WHERE shared_techniques > 10
RETURN f1.attributed_group_name, f2.attributed_group_name, shared_techniques
ORDER BY shared_techniques DESC
```

**Identify technique clusters**:
```cypher
MATCH (a1:AttackAction)-[n:NEXT]->(a2:AttackAction)
WHERE n.probability > 0.3
RETURN a1.attack_pattern_ref, a2.attack_pattern_ref, n.probability
ORDER BY n.probability DESC
```

## Troubleshooting

### Common Issues

**Rate Limiting (429 errors)**:
- Increase delay between requests in script
- Check rate limit settings in API middleware
- Use `--force` sparingly to avoid regenerating all flows

**Memory Issues**:
- Script processes one intrusion set at a time
- Large groups (>100 techniques) create many edges
- Monitor heap size during bulk generation

**Graph Query Performance**:
- Ensure Neo4j constraints exist on `stix_id` fields
- Use LIMIT clauses for exploratory queries
- Consider indexes on `attributed_group_id`

**Inconsistent Edge Counts**:
- Co-occurrence patterns vary by technique distribution
- Hub-spoke vs. full mesh affects edge density
- Cross-tactic edges depend on tactic coverage

### Performance Optimization

**Database Tuning**:
```cypher
// Create indexes for faster queries
CREATE CONSTRAINT flow_id_unique FOR (f:AttackFlow) REQUIRE f.flow_id IS UNIQUE;
CREATE INDEX action_pattern_ref FOR (a:AttackAction) ON (a.attack_pattern_ref);
CREATE INDEX group_attribution FOR (f:AttackFlow) ON (f.attributed_group_id);
```

**Bulk Generation Optimization**:
- Run during off-peak hours to avoid API conflicts
- Use `--limit` for testing before full generation
- Monitor database connection pool under load
- Consider parallel processing for very large datasets

### Data Quality

**Validation Checks**:
```bash
# Verify all flows have edges
curl -s "http://localhost:8000/v1/graph/query" -d '{
  "query": "MATCH (f:AttackFlow) WHERE NOT (f)-[:CONTAINS_EPISODE]->()-[:CONTAINS]->()-[:NEXT]->() RETURN f.attributed_group_name as orphan_flows"
}'

# Check for isolated techniques (no edges)
curl -s "http://localhost:8000/v1/graph/query" -d '{
  "query": "MATCH (f:AttackFlow)-[:CONTAINS_EPISODE]->()-[:CONTAINS]->(a:AttackAction) WHERE NOT (a)-[:NEXT]-() AND NOT ()-[:NEXT]->(a) RETURN f.attributed_group_name, a.attack_pattern_ref as isolated_technique"
}'
```

## Future Enhancements

### Sequence Inference Module

A future enhancement could add a dedicated sequence inference module that:

- Analyzes technique co-occurrence patterns across multiple flows
- Uses machine learning to infer likely sequences based on:
  - Tactic ordering from kill chain
  - Historical attack patterns from reports
  - Technique prerequisites and dependencies
- Provides confidence scores for inferred sequences
- Maintains co-occurrence as the base model

### Advanced Analytics

Potential improvements for analysis capabilities:

- **Similarity scoring**: Compare flows using technique overlap, edge patterns
- **Anomaly detection**: Flag unusual technique combinations
- **Evolution tracking**: Monitor how threat actor techniques change over time
- **Gap analysis**: Identify uncovered technique combinations

### Integration Points

AttackFlow models can integrate with:

- **STIX Attack Flow extension**: Export as standard STIX Attack Flow objects
- **D3FEND mapping**: Overlay defensive techniques on co-occurrence patterns
- **Simulation engines**: Use as input for attack simulation scenarios
- **Threat hunting**: Generate hunting hypotheses from common patterns

## References

- [MITRE ATT&CK Data Model](https://attack.mitre.org/resources/attack-data-model/)
- [STIX Attack Flow Extension](https://docs.oasis-open.org/cti/attack-flow/v1.0/attack-flow-v1.0.html)
- [Neo4j Cypher Reference](https://neo4j.com/docs/cypher-manual/current/)
- [Bandjacks API Documentation](./API_DOCUMENTATION.md)