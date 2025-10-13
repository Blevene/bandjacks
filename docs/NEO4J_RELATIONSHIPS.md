# Neo4j Native Relationships Documentation

## Overview

The Bandjacks system uses Neo4j to model threat intelligence as a property graph with native relationships for efficient traversal and analytics. This document describes the relationship structure, creation patterns, and query examples.

## Relationship Types

### Report-to-Entity Relationships

The system creates direct relationships between Report nodes and extracted entities for native graph traversal:

#### Generic Relationship
- **`EXTRACTED_ENTITY`** - Universal relationship from Report to any entity type
  - Properties: `confidence`, `extraction_method`, `reviewed`, `created`
  - Target nodes: IntrusionSet, Software, Campaign

#### Specific Entity Relationships
- **`IDENTIFIED_ACTOR`** - Report → IntrusionSet (threat actors)
  - Properties: `confidence`, `created`, `migrated`
  - Example: Report identifies APT28 as the threat actor

- **`EXTRACTED_MALWARE`** - Report → Software (type='malware')
  - Properties: `confidence`, `created`, `migrated`
  - Example: Report extracts AridSpy malware

- **`MENTIONS_TOOL`** - Report → Software (type='tool')
  - Properties: `confidence`, `created`, `migrated`
  - Example: Report mentions use of Mimikatz tool

- **`DESCRIBES_CAMPAIGN`** - Report → Campaign
  - Properties: `confidence`, `created`, `migrated`
  - Example: Report describes Operation Aurora campaign

### Report-to-Technique Relationships

- **`EXTRACTED_TECHNIQUE`** - Report → AttackPattern
  - Properties: `confidence`, `reviewed`, `extraction_method`
  - Example: Report extracts T1566.001 (Spearphishing Attachment)

### Report-to-Flow Relationships

- **`HAS_FLOW`** - Report → AttackEpisode
  - Properties: `flow_type`, `step_count`, `created`
  - Example: Report contains attack sequence with 23 steps

### Flow Internal Relationships

- **`CONTAINS`** - AttackEpisode → AttackAction
  - Properties: none (structural relationship)
  - Example: Episode contains individual attack actions

- **`NEXT`** - AttackAction → AttackAction
  - Properties: `probability`, `reasoning`
  - Example: T1566 → T1059 with 0.8 probability

## Node Properties

### Report Node
```
Report {
  stix_id: "report--uuid",
  name: "Report Title",
  created: datetime,
  modified: datetime
}
```

### Entity Nodes
```
IntrusionSet|Software|Campaign {
  stix_id: "entity--uuid",
  name: "Entity Name",
  type: "intrusion-set|malware|tool|campaign",
  confidence: 85,
  source_report: "report--uuid",
  verified: true,
  created: datetime
}
```

### Attack Flow Nodes
```
AttackEpisode {
  episode_id: "episode--uuid",
  stix_id: "episode--uuid",
  report_id: "report--uuid",
  flow_id: "flow--uuid",
  name: "Attack Flow Name",
  created: datetime
}

AttackAction {
  action_id: "action--uuid",
  stix_id: "action--uuid",
  attack_pattern_ref: "attack-pattern--uuid",
  order: 1,
  confidence: 90,
  evidence: "Supporting text"
}
```

## Relationship Creation Patterns

### During Unified Review Submission

When entities are approved through the unified review system:

```python
# In unified_review.py - _upsert_entities_to_graph()

# 1. Create entity node
session.run("""
    MERGE (e:EntityType {stix_id: $stix_id})
    SET e.name = $name,
        e.type = $entity_type,
        e.confidence = $confidence,
        e.source_report = $report_id
""")

# 2. Create generic EXTRACTED_ENTITY relationship
session.run("""
    MATCH (r:Report {stix_id: $report_id})
    MATCH (e:EntityType {stix_id: $stix_id})
    MERGE (r)-[rel:EXTRACTED_ENTITY]->(e)
    ON CREATE SET
        rel.created = datetime(),
        rel.confidence = $confidence,
        rel.extraction_method = 'llm',
        rel.reviewed = true
""")

# 3. Create specific relationship based on type
if entity_type == "intrusion-set":
    rel_type = "IDENTIFIED_ACTOR"
elif entity_type == "malware":
    rel_type = "EXTRACTED_MALWARE"
elif entity_type == "tool":
    rel_type = "MENTIONS_TOOL"
elif entity_type == "campaign":
    rel_type = "DESCRIBES_CAMPAIGN"

session.run(f"""
    MATCH (r:Report {{stix_id: $report_id}})
    MATCH (e:EntityType {{stix_id: $stix_id}})
    MERGE (r)-[rel:{rel_type}]->(e)
    ON CREATE SET
        rel.created = datetime(),
        rel.confidence = $confidence
""")
```

### During Attack Flow Creation

When attack flow steps are approved:

```python
# In unified_review.py - _create_attack_flow_graph()

# 1. Create AttackEpisode
session.run("""
    MERGE (ep:AttackEpisode {episode_id: $episode_id})
    SET ep.stix_id = $episode_id,
        ep.report_id = $report_id,
        ep.flow_id = $flow_id,
        ep.name = $report_name,
        ep.created = datetime()
""")

# 2. Create HAS_FLOW relationship
session.run("""
    MATCH (r:Report {stix_id: $report_id})
    MATCH (e:AttackEpisode {episode_id: $episode_id})
    MERGE (r)-[rel:HAS_FLOW]->(e)
    ON CREATE SET
        rel.created = datetime(),
        rel.flow_type = 'sequential',
        rel.step_count = $step_count
""")

# 3. Create AttackAction nodes and CONTAINS relationships
for action in actions:
    session.run("""
        MERGE (act:AttackAction {action_id: $action_id})
        SET act.stix_id = $stix_id,
            act.attack_pattern_ref = $technique_ref,
            act.order = $order,
            act.confidence = $confidence

        WITH act
        MATCH (ep:AttackEpisode {episode_id: $episode_id})
        MERGE (ep)-[:CONTAINS]->(act)
    """)
```

## Query Examples

### Find All Entities from a Report
```cypher
MATCH (r:Report {stix_id: "report--uuid"})-[:EXTRACTED_ENTITY]->(e)
RETURN e.name, labels(e)[0] as type, e.confidence
ORDER BY e.confidence DESC
```

### Find Threat Actors Across Reports
```cypher
MATCH (r:Report)-[:IDENTIFIED_ACTOR]->(a:IntrusionSet)
RETURN a.name, count(r) as report_count
ORDER BY report_count DESC
```

### Find Malware and Their Tools
```cypher
MATCH (r:Report)-[:EXTRACTED_MALWARE]->(m:Software)
MATCH (r)-[:MENTIONS_TOOL]->(t:Software)
RETURN r.stix_id, m.name as malware, collect(t.name) as tools
```

### Get Attack Flow with Actions
```cypher
MATCH (r:Report {stix_id: "report--uuid"})-[:HAS_FLOW]->(ep:AttackEpisode)
MATCH (ep)-[:CONTAINS]->(act:AttackAction)
MATCH (act)-[:USES]->(t:AttackPattern)
RETURN act.order, t.name, act.confidence
ORDER BY act.order
```

### Find Reports by Campaign
```cypher
MATCH (r:Report)-[:DESCRIBES_CAMPAIGN]->(c:Campaign {name: "Operation Aurora"})
RETURN r.stix_id, r.name, r.created
ORDER BY r.created DESC
```

### Trace Attack Sequence
```cypher
MATCH path = (a1:AttackAction)-[:NEXT*1..5]->(a2:AttackAction)
WHERE a1.order = 1
RETURN path
```

### Find Co-occurring Entities
```cypher
MATCH (r:Report)-[:IDENTIFIED_ACTOR]->(actor:IntrusionSet {name: "APT28"})
MATCH (r)-[:EXTRACTED_MALWARE]->(malware:Software)
RETURN malware.name, count(r) as co_occurrence_count
ORDER BY co_occurrence_count DESC
```

## Migration Support

For existing data that uses property-based connections (`source_report` property), a migration script is provided:

```bash
python migrations/add_native_relationships.py
```

This script:
1. Creates EXTRACTED_ENTITY relationships for all entities with `source_report` property
2. Creates specific typed relationships based on entity type
3. Creates HAS_FLOW relationships for existing AttackEpisodes
4. Fixes missing `report_id` properties on AttackEpisode nodes

### Migration Statistics Example
```
Creating entity relationships...
  Created 70 EXTRACTED_ENTITY relationships
  Created 5 IDENTIFIED_ACTOR relationships
  Created 21 EXTRACTED_MALWARE relationships
  Created 32 MENTIONS_TOOL relationships
  Created 12 DESCRIBES_CAMPAIGN relationships

Creating flow relationships...
  Created 1 HAS_FLOW relationships
  Fixed 168 AttackEpisode nodes with missing report_id
```

## Performance Benefits

Native relationships provide significant performance improvements:

1. **Faster Traversal**: Direct relationships eliminate property lookups
   - Before: `MATCH (e) WHERE e.source_report = $report_id`
   - After: `MATCH (r)-[:EXTRACTED_ENTITY]->(e)`

2. **Index Optimization**: Relationship indexes are more efficient than property indexes

3. **Query Simplification**: More intuitive Cypher queries

4. **Visualization**: Graph visualization tools can display relationships directly

## Best Practices

1. **Always Create Both Relationships**: Create both generic (EXTRACTED_ENTITY) and specific relationships for flexibility

2. **Use MERGE for Idempotency**: Always use MERGE to prevent duplicate relationships

3. **Include Metadata**: Add confidence, extraction_method, and timestamps to relationships

4. **Maintain Consistency**: Ensure both node properties and relationships are in sync

5. **Query Optimization**: Use specific relationship types when possible for better performance

## Relationship Constraints

The system enforces these constraints:

1. **Unique Relationships**: A Report can have only one relationship of each type to a specific entity
2. **Required Properties**: All relationships must have `created` timestamp
3. **Type Consistency**: Entity types must match relationship types (e.g., IDENTIFIED_ACTOR only connects to IntrusionSet)

## Future Enhancements

Planned improvements to the relationship model:

1. **Weighted Relationships**: Add weight properties for graph algorithms
2. **Temporal Relationships**: Include time-based properties for temporal analysis
3. **Confidence Decay**: Model confidence degradation over time
4. **Relationship Provenance**: Track extraction method and reviewer for each relationship
5. **Cross-Report Relationships**: Link entities across multiple reports