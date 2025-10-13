#!/usr/bin/env python3
"""
Migration script to add native Neo4j relationships between Reports and their entities/flows.

This script creates direct relationships that were previously only tracked via properties:
- EXTRACTED_ENTITY: Generic relationship to all extracted entities
- IDENTIFIED_ACTOR: Report -> IntrusionSet (threat actors)
- EXTRACTED_MALWARE: Report -> Software (type=malware)
- MENTIONS_TOOL: Report -> Software (type=tool)
- DESCRIBES_CAMPAIGN: Report -> Campaign
- HAS_FLOW: Report -> AttackEpisode

Run this script to migrate existing data to use native graph relationships.
"""

from neo4j import GraphDatabase
import os
from datetime import datetime


def create_entity_relationships(session):
    """Create relationships between Reports and their entities."""

    print("Creating entity relationships...")

    # Create EXTRACTED_ENTITY relationships for all entities
    result = session.run("""
        MATCH (r:Report)
        MATCH (e)
        WHERE (e:IntrusionSet OR e:Software OR e:Campaign)
        AND e.source_report = r.stix_id
        MERGE (r)-[rel:EXTRACTED_ENTITY]->(e)
        ON CREATE SET
            rel.created = datetime(),
            rel.confidence = coalesce(e.confidence, 75),
            rel.extraction_method = 'llm',
            rel.migrated = true
        RETURN count(rel) as created
    """)
    count = result.single()['created']
    print(f"  Created {count} EXTRACTED_ENTITY relationships")

    # Create IDENTIFIED_ACTOR relationships
    result = session.run("""
        MATCH (r:Report)
        MATCH (a:IntrusionSet)
        WHERE a.source_report = r.stix_id
        MERGE (r)-[rel:IDENTIFIED_ACTOR]->(a)
        ON CREATE SET
            rel.created = datetime(),
            rel.confidence = coalesce(a.confidence, 75),
            rel.migrated = true
        RETURN count(rel) as created
    """)
    count = result.single()['created']
    print(f"  Created {count} IDENTIFIED_ACTOR relationships")

    # Create EXTRACTED_MALWARE relationships
    result = session.run("""
        MATCH (r:Report)
        MATCH (m:Software)
        WHERE m.source_report = r.stix_id
        AND m.type = 'malware'
        MERGE (r)-[rel:EXTRACTED_MALWARE]->(m)
        ON CREATE SET
            rel.created = datetime(),
            rel.confidence = coalesce(m.confidence, 75),
            rel.migrated = true
        RETURN count(rel) as created
    """)
    count = result.single()['created']
    print(f"  Created {count} EXTRACTED_MALWARE relationships")

    # Create MENTIONS_TOOL relationships
    result = session.run("""
        MATCH (r:Report)
        MATCH (t:Software)
        WHERE t.source_report = r.stix_id
        AND t.type = 'tool'
        MERGE (r)-[rel:MENTIONS_TOOL]->(t)
        ON CREATE SET
            rel.created = datetime(),
            rel.confidence = coalesce(t.confidence, 75),
            rel.migrated = true
        RETURN count(rel) as created
    """)
    count = result.single()['created']
    print(f"  Created {count} MENTIONS_TOOL relationships")

    # Create DESCRIBES_CAMPAIGN relationships
    result = session.run("""
        MATCH (r:Report)
        MATCH (c:Campaign)
        WHERE c.source_report = r.stix_id
        MERGE (r)-[rel:DESCRIBES_CAMPAIGN]->(c)
        ON CREATE SET
            rel.created = datetime(),
            rel.confidence = coalesce(c.confidence, 75),
            rel.migrated = true
        RETURN count(rel) as created
    """)
    count = result.single()['created']
    print(f"  Created {count} DESCRIBES_CAMPAIGN relationships")


def create_flow_relationships(session):
    """Create HAS_FLOW relationships between Reports and AttackEpisodes."""

    print("\nCreating flow relationships...")

    # Create HAS_FLOW relationships
    result = session.run("""
        MATCH (r:Report)
        MATCH (e:AttackEpisode)
        WHERE e.report_id = r.stix_id OR e.source_report = r.stix_id
        MERGE (r)-[rel:HAS_FLOW]->(e)
        ON CREATE SET
            rel.created = datetime(),
            rel.flow_type = 'sequential',
            rel.migrated = true
        WITH r, e, rel
        OPTIONAL MATCH (e)-[:CONTAINS]->(a:AttackAction)
        WITH r, e, rel, count(a) as action_count
        SET rel.step_count = action_count
        RETURN count(DISTINCT rel) as created
    """)
    count = result.single()['created']
    print(f"  Created {count} HAS_FLOW relationships")

    # Fix any AttackEpisode nodes missing report_id
    result = session.run("""
        MATCH (e:AttackEpisode)
        WHERE e.episode_id CONTAINS 'episode--'
        AND e.report_id IS NULL
        WITH e,
             'report--' + substring(e.episode_id, 10) as inferred_report_id
        SET e.report_id = inferred_report_id
        RETURN count(e) as fixed
    """)
    count = result.single()['fixed']
    if count > 0:
        print(f"  Fixed {count} AttackEpisode nodes with missing report_id")


def verify_migration(session):
    """Verify the migration results."""

    print("\nVerifying migration results...")

    # Count relationship types
    result = session.run("""
        MATCH ()-[r]->()
        WHERE type(r) IN ['EXTRACTED_ENTITY', 'IDENTIFIED_ACTOR',
                         'EXTRACTED_MALWARE', 'MENTIONS_TOOL',
                         'DESCRIBES_CAMPAIGN', 'HAS_FLOW']
        RETURN type(r) as rel_type, count(r) as count
        ORDER BY count DESC
    """)

    print("\nRelationship counts after migration:")
    for record in result:
        print(f"  {record['rel_type']}: {record['count']}")

    # Sample report with relationships
    result = session.run("""
        MATCH (r:Report)
        WHERE EXISTS((r)-[:EXTRACTED_ENTITY|IDENTIFIED_ACTOR|
                        EXTRACTED_MALWARE|MENTIONS_TOOL|
                        DESCRIBES_CAMPAIGN|HAS_FLOW]->())
        RETURN r.stix_id as report_id
        LIMIT 1
    """)

    sample = result.single()
    if sample:
        report_id = sample['report_id']
        print(f"\nSample report with relationships: {report_id}")

        result = session.run("""
            MATCH (r:Report {stix_id: $report_id})-[rel]->()
            RETURN type(rel) as rel_type, count(*) as count
            ORDER BY count DESC
        """, report_id=report_id)

        for record in result:
            print(f"  {record['rel_type']}: {record['count']}")


def main():
    """Main migration function."""

    print("="*60)
    print("NATIVE NEO4J RELATIONSHIPS MIGRATION")
    print("="*60)
    print(f"Started at: {datetime.now().isoformat()}")

    # Connect to Neo4j
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    username = os.getenv("NEO4J_USERNAME", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "")

    driver = GraphDatabase.driver(uri, auth=(username, password))

    try:
        with driver.session() as session:
            # Create entity relationships
            create_entity_relationships(session)

            # Create flow relationships
            create_flow_relationships(session)

            # Verify migration
            verify_migration(session)

    finally:
        driver.close()

    print("\n" + "="*60)
    print("MIGRATION COMPLETE")
    print(f"Finished at: {datetime.now().isoformat()}")
    print("="*60)


if __name__ == "__main__":
    main()