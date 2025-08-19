#!/usr/bin/env python3
"""
Fix existing Mitigation nodes by populating external_id from ATT&CK data.

This script:
1. Fetches the current ATT&CK bundle
2. Extracts external_id for each mitigation
3. Updates existing Mitigation nodes in Neo4j
4. Re-runs D3FEND relationship creation
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from neo4j import GraphDatabase
from bandjacks.loaders.attack_catalog import fetch_catalog
from bandjacks.loaders.attack_upsert import resolve_bundle, fetch_bundle
from bandjacks.loaders.d3fend_loader import D3FENDLoader
from bandjacks.services.api.settings import settings


def fix_mitigation_external_ids():
    """Update existing Mitigation nodes with external_id."""
    print("="*80)
    print("FIXING MITIGATION EXTERNAL IDs")
    print("="*80)
    
    # Connect to Neo4j
    driver = GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password)
    )
    
    try:
        # 1. Get current collection info from database
        with driver.session() as session:
            result = session.run("""
                MATCH (m:Mitigation)
                WHERE m.source_collection IS NOT NULL
                RETURN DISTINCT m.source_collection as collection, 
                       m.source_version as version
                LIMIT 1
            """)
            record = result.single()
            
            if not record:
                print("No Mitigations found in database. Please load ATT&CK data first.")
                return False
            
            collection = record["collection"]
            version = record["version"]
            print(f"Found existing collection: {collection} version: {version}")
        
        # 2. Fetch the ATT&CK bundle
        print(f"\nFetching ATT&CK bundle for {collection}...")
        url, resolved_version, modified = resolve_bundle(
            settings.attack_index_url, 
            collection, 
            version or "latest"
        )
        bundle = fetch_bundle(url)
        print(f"Fetched bundle with {len(bundle.get('objects', []))} objects")
        
        # 3. Extract external_ids for mitigations
        mitigation_ids = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") == "course-of-action":
                stix_id = obj.get("id")
                external_id = None
                
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                        external_id = ref.get("external_id")
                        break
                
                if external_id:
                    mitigation_ids[stix_id] = external_id
        
        print(f"Found {len(mitigation_ids)} mitigations with external_ids")
        
        # 4. Update Mitigation nodes
        print("\nUpdating Mitigation nodes...")
        updated_count = 0
        
        with driver.session() as session:
            for stix_id, external_id in mitigation_ids.items():
                result = session.run("""
                    MATCH (m:Mitigation {stix_id: $stix_id})
                    SET m.external_id = $external_id
                    RETURN m.name as name
                """, stix_id=stix_id, external_id=external_id)
                
                record = result.single()
                if record:
                    updated_count += 1
                    print(f"  Updated {external_id}: {record['name']}")
        
        print(f"\nUpdated {updated_count} Mitigation nodes with external_id")
        
        # 5. Verify the update
        with driver.session() as session:
            result = session.run("""
                MATCH (m:Mitigation)
                RETURN 
                    count(m) as total,
                    sum(CASE WHEN m.external_id IS NOT NULL THEN 1 ELSE 0 END) as with_external_id
            """)
            record = result.single()
            print(f"\nVerification: {record['with_external_id']}/{record['total']} Mitigations have external_id")
        
        # 6. Re-run D3FEND relationship creation
        print("\n" + "="*80)
        print("RE-CREATING D3FEND RELATIONSHIPS")
        print("="*80)
        
        d3fend_loader = D3FENDLoader(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Clear existing relationships first
        with driver.session() as session:
            session.run("MATCH (:D3fendTechnique)-[r:IMPLEMENTS]->() DELETE r")
            session.run("MATCH (:D3fendTechnique)-[r:COUNTERS]->() DELETE r")
            print("Cleared existing D3FEND relationships")
        
        # Re-create relationships
        relationships_created = d3fend_loader.create_counters_relationships()
        print(f"Created {relationships_created} D3FEND relationships")
        
        # 7. Final verification
        print("\n" + "="*80)
        print("FINAL VERIFICATION")
        print("="*80)
        
        with driver.session() as session:
            # Check IMPLEMENTS edges
            result = session.run("""
                MATCH (:D3fendTechnique)-[r:IMPLEMENTS]->(:Mitigation)
                RETURN count(r) as implements_count
            """)
            implements_count = result.single()["implements_count"]
            
            # Check COUNTERS edges
            result = session.run("""
                MATCH (:D3fendTechnique)-[r:COUNTERS]->(:AttackPattern)
                RETURN count(r) as counters_count
            """)
            counters_count = result.single()["counters_count"]
            
            # Sample some relationships
            result = session.run("""
                MATCH (d:D3fendTechnique)-[:IMPLEMENTS]->(m:Mitigation)
                RETURN d.name as d3fend_name, m.external_id as mitigation_id, m.name as mitigation_name
                LIMIT 5
            """)
            
            print(f"IMPLEMENTS edges: {implements_count}")
            print(f"COUNTERS edges: {counters_count}")
            print("\nSample D3FEND → Mitigation mappings:")
            for record in result:
                print(f"  {record['d3fend_name']} → {record['mitigation_id']}: {record['mitigation_name']}")
        
        d3fend_loader.close()
        
        if implements_count > 0 and counters_count > 0:
            print("\n✅ SUCCESS: D3FEND relationships have been created!")
            return True
        else:
            print("\n⚠️ WARNING: Relationships may not have been created. Check the mappings.")
            return False
            
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        driver.close()


if __name__ == "__main__":
    success = fix_mitigation_external_ids()
    sys.exit(0 if success else 1)