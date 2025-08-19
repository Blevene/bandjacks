#!/usr/bin/env python3
"""
Fix missing external_ids for mobile-attack AttackPattern nodes.

Mobile techniques have T-numbers (T1600-T1663 range) but they weren't 
extracted during the initial ingestion.
"""

import sys
import httpx
from neo4j import GraphDatabase
from opensearchpy import OpenSearch
from bandjacks.loaders.embedder import encode
from bandjacks.loaders.opensearch_index import upsert_node_embedding
from bandjacks.services.api.settings import settings


def fix_mobile_external_ids():
    """Update mobile-attack AttackPattern nodes with their external_ids."""
    
    print("="*80)
    print("FIXING MOBILE-ATTACK EXTERNAL IDs")
    print("="*80)
    
    # Connect to Neo4j
    driver = GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password)
    )
    
    try:
        # 1. Check current state
        with driver.session() as session:
            result = session.run("""
                MATCH (n:AttackPattern)
                WHERE n.source_collection = 'mobile-attack'
                RETURN count(n) as total,
                       sum(CASE WHEN n.external_id IS NOT NULL THEN 1 ELSE 0 END) as with_id
            """)
            record = result.single()
            total = record["total"]
            with_id = record["with_id"]
            
            if total == 0:
                print("No mobile-attack techniques found in database.")
                return False
            
            print(f"Found {total} mobile-attack techniques")
            print(f"  With external_id: {with_id}")
            print(f"  Without external_id: {total - with_id}")
            
            if with_id == total:
                print("\nAll mobile techniques already have external_ids!")
                return True
        
        # 2. Fetch mobile-attack bundle
        print(f"\nFetching mobile-attack bundle...")
        url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-17.1.json"
        
        response = httpx.get(url, timeout=60)
        response.raise_for_status()
        bundle = response.json()
        
        print(f"Fetched bundle with {len(bundle.get('objects', []))} objects")
        
        # 3. Extract external_ids for attack patterns
        mobile_ids = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") == "attack-pattern":
                stix_id = obj.get("id")
                external_id = None
                
                # Look for mitre-attack external_id
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                        external_id = ref.get("external_id")
                        break
                
                if external_id and stix_id:
                    mobile_ids[stix_id] = {
                        'external_id': external_id,
                        'name': obj.get("name", ""),
                        'revoked': obj.get("revoked", False)
                    }
        
        print(f"Found {len(mobile_ids)} mobile techniques with external_ids in bundle")
        
        # 4. Update Neo4j nodes
        print("\nUpdating AttackPattern nodes...")
        updated_count = 0
        updated_nodes = []
        
        with driver.session() as session:
            for stix_id, info in mobile_ids.items():
                result = session.run("""
                    MATCH (n:AttackPattern {stix_id: $stix_id})
                    WHERE n.source_collection = 'mobile-attack'
                    SET n.external_id = $external_id
                    RETURN n.name as name, n.description as desc,
                           n.revoked as revoked, n.x_mitre_is_subtechnique as is_sub
                """, stix_id=stix_id, external_id=info['external_id'])
                
                record = result.single()
                if record:
                    updated_count += 1
                    updated_nodes.append({
                        'stix_id': stix_id,
                        'external_id': info['external_id'],
                        'name': record['name'],
                        'description': record['desc'],
                        'revoked': record['revoked'],
                        'is_subtechnique': record['is_sub']
                    })
                    print(f"  Updated {info['external_id']}: {record['name']}")
        
        print(f"\nUpdated {updated_count} mobile AttackPattern nodes with external_id")
        
        # 5. Update OpenSearch embeddings
        if updated_nodes:
            print("\n" + "="*80)
            print("UPDATING OPENSEARCH EMBEDDINGS")
            print("="*80)
            
            os_client = OpenSearch(settings.opensearch_url, timeout=30)
            
            # Get mobile tactics for embedding text
            tactic_map = {}
            with driver.session() as session:
                result = session.run("""
                    MATCH (ap:AttackPattern)-[:HAS_TACTIC]->(t:Tactic)
                    WHERE ap.source_collection = 'mobile-attack'
                    RETURN ap.stix_id as ap_id, collect(t.name) as tactics
                """)
                for record in result:
                    tactic_map[record['ap_id']] = record['tactics']
            
            print(f"Updating embeddings for {len(updated_nodes)} mobile techniques...")
            
            for i, node in enumerate(updated_nodes):
                # Generate embedding text (similar to _ap_text in attack_upsert.py)
                tactics = tactic_map.get(node['stix_id'], [])
                text = f"{node['name']} {node['external_id']}\n{node['description']}\nTactics: {', '.join(tactics)}"
                
                try:
                    vec = encode(text)
                    if vec and len(vec) == 768:
                        upsert_node_embedding(
                            os_url=settings.opensearch_url,
                            index="bandjacks_attack_nodes-v1",
                            doc={
                                "id": node['stix_id'],
                                "kb_type": "AttackPattern",
                                "attack_version": "17.1",
                                "revoked": node['revoked'],
                                "external_id": node['external_id'],
                                "name": node['name'],
                                "text": text,
                                "embedding": vec
                            }
                        )
                        
                        if (i + 1) % 20 == 0:
                            print(f"  Progress: {i+1}/{len(updated_nodes)}")
                    else:
                        print(f"  Failed to generate embedding for {node['external_id']}")
                        
                except Exception as e:
                    print(f"  Error updating {node['external_id']}: {e}")
            
            print(f"\nCompleted embedding updates")
        
        # 6. Final verification
        print("\n" + "="*80)
        print("FINAL VERIFICATION")
        print("="*80)
        
        with driver.session() as session:
            result = session.run("""
                MATCH (n:AttackPattern)
                WHERE n.source_collection = 'mobile-attack'
                RETURN 
                    count(n) as total,
                    sum(CASE WHEN n.external_id IS NOT NULL THEN 1 ELSE 0 END) as with_external_id
            """)
            record = result.single()
            print(f"Mobile techniques: {record['with_external_id']}/{record['total']} have external_id")
            
            # Sample some
            result = session.run("""
                MATCH (n:AttackPattern)
                WHERE n.source_collection = 'mobile-attack' AND n.external_id IS NOT NULL
                RETURN n.external_id as id, n.name as name
                ORDER BY n.external_id
                LIMIT 5
            """)
            
            print("\nSample mobile techniques with external_id:")
            for record in result:
                print(f"  {record['id']}: {record['name']}")
        
        print("\n✅ SUCCESS: Mobile external_ids have been fixed!")
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        driver.close()


if __name__ == "__main__":
    success = fix_mobile_external_ids()
    sys.exit(0 if success else 1)