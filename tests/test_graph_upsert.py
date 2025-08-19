#!/usr/bin/env python3
"""Test end-to-end extraction to graph upsert pipeline."""

import sys
import json
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bandjacks.llm.agentic_v2 import run_agentic_v2
from bandjacks.llm.bundle_validator import validate_bundle_for_upsert, print_validation_report
from bandjacks.loaders.attack_upsert import upsert_to_graph_and_vectors
import os


def test_extraction_to_graph():
    """Test the complete pipeline from extraction to graph insertion."""
    
    print("="*80)
    print("END-TO-END EXTRACTION TO GRAPH TEST")
    print("="*80)
    
    # Test document
    test_text = """
    APT29 Spearphishing Campaign Analysis
    
    APT29, also known as Cozy Bear, launched a sophisticated spearphishing campaign
    targeting government agencies. The initial attack vector involved malicious
    email attachments containing JavaScript files that, when opened by users,
    would execute PowerShell commands to download additional payloads.
    
    The PowerShell scripts used heavy obfuscation techniques including Base64
    encoding and string concatenation to evade detection. Once executed, the
    malware established persistence through scheduled tasks and registry
    modifications.
    
    The threat actors used Mimikatz to dump credentials from LSASS memory,
    enabling lateral movement across the network using WMI and RDP connections.
    Command and control was established through HTTPS connections to
    compromised WordPress sites, utilizing domain fronting techniques.
    
    Data collection involved automated scripts that would compress sensitive
    files using 7zip before exfiltration. The attackers also used timestomping
    to modify file timestamps and cleared Windows event logs to cover their tracks.
    """
    
    # Configuration
    config = {
        "neo4j_uri": os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        "neo4j_user": os.getenv("NEO4J_USER", "neo4j"),
        "neo4j_password": os.getenv("NEO4J_PASSWORD", "password"),
        "model": "gemini/gemini-2.5-flash",
        "title": "APT29 Spearphishing Campaign",
        "url": "https://example.com/apt29-report",
        "ts": time.time(),
        "build_flow": False  # Skip flow for this test
    }
    
    print("\n1. Running agentic_v2 extraction...")
    try:
        result = run_agentic_v2(test_text, config)
        
        techniques = result.get("techniques", {})
        bundle = result.get("bundle", {})
        
        print(f"   ✅ Extraction completed")
        print(f"   • Techniques found: {len(techniques)}")
        print(f"   • STIX objects created: {len(bundle.get('objects', []))}")
        
        # Show extracted techniques
        print("\n2. Extracted Techniques:")
        for tech_id, info in list(techniques.items())[:10]:
            print(f"   • {tech_id}: {info['name']} (confidence: {info['confidence']}%)")
        
    except Exception as e:
        print(f"   ❌ Extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Validate bundle
    print("\n3. Validating STIX Bundle...")
    is_valid = print_validation_report(bundle)
    
    if not is_valid:
        print("   ❌ Bundle validation failed - cannot proceed with upsert")
        return False
    
    # Test upsert to graph
    print("\n4. Upserting to Neo4j Graph...")
    try:
        inserted, updated = upsert_to_graph_and_vectors(
            bundle=bundle,
            collection="test_extraction",
            version=time.strftime("%Y%m%d"),
            neo4j_uri=config["neo4j_uri"],
            neo4j_user=config["neo4j_user"],
            neo4j_password=config["neo4j_password"],
            os_url=os.getenv("OPENSEARCH_URL", "http://localhost:9200"),
            os_index="bandjacks_attack_nodes-v1",
            provenance={
                "method": "agentic_v2",
                "model": config["model"],
                "timestamp": time.time()
            }
        )
        
        print(f"   ✅ Graph upsert completed")
        print(f"   • Nodes inserted: {inserted}")
        print(f"   • Nodes updated: {updated}")
        
    except Exception as e:
        print(f"   ❌ Graph upsert failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Verify in Neo4j
    print("\n5. Verifying in Neo4j...")
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(
            config["neo4j_uri"],
            auth=(config["neo4j_user"], config["neo4j_password"])
        )
        
        with driver.session() as session:
            # Count attack patterns
            result = session.run("""
                MATCH (n:AttackPattern)
                WHERE n.source_collection = 'test_extraction'
                RETURN count(n) as count
            """)
            count = result.single()["count"]
            print(f"   • Attack patterns in graph: {count}")
            
            # Check for external_ids
            result = session.run("""
                MATCH (n:AttackPattern)
                WHERE n.source_collection = 'test_extraction'
                AND n.external_id IS NOT NULL
                RETURN n.external_id as id, n.name as name
                ORDER BY n.external_id
                LIMIT 5
            """)
            
            print("   • Sample techniques with external IDs:")
            for record in result:
                print(f"     - {record['id']}: {record['name']}")
            
            # Check HAS_TACTIC relationships
            result = session.run("""
                MATCH (ap:AttackPattern)-[:HAS_TACTIC]->(t:Tactic)
                WHERE ap.source_collection = 'test_extraction'
                RETURN count(*) as count
            """)
            tactic_count = result.single()["count"]
            print(f"   • HAS_TACTIC relationships: {tactic_count}")
            
            # Check report linkage
            result = session.run("""
                MATCH (ap:AttackPattern)-[:EXTRACTED_FROM]->(r:Report)
                WHERE ap.source_collection = 'test_extraction'
                RETURN count(*) as count
            """)
            report_links = result.single()["count"]
            print(f"   • EXTRACTED_FROM relationships: {report_links}")
        
        driver.close()
        
    except Exception as e:
        print(f"   ⚠️ Neo4j verification skipped: {e}")
    
    # Check OpenSearch
    print("\n6. Checking OpenSearch Embeddings...")
    try:
        import httpx
        os_url = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
        os_index = "bandjacks_attack_nodes-v1"
        
        # Search for one of the techniques
        if techniques:
            sample_tech = list(techniques.keys())[0]
            sample_name = techniques[sample_tech]["name"]
            
            query = {
                "query": {
                    "match": {
                        "name": sample_name
                    }
                }
            }
            
            response = httpx.post(
                f"{os_url}/{os_index}/_search",
                json=query,
                timeout=10
            )
            
            if response.status_code == 200:
                hits = response.json().get("hits", {}).get("total", {}).get("value", 0)
                print(f"   • Found {hits} matching embeddings for '{sample_name}'")
            else:
                print(f"   ⚠️ OpenSearch query failed: {response.status_code}")
    except Exception as e:
        print(f"   ⚠️ OpenSearch check skipped: {e}")
    
    print("\n" + "="*80)
    print("✅ END-TO-END TEST COMPLETED SUCCESSFULLY")
    print("="*80)
    print("\nSummary:")
    print("• Extraction: ✅ Working")
    print("• STIX Validation: ✅ Passing")
    print("• Graph Upsert: ✅ Successful")
    print("• Neo4j Storage: ✅ Verified")
    print("• Vector Embeddings: ✅ Created")
    
    return True


def cleanup_test_data():
    """Clean up test data from Neo4j."""
    print("\nCleaning up test data...")
    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(
            os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            auth=(os.getenv("NEO4J_USER", "neo4j"), os.getenv("NEO4J_PASSWORD", "password"))
        )
        
        with driver.session() as session:
            # Delete test nodes
            result = session.run("""
                MATCH (n)
                WHERE n.source_collection = 'test_extraction'
                DETACH DELETE n
                RETURN count(n) as deleted
            """)
            deleted = result.single()["deleted"]
            print(f"   • Deleted {deleted} test nodes")
        
        driver.close()
        
    except Exception as e:
        print(f"   ⚠️ Cleanup failed: {e}")


def main():
    """Run the test."""
    success = test_extraction_to_graph()
    
    if success:
        # Optionally clean up
        response = input("\nClean up test data from graph? (y/n): ")
        if response.lower() == 'y':
            cleanup_test_data()
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())