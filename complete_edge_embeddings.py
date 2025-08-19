#!/usr/bin/env python3
"""Complete missing edge embeddings for USES relationships."""

import sys
import time
from neo4j import GraphDatabase
from opensearchpy import OpenSearch
from bandjacks.loaders.embedder import encode
from bandjacks.loaders.edge_embeddings import upsert_edge_doc
from bandjacks.services.api.settings import settings

def get_existing_edge_ids(os_url: str, index: str = "bandjacks_attack_edges-v1"):
    """Get set of edge IDs already in OpenSearch."""
    client = OpenSearch(hosts=[os_url], timeout=30, use_ssl=False, verify_certs=False)
    
    existing_ids = set()
    
    # Use scroll to get all document IDs
    resp = client.search(
        index=index,
        body={
            "size": 10000,
            "_source": False,
            "query": {"match_all": {}}
        },
        scroll='2m'
    )
    
    scroll_id = resp['_scroll_id']
    hits = resp['hits']['hits']
    
    while hits:
        for hit in hits:
            existing_ids.add(hit['_id'])
        
        resp = client.scroll(scroll_id=scroll_id, scroll='2m')
        hits = resp['hits']['hits']
    
    return existing_ids

def complete_edge_embeddings():
    """Generate embeddings for missing edges."""
    
    print("="*80)
    print("COMPLETING EDGE EMBEDDINGS")
    print("="*80)
    
    # Get existing edge IDs from OpenSearch
    print("\nFetching existing edge IDs from OpenSearch...")
    existing_ids = get_existing_edge_ids(settings.opensearch_url)
    print(f"Found {len(existing_ids)} existing edge embeddings")
    
    # Connect to Neo4j
    driver = GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password)
    )
    
    try:
        with driver.session() as session:
            # Count total USES edges
            result = session.run("""
                MATCH ()-[r:USES]->()
                RETURN count(r) as total
            """)
            total_uses = result.single()["total"]
            print(f"\nTotal USES edges in Neo4j: {total_uses}")
            
            # Get all USES relationships with node names
            print("\nFetching USES relationships...")
            result = session.run("""
                MATCH (s)-[r:USES]->(t)
                RETURN 
                    s.stix_id as source_id,
                    s.name as source_name,
                    s.type as source_type,
                    t.stix_id as target_id,
                    t.name as target_name,
                    t.type as target_type,
                    id(r) as rel_id
            """)
            
            edges = []
            for record in result:
                # Create edge ID
                edge_id = f"{record['source_id']}-uses-{record['target_id']}"
                
                # Skip if already exists
                if edge_id in existing_ids:
                    continue
                    
                edges.append({
                    'id': edge_id,
                    'source_id': record['source_id'],
                    'source_name': record['source_name'] or record['source_id'],
                    'target_id': record['target_id'],
                    'target_name': record['target_name'] or record['target_id'],
                    'rel_id': record['rel_id']
                })
            
            print(f"Found {len(edges)} missing USES edge embeddings to generate")
            
            if not edges:
                print("No missing edges found!")
                return
            
            # Generate embeddings and upload
            print(f"\nGenerating embeddings for {len(edges)} edges...")
            start_time = time.time()
            
            for i, edge in enumerate(edges):
                # Generate embedding text
                text = f"{edge['source_name']} uses {edge['target_name']}"
                
                try:
                    # Generate embedding
                    vec = encode(text)
                    
                    if vec and len(vec) == 768:
                        # Upload to OpenSearch
                        upsert_edge_doc(
                            settings.opensearch_url,
                            "bandjacks_attack_edges-v1",
                            {
                                "id": edge['id'],
                                "edge_type": "USES",
                                "source_id": edge['source_id'],
                                "target_id": edge['target_id'],
                                "attack_version": "17.1",  # Current version
                                "text": text,
                                "embedding": vec
                            }
                        )
                        
                        if (i + 1) % 100 == 0:
                            elapsed = time.time() - start_time
                            rate = (i + 1) / elapsed
                            eta = (len(edges) - i - 1) / rate
                            print(f"Progress: {i+1}/{len(edges)} ({(i+1)/len(edges)*100:.1f}%) - "
                                  f"Rate: {rate:.1f}/s - ETA: {eta/60:.1f} min")
                    else:
                        print(f"Failed to generate embedding for: {edge['id']}")
                        
                except Exception as e:
                    print(f"Error processing edge {edge['id']}: {e}")
                    
            elapsed = time.time() - start_time
            print(f"\nCompleted in {elapsed/60:.1f} minutes")
            
            # Verify final counts
            print("\n" + "="*80)
            print("VERIFICATION")
            print("="*80)
            
            # Check OpenSearch
            os_client = OpenSearch(settings.opensearch_url, timeout=30)
            resp = os_client.count(index="bandjacks_attack_edges-v1")
            os_count = resp['count']
            
            print(f"Total edges in OpenSearch: {os_count}")
            print(f"Expected total: {total_uses + 1584}")  # USES + MITIGATES
            print(f"Completion: {os_count/(total_uses + 1584)*100:.1f}%")
            
    finally:
        driver.close()

if __name__ == "__main__":
    complete_edge_embeddings()