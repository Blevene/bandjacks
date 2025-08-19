#!/usr/bin/env python3
"""Monitor embedding generation progress during ATT&CK ingestion."""

import time
from neo4j import GraphDatabase
from opensearchpy import OpenSearch
import sys

def get_counts():
    """Get current counts from Neo4j and OpenSearch."""
    
    # Neo4j counts
    driver = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'password'))
    neo4j_counts = {}
    
    with driver.session() as s:
        # Node counts
        result = s.run('''
            MATCH (n)
            WHERE n:AttackPattern OR n:IntrusionSet OR n:Software OR n:Mitigation
            RETURN labels(n)[0] as type, count(n) as count
        ''')
        for r in result:
            neo4j_counts[f"neo4j_{r['type']}"] = r['count']
        
        # Relationship counts
        result = s.run('''
            MATCH ()-[r]->()
            WHERE type(r) IN ['USES', 'MITIGATES']
            RETURN type(r) as rel_type, count(r) as count
        ''')
        for r in result:
            neo4j_counts[f"neo4j_rel_{r['rel_type']}"] = r['count']
    
    driver.close()
    
    # OpenSearch counts
    os_client = OpenSearch('http://localhost:9200', timeout=30)
    os_counts = {}
    
    # Node embeddings
    try:
        resp = os_client.count(index='bandjacks_attack_nodes-v1')
        os_counts['os_nodes_total'] = resp['count']
        
        # By type
        resp = os_client.search(
            index='bandjacks_attack_nodes-v1',
            body={
                "size": 0,
                "aggs": {
                    "by_type": {
                        "terms": {"field": "kb_type", "size": 10}
                    }
                }
            }
        )
        for bucket in resp['aggregations']['by_type']['buckets']:
            os_counts[f"os_{bucket['key']}"] = bucket['doc_count']
    except:
        pass
    
    # Edge embeddings
    try:
        resp = os_client.count(index='bandjacks_attack_edges-v1')
        os_counts['os_edges_total'] = resp['count']
    except:
        pass
    
    return {**neo4j_counts, **os_counts}

def monitor_progress(interval=5):
    """Monitor and display progress."""
    print("Monitoring embedding generation progress...")
    print("Press Ctrl+C to stop\n")
    
    prev_counts = {}
    start_time = time.time()
    
    try:
        while True:
            counts = get_counts()
            elapsed = time.time() - start_time
            
            # Clear screen and show header
            print("\033[2J\033[H")  # Clear screen
            print(f"=== Embedding Progress Monitor === [{elapsed:.0f}s elapsed]\n")
            
            # Neo4j status
            print("Neo4j Database:")
            print(f"  AttackPatterns: {counts.get('neo4j_AttackPattern', 0)}")
            print(f"  IntrusionSets:  {counts.get('neo4j_IntrusionSet', 0)}")
            print(f"  Software:       {counts.get('neo4j_Software', 0)}")
            print(f"  Mitigations:    {counts.get('neo4j_Mitigation', 0)}")
            print(f"  USES edges:     {counts.get('neo4j_rel_USES', 0)}")
            print(f"  MITIGATES:      {counts.get('neo4j_rel_MITIGATES', 0)}")
            
            # OpenSearch status
            print("\nOpenSearch Embeddings:")
            print(f"  AttackPatterns: {counts.get('os_AttackPattern', 0)} / {counts.get('neo4j_AttackPattern', 0)}")
            print(f"  IntrusionSets:  {counts.get('os_IntrusionSet', 0)} / {counts.get('neo4j_IntrusionSet', 0)}")
            print(f"  Software:       {counts.get('os_Software', 0)} / {counts.get('neo4j_Software', 0)}")
            print(f"  Total nodes:    {counts.get('os_nodes_total', 0)}")
            print(f"  Edge embeddings: {counts.get('os_edges_total', 0)} / {counts.get('neo4j_rel_USES', 0) + counts.get('neo4j_rel_MITIGATES', 0)}")
            
            # Calculate progress
            total_expected = (counts.get('neo4j_AttackPattern', 0) + 
                            counts.get('neo4j_IntrusionSet', 0) + 
                            counts.get('neo4j_Software', 0))
            total_done = counts.get('os_nodes_total', 0)
            
            if total_expected > 0:
                node_progress = (total_done / total_expected) * 100
                print(f"\nNode embedding progress: {node_progress:.1f}%")
            
            edge_expected = counts.get('neo4j_rel_USES', 0) + counts.get('neo4j_rel_MITIGATES', 0)
            edge_done = counts.get('os_edges_total', 0)
            
            if edge_expected > 0:
                edge_progress = (edge_done / edge_expected) * 100
                print(f"Edge embedding progress: {edge_progress:.1f}%")
            
            # Show rate
            if prev_counts and elapsed > 0:
                node_rate = (counts.get('os_nodes_total', 0) - prev_counts.get('os_nodes_total', 0)) / interval
                edge_rate = (counts.get('os_edges_total', 0) - prev_counts.get('os_edges_total', 0)) / interval
                
                if node_rate > 0 or edge_rate > 0:
                    print(f"\nProcessing rate:")
                    if node_rate > 0:
                        print(f"  Nodes: {node_rate:.1f}/sec")
                    if edge_rate > 0:
                        print(f"  Edges: {edge_rate:.1f}/sec")
                    
                    # Estimate time remaining
                    nodes_left = total_expected - total_done
                    edges_left = edge_expected - edge_done
                    
                    if node_rate > 0 and nodes_left > 0:
                        node_eta = nodes_left / node_rate
                        print(f"  Est. time for nodes: {node_eta/60:.1f} min")
                    
                    if edge_rate > 0 and edges_left > 0:
                        edge_eta = edges_left / edge_rate
                        print(f"  Est. time for edges: {edge_eta/60:.1f} min")
            
            prev_counts = counts
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped.")
        return counts

if __name__ == "__main__":
    final_counts = monitor_progress()
    print("\nFinal counts:", final_counts)