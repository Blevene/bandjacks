#!/usr/bin/env python3
"""
Build AttackFlow co-occurrence models for all IntrusionSets in the Bandjacks knowledge base.

This script generates AttackFlow models that represent how threat actors use MITRE ATT&CK
techniques together. Unlike sequential flows, these use co-occurrence models that show
technique relationships without implying false temporal ordering.

Key Features:
- Processes all 165+ intrusion sets that have associated techniques
- Creates co-occurrence edges within tactics and across adjacent tactics  
- Handles API rate limiting with automatic pauses
- Skips existing flows to avoid duplicates
- Provides real-time progress tracking

Usage Examples:
  # Generate flows for all intrusion sets
  uv run python scripts/build_intrusion_flows_simple.py
  
  # Test with first 10 intrusion sets
  uv run python scripts/build_intrusion_flows_simple.py --limit 10
  
  # Force regeneration of existing flows
  uv run python scripts/build_intrusion_flows_simple.py --force

Performance:
- ~1-3 seconds per intrusion set
- Total runtime: ~10-15 minutes (with rate limiting)
- Automatic 25-second pauses every 20 requests
- Single optimized database query per intrusion set

Output:
- Real-time progress with success/skip/error indicators
- Summary statistics and error reporting
- JSON log file with detailed results
- AttackFlow nodes stored in Neo4j graph database

See docs/ATTACKFLOW_GENERATION.md for complete documentation.
"""

import json
import requests
from neo4j import GraphDatabase
import os
from datetime import datetime
import time

# Configuration
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")


def get_intrusion_sets_with_techniques():
    """Get all intrusion sets that have associated techniques."""
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    
    with driver.session() as session:
        result = session.run("""
            MATCH (g:IntrusionSet)-[:USES]->(t:AttackPattern)
            WITH g, count(t) as technique_count
            WHERE technique_count > 0
            RETURN g.stix_id as stix_id, g.name as name, technique_count
            ORDER BY technique_count DESC
        """)
        
        intrusion_sets = []
        for record in result:
            intrusion_sets.append({
                "stix_id": record["stix_id"],
                "name": record["name"],
                "technique_count": record["technique_count"]
            })
    
    driver.close()
    return intrusion_sets


def check_existing_flow(stix_id):
    """Check if a flow already exists for this intrusion set."""
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    
    with driver.session() as session:
        result = session.run("""
            MATCH (f:AttackFlow {source_id: $source_id})
            RETURN count(f) as flow_count
        """, source_id=stix_id)
        
        record = result.single()
        exists = record["flow_count"] > 0
    
    driver.close()
    return exists


def build_flow_for_intrusion_set(intrusion_set, skip_existing=True):
    """Build a flow for a single intrusion set."""
    
    stix_id = intrusion_set["stix_id"]
    name = intrusion_set["name"]
    
    # Check if flow already exists
    if skip_existing and check_existing_flow(stix_id):
        return {
            "status": "skipped",
            "stix_id": stix_id,
            "name": name,
            "reason": "Flow already exists"
        }
    
    # Build the flow via API
    url = f"{API_BASE_URL}/v1/flows/build"
    payload = {"intrusion_set_id": stix_id}
    
    try:
        response = requests.post(url, json=payload, timeout=30)
        if response.status_code == 200:
            data = response.json()
            return {
                "status": "success",
                "stix_id": stix_id,
                "name": name,
                "flow_id": data["flow_id"],
                "steps_count": len(data["steps"]),
                "edges_count": len(data["edges"])
            }
        else:
            return {
                "status": "error",
                "stix_id": stix_id,
                "name": name,
                "error": f"HTTP {response.status_code}: {response.text}"
            }
    except requests.Timeout:
        return {
            "status": "error",
            "stix_id": stix_id,
            "name": name,
            "error": "Request timeout (30s)"
        }
    except Exception as e:
        return {
            "status": "error",
            "stix_id": stix_id,
            "name": name,
            "error": str(e)
        }


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Build AttackFlow co-occurrence models for all IntrusionSets",
        epilog="""
Examples:
  %(prog)s                    # Generate flows for all 165+ intrusion sets
  %(prog)s --limit 10         # Test with first 10 intrusion sets  
  %(prog)s --force            # Regenerate existing flows
  %(prog)s --limit 5 --force  # Force regeneration of first 5 flows

The script automatically handles rate limiting and provides real-time progress.
Generated flows are stored as AttackFlow nodes in the Neo4j knowledge graph.

For detailed documentation, see docs/ATTACKFLOW_GENERATION.md
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--force", action="store_true", 
                       help="Rebuild existing flows (default: skip existing)")
    parser.add_argument("--limit", type=int, metavar="N",
                       help="Limit number of intrusion sets to process (default: all)")
    
    args = parser.parse_args()
    
    print(f"Starting flow generation at {datetime.now().isoformat()}")
    print(f"Skip existing: {not args.force}")
    print("-" * 60)
    
    # Get all intrusion sets with techniques
    intrusion_sets = get_intrusion_sets_with_techniques()
    
    if args.limit:
        intrusion_sets = intrusion_sets[:args.limit]
    
    print(f"Found {len(intrusion_sets)} intrusion sets with techniques")
    print("-" * 60)
    
    # Process each intrusion set
    results = []
    for i, intrusion_set in enumerate(intrusion_sets, 1):
        print(f"\n[{i}/{len(intrusion_sets)}] Processing {intrusion_set['name']} ({intrusion_set['technique_count']} techniques)...")
        
        result = build_flow_for_intrusion_set(intrusion_set, skip_existing=not args.force)
        
        # Print result
        status_symbol = {
            "success": "✓",
            "skipped": "○",
            "error": "✗"
        }.get(result["status"], "?")
        
        print(f"  {status_symbol} {result['status']}", end="")
        
        if result["status"] == "success":
            print(f" - flow: {result['flow_id'][:20]}..., {result['steps_count']} steps, {result['edges_count']} edges")
        elif result["status"] == "error":
            print(f" - {result['error']}")
        else:
            print(f" - {result.get('reason', '')}")
        
        results.append(result)
        
        # Delay between requests to avoid rate limiting
        # Longer delay every 20 requests
        if i % 20 == 0 and i > 0:
            print("  [Rate limit pause - waiting 25 seconds...]")
            time.sleep(25)
        elif i < len(intrusion_sets):
            time.sleep(2)  # 2 second delay between requests
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    success_count = sum(1 for r in results if r["status"] == "success")
    skipped_count = sum(1 for r in results if r["status"] == "skipped")
    error_count = sum(1 for r in results if r["status"] == "error")
    
    print(f"Total processed: {len(results)}")
    print(f"  ✓ Success: {success_count}")
    print(f"  ○ Skipped: {skipped_count}")
    print(f"  ✗ Errors: {error_count}")
    
    if error_count > 0:
        print("\nErrors encountered:")
        for result in results:
            if result["status"] == "error":
                print(f"  - {result['name']}: {result['error']}")
    
    # Save results to file
    output_file = f"intrusion_set_flows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {output_file}")
    
    print(f"\nCompleted at {datetime.now().isoformat()}")


if __name__ == "__main__":
    main()