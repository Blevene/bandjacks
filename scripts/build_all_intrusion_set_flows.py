#!/usr/bin/env python3
"""
Build AttackFlow co-occurrence models for all IntrusionSets in the database.
"""

import asyncio
import json
import sys
from typing import List, Dict, Any
import aiohttp
from neo4j import GraphDatabase
import os
from datetime import datetime

# Configuration
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")


async def get_intrusion_sets_with_techniques() -> List[Dict[str, Any]]:
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


async def check_existing_flow(stix_id: str) -> bool:
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


async def build_flow_for_intrusion_set(
    session: aiohttp.ClientSession,
    intrusion_set: Dict[str, Any],
    skip_existing: bool = True
) -> Dict[str, Any]:
    """Build a flow for a single intrusion set."""
    
    stix_id = intrusion_set["stix_id"]
    name = intrusion_set["name"]
    
    # Check if flow already exists
    if skip_existing and await check_existing_flow(stix_id):
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
        async with session.post(url, json=payload, timeout=30) as response:
            if response.status == 200:
                data = await response.json()
                return {
                    "status": "success",
                    "stix_id": stix_id,
                    "name": name,
                    "flow_id": data["flow_id"],
                    "steps_count": len(data["steps"]),
                    "edges_count": len(data["edges"])
                }
            else:
                error = await response.text()
                return {
                    "status": "error",
                    "stix_id": stix_id,
                    "name": name,
                    "error": f"HTTP {response.status}: {error}"
                }
    except asyncio.TimeoutError:
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


async def build_all_flows(batch_size: int = 5, skip_existing: bool = True):
    """Build flows for all intrusion sets in batches."""
    
    print(f"Starting flow generation at {datetime.now().isoformat()}")
    print(f"Batch size: {batch_size}, Skip existing: {skip_existing}")
    print("-" * 60)
    
    # Get all intrusion sets with techniques
    intrusion_sets = await get_intrusion_sets_with_techniques()
    print(f"Found {len(intrusion_sets)} intrusion sets with techniques")
    print("-" * 60)
    
    # Process in batches
    results = []
    async with aiohttp.ClientSession() as session:
        for i in range(0, len(intrusion_sets), batch_size):
            batch = intrusion_sets[i:i+batch_size]
            print(f"\nProcessing batch {i//batch_size + 1} ({i+1}-{min(i+batch_size, len(intrusion_sets))} of {len(intrusion_sets)})")
            
            # Create tasks for this batch
            tasks = [
                build_flow_for_intrusion_set(session, intrusion_set, skip_existing)
                for intrusion_set in batch
            ]
            
            # Run batch concurrently
            batch_results = await asyncio.gather(*tasks)
            
            # Print batch results
            for result in batch_results:
                status_symbol = {
                    "success": "✓",
                    "skipped": "○",
                    "error": "✗"
                }.get(result["status"], "?")
                
                print(f"  {status_symbol} {result['name'][:40]:40} - {result['status']}", end="")
                
                if result["status"] == "success":
                    print(f" (flow: {result['flow_id'][:20]}..., {result['steps_count']} steps, {result['edges_count']} edges)")
                elif result["status"] == "error":
                    print(f" - {result['error']}")
                else:
                    print(f" - {result.get('reason', '')}")
                
                results.append(result)
            
            # Small delay between batches to avoid overwhelming the API
            if i + batch_size < len(intrusion_sets):
                await asyncio.sleep(1)
    
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


async def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Build AttackFlow models for all IntrusionSets")
    parser.add_argument("--batch-size", type=int, default=5, help="Number of concurrent requests per batch")
    parser.add_argument("--force", action="store_true", help="Rebuild existing flows")
    parser.add_argument("--limit", type=int, help="Limit number of intrusion sets to process")
    
    args = parser.parse_args()
    
    await build_all_flows(
        batch_size=args.batch_size,
        skip_existing=not args.force
    )


if __name__ == "__main__":
    asyncio.run(main())