#!/usr/bin/env python3
"""
Example: Search for MITRE ATT&CK techniques using natural language.

Usage:
    python search_techniques.py "ransomware encryption"
    python search_techniques.py --api "phishing with attachments"
"""

import sys
import json
from pathlib import Path
import argparse

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from neo4j import GraphDatabase
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def search_via_api(query: str, top_k: int = 10) -> list:
    """Search for techniques using the API."""
    
    api_url = "http://localhost:8000/v1/search/ttx"
    
    print(f"🔍 Searching via API for: '{query}'")
    
    try:
        response = httpx.post(
            api_url,
            json={
                "query": query,
                "top_k": top_k,
                "include_descriptions": True
            },
            timeout=30
        )
        response.raise_for_status()
        
        data = response.json()
        return data.get("results", [])
        
    except httpx.HTTPError as e:
        print(f"❌ API request failed: {e}")
        return []


def search_via_graph(query: str, top_k: int = 10) -> list:
    """Search for techniques directly in Neo4j using full-text search."""
    
    neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password = os.getenv("NEO4J_PASSWORD", "")
    
    print(f"🔍 Searching in graph for: '{query}'")
    
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    
    results = []
    
    with driver.session() as session:
        # Search using text matching
        result = session.run("""
            MATCH (t:AttackPattern)
            WHERE toLower(t.name) CONTAINS toLower($query)
               OR toLower(t.description) CONTAINS toLower($query)
            RETURN t.external_id as id,
                   t.name as name,
                   t.description as description,
                   t.x_mitre_platforms as platforms,
                   t.kill_chain_phases as tactics
            ORDER BY 
                CASE WHEN toLower(t.name) CONTAINS toLower($query) THEN 0 ELSE 1 END,
                t.name
            LIMIT $limit
        """, query=query, limit=top_k)
        
        for record in result:
            results.append({
                "external_id": record["id"],
                "name": record["name"],
                "description": record["description"][:200] + "..." if record["description"] and len(record["description"]) > 200 else record["description"],
                "platforms": record["platforms"],
                "tactics": record["tactics"]
            })
    
    driver.close()
    return results


def search_related_techniques(technique_id: str) -> dict:
    """Find techniques related to a given technique."""
    
    neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password = os.getenv("NEO4J_PASSWORD", "")
    
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    
    related = {
        "subtechniques": [],
        "parent": None,
        "same_tactic": [],
        "used_by_same_groups": [],
        "mitigated_by_same": []
    }
    
    with driver.session() as session:
        # Find subtechniques
        result = session.run("""
            MATCH (p:AttackPattern {external_id: $tech_id})
            OPTIONAL MATCH (p)<-[:SUBTECHNIQUE_OF]-(s:AttackPattern)
            RETURN collect({
                id: s.external_id,
                name: s.name
            }) as subtechniques
        """, tech_id=technique_id)
        
        record = result.single()
        if record:
            related["subtechniques"] = [s for s in record["subtechniques"] if s["id"]]
        
        # Find parent technique
        result = session.run("""
            MATCH (c:AttackPattern {external_id: $tech_id})-[:SUBTECHNIQUE_OF]->(p:AttackPattern)
            RETURN p.external_id as id, p.name as name
        """, tech_id=technique_id)
        
        record = result.single()
        if record:
            related["parent"] = {"id": record["id"], "name": record["name"]}
        
        # Find techniques with same tactic
        result = session.run("""
            MATCH (t1:AttackPattern {external_id: $tech_id})-[:HAS_TACTIC]->(tactic:Tactic)
            MATCH (t2:AttackPattern)-[:HAS_TACTIC]->(tactic)
            WHERE t2.external_id <> $tech_id
            RETURN DISTINCT t2.external_id as id, t2.name as name
            LIMIT 5
        """, tech_id=technique_id)
        
        for record in result:
            related["same_tactic"].append({"id": record["id"], "name": record["name"]})
        
        # Find techniques used by same groups
        result = session.run("""
            MATCH (t1:AttackPattern {external_id: $tech_id})<-[:USES]-(g:IntrusionSet)
            MATCH (g)-[:USES]->(t2:AttackPattern)
            WHERE t2.external_id <> $tech_id
            RETURN DISTINCT t2.external_id as id, t2.name as name, g.name as group
            LIMIT 5
        """, tech_id=technique_id)
        
        for record in result:
            related["used_by_same_groups"].append({
                "id": record["id"],
                "name": record["name"],
                "group": record["group"]
            })
    
    driver.close()
    return related


def main():
    parser = argparse.ArgumentParser(description="Search for MITRE ATT&CK techniques")
    parser.add_argument("query", help="Search query")
    parser.add_argument("--api", action="store_true", help="Use API instead of direct graph search")
    parser.add_argument("--top-k", type=int, default=10, help="Number of results to return")
    parser.add_argument("--related", help="Find techniques related to a specific technique ID")
    
    args = parser.parse_args()
    
    if args.related:
        # Find related techniques
        print(f"🔗 Finding techniques related to: {args.related}")
        print("=" * 60)
        
        related = search_related_techniques(args.related)
        
        if related["parent"]:
            print(f"\n⬆️ Parent Technique:")
            print(f"   {related['parent']['id']}: {related['parent']['name']}")
        
        if related["subtechniques"]:
            print(f"\n⬇️ Subtechniques ({len(related['subtechniques'])}):")
            for sub in related["subtechniques"][:5]:
                print(f"   {sub['id']}: {sub['name']}")
        
        if related["same_tactic"]:
            print(f"\n🎯 Same Tactic ({len(related['same_tactic'])}):")
            for tech in related["same_tactic"][:5]:
                print(f"   {tech['id']}: {tech['name']}")
        
        if related["used_by_same_groups"]:
            print(f"\n👥 Used by Same Groups ({len(related['used_by_same_groups'])}):")
            for tech in related["used_by_same_groups"][:5]:
                print(f"   {tech['id']}: {tech['name']} (via {tech['group']})")
        
        return
    
    # Regular search
    if args.api:
        results = search_via_api(args.query, args.top_k)
    else:
        results = search_via_graph(args.query, args.top_k)
    
    if not results:
        print(f"❌ No results found for: '{args.query}'")
        return
    
    print(f"\n✅ Found {len(results)} techniques matching '{args.query}':")
    print("=" * 60)
    
    for i, tech in enumerate(results, 1):
        # Format the output
        tech_id = tech.get("external_id", "Unknown")
        name = tech.get("name", "Unknown")
        score = tech.get("score", 0)
        description = tech.get("description", "")
        
        print(f"\n{i}. {tech_id}: {name}")
        
        if score > 0:
            # Score indicator for API results
            if score >= 0.8:
                score_icon = "🟢"
            elif score >= 0.6:
                score_icon = "🟡"
            else:
                score_icon = "🔴"
            print(f"   {score_icon} Score: {score:.3f}")
        
        if description:
            # Wrap description text
            import textwrap
            wrapped = textwrap.fill(description, width=70, initial_indent="   ", subsequent_indent="   ")
            print(wrapped)
        
        # Show platforms if available
        platforms = tech.get("platforms", [])
        if platforms and isinstance(platforms, list):
            print(f"   Platforms: {', '.join(platforms[:5])}")
        
        # Show tactics if available
        tactics = tech.get("tactics", [])
        if tactics:
            if isinstance(tactics, list) and len(tactics) > 0:
                if isinstance(tactics[0], dict):
                    tactic_names = [t.get("phase_name", "") for t in tactics]
                else:
                    tactic_names = tactics
                print(f"   Tactics: {', '.join(tactic_names)}")
    
    # Save results
    if len(results) > 0:
        output_file = f"search_results_{args.query.replace(' ', '_')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to: {output_file}")


if __name__ == "__main__":
    main()