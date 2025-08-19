"""Tool adapters for LLM to interact with Bandjacks APIs."""

import os
from typing import List, Optional, Dict, Any
import httpx
from bandjacks.loaders.search_nodes import ttx_search_kb
from bandjacks.services.api.settings import settings
from neo4j import GraphDatabase


# Base API URL - can be overridden by environment variable
API_BASE = os.getenv("BANDJACKS_API_BASE", "http://localhost:8000/v1")
TIMEOUT = 30  # seconds


def vector_search_ttx(
    text: str,
    kb_types: Optional[List[str]] = None,
    top_k: int = 8
) -> List[Dict[str, Any]]:
    """
    Search for ATT&CK techniques/entities using vector similarity.
    
    Args:
        text: Query text to search for
        kb_types: Optional list of entity types to filter (e.g., ["AttackPattern"])
        top_k: Number of results to return
        
    Returns:
        List of matching entities with scores
    """
    body = {
        "text": text,
        "top_k": top_k
    }
    if kb_types:
        body["kb_types"] = kb_types
    
    try:
        # Call search function directly to avoid HTTP deadlock
        results = ttx_search_kb(
            os_url=settings.opensearch_url,
            index=settings.os_index_nodes,
            text=text,
            top_k=top_k,
            kb_types=kb_types
        )
        return results
    except Exception as e:
        return [{"error": str(e)}]


def graph_lookup(stix_id: str) -> Optional[Dict[str, Any]]:
    """
    Look up a STIX object by ID and return its metadata.
    
    Args:
        stix_id: STIX ID to look up (e.g., "attack-pattern--...")
        
    Returns:
        Object metadata including name, description, tactics, or None if not found
    """
    try:
        # Query Neo4j directly to avoid HTTP deadlock
        driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password)
        )
        
        with driver.session() as session:
            result = session.run("""
                MATCH (n {stix_id: $stix_id})
                RETURN n.stix_id as stix_id, n.name as name, n.description as description,
                       n.type as type, n.external_id as external_id, n.x_mitre_platforms as platforms,
                       labels(n) as labels
                LIMIT 1
            """, stix_id=stix_id)
            
            record = result.single()
            if record:
                return {
                    "stix_id": record["stix_id"],
                    "name": record["name"],
                    "external_id": record["external_id"],
                    "description": record["description"],
                    "type": record["type"],
                    "platforms": record["platforms"] or [],
                    "labels": record["labels"]
                }
            return None
            
        driver.close()
    except Exception as e:
        return {"error": str(e)}


def list_tactics() -> List[Dict[str, str]]:
    """
    Get list of all ATT&CK tactics with shortnames.
    
    Returns:
        List of tactics with stix_id, shortname, and name
    """
    try:
        # Query Neo4j directly to avoid HTTP deadlock
        driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password)
        )
        
        with driver.session() as session:
            result = session.run("""
                MATCH (t:Tactic)
                RETURN t.shortname as shortname, t.name as name
                ORDER BY t.name
            """)
            
            tactics = []
            for record in result:
                if record["shortname"] and record["name"]:
                    tactics.append({
                        "shortname": record["shortname"],
                        "name": record["name"]
                    })
            
            if tactics:
                return tactics
                
        driver.close()
    except Exception as e:
        # Return a fallback list of common tactics if API fails
        return [
            {"shortname": "reconnaissance", "name": "Reconnaissance"},
            {"shortname": "resource-development", "name": "Resource Development"},
            {"shortname": "initial-access", "name": "Initial Access"},
            {"shortname": "execution", "name": "Execution"},
            {"shortname": "persistence", "name": "Persistence"},
            {"shortname": "privilege-escalation", "name": "Privilege Escalation"},
            {"shortname": "defense-evasion", "name": "Defense Evasion"},
            {"shortname": "credential-access", "name": "Credential Access"},
            {"shortname": "discovery", "name": "Discovery"},
            {"shortname": "lateral-movement", "name": "Lateral Movement"},
            {"shortname": "collection", "name": "Collection"},
            {"shortname": "command-and-control", "name": "Command and Control"},
            {"shortname": "exfiltration", "name": "Exfiltration"},
            {"shortname": "impact", "name": "Impact"}
        ]


def get_tool_definitions() -> List[Dict[str, Any]]:
    """
    Get OpenAI-compatible tool definitions for the LLM.
    
    Returns:
        List of tool definitions in OpenAI function calling format
    """
    return [
        {
            "type": "function",
            "function": {
                "name": "vector_search_ttx",
                "description": "Search for ATT&CK techniques, groups, or software using semantic similarity",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "The text to search for similar techniques"
                        },
                        "kb_types": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Entity types to filter: AttackPattern, IntrusionSet, Software"
                        },
                        "top_k": {
                            "type": "integer",
                            "description": "Number of results to return",
                            "default": 8
                        }
                    },
                    "required": ["text"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "resolve_technique_by_external_id",
                "description": "Resolve ATT&CK technique meta by external_id (e.g., T1059.001)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "external_id": {
                            "type": "string",
                            "description": "ATT&CK external_id (Txxxx or Txxxx.xxx)"
                        }
                    },
                    "required": ["external_id"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_techniques_for_tactic",
                "description": "List ATT&CK techniques for a tactic shortname (e.g., command-and-control)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tactic_shortname": {"type": "string"},
                        "limit": {"type": "integer", "default": 10}
                    },
                    "required": ["tactic_shortname"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "graph_lookup",
                "description": "Look up detailed information about a specific ATT&CK object by its STIX ID",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "stix_id": {
                            "type": "string",
                            "description": "The STIX ID to look up (e.g., attack-pattern--...)"
                        }
                    },
                    "required": ["stix_id"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_tactics",
                "description": "Get a list of all ATT&CK tactics with their shortnames",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            }
        }
    ]


def get_tool_functions() -> Dict[str, callable]:
    """
    Get mapping of tool names to Python functions.
    
    Returns:
        Dict mapping tool names to their implementation functions
    """
    return {
        "vector_search_ttx": vector_search_ttx,
        "resolve_technique_by_external_id": resolve_technique_by_external_id,
        "list_techniques_for_tactic": list_techniques_for_tactic,
        "graph_lookup": graph_lookup,
        "list_tactics": list_tactics,
        "list_subtechniques": list_subtechniques
    }


def resolve_technique_by_external_id(external_id: str) -> Optional[Dict[str, Any]]:
    """
    Resolve ATT&CK technique metadata from external_id (Txxxx[.xxx]).
    Returns dict with stix_id, name, external_id, tactic, or None if not found.
    """
    try:
        driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password)
        )
        with driver.session() as session:
            rec = session.run(
                """
                MATCH (ap:AttackPattern {external_id: $ext})
                OPTIONAL MATCH (ap)-[:HAS_TACTIC]->(t:Tactic)
                RETURN ap.stix_id AS stix_id, ap.name AS name, ap.external_id AS external_id, t.shortname AS tactic
                LIMIT 1
                """,
                ext=external_id
            ).single()
            if rec:
                return {
                    "stix_id": rec["stix_id"],
                    "name": rec["name"],
                    "external_id": rec["external_id"],
                    "tactic": rec["tactic"],
                }
            return None
    except Exception as e:
        return {"error": str(e)}
    finally:
        try:
            driver.close()
        except Exception:
            pass


def list_techniques_for_tactic(tactic_shortname: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    List ATT&CK techniques for a given tactic shortname.
    """
    try:
        driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password)
        )
        with driver.session() as session:
            result = session.run(
                """
                MATCH (t:Tactic {shortname: $tac})<-[:HAS_TACTIC]-(ap:AttackPattern)
                RETURN ap.external_id AS external_id, ap.name AS name, ap.stix_id AS stix_id
                ORDER BY ap.name
                LIMIT $limit
                """,
                tac=tactic_shortname,
                limit=limit,
            )
            return [
                {"external_id": r["external_id"], "name": r["name"], "stix_id": r["stix_id"]}
                for r in result
            ]
    except Exception as e:
        return [{"error": str(e)}]
    finally:
        try:
            driver.close()
        except Exception:
            pass


def list_subtechniques(parent_external_id: str) -> List[Dict[str, Any]]:
    """List sub-techniques for a parent technique external_id."""
    try:
        driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password)
        )
        with driver.session() as session:
            rows = session.run(
                """
                MATCH (ap:AttackPattern {external_id: $pid})<-[:IS_PARENT]-(sub:AttackPattern)
                RETURN sub.external_id AS external_id, sub.name AS name
                ORDER BY sub.name
                """,
                pid=parent_external_id,
            )
            return [{"external_id": r["external_id"], "name": r["name"]} for r in rows]
    except Exception as e:
        return [{"error": str(e)}]
    finally:
        try:
            driver.close()
        except Exception:
            pass