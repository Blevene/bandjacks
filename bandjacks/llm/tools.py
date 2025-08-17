"""Tool adapters for LLM to interact with Bandjacks APIs."""

import os
from typing import List, Optional, Dict, Any
import httpx


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
        with httpx.Client() as client:
            response = client.post(
                f"{API_BASE}/search/ttx",
                json=body,
                timeout=TIMEOUT
            )
            response.raise_for_status()
            return response.json().get("results", [])
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
        with httpx.Client() as client:
            response = client.get(
                f"{API_BASE}/stix/objects/{stix_id}",
                timeout=TIMEOUT
            )
            if response.status_code == 200:
                data = response.json()
                # Extract relevant fields for LLM
                obj = data.get("object", {})
                return {
                    "stix_id": obj.get("id"),
                    "name": obj.get("name"),
                    "description": obj.get("description"),
                    "type": obj.get("type"),
                    "tactics": obj.get("kill_chain_phases", []),
                    "platforms": obj.get("x_mitre_platforms", [])
                }
            return None
    except Exception as e:
        return {"error": str(e)}


def list_tactics() -> List[Dict[str, str]]:
    """
    Get list of all ATT&CK tactics with shortnames.
    
    Returns:
        List of tactics with stix_id, shortname, and name
    """
    try:
        with httpx.Client() as client:
            response = client.get(
                f"{API_BASE}/catalog/tactics",
                timeout=TIMEOUT
            )
            response.raise_for_status()
            return response.json()
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
        "graph_lookup": graph_lookup,
        "list_tactics": list_tactics
    }