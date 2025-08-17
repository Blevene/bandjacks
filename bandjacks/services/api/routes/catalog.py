"""Catalog routes for ATT&CK releases."""

from typing import List, Dict
from fastapi import APIRouter, HTTPException
from bandjacks.services.api.settings import settings
from bandjacks.loaders.attack_catalog import fetch_catalog
from bandjacks.services.api.schemas import CatalogItem, VersionRef
from neo4j import GraphDatabase
from functools import lru_cache

router = APIRouter(tags=["catalog"])

@router.get("/catalog/attack/releases", response_model=list[CatalogItem])
async def get_attack_releases():
    try:
        cat = fetch_catalog(settings.attack_index_url)
        return [
            CatalogItem(
                name=c.name,
                key=c.key,
                versions=[VersionRef(version=v.version, url=v.url, modified=v.modified) for v in c.versions]
            )
            for c in cat.values()
        ]
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch catalog: {e}")


@lru_cache(maxsize=1, typed=False)
def _get_tactics_cached() -> List[Dict[str, str]]:
    """Get tactics from Neo4j (cached for 6 hours)."""
    driver = GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password)
    )
    
    try:
        with driver.session() as session:
            result = session.run("""
                MATCH (t:Tactic)
                RETURN t.stix_id as stix_id, 
                       t.shortname as shortname, 
                       t.name as name
                ORDER BY t.shortname
            """)
            
            tactics = []
            for record in result:
                tactics.append({
                    "stix_id": record["stix_id"],
                    "shortname": record["shortname"],
                    "name": record["name"]
                })
            
            # If no tactics in DB, return standard list
            if not tactics:
                tactics = [
                    {"stix_id": "x-mitre-tactic--reconnaissance", "shortname": "reconnaissance", "name": "Reconnaissance"},
                    {"stix_id": "x-mitre-tactic--resource-development", "shortname": "resource-development", "name": "Resource Development"},
                    {"stix_id": "x-mitre-tactic--initial-access", "shortname": "initial-access", "name": "Initial Access"},
                    {"stix_id": "x-mitre-tactic--execution", "shortname": "execution", "name": "Execution"},
                    {"stix_id": "x-mitre-tactic--persistence", "shortname": "persistence", "name": "Persistence"},
                    {"stix_id": "x-mitre-tactic--privilege-escalation", "shortname": "privilege-escalation", "name": "Privilege Escalation"},
                    {"stix_id": "x-mitre-tactic--defense-evasion", "shortname": "defense-evasion", "name": "Defense Evasion"},
                    {"stix_id": "x-mitre-tactic--credential-access", "shortname": "credential-access", "name": "Credential Access"},
                    {"stix_id": "x-mitre-tactic--discovery", "shortname": "discovery", "name": "Discovery"},
                    {"stix_id": "x-mitre-tactic--lateral-movement", "shortname": "lateral-movement", "name": "Lateral Movement"},
                    {"stix_id": "x-mitre-tactic--collection", "shortname": "collection", "name": "Collection"},
                    {"stix_id": "x-mitre-tactic--command-and-control", "shortname": "command-and-control", "name": "Command and Control"},
                    {"stix_id": "x-mitre-tactic--exfiltration", "shortname": "exfiltration", "name": "Exfiltration"},
                    {"stix_id": "x-mitre-tactic--impact", "shortname": "impact", "name": "Impact"}
                ]
            
            return tactics
    finally:
        driver.close()


@router.get("/catalog/tactics")
async def get_tactics() -> List[Dict[str, str]]:
    """
    Get list of all ATT&CK tactics with their IDs and names.
    
    Returns:
        List of tactics with stix_id, shortname, and name
    """
    try:
        return _get_tactics_cached()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch tactics: {e}")