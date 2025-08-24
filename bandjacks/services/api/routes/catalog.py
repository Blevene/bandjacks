"""Catalog routes for ATT&CK releases."""

from typing import List, Dict
from fastapi import APIRouter, HTTPException, status
from bandjacks.services.api.settings import settings
from bandjacks.loaders.attack_catalog import fetch_catalog
from bandjacks.services.api.schemas import CatalogItem, VersionRef, CatalogTacticsResponse
from typing import Optional
from neo4j import GraphDatabase
from functools import lru_cache
import uuid

router = APIRouter(tags=["catalog"])

@router.get(
    "/catalog/attack/releases",
    response_model=List[CatalogItem],
    status_code=status.HTTP_200_OK,
    summary="List ATT&CK Releases",
    description="""
    Retrieve available MITRE ATT&CK framework releases and their collection URLs.
    
    Returns a list of available ATT&CK collections (enterprise, mobile, ICS) with
    their version history and download URLs from the official MITRE repository.
    
    **Collections included:**
    - enterprise-attack (Enterprise techniques)
    - mobile-attack (Mobile techniques)
    - ics-attack (Industrial Control Systems)
    
    **Use cases:**
    - Check for new ATT&CK releases
    - Select specific version for loading
    - Audit framework versions in use
    """,
    response_description="List of ATT&CK collections with version information",
    operation_id="getAttackReleases"
)
async def get_attack_releases() -> List[CatalogItem]:
    """List available ATT&CK releases and their collection URLs."""
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
        trace_id = str(uuid.uuid4())
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "CatalogFetchError",
                "message": f"Failed to fetch ATT&CK catalog: {str(e)}",
                "trace_id": trace_id
            }
        )


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


@router.get(
    "/catalog/tactics",
    response_model=CatalogTacticsResponse,
    status_code=status.HTTP_200_OK,
    summary="List ATT&CK Tactics",
    description="""
    Get the complete list of MITRE ATT&CK tactics (kill chain phases).
    
    Returns all tactics from the loaded ATT&CK framework with their STIX IDs,
    shortnames, and full names. Falls back to standard tactics if none are
    loaded in the database.
    
    **Use cases:**
    - Build tactic filters for UI
    - Validate tactic references  
    - Generate kill chain visualizations
    """,
    response_description="List of ATT&CK tactics with metadata",
    operation_id="getAttackTactics"
)
async def get_tactics() -> CatalogTacticsResponse:
    """
    Get list of all ATT&CK tactics with their IDs and names.
    
    Returns:
        CatalogTacticsResponse with tactics list and metadata
    """
    trace_id = str(uuid.uuid4())
    
    try:
        tactics_list = _get_tactics_cached()
        
        return CatalogTacticsResponse(
            tactics=tactics_list,
            total=len(tactics_list),
            version="v14.1",  # Current ATT&CK version
            trace_id=trace_id
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "TacticsFetchError", 
                "message": f"Failed to fetch tactics: {str(e)}",
                "trace_id": trace_id
            }
        )


@router.get(
    "/catalog/techniques",
    status_code=status.HTTP_200_OK,
    summary="List All Techniques by Tactic",
    description="""
    Get all ATT&CK techniques organized by tactic.
    
    Returns all techniques from the loaded ATT&CK framework, optionally filtered
    by a specific tactic. Includes full technique metadata and relationships.
    
    **Use cases:**
    - Display all techniques in a tactic
    - Build technique selection UI
    - Generate coverage matrices
    """,
    response_description="List of techniques with metadata",
    operation_id="getTechniquesByTactic"
)
async def get_techniques_by_tactic(
    tactic: Optional[str] = None,
    include_subtechniques: bool = True,
    include_revoked: bool = False,
    include_deprecated: bool = False
) -> Dict:
    """
    Get all techniques, optionally filtered by tactic.
    
    Args:
        tactic: Optional tactic name or shortname to filter by
        include_subtechniques: Include sub-techniques in results
        include_revoked: Include revoked techniques
        include_deprecated: Include deprecated techniques
        
    Returns:
        Dictionary with techniques organized by tactic
    """
    trace_id = str(uuid.uuid4())
    
    driver = GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password)
    )
    
    try:
        with driver.session() as session:
            # Build the query based on filters
            filters = []
            if not include_revoked:
                filters.append("(ap.revoked IS NULL OR ap.revoked = false)")
            if not include_deprecated:
                filters.append("(ap.x_mitre_deprecated IS NULL OR ap.x_mitre_deprecated = false)")
            
            where_clause = " AND ".join(filters) if filters else "1=1"
            
            # Query for techniques with their tactics
            if tactic:
                # Filter by specific tactic
                query = f"""
                    MATCH (ap:AttackPattern)-[:HAS_TACTIC]->(t:Tactic)
                    WHERE ({where_clause})
                    AND (t.name = $tactic OR t.shortname = $tactic)
                    {'AND (ap.x_mitre_is_subtechnique IS NULL OR ap.x_mitre_is_subtechnique = false)' if not include_subtechniques else ''}
                    RETURN t.name as tactic_name, 
                           t.shortname as tactic_shortname,
                           t.stix_id as tactic_id,
                           collect(DISTINCT {{
                               stix_id: ap.stix_id,
                               name: ap.name,
                               description: ap.description,
                               external_id: ap.external_id,
                               is_subtechnique: ap.x_mitre_is_subtechnique,
                               platforms: ap.x_mitre_platforms,
                               revoked: ap.revoked,
                               deprecated: ap.x_mitre_deprecated
                           }}) as techniques
                    ORDER BY tactic_name
                """
                result = session.run(query, tactic=tactic)
            else:
                # Get all techniques grouped by tactic
                query = f"""
                    MATCH (ap:AttackPattern)-[:HAS_TACTIC]->(t:Tactic)
                    WHERE {where_clause}
                    {'AND (ap.x_mitre_is_subtechnique IS NULL OR ap.x_mitre_is_subtechnique = false)' if not include_subtechniques else ''}
                    RETURN t.name as tactic_name,
                           t.shortname as tactic_shortname,
                           t.stix_id as tactic_id,
                           collect(DISTINCT {{
                               stix_id: ap.stix_id,
                               name: ap.name,
                               description: ap.description,
                               external_id: ap.external_id,
                               is_subtechnique: ap.x_mitre_is_subtechnique,
                               platforms: ap.x_mitre_platforms,
                               revoked: ap.revoked,
                               deprecated: ap.x_mitre_deprecated
                           }}) as techniques
                    ORDER BY tactic_name
                """
                result = session.run(query)
            
            tactics_data = []
            total_techniques = 0
            
            for record in result:
                tactic_techniques = record["techniques"]
                tactics_data.append({
                    "tactic_name": record["tactic_name"],
                    "tactic_shortname": record["tactic_shortname"],
                    "tactic_id": record["tactic_id"],
                    "technique_count": len(tactic_techniques),
                    "techniques": tactic_techniques
                })
                total_techniques += len(tactic_techniques)
            
            return {
                "tactics": tactics_data,
                "total_tactics": len(tactics_data),
                "total_techniques": total_techniques,
                "filters": {
                    "tactic": tactic,
                    "include_subtechniques": include_subtechniques,
                    "include_revoked": include_revoked,
                    "include_deprecated": include_deprecated
                },
                "trace_id": trace_id
            }
            
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "TechniquesFetchError",
                "message": f"Failed to fetch techniques: {str(e)}",
                "trace_id": trace_id
            }
        )
    finally:
        driver.close()