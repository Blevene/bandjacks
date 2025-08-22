"""Sigma rule management API endpoints."""

import json
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, status
from pydantic import BaseModel, Field

from bandjacks.services.api.deps import get_neo4j_session
from bandjacks.services.api.settings import settings
from bandjacks.loaders.sigma_loader import SigmaLoader
from bandjacks.services.api.middleware.tracing import get_trace_id

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/sigma", tags=["sigma"])


class SigmaIngestRequest(BaseModel):
    """Request to ingest Sigma rules."""
    repo_url: Optional[str] = Field(None, description="Git repository URL")
    zip_url: Optional[str] = Field(None, description="ZIP archive URL")
    rules: Optional[List[Dict[str, Any]]] = Field(None, description="List of rules with yaml_content")
    link: Optional[List[Dict[str, str]]] = Field(None, description="Analytics to link [{analytic_id, rule_id}]")


class SigmaIngestResponse(BaseModel):
    """Response from Sigma rule ingestion."""
    success: bool
    inserted: int
    updated: int
    rejected: List[Dict[str, Any]]
    warnings: List[str]
    linked_analytics: int
    trace_id: Optional[str]


class SigmaRule(BaseModel):
    """Sigma rule information."""
    rule_id: str
    title: str
    status: str
    description: Optional[str]
    author: Optional[str]
    license: Optional[str]
    severity: Optional[str]
    tags: List[str]
    attack_techniques: List[str]
    platforms: List[str]
    logsource_product: Optional[str]
    logsource_service: Optional[str]
    keys: List[str]
    repo_url: Optional[str]
    path: Optional[str]
    commit_sha: Optional[str]
    blob_uri: str
    
    # Related entities
    log_sources: List[str]
    techniques: List[str]
    analytics: List[Dict[str, str]]


class SigmaSearchRequest(BaseModel):
    """Search request for Sigma rules."""
    query: Optional[str] = Field(None, description="Text search query")
    technique: Optional[str] = Field(None, description="ATT&CK technique ID")
    platform: Optional[str] = Field(None, description="Platform filter")
    status: Optional[str] = Field(None, description="Status filter (stable, experimental, etc.)")
    severity: Optional[str] = Field(None, description="Severity filter")
    limit: int = Field(20, ge=1, le=100)


@router.post("/ingest",
    response_model=SigmaIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest Sigma Rules",
    description="""
    Ingest Sigma detection rules from various sources.
    
    Supports:
    - Git repository URL (clones and processes all .yml files)
    - ZIP archive URL (downloads and extracts rules)
    - Direct rule list (yaml_content and metadata)
    
    Rules are validated against Sigma schema and license policy.
    Invalid rules are rejected with explicit reasons.
    
    Optionally link rules to Analytics during ingestion.
    """
)
async def ingest_sigma_rules(
    request: SigmaIngestRequest,
    neo4j_session=Depends(get_neo4j_session)
) -> SigmaIngestResponse:
    """Ingest Sigma detection rules."""
    
    trace_id = get_trace_id()
    
    # Validate request
    if not any([request.repo_url, request.zip_url, request.rules]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide repo_url, zip_url, or rules list"
        )
    
    # Initialize loader
    loader = SigmaLoader(
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=settings.neo4j_password,
        blob_base=settings.blob_base if hasattr(settings, 'blob_base') else "s3://sigma-rules/"
    )
    
    try:
        # Ingest rules
        result = loader.ingest_sigma_rules(
            repo_url=request.repo_url,
            zip_url=request.zip_url,
            rules=request.rules,
            link_analytics=request.link
        )
        
        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.get("error", "Ingestion failed")
            )
        
        return SigmaIngestResponse(
            success=result["success"],
            inserted=result["inserted"],
            updated=result["updated"],
            rejected=result["rejected"],
            warnings=result.get("warnings", []),
            linked_analytics=result.get("linked_analytics", 0),
            trace_id=trace_id
        )
        
    except Exception as e:
        logger.error(f"Failed to ingest Sigma rules: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest Sigma rules: {str(e)}"
        )
    finally:
        loader.close()


@router.get("/rules/{rule_id}",
    response_model=SigmaRule,
    summary="Get Sigma Rule",
    description="""
    Get detailed information about a specific Sigma rule.
    
    Returns:
    - Rule metadata and content location
    - Related log sources
    - Detected techniques
    - Linked analytics
    """
)
async def get_sigma_rule(
    rule_id: str,
    neo4j_session=Depends(get_neo4j_session)
) -> SigmaRule:
    """Get Sigma rule details."""
    
    loader = SigmaLoader(
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=settings.neo4j_password
    )
    
    try:
        rule = loader.get_sigma_rule(rule_id)
        
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Sigma rule {rule_id} not found"
            )
        
        # Ensure lists are properly formatted
        rule["tags"] = rule.get("tags", [])
        rule["attack_techniques"] = rule.get("attack_techniques", [])
        rule["platforms"] = rule.get("platforms", [])
        rule["keys"] = rule.get("keys", [])
        rule["log_sources"] = rule.get("log_sources", [])
        rule["techniques"] = rule.get("techniques", [])
        rule["analytics"] = rule.get("analytics", [])
        
        return SigmaRule(**rule)
        
    finally:
        loader.close()


@router.post("/rules/search",
    response_model=List[SigmaRule],
    summary="Search Sigma Rules",
    description="""
    Search for Sigma rules using various filters.
    
    Supports:
    - Text search across title, description, tags
    - Filter by ATT&CK technique
    - Filter by platform
    - Filter by status (stable, experimental)
    - Filter by severity
    """
)
async def search_sigma_rules(
    request: SigmaSearchRequest,
    neo4j_session=Depends(get_neo4j_session)
) -> List[SigmaRule]:
    """Search Sigma rules."""
    
    # Build query
    filters = []
    params = {"limit": request.limit}
    
    # Status filter
    if request.status:
        filters.append("sr.status = $status")
        params["status"] = request.status
    
    # Severity filter
    if request.severity:
        filters.append("sr.severity = $severity")
        params["severity"] = request.severity
    
    # Platform filter
    if request.platform:
        filters.append("$platform IN sr.platforms")
        params["platform"] = request.platform
    
    # Technique filter
    if request.technique:
        technique_filter = """
            MATCH (sr)-[:DETECTS]->(ap:AttackPattern)
            WHERE ap.external_id = $technique OR ap.external_id STARTS WITH ($technique + '.')
            WITH DISTINCT sr
        """
    else:
        technique_filter = ""
    
    # Text search
    if request.query:
        # Use fulltext index
        text_search = """
            CALL db.index.fulltext.queryNodes('sigma_rule_search', $query)
            YIELD node as sr, score
            WITH sr, score
        """
        params["query"] = request.query
        order_by = "ORDER BY score DESC"
    else:
        text_search = "MATCH (sr:SigmaRule)"
        order_by = "ORDER BY sr.ingested_at DESC"
    
    filter_clause = " WHERE " + " AND ".join(filters) if filters else ""
    
    query = f"""
        {text_search}
        {filter_clause}
        {technique_filter}
        OPTIONAL MATCH (sr)-[:TARGETS_LOG_SOURCE]->(ls:LogSource)
        OPTIONAL MATCH (sr)-[:DETECTS]->(ap:AttackPattern)
        OPTIONAL MATCH (a:Analytic)-[:IMPLEMENTED_BY]->(sr)
        WITH sr,
             collect(DISTINCT ls.name) as log_sources,
             collect(DISTINCT ap.external_id) as techniques,
             collect(DISTINCT {{
                 analytic_id: a.stix_id,
                 analytic_name: a.name
             }}) as analytics
        RETURN sr {{
            .*,
            log_sources: log_sources,
            techniques: techniques,
            analytics: analytics
        }} as rule
        {order_by}
        LIMIT $limit
    """
    
    result = neo4j_session.run(query, **params)
    
    rules = []
    for record in result:
        rule_data = dict(record["rule"])
        
        # Parse JSON fields
        for field in ["tags", "attack_techniques", "platforms", "keys"]:
            if field in rule_data and rule_data[field]:
                try:
                    rule_data[field] = json.loads(rule_data[field])
                except:
                    rule_data[field] = []
            else:
                rule_data[field] = []
        
        # Ensure required fields
        rule_data["log_sources"] = rule_data.get("log_sources", [])
        rule_data["techniques"] = rule_data.get("techniques", [])
        rule_data["analytics"] = [a for a in rule_data.get("analytics", []) if a.get("analytic_id")]
        
        rules.append(SigmaRule(**rule_data))
    
    return rules