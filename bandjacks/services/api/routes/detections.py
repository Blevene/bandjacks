"""Detection strategies, analytics, and log sources API endpoints."""

import json
import logging
from typing import Dict, Any, List, Optional, Literal
from fastapi import APIRouter, HTTPException, Depends, Query, Request, status
from pydantic import BaseModel, Field

from bandjacks.services.api.deps import get_neo4j_session
from bandjacks.services.api.settings import settings
from bandjacks.loaders.detection_loader import DetectionLoader
from bandjacks.llm.bundle_validator import validate_bundle_for_upsert
from bandjacks.services.api.middleware.tracing import get_trace_id

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/detections", tags=["detections"])


class DetectionIngestRequest(BaseModel):
    """Request to ingest detection strategies bundle."""
    bundle: Dict[str, Any] = Field(..., description="STIX 2.1 bundle with detection objects")
    collection: str = Field("detection-strategies", description="Source collection name")
    version: str = Field("latest", description="Collection version")
    domain: str = Field("enterprise-attack", description="ATT&CK domain")
    strict_validation: bool = Field(True, description="Enforce strict ADM validation")


class DetectionIngestResponse(BaseModel):
    """Response from detection bundle ingestion."""
    success: bool
    detection_strategies: int
    analytics: int
    log_sources: int
    detects_relationships: int
    has_analytic_relationships: int
    uses_log_source_relationships: int
    validation_errors: List[str] = Field(default_factory=list)
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class DetectionStrategyQuery(BaseModel):
    """Query parameters for detection strategies."""
    technique: Optional[str] = Field(None, description="ATT&CK technique ID (e.g., T1003)")
    platform: Optional[str] = Field(None, description="Platform filter (e.g., windows, linux)")
    include_revoked: bool = Field(False, description="Include revoked strategies")
    include_deprecated: bool = Field(False, description="Include deprecated strategies")
    limit: int = Field(10, ge=1, le=100, description="Maximum results to return")


class DetectionStrategy(BaseModel):
    """Detection strategy information."""
    stix_id: str
    name: str
    description: Optional[str]
    det_id: Optional[str]
    x_mitre_version: Optional[str]
    x_mitre_domains: List[str]
    analytics_count: int
    detected_techniques: List[str]


class AnalyticDetail(BaseModel):
    """Detailed analytic information."""
    stix_id: str
    name: str
    description: Optional[str]
    platforms: List[str]
    x_mitre_detects: str
    x_mitre_mutable_elements: List[str]
    log_sources: List[Dict[str, Any]]
    parent_strategies: List[str]


@router.post("/ingest",
    response_model=DetectionIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest Detection Bundle",
    description="""
    Ingest a STIX 2.1 bundle containing detection strategies, analytics, and log sources.
    
    The bundle must contain:
    - x-mitre-detection-strategy objects with x_mitre_analytics arrays
    - x-mitre-analytic objects with x_mitre_log_sources and x_mitre_detects
    - x-mitre-log-source objects with x_mitre_log_source_permutations
    - relationship objects with type="detects" linking strategies to techniques
    
    Validation is performed according to ADM requirements.
    """
)
async def ingest_detection_bundle(
    request: DetectionIngestRequest,
    req: Request,
    neo4j_session=Depends(get_neo4j_session)
) -> DetectionIngestResponse:
    """Ingest detection strategies, analytics, and log sources."""
    
    trace_id = get_trace_id()
    
    # Validate bundle if strict mode
    validation_errors = []
    if request.strict_validation:
        is_valid, errors = validate_bundle_for_upsert(request.bundle)
        if not is_valid:
            validation_errors = errors
            if len(errors) > 5:  # Too many errors, fail fast
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "message": "Bundle validation failed",
                        "errors": errors[:10],  # Return first 10 errors
                        "total_errors": len(errors)
                    }
                )
    
    # Initialize loader
    loader = DetectionLoader(
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=settings.neo4j_password
    )
    
    try:
        # Ingest the bundle
        result = loader.ingest_detection_bundle(
            bundle=request.bundle,
            collection=request.collection,
            version=request.version,
            domain=request.domain
        )
        
        return DetectionIngestResponse(
            success=result["success"],
            detection_strategies=result["detection_strategies"],
            analytics=result["analytics"],
            log_sources=result["log_sources"],
            detects_relationships=result["detects_relationships"],
            has_analytic_relationships=result["has_analytic_relationships"],
            uses_log_source_relationships=result["uses_log_source_relationships"],
            validation_errors=validation_errors,
            trace_id=trace_id
        )
        
    except Exception as e:
        logger.error(f"Failed to ingest detection bundle: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest detection bundle: {str(e)}"
        )
    finally:
        loader.close()


@router.get("/strategies",
    response_model=List[DetectionStrategy],
    summary="Query Detection Strategies",
    description="""
    Query detection strategies by technique, platform, and other filters.
    
    Returns strategies with their associated analytics count and detected techniques.
    By default, excludes revoked and deprecated strategies.
    """
)
async def get_detection_strategies(
    technique: Optional[str] = Query(None, description="ATT&CK technique ID"),
    platform: Optional[str] = Query(None, description="Platform filter"),
    include_revoked: bool = Query(False, description="Include revoked strategies"),
    include_deprecated: bool = Query(False, description="Include deprecated strategies"),
    limit: int = Query(10, ge=1, le=100, description="Maximum results"),
    neo4j_session=Depends(get_neo4j_session)
) -> List[DetectionStrategy]:
    """Get detection strategies matching the query."""
    
    # Build filter conditions
    filters = []
    params = {"limit": limit}
    
    if not include_revoked:
        filters.append("NOT ds.revoked")
    if not include_deprecated:
        filters.append("NOT ds.x_mitre_deprecated")
    
    # Technique filter
    if technique:
        params["technique"] = technique
        technique_match = """
            MATCH (ap:AttackPattern)
            WHERE ap.external_id = $technique OR ap.external_id STARTS WITH ($technique + '.')
            MATCH (ds)-[:DETECTS]->(ap)
        """
    else:
        technique_match = ""
    
    # Platform filter (through analytics)
    if platform:
        params["platform"] = f'["{platform.lower()}"]'
        platform_match = """
            MATCH (ds)-[:HAS_ANALYTIC]->(a:Analytic)
            WHERE $platform IN a.platforms
            WITH DISTINCT ds
        """
    else:
        platform_match = ""
    
    filter_clause = " AND ".join(filters) if filters else "TRUE"
    
    query = f"""
        MATCH (ds:DetectionStrategy)
        WHERE {filter_clause}
        {technique_match}
        {platform_match}
        OPTIONAL MATCH (ds)-[:HAS_ANALYTIC]->(a:Analytic)
        OPTIONAL MATCH (ds)-[:DETECTS]->(ap:AttackPattern)
        WITH ds, 
             count(DISTINCT a) as analytics_count,
             collect(DISTINCT ap.external_id) as detected_techniques
        RETURN ds {{
            .*,
            analytics_count: analytics_count,
            detected_techniques: detected_techniques
        }} as strategy
        ORDER BY ds.name
        LIMIT $limit
    """
    
    result = neo4j_session.run(query, **params)
    
    strategies = []
    for record in result:
        strategy_data = dict(record["strategy"])
        
        # Parse JSON fields
        if strategy_data.get("x_mitre_domains"):
            strategy_data["x_mitre_domains"] = json.loads(strategy_data["x_mitre_domains"])
        else:
            strategy_data["x_mitre_domains"] = []
        
        strategies.append(DetectionStrategy(
            stix_id=strategy_data["stix_id"],
            name=strategy_data["name"],
            description=strategy_data.get("description"),
            det_id=strategy_data.get("det_id"),
            x_mitre_version=strategy_data.get("x_mitre_version"),
            x_mitre_domains=strategy_data["x_mitre_domains"],
            analytics_count=strategy_data["analytics_count"],
            detected_techniques=strategy_data["detected_techniques"]
        ))
    
    return strategies


@router.get("/analytics/{analytic_id}",
    response_model=AnalyticDetail,
    summary="Get Analytic Details",
    description="""
    Get detailed information about a specific analytic.
    
    Returns the analytic with its log sources, mutable elements, and parent strategies.
    """
)
async def get_analytic_details(
    analytic_id: str,
    neo4j_session=Depends(get_neo4j_session)
) -> AnalyticDetail:
    """Get detailed information about an analytic."""
    
    query = """
        MATCH (a:Analytic {stix_id: $analytic_id})
        OPTIONAL MATCH (ds:DetectionStrategy)-[:HAS_ANALYTIC]->(a)
        OPTIONAL MATCH (a)-[uls:USES_LOG_SOURCE]->(ls:LogSource)
        RETURN a {
            .*,
            parent_strategies: collect(DISTINCT ds.stix_id),
            log_sources_detail: collect(DISTINCT {
                log_source_id: ls.stix_id,
                log_source_name: ls.name,
                keys: uls.keys
            })
        } as analytic
    """
    
    result = neo4j_session.run(query, analytic_id=analytic_id)
    record = result.single()
    
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analytic {analytic_id} not found"
        )
    
    analytic_data = dict(record["analytic"])
    
    # Parse JSON fields
    platforms = json.loads(analytic_data.get("platforms", "[]"))
    mutable_elements = json.loads(analytic_data.get("x_mitre_mutable_elements", "[]"))
    
    # Process log sources
    log_sources = []
    for ls in analytic_data.get("log_sources_detail", []):
        if ls["log_source_id"]:
            log_sources.append({
                "log_source_id": ls["log_source_id"],
                "log_source_name": ls["log_source_name"],
                "keys": json.loads(ls.get("keys", "[]")) if ls.get("keys") else []
            })
    
    return AnalyticDetail(
        stix_id=analytic_data["stix_id"],
        name=analytic_data["name"],
        description=analytic_data.get("description"),
        platforms=platforms,
        x_mitre_detects=analytic_data.get("x_mitre_detects", ""),
        x_mitre_mutable_elements=mutable_elements,
        log_sources=log_sources,
        parent_strategies=analytic_data.get("parent_strategies", [])
    )