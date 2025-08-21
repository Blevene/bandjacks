"""Coverage analysis endpoints for techniques including detections, mitigations, and D3FEND."""

import json
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, Request, status
from pydantic import BaseModel, Field

from bandjacks.services.api.deps import get_neo4j_session
from bandjacks.services.api.settings import settings
from bandjacks.services.api.middleware.tracing import get_trace_id

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/coverage", tags=["coverage"])


class DetectionCoverage(BaseModel):
    """Detection coverage for a technique."""
    detection_strategies: List[Dict[str, Any]]
    analytics: List[Dict[str, Any]]
    log_sources: List[Dict[str, Any]]
    strategy_count: int
    analytic_count: int
    log_source_count: int
    has_detections: bool


class MitigationCoverage(BaseModel):
    """Mitigation coverage for a technique."""
    mitigations: List[Dict[str, Any]]
    mitigation_count: int
    has_mitigations: bool


class D3FENDCoverage(BaseModel):
    """D3FEND coverage for a technique."""
    d3fend_techniques: List[Dict[str, Any]]
    digital_artifacts: List[Dict[str, Any]]
    d3fend_count: int
    artifact_count: int
    has_d3fend: bool


class TechniqueCoverageResponse(BaseModel):
    """Complete coverage analysis for a technique."""
    technique_id: str
    technique_name: Optional[str]
    technique_description: Optional[str]
    is_subtechnique: bool
    parent_technique: Optional[str]
    tactics: List[str]
    platforms: List[str]
    detection_coverage: DetectionCoverage
    mitigation_coverage: MitigationCoverage
    d3fend_coverage: D3FENDCoverage
    coverage_score: float
    coverage_gaps: List[str]
    recommendations: List[str]
    trace_id: Optional[str] = Field(None, description="Request trace ID")


@router.get("/technique/{technique_id}",
    response_model=TechniqueCoverageResponse,
    summary="Get Complete Coverage for Technique",
    description="""
    Get comprehensive coverage analysis for an ATT&CK technique.
    
    Returns:
    - Detection strategies and analytics
    - Mitigations
    - D3FEND defensive techniques
    - Coverage gaps and recommendations
    - Overall coverage score
    
    By default, excludes revoked and deprecated items.
    """
)
async def get_technique_coverage(
    technique_id: str,
    req: Request,
    include_revoked: bool = Query(False, description="Include revoked items"),
    include_deprecated: bool = Query(False, description="Include deprecated items"),
    include_subtechniques: bool = Query(True, description="Include subtechniques in analysis"),
    neo4j_session=Depends(get_neo4j_session)
) -> TechniqueCoverageResponse:
    """Get complete coverage analysis for a technique."""
    
    trace_id = get_trace_id()
    
    # Build filter conditions
    filters = []
    if not include_revoked:
        filters.append("NOT item.revoked")
    if not include_deprecated:
        filters.append("NOT item.x_mitre_deprecated")
    
    filter_clause = " AND ".join(filters) if filters else "TRUE"
    
    # Get technique information
    technique_query = """
        MATCH (t:AttackPattern)
        WHERE t.external_id = $technique_id OR 
              ($include_subtechniques AND t.external_id STARTS WITH ($technique_id + '.'))
        OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tactic:Tactic)
        OPTIONAL MATCH (t)-[:SUBTECHNIQUE_OF]->(parent:AttackPattern)
        RETURN t {
            .*,
            tactics: collect(DISTINCT tactic.shortname),
            parent_id: parent.external_id,
            parent_name: parent.name
        } as technique
        ORDER BY t.external_id
        LIMIT 1
    """
    
    result = neo4j_session.run(
        technique_query,
        technique_id=technique_id,
        include_subtechniques=include_subtechniques
    )
    record = result.single()
    
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique {technique_id} not found"
        )
    
    technique_data = dict(record["technique"])
    
    # Get detection coverage
    detection_query = f"""
        MATCH (t:AttackPattern {{external_id: $technique_id}})
        OPTIONAL MATCH (ds:DetectionStrategy)-[:DETECTS]->(t)
        WHERE {filter_clause.replace('item', 'ds')}
        OPTIONAL MATCH (ds)-[:HAS_ANALYTIC]->(a:Analytic)
        WHERE {filter_clause.replace('item', 'a')}
        OPTIONAL MATCH (a)-[:USES_LOG_SOURCE]->(ls:LogSource)
        RETURN 
            collect(DISTINCT {{
                strategy_id: ds.stix_id,
                strategy_name: ds.name,
                det_id: ds.det_id
            }}) as strategies,
            collect(DISTINCT {{
                analytic_id: a.stix_id,
                analytic_name: a.name,
                platforms: a.platforms
            }}) as analytics,
            collect(DISTINCT {{
                log_source_id: ls.stix_id,
                log_source_name: ls.name
            }}) as log_sources
    """
    
    detection_result = neo4j_session.run(detection_query, technique_id=technique_data["external_id"])
    detection_record = detection_result.single()
    
    # Filter out null entries
    strategies = [s for s in detection_record["strategies"] if s["strategy_id"]]
    analytics = [a for a in detection_record["analytics"] if a["analytic_id"]]
    log_sources = [ls for ls in detection_record["log_sources"] if ls["log_source_id"]]
    
    # Parse platforms from analytics
    for analytic in analytics:
        if analytic.get("platforms"):
            analytic["platforms"] = json.loads(analytic["platforms"])
        else:
            analytic["platforms"] = []
    
    detection_coverage = DetectionCoverage(
        detection_strategies=strategies,
        analytics=analytics,
        log_sources=log_sources,
        strategy_count=len(strategies),
        analytic_count=len(analytics),
        log_source_count=len(log_sources),
        has_detections=len(strategies) > 0
    )
    
    # Get mitigation coverage
    mitigation_query = f"""
        MATCH (t:AttackPattern {{external_id: $technique_id}})
        OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
        WHERE {filter_clause.replace('item', 'm')}
        RETURN collect(DISTINCT {{
            mitigation_id: m.stix_id,
            mitigation_name: m.name,
            mitigation_description: m.description
        }}) as mitigations
    """
    
    mitigation_result = neo4j_session.run(mitigation_query, technique_id=technique_data["external_id"])
    mitigation_record = mitigation_result.single()
    
    mitigations = [m for m in mitigation_record["mitigations"] if m["mitigation_id"]]
    
    mitigation_coverage = MitigationCoverage(
        mitigations=mitigations,
        mitigation_count=len(mitigations),
        has_mitigations=len(mitigations) > 0
    )
    
    # Get D3FEND coverage
    d3fend_query = """
        MATCH (t:AttackPattern {external_id: $technique_id})
        OPTIONAL MATCH (d:D3fendTechnique)-[:COUNTERS]->(t)
        OPTIONAL MATCH (d)-[:PROTECTS]->(da:DigitalArtifact)
        RETURN 
            collect(DISTINCT {
                d3fend_id: d.d3fend_id,
                d3fend_name: d.name,
                d3fend_category: d.category
            }) as d3fend_techniques,
            collect(DISTINCT {
                artifact_name: da.name,
                artifact_type: da.type
            }) as digital_artifacts
    """
    
    d3fend_result = neo4j_session.run(d3fend_query, technique_id=technique_data["external_id"])
    d3fend_record = d3fend_result.single()
    
    d3fend_techniques = [d for d in d3fend_record["d3fend_techniques"] if d["d3fend_id"]]
    digital_artifacts = [da for da in d3fend_record["digital_artifacts"] if da["artifact_name"]]
    
    d3fend_coverage = D3FENDCoverage(
        d3fend_techniques=d3fend_techniques,
        digital_artifacts=digital_artifacts,
        d3fend_count=len(d3fend_techniques),
        artifact_count=len(digital_artifacts),
        has_d3fend=len(d3fend_techniques) > 0
    )
    
    # Calculate coverage score and identify gaps
    coverage_components = {
        "detection": 1 if detection_coverage.has_detections else 0,
        "mitigation": 1 if mitigation_coverage.has_mitigations else 0,
        "d3fend": 1 if d3fend_coverage.has_d3fend else 0,
        "log_sources": min(1, len(log_sources) / 3)  # Expect at least 3 log sources for good coverage
    }
    
    coverage_score = sum(coverage_components.values()) / len(coverage_components)
    
    # Identify coverage gaps
    coverage_gaps = []
    if not detection_coverage.has_detections:
        coverage_gaps.append("No detection strategies defined")
    elif len(analytics) == 0:
        coverage_gaps.append("Detection strategies lack analytics")
    elif len(log_sources) == 0:
        coverage_gaps.append("Analytics lack log source definitions")
    elif len(log_sources) < 3:
        coverage_gaps.append("Limited log source coverage")
    
    if not mitigation_coverage.has_mitigations:
        coverage_gaps.append("No mitigations defined")
    
    if not d3fend_coverage.has_d3fend:
        coverage_gaps.append("No D3FEND defensive techniques mapped")
    
    # Generate recommendations
    recommendations = []
    if not detection_coverage.has_detections:
        recommendations.append("Define detection strategies with analytics for this technique")
    elif len(log_sources) < 3:
        recommendations.append("Add more diverse log sources for comprehensive detection")
    
    if not mitigation_coverage.has_mitigations:
        recommendations.append("Research and define mitigations for this technique")
    
    if not d3fend_coverage.has_d3fend:
        recommendations.append("Map D3FEND defensive techniques to improve coverage")
    elif len(d3fend_techniques) < 3:
        recommendations.append("Consider additional D3FEND techniques for defense-in-depth")
    
    if coverage_score < 0.5:
        recommendations.append("This technique has significant coverage gaps - prioritize for improvement")
    
    # Extract platforms from technique
    platforms = []
    if technique_data.get("x_mitre_platforms"):
        try:
            platforms = json.loads(technique_data["x_mitre_platforms"])
        except:
            platforms = []
    
    return TechniqueCoverageResponse(
        technique_id=technique_data["external_id"],
        technique_name=technique_data.get("name"),
        technique_description=technique_data.get("description"),
        is_subtechnique=technique_data.get("x_mitre_is_subtechnique", False),
        parent_technique=technique_data.get("parent_id"),
        tactics=technique_data.get("tactics", []),
        platforms=platforms,
        detection_coverage=detection_coverage,
        mitigation_coverage=mitigation_coverage,
        d3fend_coverage=d3fend_coverage,
        coverage_score=round(coverage_score, 2),
        coverage_gaps=coverage_gaps,
        recommendations=recommendations,
        trace_id=trace_id
    )


@router.get("/gap-analysis",
    summary="Coverage Gap Analysis",
    description="""
    Analyze coverage gaps across all techniques or specific subsets.
    
    Returns techniques with the lowest coverage scores and recommendations for improvement.
    """
)
async def get_coverage_gaps(
    tactic: Optional[str] = Query(None, description="Filter by tactic"),
    platform: Optional[str] = Query(None, description="Filter by platform"),
    min_coverage: float = Query(0.5, ge=0, le=1, description="Minimum coverage threshold"),
    limit: int = Query(20, ge=1, le=100, description="Maximum results"),
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """Analyze coverage gaps across techniques."""
    
    # Build filters
    filters = ["NOT t.revoked", "NOT t.x_mitre_deprecated"]
    params = {"min_coverage": min_coverage, "limit": limit}
    
    if tactic:
        filters.append("tactic.shortname = $tactic")
        params["tactic"] = tactic
    
    if platform:
        filters.append("$platform IN t.x_mitre_platforms")
        params["platform"] = platform
    
    filter_clause = " AND ".join(filters)
    
    # Query for techniques with coverage metrics
    query = f"""
        MATCH (t:AttackPattern)
        WHERE {filter_clause}
        {"MATCH (t)-[:HAS_TACTIC]->(tactic:Tactic)" if tactic else "OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tactic:Tactic)"}
        OPTIONAL MATCH (ds:DetectionStrategy)-[:DETECTS]->(t)
        WHERE NOT ds.revoked AND NOT ds.x_mitre_deprecated
        OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
        WHERE NOT m.revoked
        OPTIONAL MATCH (d:D3fendTechnique)-[:COUNTERS]->(t)
        WITH t,
             count(DISTINCT ds) as detection_count,
             count(DISTINCT m) as mitigation_count,
             count(DISTINCT d) as d3fend_count,
             collect(DISTINCT tactic.shortname) as tactics
        WITH t, detection_count, mitigation_count, d3fend_count, tactics,
             (CASE 
                WHEN detection_count > 0 THEN 0.4 ELSE 0 END +
              CASE 
                WHEN mitigation_count > 0 THEN 0.3 ELSE 0 END +
              CASE 
                WHEN d3fend_count > 0 THEN 0.3 ELSE 0 END
             ) as coverage_score
        WHERE coverage_score < $min_coverage
        RETURN t.external_id as technique_id,
               t.name as technique_name,
               tactics,
               detection_count,
               mitigation_count,
               d3fend_count,
               coverage_score
        ORDER BY coverage_score ASC, technique_id
        LIMIT $limit
    """
    
    result = neo4j_session.run(query, **params)
    
    gaps = []
    for record in result:
        gap_types = []
        if record["detection_count"] == 0:
            gap_types.append("detection")
        if record["mitigation_count"] == 0:
            gap_types.append("mitigation")
        if record["d3fend_count"] == 0:
            gap_types.append("d3fend")
        
        gaps.append({
            "technique_id": record["technique_id"],
            "technique_name": record["technique_name"],
            "tactics": record["tactics"],
            "detection_count": record["detection_count"],
            "mitigation_count": record["mitigation_count"],
            "d3fend_count": record["d3fend_count"],
            "coverage_score": round(record["coverage_score"], 2),
            "gap_types": gap_types
        })
    
    # Summary statistics
    total_gaps = len(gaps)
    detection_gaps = sum(1 for g in gaps if "detection" in g["gap_types"])
    mitigation_gaps = sum(1 for g in gaps if "mitigation" in g["gap_types"])
    d3fend_gaps = sum(1 for g in gaps if "d3fend" in g["gap_types"])
    
    return {
        "summary": {
            "total_gaps": total_gaps,
            "detection_gaps": detection_gaps,
            "mitigation_gaps": mitigation_gaps,
            "d3fend_gaps": d3fend_gaps,
            "coverage_threshold": min_coverage
        },
        "gaps": gaps,
        "recommendations": [
            f"Focus on {gaps[0]['technique_name']} ({gaps[0]['technique_id']}) - lowest coverage" if gaps else None,
            f"{detection_gaps} techniques need detection strategies" if detection_gaps > 0 else None,
            f"{mitigation_gaps} techniques need mitigations" if mitigation_gaps > 0 else None,
            f"{d3fend_gaps} techniques need D3FEND mappings" if d3fend_gaps > 0 else None
        ]
    }