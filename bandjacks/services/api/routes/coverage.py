"""Coverage analytics API endpoints for detection strategies."""

import json
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, status
from pydantic import BaseModel, Field

from bandjacks.services.api.deps import get_neo4j_session
from bandjacks.services.api.settings import settings
from bandjacks.services.api.middleware.tracing import get_trace_id

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/coverage", tags=["coverage"])


class TechniqueCoverage(BaseModel):
    """Coverage information for a specific technique."""
    technique_id: str
    technique_name: str
    coverage_status: str  # "covered", "partial", "uncovered"
    detection_strategies: List[Dict[str, Any]]
    analytics: List[Dict[str, Any]]
    log_sources: List[Dict[str, Any]]
    gaps: List[Dict[str, Any]]
    platforms_covered: List[str]
    platforms_missing: List[str]
    sigma_rules_total: int = Field(0, description="Total Sigma rules for this technique")
    sigma_rules_by_platform: Dict[str, int] = Field(default_factory=dict)
    missing_logsource_permutations_from_sigma: List[str] = Field(default_factory=list)


class AggregatedCoverage(BaseModel):
    """Aggregated coverage statistics."""
    total_techniques: int
    covered_techniques: int
    partial_coverage: int
    uncovered_techniques: int
    coverage_percentage: float
    by_tactic: Dict[str, Dict[str, int]]
    by_platform: Dict[str, Dict[str, int]]
    top_gaps: List[Dict[str, Any]]


class LogSourceGap(BaseModel):
    """Represents a gap in log source coverage."""
    analytic_id: str
    analytic_name: str
    required_log_source: str
    required_keys: List[str]
    available_keys: List[str]
    missing_keys: List[str]
    gap_severity: str  # "critical", "high", "medium", "low"


@router.get("/technique/{technique_id}",
    response_model=TechniqueCoverage,
    summary="Get Technique Coverage",
    description="""
    Get detailed coverage information for a specific technique.
    
    Returns:
    - Detection strategies that cover this technique
    - Analytics available for detection
    - Required log sources and their availability
    - Coverage gaps derived from log source permutations
    """
)
async def get_technique_coverage(
    technique_id: str,
    platform: Optional[str] = Query(None, description="Filter by platform"),
    include_revoked: bool = Query(False, description="Include revoked detections"),
    include_deprecated: bool = Query(False, description="Include deprecated detections"),
    neo4j_session=Depends(get_neo4j_session)
) -> TechniqueCoverage:
    """Get coverage snapshot for a specific technique."""
    
    # Build filter conditions
    filters = []
    if not include_revoked:
        filters.append("NOT ds.revoked")
    if not include_deprecated:
        filters.append("NOT ds.x_mitre_deprecated")
    
    filter_clause = " AND ".join(filters) if filters else "TRUE"
    
    # Query for technique and its coverage (including Sigma rules)
    query = f"""
        MATCH (ap:AttackPattern)
        WHERE ap.external_id = $technique_id OR ap.external_id STARTS WITH ($technique_id + '.')
        OPTIONAL MATCH (ds:DetectionStrategy)-[:DETECTS]->(ap)
        WHERE {filter_clause}
        OPTIONAL MATCH (ds)-[:HAS_ANALYTIC]->(a:Analytic)
        WHERE NOT a.revoked AND NOT a.x_mitre_deprecated
        OPTIONAL MATCH (a)-[uls:USES_LOG_SOURCE]->(ls:LogSource)
        OPTIONAL MATCH (sr:SigmaRule)-[:DETECTS]->(ap)
        WHERE sr.status IN ['stable', 'test']
        WITH ap, ds, a, ls, uls,
             collect(DISTINCT sr) as sigma_rules
        RETURN 
            ap.external_id as technique_id,
            ap.name as technique_name,
            collect(DISTINCT {{
                strategy_id: ds.stix_id,
                strategy_name: ds.name,
                det_id: ds.det_id
            }}) as strategies,
            collect(DISTINCT {{
                analytic_id: a.stix_id,
                analytic_name: a.name,
                platforms: a.platforms,
                x_mitre_detects: a.x_mitre_detects,
                x_mitre_log_sources: a.x_mitre_log_sources
            }}) as analytics,
            collect(DISTINCT {{
                log_source_id: ls.stix_id,
                log_source_name: ls.name,
                permutations: ls.x_mitre_log_source_permutations,
                keys: uls.keys
            }}) as log_sources,
            sigma_rules,
            size(sigma_rules) as sigma_rules_total
    """
    
    result = neo4j_session.run(query, technique_id=technique_id)
    record = result.single()
    
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Technique {technique_id} not found"
        )
    
    # Filter out null entries
    strategies = [s for s in record["strategies"] if s["strategy_id"]]
    analytics = [a for a in record["analytics"] if a["analytic_id"]]
    log_sources = [ls for ls in record["log_sources"] if ls["log_source_id"]]
    
    # Parse analytics to get platforms
    all_platforms = set()
    for analytic in analytics:
        if analytic["platforms"]:
            platforms = json.loads(analytic["platforms"])
            all_platforms.update(platforms)
    
    # Apply platform filter if specified
    if platform:
        analytics = [a for a in analytics 
                    if platform in json.loads(a.get("platforms", "[]"))]
        all_platforms = {platform} if platform in all_platforms else set()
    
    # Compute coverage gaps
    gaps = compute_log_source_gaps(analytics, log_sources)
    
    # Determine coverage status
    if not strategies:
        coverage_status = "uncovered"
    elif gaps:
        coverage_status = "partial"
    else:
        coverage_status = "covered"
    
    # Determine missing platforms (simplified - would need full platform list)
    known_platforms = ["Windows", "Linux", "macOS", "Cloud"]
    platforms_missing = [p for p in known_platforms if p not in all_platforms]
    
    # Process Sigma rules
    sigma_rules = record.get("sigma_rules", [])
    sigma_rules_total = record.get("sigma_rules_total", 0)
    sigma_rules_by_platform = {}
    missing_logsource_permutations = []
    
    for rule in sigma_rules:
        if rule and hasattr(rule, 'get'):
            # Count by platform
            platforms = rule.get("platforms", "[]")
            if isinstance(platforms, str):
                try:
                    platforms = json.loads(platforms)
                except:
                    platforms = []
            
            for p in platforms:
                sigma_rules_by_platform[p] = sigma_rules_by_platform.get(p, 0) + 1
            
            # Check for missing log source permutations
            logsource_product = rule.get("logsource_product")
            if logsource_product:
                # Check if we have matching log sources
                has_matching_ls = any(
                    ls.get("log_source_name", "").lower() == logsource_product.lower()
                    for ls in log_sources
                )
                if not has_matching_ls:
                    missing_logsource_permutations.append(f"sigma:{logsource_product}")
    
    return TechniqueCoverage(
        technique_id=record["technique_id"],
        technique_name=record["technique_name"],
        coverage_status=coverage_status,
        detection_strategies=strategies,
        analytics=analytics,
        log_sources=log_sources,
        gaps=gaps,
        platforms_covered=list(all_platforms),
        platforms_missing=platforms_missing,
        sigma_rules_total=sigma_rules_total,
        sigma_rules_by_platform=sigma_rules_by_platform,
        missing_logsource_permutations_from_sigma=missing_logsource_permutations
    )


@router.get("/analytics/coverage",
    response_model=AggregatedCoverage,
    summary="Get Aggregated Coverage",
    description="""
    Get aggregated coverage analytics across techniques.
    
    Can be filtered by:
    - Tactic
    - Platform
    
    Returns coverage statistics and top gaps.
    """
)
async def get_aggregated_coverage(
    tactic: Optional[str] = Query(None, description="Filter by tactic"),
    platform: Optional[str] = Query(None, description="Filter by platform"),
    include_revoked: bool = Query(False),
    include_deprecated: bool = Query(False),
    neo4j_session=Depends(get_neo4j_session)
) -> AggregatedCoverage:
    """Get aggregated coverage view."""
    
    # Build filters
    filters = []
    if not include_revoked:
        filters.append("NOT ds.revoked")
    if not include_deprecated:
        filters.append("NOT ds.x_mitre_deprecated")
    
    filter_clause = " AND ".join(filters) if filters else "TRUE"
    
    # Base query
    query = """
        MATCH (ap:AttackPattern)
        WHERE NOT ap.x_mitre_is_subtechnique
    """
    
    # Add tactic filter
    if tactic:
        query += """
        MATCH (ap)-[:HAS_TACTIC]->(t:Tactic {shortname: $tactic})
        """
    
    # Continue query
    query += f"""
        OPTIONAL MATCH (ds:DetectionStrategy)-[:DETECTS]->(ap)
        WHERE {filter_clause}
        OPTIONAL MATCH (ds)-[:HAS_ANALYTIC]->(a:Analytic)
    """
    
    # Add platform filter
    if platform:
        query += """
        WHERE $platform IN a.platforms
        """
    
    query += """
        WITH ap, count(DISTINCT ds) as strategy_count
        OPTIONAL MATCH (ap)-[:HAS_TACTIC]->(t:Tactic)
        RETURN 
            count(DISTINCT ap) as total_techniques,
            sum(CASE WHEN strategy_count > 0 THEN 1 ELSE 0 END) as covered_techniques,
            collect(DISTINCT t.shortname) as tactics
    """
    
    params = {"tactic": tactic, "platform": platform}
    result = neo4j_session.run(query, **params)
    record = result.single()
    
    if not record:
        return AggregatedCoverage(
            total_techniques=0,
            covered_techniques=0,
            partial_coverage=0,
            uncovered_techniques=0,
            coverage_percentage=0.0,
            by_tactic={},
            by_platform={},
            top_gaps=[]
        )
    
    total = record["total_techniques"]
    covered = record["covered_techniques"]
    uncovered = total - covered
    coverage_pct = (covered / total * 100) if total > 0 else 0
    
    # Get tactic breakdown
    tactic_breakdown = {}
    if not tactic:  # Only compute if not filtering by specific tactic
        tactic_query = """
            MATCH (t:Tactic)<-[:HAS_TACTIC]-(ap:AttackPattern)
            WHERE NOT ap.x_mitre_is_subtechnique
            OPTIONAL MATCH (ds:DetectionStrategy)-[:DETECTS]->(ap)
            WHERE NOT ds.revoked AND NOT ds.x_mitre_deprecated
            WITH t.shortname as tactic,
                 count(DISTINCT ap) as total,
                 count(DISTINCT CASE WHEN ds IS NOT NULL THEN ap END) as covered
            RETURN tactic, total, covered
        """
        tactic_result = neo4j_session.run(tactic_query)
        for rec in tactic_result:
            tactic_breakdown[rec["tactic"]] = {
                "total": rec["total"],
                "covered": rec["covered"],
                "uncovered": rec["total"] - rec["covered"]
            }
    
    # Get platform breakdown (simplified)
    platform_breakdown = {}
    if not platform:
        platform_query = """
            MATCH (a:Analytic)
            WHERE NOT a.revoked AND NOT a.x_mitre_deprecated
            UNWIND a.platforms as platform
            WITH platform, count(DISTINCT a) as analytic_count
            RETURN platform, analytic_count
        """
        platform_result = neo4j_session.run(platform_query)
        for rec in platform_result:
            platform_breakdown[rec["platform"]] = {
                "analytics": rec["analytic_count"]
            }
    
    # Get top gaps (techniques with no coverage)
    gap_query = """
        MATCH (ap:AttackPattern)
        WHERE NOT ap.x_mitre_is_subtechnique
        AND NOT EXISTS((ap)<-[:DETECTS]-(:DetectionStrategy))
        RETURN ap.external_id as technique_id,
               ap.name as technique_name
        LIMIT 10
    """
    gap_result = neo4j_session.run(gap_query)
    top_gaps = [{"technique_id": r["technique_id"], 
                 "technique_name": r["technique_name"]} 
                for r in gap_result]
    
    return AggregatedCoverage(
        total_techniques=total,
        covered_techniques=covered,
        partial_coverage=0,  # TODO: Compute partial coverage
        uncovered_techniques=uncovered,
        coverage_percentage=coverage_pct,
        by_tactic=tactic_breakdown,
        by_platform=platform_breakdown,
        top_gaps=top_gaps
    )


def compute_log_source_gaps(
    analytics: List[Dict[str, Any]], 
    log_sources: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Compute gaps between required and available log sources.
    
    Args:
        analytics: List of analytics with their log source requirements
        log_sources: List of available log sources
        
    Returns:
        List of identified gaps
    """
    gaps = []
    
    for analytic in analytics:
        if not analytic.get("x_mitre_log_sources"):
            continue
            
        required_sources = json.loads(analytic["x_mitre_log_sources"])
        
        for req_source in required_sources:
            source_ref = req_source.get("log_source_ref")
            required_keys = req_source.get("keys", [])
            
            # Find matching log source
            available_source = None
            for ls in log_sources:
                if ls["log_source_id"] == source_ref:
                    available_source = ls
                    break
            
            if not available_source:
                # Complete gap - log source not available
                gaps.append({
                    "analytic_id": analytic["analytic_id"],
                    "analytic_name": analytic["analytic_name"],
                    "gap_type": "missing_source",
                    "required_source": source_ref,
                    "severity": "critical"
                })
            else:
                # Check key availability
                available_keys = json.loads(available_source.get("keys", "[]"))
                missing_keys = [k for k in required_keys if k not in available_keys]
                
                if missing_keys:
                    gaps.append({
                        "analytic_id": analytic["analytic_id"],
                        "analytic_name": analytic["analytic_name"],
                        "gap_type": "missing_keys",
                        "required_source": source_ref,
                        "missing_keys": missing_keys,
                        "severity": "high" if len(missing_keys) > len(required_keys) / 2 else "medium"
                    })
    
    return gaps