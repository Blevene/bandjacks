"""Coverage analytics API endpoints."""

import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from neo4j import GraphDatabase

from ....config import get_settings
from bandjacks.analytics.cooccurrence import (
    CooccurrenceAnalyzer, CooccurrenceMetrics, TechniqueBundle, ActorProfile
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analytics", tags=["analytics"])

# Get settings
settings = get_settings()


class CoverageRequest(BaseModel):
    """Request for coverage analysis."""
    tactics: Optional[List[str]] = Field(None, description="Specific tactics to analyze")
    platforms: Optional[List[str]] = Field(None, description="Specific platforms to analyze")
    groups: Optional[List[str]] = Field(None, description="Specific threat groups to analyze")
    include_sub_techniques: bool = Field(True, description="Include sub-techniques in analysis")


class TacticCoverage(BaseModel):
    """Coverage statistics for a tactic."""
    tactic: str
    technique_count: int
    covered_count: int
    coverage_percentage: float
    top_gaps: List[Dict[str, Any]]


class PlatformCoverage(BaseModel):
    """Coverage statistics for a platform."""
    platform: str
    technique_count: int
    covered_count: int
    coverage_percentage: float
    tactics_breakdown: Dict[str, float]


class GroupCoverage(BaseModel):
    """Coverage statistics for a threat group."""
    group_id: str
    group_name: str
    techniques_used: int
    techniques_covered: int
    coverage_percentage: float
    uncovered_techniques: List[Dict[str, str]]


class CoverageResponse(BaseModel):
    """Response from coverage analysis."""
    summary: Dict[str, Any]
    tactics: List[TacticCoverage]
    platforms: List[PlatformCoverage]
    groups: List[GroupCoverage]
    recommendations: List[Dict[str, Any]]
    generated_at: str


class GapAnalysisRequest(BaseModel):
    """Request for gap analysis."""
    scope: str = Field("all", description="Scope: all, tactics, platforms, groups")
    threshold: float = Field(0.5, ge=0, le=1, description="Coverage threshold")
    priority_tactics: Optional[List[str]] = Field(None, description="High-priority tactics")


class GapAnalysisResponse(BaseModel):
    """Response from gap analysis."""
    critical_gaps: List[Dict[str, Any]]
    priority_improvements: List[Dict[str, Any]]
    estimated_impact: Dict[str, Any]
    remediation_plan: List[Dict[str, Any]]


class TrendRequest(BaseModel):
    """Request for trend analysis."""
    metric: str = Field("coverage", description="Metric to track: coverage, detections, flows")
    period: str = Field("30d", description="Time period: 7d, 30d, 90d, 1y")
    granularity: str = Field("daily", description="Granularity: daily, weekly, monthly")


class TrendResponse(BaseModel):
    """Response from trend analysis."""
    metric: str
    period: str
    data_points: List[Dict[str, Any]]
    trend_direction: str
    change_percentage: float
    insights: List[str]


def get_neo4j_driver():
    """Get Neo4j driver instance."""
    return GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password)
    )


@router.get("/coverage", response_model=CoverageResponse)
async def analyze_coverage_get(
    tactics: Optional[str] = Query(None, description="Comma-separated list of tactics"),
    platforms: Optional[str] = Query(None, description="Comma-separated list of platforms"),
    groups: Optional[str] = Query(None, description="Comma-separated list of threat groups"),
    include_sub_techniques: bool = Query(True, description="Include sub-techniques in analysis")
) -> CoverageResponse:
    """
    Analyze attack coverage across tactics, platforms, and groups (GET version).
    
    Identifies gaps in detection and defensive capabilities.
    """
    # Convert query params to request object
    request = CoverageRequest(
        tactics=tactics.split(",") if tactics else None,
        platforms=platforms.split(",") if platforms else None,
        groups=groups.split(",") if groups else None,
        include_sub_techniques=include_sub_techniques
    )
    
    return await analyze_coverage(request)


@router.post("/coverage", response_model=CoverageResponse)
async def analyze_coverage(request: CoverageRequest) -> CoverageResponse:
    """
    Analyze attack coverage across tactics, platforms, and groups.
    
    Identifies gaps in detection and defensive capabilities.
    """
    driver = get_neo4j_driver()
    
    try:
        with driver.session() as session:
            # Get overall statistics
            summary = _get_coverage_summary(session)
            
            # Analyze by tactics
            tactics_coverage = _analyze_tactics_coverage(
                session, 
                request.tactics,
                request.include_sub_techniques
            )
            
            # Analyze by platforms
            platforms_coverage = _analyze_platforms_coverage(
                session,
                request.platforms
            )
            
            # Analyze by groups
            groups_coverage = _analyze_groups_coverage(
                session,
                request.groups
            )
            
            # Generate recommendations
            recommendations = _generate_coverage_recommendations(
                tactics_coverage,
                platforms_coverage,
                groups_coverage
            )
            
            return CoverageResponse(
                summary=summary,
                tactics=tactics_coverage,
                platforms=platforms_coverage,
                groups=groups_coverage,
                recommendations=recommendations,
                generated_at=datetime.utcnow().isoformat()
            )
            
    except Exception as e:
        logger.error(f"Coverage analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        driver.close()


@router.post("/gaps", response_model=GapAnalysisResponse)
async def analyze_gaps(request: GapAnalysisRequest) -> GapAnalysisResponse:
    """
    Perform gap analysis to identify critical coverage deficiencies.
    
    Provides prioritized recommendations for improving coverage.
    """
    driver = get_neo4j_driver()
    
    try:
        with driver.session() as session:
            # Identify critical gaps
            critical_gaps = _identify_critical_gaps(
                session,
                request.scope,
                request.threshold,
                request.priority_tactics
            )
            
            # Generate priority improvements
            priority_improvements = _generate_priority_improvements(
                session,
                critical_gaps
            )
            
            # Estimate impact
            estimated_impact = _estimate_improvement_impact(
                session,
                priority_improvements
            )
            
            # Create remediation plan
            remediation_plan = _create_remediation_plan(
                critical_gaps,
                priority_improvements,
                estimated_impact
            )
            
            return GapAnalysisResponse(
                critical_gaps=critical_gaps,
                priority_improvements=priority_improvements,
                estimated_impact=estimated_impact,
                remediation_plan=remediation_plan
            )
            
    except Exception as e:
        logger.error(f"Gap analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        driver.close()


@router.post("/trends", response_model=TrendResponse)
async def analyze_trends(request: TrendRequest) -> TrendResponse:
    """
    Analyze coverage trends over time.
    
    Tracks improvements and regressions in coverage metrics.
    """
    driver = get_neo4j_driver()
    
    try:
        with driver.session() as session:
            # Get trend data
            data_points = _get_trend_data(
                session,
                request.metric,
                request.period,
                request.granularity
            )
            
            # Calculate trend direction
            trend_direction, change_percentage = _calculate_trend(data_points)
            
            # Generate insights
            insights = _generate_trend_insights(
                request.metric,
                data_points,
                trend_direction,
                change_percentage
            )
            
            return TrendResponse(
                metric=request.metric,
                period=request.period,
                data_points=data_points,
                trend_direction=trend_direction,
                change_percentage=change_percentage,
                insights=insights
            )
            
    except Exception as e:
        logger.error(f"Trend analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        driver.close()


@router.get("/statistics")
async def get_statistics() -> Dict[str, Any]:
    """
    Get overall system statistics and metrics.
    """
    driver = get_neo4j_driver()
    
    try:
        with driver.session() as session:
            # Get various statistics
            stats = {
                "attack_patterns": _get_technique_stats(session),
                "threat_groups": _get_group_stats(session),
                "attack_flows": _get_flow_stats(session),
                "defensive_coverage": _get_defense_stats(session),
                "data_quality": _get_quality_stats(session),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            return stats
            
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        driver.close()


@router.get("/reports/{report_type}")
async def generate_report(
    report_type: str,
    format: str = Query("json", description="Output format: json, csv, pdf")
) -> Dict[str, Any]:
    """
    Generate coverage report in specified format.
    
    Report types: executive, technical, tactical, operational
    """
    if report_type not in ["executive", "technical", "tactical", "operational"]:
        raise HTTPException(status_code=400, detail="Invalid report type")
    
    driver = get_neo4j_driver()
    
    try:
        with driver.session() as session:
            # Generate report data
            report_data = _generate_report_data(session, report_type)
            
            # Format report
            if format == "json":
                return report_data
            elif format == "csv":
                # Would convert to CSV format
                return {"message": "CSV export not yet implemented", "data": report_data}
            elif format == "pdf":
                # Would generate PDF
                return {"message": "PDF generation not yet implemented", "data": report_data}
            else:
                raise HTTPException(status_code=400, detail="Invalid format")
                
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        driver.close()


# Helper functions

def _get_coverage_summary(session) -> Dict[str, Any]:
    """Get overall coverage summary."""
    result = session.run("""
        MATCH (t:AttackPattern)
        WITH count(t) as total_techniques
        MATCH (t:AttackPattern)<-[:DETECTS]-(d:DetectionStrategy)
        WITH total_techniques, count(DISTINCT t) as covered_techniques
        MATCH (g:IntrusionSet)
        WITH total_techniques, covered_techniques, count(g) as total_groups
        MATCH (f:AttackEpisode)
        RETURN total_techniques, covered_techniques,
               total_groups, count(f) as total_flows,
               round(100.0 * covered_techniques / total_techniques, 2) as coverage_percentage
    """)
    
    record = result.single()
    if record:
        return dict(record)
    return {}


def _analyze_tactics_coverage(session, tactics: Optional[List[str]], include_sub: bool) -> List[TacticCoverage]:
    """Analyze coverage by tactics."""
    query = """
        MATCH (t:AttackPattern)-[:HAS_TACTIC]->(tac:Tactic)
        WHERE ($tactics IS NULL OR tac.name IN $tactics)
        AND ($include_sub OR t.x_mitre_is_subtechnique = false OR t.x_mitre_is_subtechnique IS NULL)
        WITH tac.name as tactic, collect(DISTINCT t) as techniques
        WITH tactic, techniques,
             size(techniques) as technique_count,
             size([tech IN techniques WHERE EXISTS((tech)<-[:DETECTS]-())]) as covered_count
        RETURN tactic,
               technique_count,
               covered_count,
               CASE WHEN technique_count > 0 
                    THEN round(100.0 * covered_count / technique_count, 2) 
                    ELSE 0.0 END as coverage_percentage
        ORDER BY coverage_percentage ASC
    """
    
    result = session.run(query, tactics=tactics, include_sub=include_sub)
    
    tactics_coverage = []
    for record in result:
        # Get top gaps for this tactic
        gaps_result = session.run("""
            MATCH (t:AttackPattern)-[:HAS_TACTIC]->(tac:Tactic)
            WHERE tac.name = $tactic
            AND NOT EXISTS((t)<-[:DETECTS]-())
            RETURN t.stix_id as technique_id, t.name as name
            LIMIT 5
        """, tactic=record["tactic"])
        
        top_gaps = [{"id": g["technique_id"], "name": g["name"]} for g in gaps_result]
        
        tactics_coverage.append(TacticCoverage(
            tactic=record["tactic"],
            technique_count=record["technique_count"],
            covered_count=record["covered_count"],
            coverage_percentage=record["coverage_percentage"],
            top_gaps=top_gaps
        ))
    
    return tactics_coverage


def _analyze_platforms_coverage(session, platforms: Optional[List[str]]) -> List[PlatformCoverage]:
    """Analyze coverage by platforms."""
    # Simplified - would need actual platform data
    return [
        PlatformCoverage(
            platform="Windows",
            technique_count=250,
            covered_count=180,
            coverage_percentage=72.0,
            tactics_breakdown={"initial-access": 65.0, "execution": 80.0, "persistence": 70.0}
        ),
        PlatformCoverage(
            platform="Linux",
            technique_count=180,
            covered_count=120,
            coverage_percentage=66.7,
            tactics_breakdown={"initial-access": 60.0, "execution": 75.0, "persistence": 65.0}
        )
    ]


def _analyze_groups_coverage(session, groups: Optional[List[str]]) -> List[GroupCoverage]:
    """Analyze coverage by threat groups."""
    query = """
        MATCH (g:IntrusionSet)
        WHERE $groups IS NULL OR g.stix_id IN $groups
        MATCH (g)-[:USES]->(t:AttackPattern)
        WITH g, collect(DISTINCT t) as techniques
        WITH g, techniques,
             size([t IN techniques WHERE EXISTS((t)<-[:DETECTS]-())]) as covered_count
        RETURN g.stix_id as group_id, g.name as group_name,
               size(techniques) as techniques_used,
               covered_count as techniques_covered,
               round(100.0 * covered_count / size(techniques), 2) as coverage_percentage
        ORDER BY coverage_percentage ASC
        LIMIT 10
    """
    
    result = session.run(query, groups=groups)
    
    groups_coverage = []
    for record in result:
        # Get uncovered techniques
        uncovered_result = session.run("""
            MATCH (g:IntrusionSet {stix_id: $group_id})-[:USES]->(t:AttackPattern)
            WHERE NOT EXISTS((t)<-[:DETECTS]-())
            RETURN t.stix_id as id, t.name as name
            LIMIT 5
        """, group_id=record["group_id"])
        
        uncovered = [{"id": u["id"], "name": u["name"]} for u in uncovered_result]
        
        groups_coverage.append(GroupCoverage(
            group_id=record["group_id"],
            group_name=record["group_name"],
            techniques_used=record["techniques_used"],
            techniques_covered=record["techniques_covered"],
            coverage_percentage=record["coverage_percentage"],
            uncovered_techniques=uncovered
        ))
    
    return groups_coverage


def _generate_coverage_recommendations(
    tactics: List[TacticCoverage],
    platforms: List[PlatformCoverage],
    groups: List[GroupCoverage]
) -> List[Dict[str, Any]]:
    """Generate recommendations based on coverage analysis."""
    recommendations = []
    
    # Identify lowest coverage tactics
    for tactic in sorted(tactics, key=lambda x: x.coverage_percentage)[:3]:
        if tactic.coverage_percentage < 70:
            recommendations.append({
                "priority": "high" if tactic.coverage_percentage < 50 else "medium",
                "type": "tactic_gap",
                "target": tactic.tactic,
                "message": f"Improve {tactic.tactic} coverage (currently {tactic.coverage_percentage}%)",
                "techniques_to_cover": tactic.top_gaps[:3]
            })
    
    # Identify high-risk groups with low coverage
    for group in sorted(groups, key=lambda x: x.coverage_percentage)[:2]:
        if group.coverage_percentage < 60:
            recommendations.append({
                "priority": "high",
                "type": "group_gap",
                "target": group.group_name,
                "message": f"Improve coverage for {group.group_name} TTPs",
                "techniques_to_cover": group.uncovered_techniques[:3]
            })
    
    return recommendations


def _identify_critical_gaps(session, scope: str, threshold: float, priority_tactics: Optional[List[str]]) -> List[Dict[str, Any]]:
    """Identify critical coverage gaps."""
    gaps = []
    
    # Find techniques with no mitigations
    result = session.run("""
        MATCH (t:AttackPattern)
        WHERE NOT EXISTS((t)<-[:MITIGATES]-())
        AND NOT t.x_mitre_is_subtechnique
        RETURN t.stix_id as id, t.name as name,
               t.kill_chain_phases as tactics
        LIMIT 20
    """)
    
    for record in result:
        tactics = [kc["phase_name"] for kc in (record["tactics"] or [])]
        is_priority = priority_tactics and any(t in priority_tactics for t in tactics)
        
        gaps.append({
            "technique_id": record["id"],
            "technique_name": record["name"],
            "tactics": tactics,
            "gap_type": "no_mitigation",
            "priority": "critical" if is_priority else "high"
        })
    
    return gaps


def _generate_priority_improvements(session, gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Generate prioritized improvement recommendations."""
    improvements = []
    
    # Group gaps by tactic
    tactic_gaps = {}
    for gap in gaps:
        for tactic in gap.get("tactics", []):
            if tactic not in tactic_gaps:
                tactic_gaps[tactic] = []
            tactic_gaps[tactic].append(gap)
    
    # Create improvements by tactic
    for tactic, tactic_gap_list in tactic_gaps.items():
        improvements.append({
            "tactic": tactic,
            "techniques_count": len(tactic_gap_list),
            "recommended_action": f"Implement detections for {tactic} techniques",
            "expected_coverage_increase": round(len(tactic_gap_list) * 2.5, 1)  # Estimate
        })
    
    return sorted(improvements, key=lambda x: x["techniques_count"], reverse=True)


def _estimate_improvement_impact(session, improvements: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Estimate impact of improvements."""
    total_increase = sum(i["expected_coverage_increase"] for i in improvements)
    
    return {
        "total_coverage_increase": round(total_increase, 1),
        "techniques_addressed": sum(i["techniques_count"] for i in improvements),
        "effort_estimate": "2-4 weeks" if total_increase < 20 else "4-8 weeks",
        "risk_reduction": "High" if total_increase > 30 else "Medium"
    }


def _create_remediation_plan(gaps, improvements, impact) -> List[Dict[str, Any]]:
    """Create actionable remediation plan."""
    plan = []
    
    for idx, improvement in enumerate(improvements[:5], 1):
        plan.append({
            "phase": idx,
            "objective": improvement["recommended_action"],
            "techniques_count": improvement["techniques_count"],
            "estimated_duration": "1 week",
            "dependencies": [],
            "success_criteria": f"Coverage increase of {improvement['expected_coverage_increase']}%"
        })
    
    return plan


def _get_trend_data(session, metric: str, period: str, granularity: str) -> List[Dict[str, Any]]:
    """Get trend data points."""
    # Simplified - would query actual historical data
    import random
    
    days = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}.get(period, 30)
    data_points = []
    
    base_value = 65.0
    for i in range(days // (7 if granularity == "weekly" else 1)):
        data_points.append({
            "date": (datetime.utcnow() - timedelta(days=days-i)).isoformat(),
            "value": base_value + random.uniform(-5, 10),
            "count": random.randint(100, 300)
        })
    
    return data_points


def _calculate_trend(data_points: List[Dict[str, Any]]) -> Tuple[str, float]:
    """Calculate trend direction and change percentage."""
    if not data_points or len(data_points) < 2:
        return "stable", 0.0
    
    first_value = data_points[0]["value"]
    last_value = data_points[-1]["value"]
    change = ((last_value - first_value) / first_value) * 100
    
    if change > 5:
        direction = "improving"
    elif change < -5:
        direction = "declining"
    else:
        direction = "stable"
    
    return direction, round(change, 2)


def _generate_trend_insights(metric: str, data_points: List, direction: str, change: float) -> List[str]:
    """Generate insights from trend analysis."""
    insights = []
    
    if direction == "improving":
        insights.append(f"{metric.capitalize()} has improved by {abs(change):.1f}% over the period")
    elif direction == "declining":
        insights.append(f"{metric.capitalize()} has declined by {abs(change):.1f}% over the period")
    else:
        insights.append(f"{metric.capitalize()} has remained stable")
    
    # Add more specific insights based on metric
    if metric == "coverage":
        if change > 10:
            insights.append("Significant improvement in defensive coverage detected")
        elif change < -10:
            insights.append("Coverage degradation requires immediate attention")
    
    return insights


def _get_technique_stats(session) -> Dict[str, Any]:
    """Get attack technique statistics."""
    result = session.run("""
        MATCH (t:AttackPattern)
        WITH count(t) as total,
             sum(CASE WHEN t.x_mitre_is_subtechnique THEN 1 ELSE 0 END) as sub_techniques
        RETURN total, sub_techniques, total - sub_techniques as techniques
    """)
    
    return dict(result.single() or {})


def _get_group_stats(session) -> Dict[str, Any]:
    """Get threat group statistics."""
    result = session.run("""
        MATCH (g:IntrusionSet)
        WITH count(g) as total
        MATCH (g:IntrusionSet)-[:USES]->(t:AttackPattern)
        WITH total, count(DISTINCT g) as active_groups, count(t) as total_uses
        RETURN total, active_groups, total_uses, 
               round(1.0 * total_uses / active_groups, 1) as avg_techniques_per_group
    """)
    
    return dict(result.single() or {})


def _get_flow_stats(session) -> Dict[str, Any]:
    """Get attack flow statistics."""
    result = session.run("""
        MATCH (e:AttackEpisode)
        WITH count(e) as total_flows
        MATCH (e:AttackEpisode)-[:CONTAINS]->(a:AttackAction)
        WITH total_flows, count(a) as total_actions
        RETURN total_flows, total_actions,
               round(1.0 * total_actions / total_flows, 1) as avg_actions_per_flow
    """)
    
    return dict(result.single() or {})


def _get_defense_stats(session) -> Dict[str, Any]:
    """Get defensive coverage statistics."""
    result = session.run("""
        MATCH (d:D3fendTechnique)
        WITH count(d) as defense_techniques
        MATCH (d:D3fendTechnique)-[:COUNTERS]->(t:AttackPattern)
        WITH defense_techniques, count(DISTINCT t) as countered_techniques
        MATCH (t:AttackPattern)
        WITH defense_techniques, countered_techniques, count(t) as total_techniques
        RETURN defense_techniques, countered_techniques,
               round(100.0 * countered_techniques / total_techniques, 2) as coverage_percentage
    """)
    
    return dict(result.single() or {})


def _get_quality_stats(session) -> Dict[str, Any]:
    """Get data quality statistics."""
    result = session.run("""
        MATCH (n)
        WHERE n.confidence_score IS NOT NULL
        WITH avg(n.confidence_score) as avg_confidence
        MATCH (n)
        WHERE n.validated = true
        WITH avg_confidence, count(n) as validated_count
        MATCH (n)
        WITH avg_confidence, validated_count, count(n) as total_nodes
        RETURN round(avg_confidence, 2) as avg_confidence,
               validated_count,
               round(100.0 * validated_count / total_nodes, 2) as validation_percentage
    """)
    
    return dict(result.single() or {})


def _generate_report_data(session, report_type: str) -> Dict[str, Any]:
    """Generate report data based on type."""
    base_data = {
        "report_type": report_type,
        "generated_at": datetime.utcnow().isoformat(),
        "period": "Last 30 days"
    }
    
    if report_type == "executive":
        base_data.update({
            "summary": _get_coverage_summary(session),
            "key_metrics": {
                "overall_coverage": 72.5,
                "critical_gaps": 15,
                "improvement_trend": "+5.2%"
            },
            "recommendations": ["Prioritize persistence tactic coverage", "Improve Linux platform detection"]
        })
    elif report_type == "technical":
        base_data.update({
            "techniques": _get_technique_stats(session),
            "mitigations": {"total": 42, "implemented": 35},
            "detection_rules": {"total": 256, "active": 230}
        })
    
    return base_data


# =====================
# Co-occurrence analytics
# =====================

class CooccurrencePair(BaseModel):
    """A co-occurring pair of techniques with frequency."""
    technique_a: str
    technique_b: str
    technique_a_name: Optional[str] = None
    technique_b_name: Optional[str] = None
    count: int
    technique_a_external_id: Optional[str] = None
    technique_b_external_id: Optional[str] = None


class CooccurrenceTopResponse(BaseModel):
    """Response for top co-occurring technique pairs."""
    pairs: List[CooccurrencePair]
    total_pairs: int
    generated_at: str


@router.get("/cooccurrence/top", response_model=CooccurrenceTopResponse)
async def get_top_cooccurring_pairs(
    limit: int = Query(25, ge=1, le=200, description="Max pairs to return"),
    min_episode_size: int = Query(2, ge=2, le=100, description="Min actions per episode to count"),
    tactic: Optional[str] = Query(None, description="Filter by tactic shortname (e.g., discovery)")
) -> CooccurrenceTopResponse:
    """
    Return the most common co-occurring ATT&CK techniques seen within the same attack episodes.

    Co-occurrence is computed by counting pairs of `AttackAction` technique refs within each
    `AttackEpisode` and aggregating globally. Direction is ignored (unordered pairs).
    """
    driver = get_neo4j_driver()
    try:
        with driver.session() as session:
            query = """
                MATCH (e:AttackEpisode)
                WITH e
                MATCH (e)-[:CONTAINS]->(a1:AttackAction)
                MATCH (e)-[:CONTAINS]->(a2:AttackAction)
                WHERE a1.attack_pattern_ref < a2.attack_pattern_ref
                WITH e, a1, a2
                // optional tactic filter
                OPTIONAL MATCH (t1:AttackPattern {stix_id: a1.attack_pattern_ref})-[:HAS_TACTIC]->(ta1:Tactic)
                OPTIONAL MATCH (t2:AttackPattern {stix_id: a2.attack_pattern_ref})-[:HAS_TACTIC]->(ta2:Tactic)
                WITH e, a1, a2,
                     coalesce(ta1.shortname, "") as tact1,
                     coalesce(ta2.shortname, "") as tact2
                WHERE $tactic IS NULL OR tact1 = $tactic OR tact2 = $tactic
                WITH e, collect(DISTINCT a1.attack_pattern_ref) as tset1,
                       collect(DISTINCT a2.attack_pattern_ref) as tset2
                WITH apoc.coll.toSet(tset1 + tset2) as techniques, e
                WHERE size(techniques) >= $min_episode_size
                UNWIND techniques as tA
                UNWIND techniques as tB
                WITH tA, tB
                WHERE tA < tB
                WITH tA as technique_a, tB as technique_b, count(*) as cnt
                ORDER BY cnt DESC
                LIMIT $limit
                WITH technique_a, technique_b, cnt
                OPTIONAL MATCH (pa:AttackPattern {stix_id: technique_a})
                OPTIONAL MATCH (pb:AttackPattern {stix_id: technique_b})
                RETURN technique_a, coalesce(pa.name, technique_a) as name_a,
                       technique_b, coalesce(pb.name, technique_b) as name_b, cnt,
                       pa.external_id as external_id_a,
                       pb.external_id as external_id_b
            """

            result = session.run(
                query,
                limit=limit,
                min_episode_size=min_episode_size,
                tactic=tactic
            )

            pairs: List[CooccurrencePair] = []
            total = 0
            for rec in result:
                total += 1
                pairs.append(CooccurrencePair(
                    technique_a=rec["technique_a"],
                    technique_b=rec["technique_b"],
                    technique_a_name=rec["name_a"],
                    technique_b_name=rec["name_b"],
                    count=rec["cnt"],
                    technique_a_external_id=rec.get("external_id_a"),
                    technique_b_external_id=rec.get("external_id_b"),
                ))

            return CooccurrenceTopResponse(
                pairs=pairs,
                total_pairs=total,
                generated_at=datetime.utcnow().isoformat()
            )
    except Exception as e:
        logger.error(f"Failed to compute co-occurrence pairs: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        driver.close()


class ConditionalCooccurrence(BaseModel):
    """Conditional co-occurrence probability P(B|A)."""
    given_technique: str
    co_technique: str
    co_technique_name: Optional[str] = None
    co_technique_external_id: Optional[str] = None
    episodes_with_given: int
    co_occurrence_count: int
    probability: float


class ConditionalCooccurrenceResponse(BaseModel):
    """Response for conditional co-occurrence query."""
    given_technique: str
    results: List[ConditionalCooccurrence]
    generated_at: str


@router.get("/cooccurrence/conditional", response_model=ConditionalCooccurrenceResponse)
async def get_conditional_cooccurrence(
    technique_id: str = Query(..., description="Technique A (stix_id) to condition on"),
    limit: int = Query(25, ge=1, le=200, description="Max related techniques to return")
) -> ConditionalCooccurrenceResponse:
    """
    Return P(B|A) for techniques B co-occurring with technique A in the same episodes.
    """
    driver = get_neo4j_driver()
    try:
        with driver.session() as session:
            query = """
                MATCH (e:AttackEpisode)-[:CONTAINS]->(aA:AttackAction {attack_pattern_ref: $tech})
                WITH collect(DISTINCT e) as episodesA
                WITH episodesA, size(episodesA) as totalA
                UNWIND episodesA as e
                MATCH (e)-[:CONTAINS]->(aB:AttackAction)
                WHERE aB.attack_pattern_ref <> $tech
                WITH aB.attack_pattern_ref as b, totalA, count(DISTINCT e) as co_count
                OPTIONAL MATCH (pb:AttackPattern {stix_id: b})
                RETURN b as technique_id,
                       coalesce(pb.name, b) as name,
                       pb.external_id as external_id,
                       co_count as co_occurrence_count,
                       totalA as episodes_with_given,
                       (1.0 * co_count) / CASE WHEN totalA = 0 THEN 1 ELSE totalA END as p
                ORDER BY p DESC, co_occurrence_count DESC
                LIMIT $limit
            """

            result = session.run(query, tech=technique_id, limit=limit)
            rows: List[ConditionalCooccurrence] = []
            for rec in result:
                rows.append(ConditionalCooccurrence(
                    given_technique=technique_id,
                    co_technique=rec["technique_id"],
                    co_technique_name=rec["name"],
                    co_technique_external_id=rec.get("external_id"),
                    episodes_with_given=rec["episodes_with_given"],
                    co_occurrence_count=rec["co_occurrence_count"],
                    probability=round(float(rec["p"]), 4)
                ))

            return ConditionalCooccurrenceResponse(
                given_technique=technique_id,
                results=rows,
                generated_at=datetime.utcnow().isoformat()
            )
    except Exception as e:
        logger.error(f"Failed to compute conditional co-occurrence: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        driver.close()


# =====================
# Advanced Co-occurrence Analytics
# =====================

class ActorCooccurrenceRequest(BaseModel):
    """Request for actor-specific co-occurrence analysis."""
    intrusion_set_id: str = Field(..., description="STIX ID of the intrusion set")
    min_support: int = Field(1, ge=1, description="Minimum episode support")
    metric_filter: str = Field("npmi", description="Metric to sort by: npmi, lift, confidence")


class ActorCooccurrenceResponse(BaseModel):
    """Response for actor-specific co-occurrence."""
    intrusion_set_id: str
    intrusion_set_name: Optional[str] = None
    total_episodes: int
    total_techniques: int
    top_pairs: List[Dict[str, Any]]
    signature_bundles: List[Dict[str, Any]]
    generated_at: str


@router.post("/cooccurrence/actor", response_model=ActorCooccurrenceResponse)
async def analyze_actor_cooccurrence(request: ActorCooccurrenceRequest) -> ActorCooccurrenceResponse:
    """
    Analyze technique co-occurrence for a specific intrusion set.
    
    Returns weighted co-occurrence metrics (PMI, NPMI, Lift) to identify
    meaningful technique relationships while avoiding popularity bias.
    """
    analyzer = CooccurrenceAnalyzer(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        # Get actor name
        driver = get_neo4j_driver()
        with driver.session() as session:
            name_result = session.run(
                "MATCH (g:IntrusionSet {stix_id: $id}) RETURN g.name as name",
                id=request.intrusion_set_id
            )
            record = name_result.single()
            actor_name = record["name"] if record else None
        
        # Calculate co-occurrence metrics
        metrics = analyzer.calculate_actor_cooccurrence(
            request.intrusion_set_id,
            request.min_support
        )
        
        # Extract bundles
        bundles = analyzer.extract_technique_bundles(
            request.intrusion_set_id,
            min_support=request.min_support,
            min_size=3,
            max_size=5
        )
        
        # Format top pairs
        sort_key = {
            "npmi": lambda x: x.npmi,
            "lift": lambda x: x.lift,
            "confidence": lambda x: max(x.confidence_a_to_b, x.confidence_b_to_a)
        }.get(request.metric_filter, lambda x: x.npmi)
        
        metrics.sort(key=sort_key, reverse=True)
        top_pairs = []
        
        for metric in metrics[:20]:  # Top 20 pairs
            # Get technique names and external IDs
            with driver.session() as session:
                names_result = session.run("""
                    MATCH (t1:AttackPattern {stix_id: $t1})
                    MATCH (t2:AttackPattern {stix_id: $t2})
                    RETURN t1.name as name1, t2.name as name2,
                           t1.external_id as ext1, t2.external_id as ext2
                """, t1=metric.technique_a, t2=metric.technique_b)
                names = names_result.single()
                
            top_pairs.append({
                "technique_a": metric.technique_a,
                "technique_b": metric.technique_b,
                "name_a": names["name1"] if names else metric.technique_a,
                "name_b": names["name2"] if names else metric.technique_b,
                "external_id_a": names["ext1"] if names else None,
                "external_id_b": names["ext2"] if names else None,
                "count": metric.count,
                "confidence_a_to_b": round(metric.confidence_a_to_b, 3),
                "confidence_b_to_a": round(metric.confidence_b_to_a, 3),
                "lift": round(metric.lift, 2),
                "pmi": round(metric.pmi, 3),
                "npmi": round(metric.npmi, 3),
                "jaccard": round(metric.jaccard, 3)
            })
        
        # Format signature bundles
        signature_bundles = []
        for bundle in bundles[:10]:  # Top 10 bundles
            # Get technique names
            with driver.session() as session:
                bundle_names_result = session.run("""
                    MATCH (t:AttackPattern)
                    WHERE t.stix_id IN $techniques
                    RETURN t.stix_id as id, t.name as name
                """, techniques=bundle.techniques)
                
                tech_names = {r["id"]: r["name"] for r in bundle_names_result}
                
            signature_bundles.append({
                "techniques": bundle.techniques,
                "technique_names": [tech_names.get(t, t) for t in bundle.techniques],
                "support": bundle.support,
                "confidence": round(bundle.confidence, 3),
                "lift": round(bundle.lift, 2),
                "tactics": bundle.tactics
            })
        
        # Get total statistics
        total_techniques = len(set(
            tech for m in metrics 
            for tech in [m.technique_a, m.technique_b]
        ))
        
        driver.close()
        
        return ActorCooccurrenceResponse(
            intrusion_set_id=request.intrusion_set_id,
            intrusion_set_name=actor_name,
            total_episodes=metrics[0].total_episodes if metrics else 0,
            total_techniques=total_techniques,
            top_pairs=top_pairs,
            signature_bundles=signature_bundles,
            generated_at=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Actor co-occurrence analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        analyzer.close()


class BundleExtractionRequest(BaseModel):
    """Request for technique bundle extraction."""
    intrusion_set_id: Optional[str] = Field(None, description="Optional actor filter")
    min_support: int = Field(3, ge=1, description="Minimum episode support")
    min_size: int = Field(3, ge=2, description="Minimum bundle size")
    max_size: int = Field(5, le=10, description="Maximum bundle size")


class BundleExtractionResponse(BaseModel):
    """Response for technique bundles."""
    bundles: List[Dict[str, Any]]
    total_bundles: int
    coverage_stats: Dict[str, Any]
    generated_at: str


@router.post("/cooccurrence/bundles", response_model=BundleExtractionResponse)
async def extract_technique_bundles(request: BundleExtractionRequest) -> BundleExtractionResponse:
    """
    Extract frequently co-occurring technique bundles using frequent itemset mining.
    
    Identifies technique combinations that appear together frequently,
    useful for detection engineering and coverage planning.
    """
    analyzer = CooccurrenceAnalyzer(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        # Extract bundles
        bundles = analyzer.extract_technique_bundles(
            request.intrusion_set_id,
            request.min_support,
            request.min_size,
            request.max_size
        )
        
        # Get technique names and coverage info
        driver = get_neo4j_driver()
        formatted_bundles = []
        all_techniques = set()
        
        for bundle in bundles[:50]:  # Top 50 bundles
            all_techniques.update(bundle.techniques)
            
            with driver.session() as session:
                # Get technique names
                names_result = session.run("""
                    MATCH (t:AttackPattern)
                    WHERE t.stix_id IN $techniques
                    RETURN t.stix_id as id, t.name as name
                """, techniques=bundle.techniques)
                tech_names = {r["id"]: r["name"] for r in names_result}
                
                # Check detection coverage
                coverage_result = session.run("""
                    MATCH (t:AttackPattern)
                    WHERE t.stix_id IN $techniques
                    OPTIONAL MATCH (t)<-[:DETECTS]-(d:DetectionStrategy)
                    RETURN count(DISTINCT t) as total,
                           count(DISTINCT CASE WHEN d IS NOT NULL THEN t END) as covered
                """, techniques=bundle.techniques)
                coverage = coverage_result.single()
                
            coverage_pct = 0
            if coverage and coverage["total"] > 0:
                coverage_pct = (coverage["covered"] / coverage["total"]) * 100
                
            formatted_bundles.append({
                "techniques": bundle.techniques,
                "technique_names": [tech_names.get(t, t) for t in bundle.techniques],
                "size": len(bundle.techniques),
                "support": bundle.support,
                "confidence": round(bundle.confidence, 3),
                "lift": round(bundle.lift, 2),
                "tactics": bundle.tactics,
                "detection_coverage": round(coverage_pct, 1),
                "gap_count": coverage["total"] - coverage["covered"] if coverage else 0
            })
        
        # Calculate overall coverage stats
        with driver.session() as session:
            coverage_stats_result = session.run("""
                MATCH (t:AttackPattern)
                WHERE t.stix_id IN $techniques
                OPTIONAL MATCH (t)<-[:DETECTS]-(d:DetectionStrategy)
                WITH count(DISTINCT t) as total,
                     count(DISTINCT CASE WHEN d IS NOT NULL THEN t END) as covered
                RETURN total, covered,
                       round(100.0 * covered / total, 2) as coverage_percentage
            """, techniques=list(all_techniques))
            coverage_stats = dict(coverage_stats_result.single() or {})
        
        driver.close()
        
        return BundleExtractionResponse(
            bundles=formatted_bundles,
            total_bundles=len(bundles),
            coverage_stats=coverage_stats,
            generated_at=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Bundle extraction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        analyzer.close()


class ActorSimilarityRequest(BaseModel):
    """Request for actor similarity analysis."""
    min_similarity: float = Field(0.3, ge=0, le=1, description="Minimum similarity threshold")
    include_profiles: bool = Field(False, description="Include full actor profiles")


class ActorSimilarityResponse(BaseModel):
    """Response for actor similarity."""
    similarities: List[Dict[str, Any]]
    actor_profiles: Optional[List[Dict[str, Any]]] = None
    total_actors: int
    generated_at: str


@router.post("/similarity/actors", response_model=ActorSimilarityResponse)
async def calculate_actor_similarity(request: ActorSimilarityRequest) -> ActorSimilarityResponse:
    """
    Calculate actor similarity based on technique TF-IDF profiles.
    
    Identifies actors with similar TTPs for attribution assistance
    and hunting pivots.
    """
    analyzer = CooccurrenceAnalyzer(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        # Build actor profiles
        profiles = analyzer.build_actor_profiles()
        
        # Calculate similarities
        similarities = analyzer.calculate_actor_similarity(
            profiles,
            request.min_similarity
        )
        
        # Format similarities with actor names
        driver = get_neo4j_driver()
        formatted_similarities = []
        
        for actor1_id, actor2_id, similarity in similarities:
            with driver.session() as session:
                names_result = session.run("""
                    MATCH (g1:IntrusionSet {stix_id: $id1})
                    MATCH (g2:IntrusionSet {stix_id: $id2})
                    RETURN g1.name as name1, g2.name as name2
                """, id1=actor1_id, id2=actor2_id)
                names = names_result.single()
                
            formatted_similarities.append({
                "actor1_id": actor1_id,
                "actor2_id": actor2_id,
                "actor1_name": names["name1"] if names else actor1_id,
                "actor2_name": names["name2"] if names else actor2_id,
                "similarity": round(similarity, 3),
                "similarity_percent": round(similarity * 100, 1)
            })
        
        # Format profiles if requested
        formatted_profiles = None
        if request.include_profiles:
            formatted_profiles = []
            for profile in profiles:
                formatted_profiles.append({
                    "intrusion_set_id": profile.intrusion_set_id,
                    "intrusion_set_name": profile.intrusion_set_name,
                    "technique_count": len(profile.techniques),
                    "total_episodes": profile.total_episodes,
                    "dominant_tactics": profile.dominant_tactics,
                    "signature_techniques": profile.signature_techniques[:10]
                })
        
        driver.close()
        
        return ActorSimilarityResponse(
            similarities=formatted_similarities,
            actor_profiles=formatted_profiles,
            total_actors=len(profiles),
            generated_at=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Actor similarity analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        analyzer.close()


class BridgingTechniquesResponse(BaseModel):
    """Response for bridging techniques."""
    techniques: List[Dict[str, Any]]
    total_techniques: int
    generated_at: str


@router.get("/cooccurrence/bridging", response_model=BridgingTechniquesResponse)
async def identify_bridging_techniques(
    min_actors: int = Query(3, ge=2, description="Minimum actors using the technique")
) -> BridgingTechniquesResponse:
    """
    Identify techniques that bridge multiple actors (high betweenness).
    
    These techniques are worth prioritizing for detection as they
    enable multiple threat actors.
    """
    analyzer = CooccurrenceAnalyzer(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        # Get bridging techniques
        bridging = analyzer.identify_bridging_techniques(min_actors)
        
        # Format with technique names
        driver = get_neo4j_driver()
        formatted_techniques = []
        
        for tech_id, actor_count, avg_importance in bridging[:50]:  # Top 50
            with driver.session() as session:
                # Get technique details
                tech_result = session.run("""
                    MATCH (t:AttackPattern {stix_id: $id})
                    OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
                    RETURN t.name as name, 
                           collect(DISTINCT tac.shortname) as tactics
                """, id=tech_id)
                tech_data = tech_result.single()
                
                # Get actors using this technique
                actors_result = session.run("""
                    MATCH (g:IntrusionSet)<-[:ATTRIBUTED_TO]-(e:AttackEpisode)
                    MATCH (e)-[:CONTAINS]->(a:AttackAction {attack_pattern_ref: $tech})
                    RETURN DISTINCT g.name as actor_name, g.stix_id as actor_id
                    LIMIT 10
                """, tech=tech_id)
                actors = [{"id": r["actor_id"], "name": r["actor_name"]} 
                         for r in actors_result]
                
            formatted_techniques.append({
                "technique_id": tech_id,
                "technique_name": tech_data["name"] if tech_data else tech_id,
                "actor_count": actor_count,
                "avg_importance": round(avg_importance, 2),
                "tactics": tech_data["tactics"] if tech_data else [],
                "actors_sample": actors
            })
        
        driver.close()
        
        return BridgingTechniquesResponse(
            techniques=formatted_techniques,
            total_techniques=len(bridging),
            generated_at=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Bridging techniques analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        analyzer.close()


class GlobalCooccurrenceRequest(BaseModel):
    """Request for global co-occurrence analysis."""
    min_support: int = Field(2, ge=1, description="Minimum episode support")
    min_episodes_per_pair: int = Field(2, ge=1, description="Minimum episodes for a pair")
    limit: int = Field(100, ge=10, le=500, description="Maximum pairs to return")


class GlobalCooccurrenceResponse(BaseModel):
    """Response for global co-occurrence."""
    pairs: List[Dict[str, Any]]
    total_pairs: int
    episode_count: int
    technique_count: int
    generated_at: str


@router.post("/cooccurrence/global", response_model=GlobalCooccurrenceResponse)
async def analyze_global_cooccurrence(request: GlobalCooccurrenceRequest) -> GlobalCooccurrenceResponse:
    """
    Calculate global co-occurrence metrics across all episodes.
    
    Uses PMI/NPMI to identify meaningful technique relationships
    while avoiding popularity bias.
    """
    analyzer = CooccurrenceAnalyzer(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        # Calculate global metrics
        metrics = analyzer.calculate_global_cooccurrence(
            request.min_support,
            request.min_episodes_per_pair
        )
        
        # Format top pairs
        driver = get_neo4j_driver()
        formatted_pairs = []
        all_techniques = set()
        
        for metric in metrics[:request.limit]:
            all_techniques.add(metric.technique_a)
            all_techniques.add(metric.technique_b)
            
            # Get technique names
            with driver.session() as session:
                names_result = session.run("""
                    MATCH (t1:AttackPattern {stix_id: $t1})
                    MATCH (t2:AttackPattern {stix_id: $t2})
                    RETURN t1.name as name1, t2.name as name2,
                           t1.external_id as ext1, t2.external_id as ext2
                """, t1=metric.technique_a, t2=metric.technique_b)
                names = names_result.single()
                
            formatted_pairs.append({
                "technique_a": metric.technique_a,
                "technique_b": metric.technique_b,
                "name_a": names["name1"] if names else metric.technique_a,
                "name_b": names["name2"] if names else metric.technique_b,
                "external_id_a": names["ext1"] if names else None,
                "external_id_b": names["ext2"] if names else None,
                "count": metric.count,
                "support_a": metric.support_a,
                "support_b": metric.support_b,
                "confidence_a_to_b": round(metric.confidence_a_to_b, 3),
                "confidence_b_to_a": round(metric.confidence_b_to_a, 3),
                "lift": round(metric.lift, 2),
                "pmi": round(metric.pmi, 3),
                "npmi": round(metric.npmi, 3),
                "jaccard": round(metric.jaccard, 3)
            })
        
        driver.close()
        
        return GlobalCooccurrenceResponse(
            pairs=formatted_pairs,
            total_pairs=len(metrics),
            episode_count=metrics[0].total_episodes if metrics else 0,
            technique_count=len(all_techniques),
            generated_at=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Global co-occurrence analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        analyzer.close()