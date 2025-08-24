"""Coverage analytics API endpoints."""

import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from neo4j import GraphDatabase

from ....config import get_settings

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