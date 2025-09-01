"""Graph analysis and choke point API endpoints for Epic 3."""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field
from neo4j import Session

from ....analysis.graph_analyzer import (
    GraphAnalyzer,
    ChokePointAnalysis
)
from ....analysis.interdiction import (
    InterdictionPlanner,
    InterdictionPlan
)
from ....config import get_settings
from ..deps import get_neo4j_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyze", tags=["analyze"])

# Get settings
settings = get_settings()


class ChokePointRequest(BaseModel):
    """Request for choke point analysis."""
    model_id: str = Field(..., description="PTG model ID to analyze")
    source_techniques: Optional[List[str]] = Field(None, description="Source technique STIX IDs")
    target_techniques: Optional[List[str]] = Field(None, description="Target technique STIX IDs")
    analysis_types: List[str] = Field(
        ["betweenness", "dominators", "mincut"],
        description="Types of analysis: betweenness, dominators, mincut, all"
    )
    k_paths: int = Field(50, ge=10, le=500, description="Number of paths for analysis")
    top_n: int = Field(10, ge=5, le=50, description="Top N choke points to return")


class ChokePointResponse(BaseModel):
    """Response from choke point analysis."""
    model_id: str
    analysis_id: str
    source_techniques: List[str]
    target_techniques: List[str]
    betweenness_centrality: Optional[Dict[str, float]]
    edge_betweenness: Optional[Dict[str, float]]
    dominator_nodes: Optional[List[str]]
    min_cut_nodes: Optional[List[str]]
    min_cut_edges: Optional[List[List[str]]]
    top_choke_points: List[Dict[str, Any]]
    statistics: Dict[str, Any]
    created_at: str


class InterdictionRequest(BaseModel):
    """Request for interdiction planning."""
    model_id: str = Field(..., description="PTG model ID")
    choke_points: List[str] = Field(..., description="Candidate techniques for interdiction")
    budget: int = Field(5, ge=1, le=20, description="Maximum techniques to interdict")
    strategy: str = Field(
        "optimal",
        description="Strategy: greedy, optimal, balanced, coverage"
    )
    source_techniques: Optional[List[str]] = Field(None, description="Attacker starting points")
    target_techniques: Optional[List[str]] = Field(None, description="Assets to protect")
    cost_model: Optional[Dict[str, float]] = Field(None, description="Custom costs per technique")


class InterdictionResponse(BaseModel):
    """Response from interdiction planning."""
    model_id: str
    plan_id: str
    selected_techniques: List[str]
    total_cost: float
    expected_impact: float
    coverage_percent: float
    blocked_paths: int
    strategy_used: str
    alternatives: List[Dict[str, Any]]
    recommendations: List[str]
    created_at: str


@router.post("/chokepoints", response_model=ChokePointResponse)
async def analyze_choke_points(
    request: ChokePointRequest,
    neo4j_session: Session = Depends(get_neo4j_session)
) -> ChokePointResponse:
    """
    Analyze choke points in attack graph using multiple algorithms.
    
    This endpoint:
    - Computes betweenness centrality to find critical nodes/edges
    - Identifies dominator nodes that must be traversed
    - Finds minimum cut sets that disconnect sources from targets
    - Returns top choke points for defensive focus
    
    Acceptance: A7 - Returns non-empty valid results on graphs
    """
    try:
        # Initialize analyzer
        analyzer = GraphAnalyzer(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Determine analysis types
        analysis_set = set(request.analysis_types)
        if "all" in analysis_set:
            analysis_set = {"betweenness", "dominators", "mincut"}
        
        # Run analysis
        analysis: ChokePointAnalysis = analyzer.analyze_choke_points(
            model_id=request.model_id,
            source_techniques=request.source_techniques,
            target_techniques=request.target_techniques,
            k_paths=request.k_paths,
            top_n=request.top_n
        )
        
        # Format response based on requested analyses
        response_data = {
            "model_id": request.model_id,
            "analysis_id": f"analysis-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "source_techniques": analysis.source_techniques,
            "target_techniques": analysis.target_techniques,
            "statistics": {
                "graph_nodes": analysis.graph_size["nodes"],
                "graph_edges": analysis.graph_size["edges"],
                "paths_analyzed": analysis.paths_analyzed,
                "runtime_seconds": analysis.runtime_seconds
            },
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Add betweenness if requested
        if "betweenness" in analysis_set:
            # Top N nodes by betweenness
            top_nodes = dict(sorted(
                analysis.betweenness_centrality.items(),
                key=lambda x: x[1],
                reverse=True
            )[:request.top_n])
            response_data["betweenness_centrality"] = top_nodes
            
            # Top N edges by betweenness
            if analysis.edge_betweenness:
                top_edges = {}
                for (u, v), score in sorted(
                    analysis.edge_betweenness.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:request.top_n]:
                    edge_key = f"{u} -> {v}"
                    top_edges[edge_key] = score
                response_data["edge_betweenness"] = top_edges
        
        # Add dominators if requested
        if "dominators" in analysis_set:
            response_data["dominator_nodes"] = analysis.dominator_nodes[:request.top_n]
        
        # Add min-cut if requested
        if "mincut" in analysis_set:
            response_data["min_cut_nodes"] = analysis.min_cut_nodes[:request.top_n]
            response_data["min_cut_edges"] = analysis.min_cut_edges[:request.top_n]
        
        # Compile top choke points from all analyses
        choke_point_scores = {}
        
        # Score from betweenness
        if analysis.betweenness_centrality:
            max_between = max(analysis.betweenness_centrality.values(), default=1.0)
            for node, score in analysis.betweenness_centrality.items():
                choke_point_scores[node] = choke_point_scores.get(node, 0) + (score / max_between)
        
        # Score from being a dominator
        for node in analysis.dominator_nodes:
            choke_point_scores[node] = choke_point_scores.get(node, 0) + 1.0
        
        # Score from being in min-cut
        for node in analysis.min_cut_nodes:
            choke_point_scores[node] = choke_point_scores.get(node, 0) + 0.8
        
        # Get top choke points with details
        top_choke_points = []
        for tech_id, score in sorted(
            choke_point_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )[:request.top_n]:
            choke_point = {
                "technique_id": tech_id,
                "score": round(score, 3),
                "is_dominator": tech_id in analysis.dominator_nodes,
                "is_min_cut": tech_id in analysis.min_cut_nodes,
                "betweenness": round(analysis.betweenness_centrality.get(tech_id, 0.0), 3)
            }
            
            # Get technique name from Neo4j
            name_query = """
                MATCH (t:AttackPattern {stix_id: $tech_id})
                RETURN t.name as name
            """
            result = neo4j_session.run(name_query, tech_id=tech_id).single()
            if result:
                choke_point["technique_name"] = result["name"]
            
            top_choke_points.append(choke_point)
        
        response_data["top_choke_points"] = top_choke_points
        
        return ChokePointResponse(**response_data)
        
    except ValueError as e:
        logger.error(f"Analysis validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Choke point analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        analyzer.close()


@router.post("/interdiction", response_model=InterdictionResponse)
async def plan_interdiction(
    request: InterdictionRequest,
    neo4j_session: Session = Depends(get_neo4j_session)
) -> InterdictionResponse:
    """
    Plan optimal interdiction strategy for defense.
    
    This endpoint:
    - Takes choke point candidates and budget constraints
    - Computes optimal selection using specified strategy
    - Returns interdiction plan with expected impact
    - Provides alternative strategies for comparison
    
    Acceptance: Supports Epic 3 T22 - Budgeted interdiction
    """
    try:
        # Initialize planner
        planner = InterdictionPlanner(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Map strategy string to internal values
        # Note: The InterdictionPlanner will handle strategy internally
        strategy = request.strategy.lower()
        
        # Plan interdiction
        plan: InterdictionPlan = planner.plan_interdiction(
            model_id=request.model_id,
            candidate_techniques=request.choke_points,
            budget=request.budget,
            strategy=strategy,
            source_techniques=request.source_techniques,
            target_techniques=request.target_techniques,
            cost_model=request.cost_model
        )
        
        # Get alternative strategies for comparison
        alternatives = []
        strategy_options = ["greedy", "optimal", "balanced", "coverage"]
        for alt_strategy_name in strategy_options:
            if alt_strategy_name != strategy:
                try:
                    alt_plan = planner.plan_interdiction(
                        model_id=request.model_id,
                        candidate_techniques=request.choke_points,
                        budget=request.budget,
                        strategy=alt_strategy_name,
                        source_techniques=request.source_techniques,
                        target_techniques=request.target_techniques,
                        cost_model=request.cost_model
                    )
                    alternatives.append({
                        "strategy": alt_strategy_name,
                        "techniques": alt_plan.selected_techniques[:3],  # Show top 3
                        "impact": round(alt_plan.expected_impact, 3),
                        "coverage": round(alt_plan.coverage_percent, 1)
                    })
                except:
                    pass  # Skip if alternative fails
        
        # Extract technique IDs from selected nodes
        selected_techniques = [node.technique_id for node in plan.selected_nodes]
        
        # Check for critical techniques (if any nodes are marked as critical)
        critical_techniques = [
            node.technique_id for node in plan.selected_nodes 
            if node.is_dominator or node.criticality_score > 0.8
        ]
        
        # Build recommendations based on analysis
        recommendations = []
        
        if plan.coverage_percentage > 80:
            recommendations.append(
                f"High coverage ({plan.coverage_percentage:.0f}%) achieved with {len(plan.selected_nodes)} techniques"
            )
        elif plan.coverage_percentage < 50:
            recommendations.append(
                f"Low coverage ({plan.coverage_percentage:.0f}%) - consider increasing budget or focusing on different choke points"
            )
        
        if plan.expected_impact > 0.7:
            recommendations.append(
                "Strong expected impact - these interdictions significantly disrupt attack paths"
            )
        
        if len(critical_techniques) > 0:
            recommendations.append(
                f"Focus on critical techniques: {', '.join(critical_techniques[:3])}"
            )
        
        # Check if better alternative exists
        best_alt = max(alternatives, key=lambda x: x["impact"], default=None)
        if best_alt and best_alt["impact"] > plan.expected_impact * 1.2:
            recommendations.append(
                f"Consider {best_alt['strategy']} strategy for {((best_alt['impact']/plan.expected_impact - 1) * 100):.0f}% better impact"
            )
        
        return InterdictionResponse(
            model_id=request.model_id,
            plan_id=plan.plan_id,
            selected_techniques=selected_techniques,
            total_cost=plan.total_cost,
            expected_impact=round(plan.expected_impact, 3),
            coverage_percent=round(plan.coverage_percentage, 1),
            blocked_paths=plan.paths_blocked,
            strategy_used=request.strategy,
            alternatives=alternatives,
            recommendations=recommendations,
            created_at=plan.created_at.isoformat()
        )
        
    except ValueError as e:
        logger.error(f"Interdiction validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Interdiction planning failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        planner.close()


@router.get("/graphs/{model_id}/stats")
async def get_graph_statistics(
    model_id: str,
    neo4j_session: Session = Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """
    Get detailed statistics about a PTG model's graph structure.
    
    Returns metrics useful for understanding the graph's topology
    and potential choke points.
    """
    try:
        # Get basic stats
        stats_query = """
            MATCH (m:PTGModel {model_id: $model_id})
            OPTIONAL MATCH (m)-[:HAS_NODE]->(n:PTGNode)
            OPTIONAL MATCH (n)-[e:NEXT_P]->()
            WITH m, count(DISTINCT n) as node_count, count(e) as edge_count
            RETURN m.scope as scope,
                   m.created_at as created_at,
                   node_count,
                   edge_count,
                   CASE WHEN node_count > 0 
                        THEN toFloat(edge_count) / node_count 
                        ELSE 0 END as avg_degree
        """
        
        result = neo4j_session.run(stats_query, model_id=model_id).single()
        
        if not result:
            raise HTTPException(status_code=404, detail=f"Model {model_id} not found")
        
        # Get degree distribution
        degree_query = """
            MATCH (m:PTGModel {model_id: $model_id})-[:HAS_NODE]->(n:PTGNode)
            OPTIONAL MATCH (n)-[e:NEXT_P]->()
            WITH n, count(e) as out_degree
            RETURN out_degree, count(n) as frequency
            ORDER BY out_degree
        """
        
        degree_result = neo4j_session.run(degree_query, model_id=model_id)
        degree_dist = {record["out_degree"]: record["frequency"] for record in degree_result}
        
        # Get strongly connected components info
        scc_query = """
            MATCH (m:PTGModel {model_id: $model_id})-[:HAS_NODE]->(n:PTGNode)
            WITH collect(n) as nodes
            CALL gds.graph.project.cypher(
                'temp_graph',
                'MATCH (n:PTGNode) RETURN id(n) AS id',
                'MATCH (n:PTGNode)-[:NEXT_P]->(m:PTGNode) RETURN id(n) AS source, id(m) AS target'
            )
            YIELD graphName
            CALL gds.scc.stats('temp_graph')
            YIELD componentCount, componentDistribution
            CALL gds.graph.drop('temp_graph')
            RETURN componentCount, componentDistribution
        """
        
        # Try to get SCC info if GDS is available
        scc_info = None
        try:
            scc_result = neo4j_session.run(scc_query, model_id=model_id).single()
            if scc_result:
                scc_info = {
                    "component_count": scc_result["componentCount"],
                    "largest_component_size": scc_result["componentDistribution"].get("max", 0)
                }
        except:
            # GDS might not be available
            pass
        
        return {
            "model_id": model_id,
            "scope": result["scope"],
            "created_at": result["created_at"],
            "graph_metrics": {
                "nodes": result["node_count"],
                "edges": result["edge_count"],
                "average_degree": round(result["avg_degree"], 2),
                "degree_distribution": degree_dist,
                "density": round(
                    result["edge_count"] / (result["node_count"] * (result["node_count"] - 1))
                    if result["node_count"] > 1 else 0,
                    4
                )
            },
            "components": scc_info,
            "analysis_ready": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get graph statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))