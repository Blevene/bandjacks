"""D3FEND defense overlay and recommendations API endpoints."""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from bandjacks.services.api.deps import get_neo4j_session
from bandjacks.services.api.settings import settings
from bandjacks.loaders.d3fend_loader import D3FENDLoader


router = APIRouter(prefix="/defense", tags=["defense"])


class DefenseTechnique(BaseModel):
    """D3FEND defensive technique."""
    technique_id: str = Field(..., description="D3FEND technique ID")
    name: str = Field(..., description="Technique name")
    description: str = Field(..., description="Technique description")
    category: str = Field(..., description="Defense category")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    artifacts: List[str] = Field(default_factory=list, description="Digital artifacts")
    via_mitigation: Optional[str] = Field(None, description="ATT&CK mitigation link")


class FlowDefenseOverlay(BaseModel):
    """Defense overlay for an attack flow."""
    flow_id: str = Field(..., description="Attack flow ID")
    total_actions: int = Field(..., description="Total attack actions in flow")
    defended_actions: int = Field(..., description="Actions with defenses")
    coverage_percentage: float = Field(..., description="Defense coverage percentage")
    defenses_by_action: List[Dict[str, Any]] = Field(..., description="Defenses per action")


class MinimalCutRequest(BaseModel):
    """Request for minimal defense set computation."""
    flow_id: str = Field(..., description="Attack flow ID")
    budget: Optional[int] = Field(None, ge=1, le=50, description="Max defense techniques")
    

class MinimalCutResponse(BaseModel):
    """Minimal defense set recommendations."""
    flow_id: str = Field(..., description="Attack flow ID")
    total_attack_techniques: int = Field(..., description="Total techniques in flow")
    covered_techniques: int = Field(..., description="Techniques covered by defenses")
    coverage_percentage: float = Field(..., description="Coverage percentage")
    uncovered_techniques: List[str] = Field(..., description="Uncovered technique IDs")
    recommendations: List[Dict[str, Any]] = Field(..., description="Recommended defenses")
    defense_count: int = Field(..., description="Number of defenses recommended")
    expected_impact: Dict[str, Any] = Field(..., description="Expected impact assessment")


@router.get("/overlay/{flow_id}",
    response_model=FlowDefenseOverlay,
    summary="Get Defense Overlay",
    description="""
    Get D3FEND defensive techniques for each action in an attack flow.
    
    For each AttackAction in the flow, returns mapped D3FEND techniques,
    rationale, and candidate digital artifacts for implementation.
    """,
    responses={
        200: {"description": "Defense overlay retrieved"},
        404: {"description": "Flow not found"},
        500: {"description": "Internal server error"}
    }
)
async def get_defense_overlay(
    flow_id: str,
    neo4j_session=Depends(get_neo4j_session)
) -> FlowDefenseOverlay:
    """Get D3FEND defense overlay for an attack flow."""
    
    try:
        # Initialize D3FEND loader
        loader = D3FENDLoader(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Get all attack actions in the flow
        actions_query = """
            MATCH (e:AttackEpisode {flow_id: $flow_id})-[:CONTAINS]->(a:AttackAction)
            OPTIONAL MATCH (a)-[:OF_TECHNIQUE]->(t:AttackPattern)
            RETURN a.action_id as action_id,
                   a.order as order,
                   a.attack_pattern_ref as technique_ref,
                   t.name as technique_name,
                   a.confidence as confidence
            ORDER BY a.order
        """
        
        actions_result = neo4j_session.run(actions_query, flow_id=flow_id)
        actions = list(actions_result)
        
        if not actions:
            raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found")
        
        # Get defenses for each action
        defenses_by_action = []
        defended_count = 0
        
        for action in actions:
            technique_ref = action["technique_ref"]
            
            # Get D3FEND techniques for this attack pattern
            defenses = loader.get_defense_techniques_for_attack(technique_ref)
            
            if defenses:
                defended_count += 1
            
            defenses_by_action.append({
                "action_id": action["action_id"],
                "order": action["order"],
                "attack_technique": {
                    "id": technique_ref,
                    "name": action["technique_name"] or "Unknown"
                },
                "defenses": defenses,
                "defense_count": len(defenses)
            })
        
        # Calculate coverage
        total_actions = len(actions)
        coverage_percentage = (defended_count / total_actions * 100) if total_actions > 0 else 0
        
        loader.close()
        
        return FlowDefenseOverlay(
            flow_id=flow_id,
            total_actions=total_actions,
            defended_actions=defended_count,
            coverage_percentage=round(coverage_percentage, 2),
            defenses_by_action=defenses_by_action
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get defense overlay: {str(e)}")


@router.post("/mincut",
    response_model=MinimalCutResponse,
    summary="Compute Minimal Defense Set",
    description="""
    Compute the minimal set of D3FEND techniques that maximizes defense coverage.
    
    Uses a greedy algorithm to select defensive techniques that cover the most
    attack techniques in the flow, optionally constrained by a budget.
    """,
    responses={
        200: {"description": "Minimal defense set computed"},
        404: {"description": "Flow not found"},
        500: {"description": "Internal server error"}
    }
)
async def compute_minimal_defense(
    request: MinimalCutRequest,
    neo4j_session=Depends(get_neo4j_session)
) -> MinimalCutResponse:
    """Compute minimal defense set for an attack flow."""
    
    try:
        # Initialize D3FEND loader
        loader = D3FENDLoader(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Compute minimal defense set
        result = loader.compute_minimal_defense_set(
            flow_id=request.flow_id,
            budget=request.budget
        )
        
        loader.close()
        
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        
        return MinimalCutResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to compute minimal defense: {str(e)}")


@router.post("/initialize",
    summary="Initialize D3FEND Data",
    description="""
    Initialize D3FEND ontology data in Neo4j.
    
    This endpoint loads the D3FEND ontology, creates technique and artifact nodes,
    and establishes COUNTERS relationships with ATT&CK techniques.
    
    This is typically run once during system setup.
    """,
    responses={
        200: {"description": "D3FEND initialized successfully"},
        500: {"description": "Initialization failed"}
    }
)
async def initialize_d3fend(
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """Initialize D3FEND ontology in the system."""
    
    try:
        # Initialize D3FEND loader
        loader = D3FENDLoader(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Run initialization
        result = loader.initialize()
        
        loader.close()
        
        if not result["success"]:
            raise HTTPException(status_code=500, detail=result.get("error", "Initialization failed"))
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"D3FEND initialization failed: {str(e)}")


@router.get("/techniques",
    summary="List D3FEND Techniques",
    description="""
    List all D3FEND defensive techniques in the system.
    
    Optionally filter by category or search by name.
    """,
    responses={
        200: {"description": "List of D3FEND techniques"},
        500: {"description": "Internal server error"}
    }
)
async def list_d3fend_techniques(
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search in name/description"),
    limit: int = Query(50, ge=1, le=200, description="Maximum results"),
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """List D3FEND techniques with optional filtering."""
    
    try:
        # Build query
        where_clauses = []
        params = {"limit": limit}
        
        if category:
            where_clauses.append("d.category = $category")
            params["category"] = category
        
        if search:
            where_clauses.append("(d.name CONTAINS $search OR d.description CONTAINS $search)")
            params["search"] = search
        
        where_clause = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        query = f"""
            MATCH (d:D3fendTechnique)
            {where_clause}
            OPTIONAL MATCH (d)-[:COUNTERS]->(t:AttackPattern)
            OPTIONAL MATCH (d)-[:PRODUCES]->(a:DigitalArtifact)
            RETURN d.d3fend_id as technique_id,
                   d.name as name,
                   d.description as description,
                   d.category as category,
                   count(DISTINCT t) as counters_count,
                   collect(DISTINCT a.name)[..5] as sample_artifacts
            ORDER BY d.name
            LIMIT $limit
        """
        
        result = neo4j_session.run(query, **params)
        
        techniques = []
        for record in result:
            techniques.append({
                "technique_id": record["technique_id"],
                "name": record["name"],
                "description": record["description"],
                "category": record["category"],
                "counters_count": record["counters_count"],
                "sample_artifacts": record["sample_artifacts"]
            })
        
        return {
            "techniques": techniques,
            "count": len(techniques),
            "filters": {
                "category": category,
                "search": search
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list techniques: {str(e)}")


@router.get("/coverage/{attack_pattern_id}",
    summary="Get Defense Coverage",
    description="""
    Get defense coverage analysis for a specific ATT&CK technique.
    
    Returns all D3FEND techniques that counter the given attack pattern,
    along with confidence scores and implementation artifacts.
    """,
    responses={
        200: {"description": "Defense coverage analysis"},
        404: {"description": "Attack pattern not found"},
        500: {"description": "Internal server error"}
    }
)
async def get_defense_coverage(
    attack_pattern_id: str,
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """Get defense coverage for a specific attack pattern."""
    
    try:
        # Initialize D3FEND loader
        loader = D3FENDLoader(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Get attack pattern details
        pattern_query = """
            MATCH (t:AttackPattern {stix_id: $attack_id})
            RETURN t.name as name,
                   t.description as description,
                   t.x_mitre_platforms as platforms
        """
        
        pattern_result = neo4j_session.run(
            pattern_query,
            attack_id=attack_pattern_id
        ).single()
        
        if not pattern_result:
            raise HTTPException(
                status_code=404,
                detail=f"Attack pattern {attack_pattern_id} not found"
            )
        
        # Get defenses
        defenses = loader.get_defense_techniques_for_attack(attack_pattern_id)
        
        loader.close()
        
        # Categorize defenses
        defense_categories = {}
        for defense in defenses:
            category = defense["category"]
            if category not in defense_categories:
                defense_categories[category] = []
            defense_categories[category].append(defense)
        
        return {
            "attack_pattern": {
                "id": attack_pattern_id,
                "name": pattern_result["name"],
                "description": pattern_result["description"][:200] + "..." 
                          if len(pattern_result["description"]) > 200 
                          else pattern_result["description"],
                "platforms": pattern_result["platforms"]
            },
            "defense_count": len(defenses),
            "has_coverage": len(defenses) > 0,
            "defenses": defenses,
            "defenses_by_category": defense_categories,
            "coverage_strength": "high" if len(defenses) >= 3 else "medium" if len(defenses) >= 1 else "low"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get defense coverage: {str(e)}")