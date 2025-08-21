"""Attack simulation API endpoints."""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field

from ....simulation import AttackSimulator, SimulationConfig
from ....config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/simulation", tags=["simulation"])

# Get settings
settings = get_settings()


class SimulationRequest(BaseModel):
    """Request to run attack path simulation."""
    start_technique: Optional[str] = Field(None, description="Starting technique STIX ID")
    start_group: Optional[str] = Field(None, description="Starting threat group STIX ID")
    target_technique: Optional[str] = Field(None, description="Target technique to reach")
    target_objective: Optional[str] = Field(None, description="Target objective/tactic")
    max_depth: int = Field(5, ge=1, le=10, description="Maximum path depth")
    num_paths: int = Field(10, ge=1, le=100, description="Number of paths to simulate")
    method: str = Field("monte_carlo", description="Simulation method: monte_carlo or deterministic")
    include_probabilities: bool = Field(True, description="Include transition probabilities")


class SimulationPath(BaseModel):
    """A simulated attack path."""
    path_id: str
    steps: List[Dict[str, Any]]
    total_probability: float
    duration_estimate: Optional[str]
    complexity_score: float
    covered_tactics: List[str]


class SimulationResponse(BaseModel):
    """Response from attack simulation."""
    simulation_id: str
    request: SimulationRequest
    paths: List[SimulationPath]
    summary: Dict[str, Any]
    created_at: str


class PathPredictionRequest(BaseModel):
    """Request to predict next steps in an attack path."""
    current_techniques: List[str] = Field(..., description="Current technique STIX IDs in order")
    threat_group: Optional[str] = Field(None, description="Threat group context")
    max_predictions: int = Field(5, ge=1, le=20, description="Maximum predictions to return")
    include_rationale: bool = Field(True, description="Include rationale for predictions")


class PathPrediction(BaseModel):
    """A predicted next step in attack path."""
    technique_id: str
    technique_name: str
    probability: float
    tactic: str
    rationale: Optional[str]
    historical_frequency: Optional[float]


class PredictionResponse(BaseModel):
    """Response from path prediction."""
    current_state: List[str]
    predictions: List[PathPrediction]
    confidence: float
    analysis: Optional[str]


class WhatIfRequest(BaseModel):
    """Request for what-if analysis."""
    scenario: str = Field(..., description="Scenario description")
    constraints: Optional[Dict[str, Any]] = Field(None, description="Constraints on simulation")
    blocked_techniques: Optional[List[str]] = Field(None, description="Techniques to exclude")
    required_techniques: Optional[List[str]] = Field(None, description="Techniques that must be included")
    threat_model: Optional[str] = Field(None, description="Threat model to use")


class WhatIfResponse(BaseModel):
    """Response from what-if analysis."""
    scenario: str
    viable_paths: List[SimulationPath]
    blocked_impact: Optional[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]
    analysis: str


# Initialize simulator (singleton)
_simulator = None

def get_simulator() -> AttackSimulator:
    """Get or create simulator instance."""
    global _simulator
    if _simulator is None:
        _simulator = AttackSimulator(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
    return _simulator


@router.post("/paths", response_model=SimulationResponse)
async def simulate_attack_paths(
    request: SimulationRequest,
    simulator: AttackSimulator = Depends(get_simulator)
) -> SimulationResponse:
    """
    Simulate multiple attack paths from a starting point.
    
    This endpoint uses Monte Carlo simulation or deterministic graph traversal
    to generate plausible attack paths based on historical data and ATT&CK relationships.
    """
    try:
        # Configure simulation
        config = SimulationConfig(
            max_depth=request.max_depth,
            num_paths=request.num_paths,
            method=request.method,
            include_probabilities=request.include_probabilities
        )
        
        # Run simulation
        result = simulator.simulate_paths(
            start_technique=request.start_technique,
            start_group=request.start_group,
            target_technique=request.target_technique,
            config=config
        )
        
        # Transform result to response
        paths = []
        for path_data in result.get("paths", []):
            paths.append(SimulationPath(
                path_id=path_data["path_id"],
                steps=path_data["steps"],
                total_probability=path_data.get("probability", 1.0),
                duration_estimate=path_data.get("duration"),
                complexity_score=path_data.get("complexity", 0.5),
                covered_tactics=path_data.get("tactics", [])
            ))
        
        return SimulationResponse(
            simulation_id=result["simulation_id"],
            request=request,
            paths=paths,
            summary=result.get("summary", {}),
            created_at=datetime.utcnow().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Simulation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/predict", response_model=PredictionResponse)
async def predict_next_steps(
    request: PathPredictionRequest,
    simulator: AttackSimulator = Depends(get_simulator)
) -> PredictionResponse:
    """
    Predict likely next steps given current attack state.
    
    Uses historical patterns and graph analysis to predict what techniques
    an attacker is likely to use next.
    """
    try:
        # Get predictions from simulator
        predictions_data = simulator.predict_next_steps(
            current_techniques=request.current_techniques,
            threat_group=request.threat_group,
            max_predictions=request.max_predictions
        )
        
        # Transform to response
        predictions = []
        for pred in predictions_data.get("predictions", []):
            predictions.append(PathPrediction(
                technique_id=pred["technique_id"],
                technique_name=pred["name"],
                probability=pred["probability"],
                tactic=pred["tactic"],
                rationale=pred.get("rationale") if request.include_rationale else None,
                historical_frequency=pred.get("frequency")
            ))
        
        return PredictionResponse(
            current_state=request.current_techniques,
            predictions=predictions,
            confidence=predictions_data.get("confidence", 0.5),
            analysis=predictions_data.get("analysis")
        )
        
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/whatif", response_model=WhatIfResponse)
async def what_if_analysis(
    request: WhatIfRequest,
    simulator: AttackSimulator = Depends(get_simulator)
) -> WhatIfResponse:
    """
    Perform what-if analysis for defensive scenarios.
    
    Simulates attack paths under various constraints to understand the impact
    of defensive measures.
    """
    try:
        # Run what-if simulation
        analysis_result = simulator.what_if_analysis(
            scenario=request.scenario,
            blocked_techniques=request.blocked_techniques,
            required_techniques=request.required_techniques,
            constraints=request.constraints
        )
        
        # Transform paths
        viable_paths = []
        for path_data in analysis_result.get("viable_paths", []):
            viable_paths.append(SimulationPath(
                path_id=path_data["path_id"],
                steps=path_data["steps"],
                total_probability=path_data.get("probability", 1.0),
                duration_estimate=path_data.get("duration"),
                complexity_score=path_data.get("complexity", 0.5),
                covered_tactics=path_data.get("tactics", [])
            ))
        
        return WhatIfResponse(
            scenario=request.scenario,
            viable_paths=viable_paths,
            blocked_impact=analysis_result.get("blocked_impact"),
            recommendations=analysis_result.get("recommendations", []),
            analysis=analysis_result.get("analysis", "")
        )
        
    except Exception as e:
        logger.error(f"What-if analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics/{technique_id}")
async def get_technique_statistics(
    technique_id: str,
    simulator: AttackSimulator = Depends(get_simulator)
) -> Dict[str, Any]:
    """
    Get simulation statistics for a specific technique.
    
    Returns historical usage patterns, common sequences, and transition probabilities.
    """
    try:
        stats = simulator.get_technique_statistics(technique_id)
        
        if not stats:
            raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
        
        return stats
        
    except Exception as e:
        logger.error(f"Failed to get technique statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/groups/{group_id}/patterns")
async def get_group_patterns(
    group_id: str,
    limit: int = Query(10, ge=1, le=50),
    simulator: AttackSimulator = Depends(get_simulator)
) -> Dict[str, Any]:
    """
    Get attack patterns commonly used by a threat group.
    
    Analyzes historical data to identify common sequences and patterns
    used by the specified threat group.
    """
    try:
        patterns = simulator.get_group_patterns(group_id, limit=limit)
        
        if not patterns:
            raise HTTPException(status_code=404, detail=f"Group {group_id} not found")
        
        return patterns
        
    except Exception as e:
        logger.error(f"Failed to get group patterns: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/compare")
async def compare_paths(
    path_ids: List[str] = Query(..., description="Path IDs to compare"),
    simulator: AttackSimulator = Depends(get_simulator)
) -> Dict[str, Any]:
    """
    Compare multiple attack paths.
    
    Analyzes similarities and differences between paths, identifying
    common techniques, divergence points, and relative effectiveness.
    """
    try:
        if len(path_ids) < 2:
            raise HTTPException(status_code=400, detail="At least 2 paths required for comparison")
        
        comparison = simulator.compare_paths(path_ids)
        
        return comparison
        
    except Exception as e:
        logger.error(f"Path comparison failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))