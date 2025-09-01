"""PTG-based simulation API endpoints for Epic 3."""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field
from neo4j import Session

from ....simulation.ptg_rollout import (
    PTGRolloutSimulator, 
    RolloutConfig, 
    RolloutResult
)
from ....simulation.mdp_solver import (
    MDPAttackerPolicy,
    MDPConfig,
    MDPPolicy,
    MitigationTransform
)
from ....config import get_settings
from ..deps import get_neo4j_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/simulate", tags=["simulate"])

# Get settings
settings = get_settings()


class RolloutRequest(BaseModel):
    """Request for PTG-based Monte Carlo rollout simulation."""
    model_id: str = Field(..., description="PTG model ID to use for simulation")
    starting_techniques: List[str] = Field(..., description="Starting technique STIX IDs")
    terminal_techniques: Optional[List[str]] = Field(None, description="Goal technique STIX IDs")
    terminal_tactics: Optional[List[str]] = Field(None, description="Goal tactics (e.g., 'impact', 'exfiltration')")
    num_rollouts: int = Field(5000, ge=100, le=50000, description="Number of Monte Carlo rollouts")
    max_depth: int = Field(8, ge=1, le=20, description="Maximum path depth")
    convergence_threshold: float = Field(0.02, description="Convergence threshold for success probability")
    convergence_window: int = Field(100, description="Window size for convergence check")


class RolloutResponse(BaseModel):
    """Response from PTG rollout simulation."""
    model_id: str
    success_probability: float
    converged: bool
    convergence_iteration: Optional[int]
    total_rollouts: int
    successful_rollouts: int
    average_path_length: float
    path_distribution: Dict[str, int]  # Top paths and their frequencies
    terminal_reached: Dict[str, int]  # Which terminals were reached
    statistics: Dict[str, Any]
    created_at: str


class MDPRequest(BaseModel):
    """Request for MDP attacker policy computation."""
    model_id: str = Field(..., description="PTG model ID to use")
    goal_techniques: List[str] = Field(..., description="Goal technique STIX IDs")
    goal_rewards: Optional[Dict[str, float]] = Field(None, description="Custom rewards for goals")
    discount_factor: float = Field(0.9, ge=0.0, le=1.0, description="MDP discount factor")
    convergence_threshold: float = Field(0.001, description="Value iteration convergence threshold")
    max_iterations: int = Field(1000, ge=10, le=10000, description="Max value iterations")
    mitigation_type: Optional[str] = Field(None, description="Mitigation type: 'remove_nodes', 'penalize_edges', 'block_paths'")
    mitigation_targets: Optional[List[str]] = Field(None, description="Technique IDs to mitigate")
    mitigation_penalty: float = Field(0.5, ge=0.0, le=1.0, description="Penalty factor for mitigated techniques")


class MDPResponse(BaseModel):
    """Response from MDP policy computation."""
    model_id: str
    policy_id: str
    converged: bool
    iterations: int
    goal_techniques: List[str]
    optimal_actions: Dict[str, str]  # state -> best action
    value_function: Dict[str, float]  # state -> expected value
    expected_reward: float
    mitigation_applied: bool
    mitigation_impact: Optional[Dict[str, Any]]
    statistics: Dict[str, Any]
    created_at: str


@router.post("/rollout", response_model=RolloutResponse)
async def simulate_rollout(
    request: RolloutRequest,
    neo4j_session: Session = Depends(get_neo4j_session)
) -> RolloutResponse:
    """
    Run Monte Carlo rollout simulation using PTG transition probabilities.
    
    This endpoint:
    - Loads the specified PTG model from Neo4j
    - Runs Monte Carlo simulations starting from given techniques
    - Computes success probability of reaching terminal states
    - Tracks path distribution and convergence metrics
    
    Acceptance: A5 - Results stable within ±2% with n≥5k rollouts
    """
    try:
        # Initialize simulator
        simulator = PTGRolloutSimulator(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Configure rollout
        config = RolloutConfig(
            num_rollouts=request.num_rollouts,
            max_depth=request.max_depth,
            terminal_techniques=request.terminal_techniques,
            terminal_tactics=request.terminal_tactics,
            convergence_threshold=request.convergence_threshold,
            convergence_window=request.convergence_window
        )
        
        # Run simulation
        result: RolloutResult = simulator.simulate_rollouts(
            model_id=request.model_id,
            starting_techniques=request.starting_techniques,
            config=config
        )
        
        # Get top paths (limit to top 20 for response)
        top_paths = {}
        for path_tuple, count in result.path_counts.most_common(20):
            path_str = " -> ".join(path_tuple[:5])  # Show first 5 steps
            if len(path_tuple) > 5:
                path_str += f" ... ({len(path_tuple)} steps)"
            top_paths[path_str] = count
        
        # Build response
        return RolloutResponse(
            model_id=request.model_id,
            success_probability=result.success_probability,
            converged=result.converged,
            convergence_iteration=result.convergence_iteration,
            total_rollouts=result.total_rollouts,
            successful_rollouts=result.successful_rollouts,
            average_path_length=result.average_path_length,
            path_distribution=top_paths,
            terminal_reached=result.terminals_reached,
            statistics={
                "variance": result.statistics.get("variance", 0.0),
                "std_dev": result.statistics.get("std_dev", 0.0),
                "confidence_95": result.statistics.get("confidence_95", [0.0, 1.0]),
                "runtime_seconds": result.statistics.get("runtime_seconds", 0.0)
            },
            created_at=datetime.utcnow().isoformat()
        )
        
    except ValueError as e:
        logger.error(f"Rollout validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Rollout simulation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        simulator.close()


@router.post("/mdp", response_model=MDPResponse)
async def compute_mdp_policy(
    request: MDPRequest,
    neo4j_session: Session = Depends(get_neo4j_session)
) -> MDPResponse:
    """
    Compute optimal attacker policy using MDP value iteration.
    
    This endpoint:
    - Loads the PTG model and converts to MDP
    - Runs value iteration to find optimal policy
    - Optionally applies mitigation transforms
    - Returns policy mapping and value function
    
    Acceptance: A6 - Mitigation reduces success probability
    """
    try:
        # Initialize MDP solver
        mdp_solver = MDPAttackerPolicy(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Configure MDP
        config = MDPConfig(
            discount_factor=request.discount_factor,
            convergence_threshold=request.convergence_threshold,
            max_iterations=request.max_iterations,
            goal_rewards=request.goal_rewards or {tech: 100.0 for tech in request.goal_techniques}
        )
        
        # Create mitigation transform if requested
        mitigation = None
        if request.mitigation_type and request.mitigation_targets:
            mitigation = MitigationTransform(
                mitigation_type=request.mitigation_type,
                target_techniques=request.mitigation_targets,
                penalty_factor=request.mitigation_penalty
            )
        
        # Compute policy
        policy: MDPPolicy = mdp_solver.compute_policy(
            model_id=request.model_id,
            config=config,
            mitigation=mitigation
        )
        
        # Extract optimal actions (limit to non-zero value states)
        optimal_actions = {}
        value_function = {}
        for state, action in policy.policy.items():
            if policy.value_function.get(state, 0.0) > 0.01:  # Only include valuable states
                optimal_actions[state] = action
                value_function[state] = round(policy.value_function[state], 3)
        
        # Calculate expected reward from starting states
        starting_values = [
            policy.value_function.get(tech, 0.0) 
            for tech in request.goal_techniques
            if tech in policy.value_function
        ]
        expected_reward = max(starting_values) if starting_values else 0.0
        
        # Mitigation impact analysis
        mitigation_impact = None
        if mitigation and policy.statistics.get("mitigation_applied"):
            # Compare with baseline if available
            baseline_policy = mdp_solver.compute_policy(
                model_id=request.model_id,
                config=config,
                mitigation=None
            )
            
            baseline_reward = max([
                baseline_policy.value_function.get(tech, 0.0)
                for tech in request.goal_techniques
            ], default=0.0)
            
            mitigation_impact = {
                "baseline_reward": round(baseline_reward, 3),
                "mitigated_reward": round(expected_reward, 3),
                "reduction_percent": round((1 - expected_reward/baseline_reward) * 100, 1) if baseline_reward > 0 else 0,
                "affected_states": len(request.mitigation_targets or []),
                "policy_changes": sum(
                    1 for s in policy.policy 
                    if s in baseline_policy.policy and policy.policy[s] != baseline_policy.policy[s]
                )
            }
        
        return MDPResponse(
            model_id=request.model_id,
            policy_id=f"mdp-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            converged=policy.converged,
            iterations=policy.iterations,
            goal_techniques=request.goal_techniques,
            optimal_actions=optimal_actions,
            value_function=value_function,
            expected_reward=round(expected_reward, 3),
            mitigation_applied=mitigation is not None,
            mitigation_impact=mitigation_impact,
            statistics={
                "total_states": len(policy.policy),
                "valuable_states": len(optimal_actions),
                "convergence_delta": policy.statistics.get("convergence_delta", 0.0),
                "runtime_seconds": policy.statistics.get("runtime_seconds", 0.0)
            },
            created_at=datetime.utcnow().isoformat()
        )
        
    except ValueError as e:
        logger.error(f"MDP validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"MDP policy computation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        mdp_solver.close()


@router.get("/models")
async def list_ptg_models(
    scope: Optional[str] = Query(None, description="Filter by scope (e.g., 'global' or intrusion-set ID)"),
    limit: int = Query(10, ge=1, le=50, description="Maximum models to return"),
    neo4j_session: Session = Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """
    List available PTG models for simulation.
    
    Returns models with their metadata and basic statistics.
    """
    try:
        # Query for PTG models
        query = """
            MATCH (m:PTGModel)
            WHERE $scope IS NULL OR m.scope = $scope
            RETURN m.model_id as model_id,
                   m.scope as scope,
                   m.created_at as created_at,
                   m.total_nodes as total_nodes,
                   m.total_edges as total_edges,
                   m.parameters as parameters
            ORDER BY m.created_at DESC
            LIMIT $limit
        """
        
        result = neo4j_session.run(query, scope=scope, limit=limit)
        
        models = []
        for record in result:
            models.append({
                "model_id": record["model_id"],
                "scope": record["scope"],
                "created_at": record["created_at"],
                "total_nodes": record["total_nodes"],
                "total_edges": record["total_edges"],
                "parameters": record["parameters"]
            })
        
        return {
            "models": models,
            "count": len(models),
            "filter": {"scope": scope} if scope else None
        }
        
    except Exception as e:
        logger.error(f"Failed to list PTG models: {e}")
        raise HTTPException(status_code=500, detail=str(e))