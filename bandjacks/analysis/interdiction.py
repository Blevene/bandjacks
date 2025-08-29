"""Interdiction planning for defensive choke points."""

import logging
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
import heapq
from datetime import datetime
from neo4j import GraphDatabase

from ..simulation.ptg_rollout import PTGRolloutSimulator, RolloutConfig
from ..simulation.mdp_solver import MDPAttackerPolicy, MDPConfig, MitigationTransform
from .graph_analyzer import GraphAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class InterdictionNode:
    """A node that can be interdicted."""
    technique_id: str
    name: str
    criticality_score: float
    mitigation_cost: float = 1.0
    mitigation_effectiveness: float = 1.0  # 1.0 = complete block
    affected_paths: int = 0
    betweenness_centrality: float = 0.0
    is_dominator: bool = False
    is_articulation_point: bool = False


@dataclass
class InterdictionPlan:
    """A defensive interdiction plan."""
    plan_id: str
    model_id: str
    selected_nodes: List[InterdictionNode]
    total_cost: float
    expected_impact: float  # Reduction in attacker success probability
    paths_blocked: int
    coverage_percentage: float  # Percentage of attack paths affected
    efficiency_ratio: float  # Impact per unit cost
    parameters: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class InterdictionConfig:
    """Configuration for interdiction planning."""
    budget: float = 10.0  # Total mitigation budget
    min_effectiveness: float = 0.5  # Minimum required effectiveness
    strategy: str = "greedy"  # greedy, optimal, balanced
    consider_synergies: bool = True  # Consider combined effects
    max_nodes: int = 20  # Maximum nodes to consider
    weight_criticality: float = 0.4
    weight_betweenness: float = 0.3
    weight_dominator: float = 0.3


class InterdictionPlanner:
    """Plans optimal defensive interdictions at choke points."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize interdiction planner.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.graph_analyzer = GraphAnalyzer(neo4j_uri, neo4j_user, neo4j_password)
        self.rollout_sim = PTGRolloutSimulator(neo4j_uri, neo4j_user, neo4j_password)
        self.mdp_solver = MDPAttackerPolicy(neo4j_uri, neo4j_user, neo4j_password)
    
    def plan_interdiction(
        self,
        model_id: str,
        candidate_techniques: Optional[List[str]] = None,
        budget: Optional[int] = None,
        strategy: Optional[str] = None,
        source_techniques: Optional[List[str]] = None,
        target_techniques: Optional[List[str]] = None,
        cost_model: Optional[Dict[str, float]] = None,
        config: Optional[InterdictionConfig] = None
    ) -> InterdictionPlan:
        """
        Plan optimal interdiction strategy.
        
        Args:
            model_id: PTG model identifier
            candidate_techniques: Candidate techniques for interdiction
            budget: Maximum techniques to interdict
            strategy: Strategy to use (greedy, optimal, balanced, coverage)
            source_techniques: Attack starting points
            target_techniques: Attack goals
            cost_model: Custom costs per technique
            config: Interdiction configuration (overrides individual params)
            
        Returns:
            Interdiction plan
        """
        # Create config from parameters if not provided
        if config is None:
            config = InterdictionConfig(
                budget=float(budget) if budget is not None else 10.0,
                strategy=strategy if strategy is not None else "greedy"
            )
        
        # Ensure we have source and target techniques
        if source_techniques is None:
            source_techniques = []
        if target_techniques is None:
            target_techniques = []
        
        logger.info(f"Planning interdiction for model {model_id} with budget {config.budget}")
        
        # Analyze choke points
        choke_analysis = self.graph_analyzer.analyze_choke_points(
            model_id=model_id,
            source_techniques=source_techniques,
            target_techniques=target_techniques
        )
        
        # Build interdiction candidates
        if candidate_techniques:
            # If specific candidates provided, use those
            candidates = self._build_specific_candidates(
                candidate_techniques=candidate_techniques,
                choke_analysis=choke_analysis,
                cost_model=cost_model
            )
        else:
            # Otherwise, analyze from choke points
            candidates = self._build_interdiction_candidates(
                model_id=model_id,
                choke_analysis=choke_analysis,
                source_techniques=source_techniques,
                target_techniques=target_techniques,
                cost_model=cost_model
            )
        
        # Select interdiction nodes based on strategy
        if config.strategy == "greedy":
            selected = self._greedy_selection(candidates, config)
        elif config.strategy == "optimal":
            selected = self._optimal_selection(candidates, config)
        else:  # balanced
            selected = self._balanced_selection(candidates, config)
        
        # Evaluate impact
        impact_analysis = self._evaluate_interdiction_impact(
            model_id=model_id,
            selected_nodes=selected,
            source_techniques=source_techniques,
            target_techniques=target_techniques
        )
        
        # Calculate metrics
        total_cost = sum(node.mitigation_cost for node in selected)
        efficiency = impact_analysis["success_reduction"] / total_cost if total_cost > 0 else 0
        
        return InterdictionPlan(
            plan_id=f"interdict-{model_id[:8]}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            model_id=model_id,
            selected_nodes=selected,
            total_cost=total_cost,
            expected_impact=impact_analysis["success_reduction"],
            paths_blocked=impact_analysis["paths_blocked"],
            coverage_percentage=impact_analysis["coverage_percentage"],
            efficiency_ratio=efficiency,
            parameters={
                "budget": config.budget,
                "strategy": config.strategy,
                "source_techniques": source_techniques,
                "target_techniques": target_techniques,
                "candidates_considered": len(candidates)
            }
        )
    
    def _build_specific_candidates(
        self,
        candidate_techniques: List[str],
        choke_analysis: Any,
        cost_model: Optional[Dict[str, float]] = None
    ) -> List[InterdictionNode]:
        """
        Build interdiction candidates from specific technique list.
        
        Args:
            candidate_techniques: Specific techniques to consider
            choke_analysis: Choke point analysis results
            cost_model: Custom costs per technique
            
        Returns:
            List of interdiction candidates
        """
        candidates = []
        
        # Get default costs if not provided
        if cost_model is None:
            cost_model = self._get_mitigation_costs()
        
        for tech_id in candidate_techniques:
            # Get criticality from choke analysis if available
            criticality = choke_analysis.betweenness_centrality.get(tech_id, 0.5) * 10
            
            # Check if it's a dominator
            is_dominator = any(tech_id in doms for doms in choke_analysis.dominators.values())
            
            node = InterdictionNode(
                technique_id=tech_id,
                name=self._get_technique_name(tech_id),
                criticality_score=criticality,
                mitigation_cost=cost_model.get(tech_id, 1.0),
                mitigation_effectiveness=1.0,
                affected_paths=0,  # Will be calculated if needed
                betweenness_centrality=choke_analysis.betweenness_centrality.get(tech_id, 0),
                is_dominator=is_dominator,
                is_articulation_point=tech_id in choke_analysis.articulation_points
            )
            candidates.append(node)
        
        return sorted(candidates, key=lambda x: x.criticality_score, reverse=True)
    
    def _build_interdiction_candidates(
        self,
        model_id: str,
        choke_analysis: Any,
        source_techniques: List[str],
        target_techniques: List[str],
        cost_model: Optional[Dict[str, float]] = None
    ) -> List[InterdictionNode]:
        """
        Build list of interdiction candidates with scores.
        
        Args:
            model_id: PTG model identifier
            choke_analysis: Choke point analysis results
            source_techniques: Source nodes
            target_techniques: Target nodes
            
        Returns:
            List of interdiction candidates
        """
        candidates = []
        
        # Get mitigation costs from Neo4j
        if cost_model is None:
            mitigation_costs = self._get_mitigation_costs()
        else:
            mitigation_costs = cost_model
        
        # Analyze paths for coverage
        path_analysis = self.graph_analyzer.analyze_paths(
            model_id=model_id,
            source_set=set(source_techniques),
            target_set=set(target_techniques)
        )
        
        # Count path coverage per node
        path_coverage = defaultdict(int)
        for path in path_analysis.all_paths:
            for node in path:
                path_coverage[node] += 1
        
        # Build candidates from top choke points
        for tech_id, criticality_score in choke_analysis.top_choke_points:
            # Skip source/target nodes
            if tech_id in source_techniques or tech_id in target_techniques:
                continue
            
            node = InterdictionNode(
                technique_id=tech_id,
                name=self._get_technique_name(tech_id),
                criticality_score=criticality_score,
                mitigation_cost=mitigation_costs.get(tech_id, 1.0),
                mitigation_effectiveness=1.0,  # Can be refined based on mitigation type
                affected_paths=path_coverage.get(tech_id, 0),
                betweenness_centrality=choke_analysis.betweenness_centrality.get(tech_id, 0),
                is_dominator=any(tech_id in doms for doms in choke_analysis.dominators.values()),
                is_articulation_point=tech_id in choke_analysis.articulation_points
            )
            
            candidates.append(node)
        
        # Add other high-betweenness nodes if not already included
        for tech_id, centrality in choke_analysis.betweenness_centrality.items():
            if tech_id in source_techniques or tech_id in target_techniques:
                continue
            
            if not any(c.technique_id == tech_id for c in candidates):
                if centrality > 0.1:  # Threshold for consideration
                    node = InterdictionNode(
                        technique_id=tech_id,
                        name=self._get_technique_name(tech_id),
                        criticality_score=centrality * 5,  # Scale centrality to criticality
                        mitigation_cost=mitigation_costs.get(tech_id, 1.0),
                        mitigation_effectiveness=1.0,
                        affected_paths=path_coverage.get(tech_id, 0),
                        betweenness_centrality=centrality,
                        is_dominator=False,
                        is_articulation_point=tech_id in choke_analysis.articulation_points
                    )
                    candidates.append(node)
        
        # Sort by criticality score
        candidates.sort(key=lambda x: x.criticality_score, reverse=True)
        
        return candidates
    
    def _greedy_selection(
        self,
        candidates: List[InterdictionNode],
        config: InterdictionConfig
    ) -> List[InterdictionNode]:
        """
        Greedy selection of interdiction nodes.
        
        Args:
            candidates: Interdiction candidates
            config: Interdiction configuration
            
        Returns:
            Selected nodes
        """
        selected = []
        remaining_budget = config.budget
        
        for candidate in candidates:
            if len(selected) >= config.max_nodes:
                break
            
            if candidate.mitigation_cost <= remaining_budget:
                # Check effectiveness threshold
                if candidate.mitigation_effectiveness >= config.min_effectiveness:
                    selected.append(candidate)
                    remaining_budget -= candidate.mitigation_cost
        
        return selected
    
    def _optimal_selection(
        self,
        candidates: List[InterdictionNode],
        config: InterdictionConfig
    ) -> List[InterdictionNode]:
        """
        Optimal selection using dynamic programming (knapsack).
        
        Args:
            candidates: Interdiction candidates
            config: Interdiction configuration
            
        Returns:
            Selected nodes
        """
        # Simplified knapsack problem
        # In practice, would use more sophisticated optimization
        
        n = min(len(candidates), 20)  # Limit for computational feasibility
        candidates = candidates[:n]
        
        # Scale budget to integer for DP
        budget_scale = 10
        budget_int = int(config.budget * budget_scale)
        
        # DP table: dp[i][w] = max value using first i items with budget w
        dp = [[0.0 for _ in range(budget_int + 1)] for _ in range(n + 1)]
        
        for i in range(1, n + 1):
            candidate = candidates[i - 1]
            cost_int = int(candidate.mitigation_cost * budget_scale)
            value = candidate.criticality_score * candidate.mitigation_effectiveness
            
            for w in range(budget_int + 1):
                # Don't take item i
                dp[i][w] = dp[i - 1][w]
                
                # Take item i if possible
                if cost_int <= w:
                    dp[i][w] = max(dp[i][w], dp[i - 1][w - cost_int] + value)
        
        # Backtrack to find selected items
        selected = []
        w = budget_int
        
        for i in range(n, 0, -1):
            if dp[i][w] != dp[i - 1][w]:
                selected.append(candidates[i - 1])
                w -= int(candidates[i - 1].mitigation_cost * budget_scale)
        
        return selected[:config.max_nodes]
    
    def _balanced_selection(
        self,
        candidates: List[InterdictionNode],
        config: InterdictionConfig
    ) -> List[InterdictionNode]:
        """
        Balanced selection considering multiple factors.
        
        Args:
            candidates: Interdiction candidates
            config: Interdiction configuration
            
        Returns:
            Selected nodes
        """
        # Score each candidate based on weighted factors
        scored_candidates = []
        
        for candidate in candidates:
            score = (
                config.weight_criticality * candidate.criticality_score +
                config.weight_betweenness * candidate.betweenness_centrality * 10 +
                config.weight_dominator * (5 if candidate.is_dominator else 0)
            )
            
            # Adjust for cost-effectiveness
            if candidate.mitigation_cost > 0:
                score /= candidate.mitigation_cost
            
            scored_candidates.append((score, candidate))
        
        # Sort by adjusted score
        scored_candidates.sort(reverse=True)
        
        # Select within budget
        selected = []
        remaining_budget = config.budget
        
        for score, candidate in scored_candidates:
            if len(selected) >= config.max_nodes:
                break
            
            if candidate.mitigation_cost <= remaining_budget:
                if candidate.mitigation_effectiveness >= config.min_effectiveness:
                    selected.append(candidate)
                    remaining_budget -= candidate.mitigation_cost
        
        return selected
    
    def _evaluate_interdiction_impact(
        self,
        model_id: str,
        selected_nodes: List[InterdictionNode],
        source_techniques: List[str],
        target_techniques: List[str]
    ) -> Dict[str, Any]:
        """
        Evaluate impact of interdiction plan.
        
        Args:
            model_id: PTG model identifier
            selected_nodes: Selected interdiction nodes
            source_techniques: Source nodes
            target_techniques: Target nodes
            
        Returns:
            Impact analysis
        """
        # Run baseline rollout
        rollout_config = RolloutConfig(
            n_rollouts=1000,
            terminal_techniques=set(target_techniques),
            random_seed=42
        )
        
        baseline_result = self.rollout_sim.simulate_rollouts(
            model_id=model_id,
            starting_techniques=source_techniques,
            config=rollout_config
        )
        
        # Create mitigation transform
        mitigation = MitigationTransform(
            removed_nodes=set(node.technique_id for node in selected_nodes 
                             if node.mitigation_effectiveness >= 1.0),
            penalized_nodes={
                node.technique_id: node.mitigation_effectiveness
                for node in selected_nodes
                if 0 < node.mitigation_effectiveness < 1.0
            }
        )
        
        # Run MDP with mitigation
        mdp_config = MDPConfig(
            terminal_techniques=set(target_techniques),
            mitigated_techniques=mitigation.removed_nodes
        )
        
        mitigated_policy = self.mdp_solver.compute_policy(
            model_id=model_id,
            config=mdp_config,
            mitigation=mitigation
        )
        
        # Estimate success reduction
        # In practice, would run another rollout with mitigation
        # For now, estimate based on value function changes
        baseline_avg_value = sum(mitigated_policy.value_function.values()) / len(mitigated_policy.value_function)
        
        # Count blocked paths
        path_analysis_before = self.graph_analyzer.analyze_paths(
            model_id=model_id,
            source_set=set(source_techniques),
            target_set=set(target_techniques),
            max_paths=100
        )
        
        paths_blocked = 0
        for path in path_analysis_before.all_paths:
            if any(node.technique_id in path for node in selected_nodes):
                paths_blocked += 1
        
        coverage_percentage = (paths_blocked / len(path_analysis_before.all_paths) * 100
                              if path_analysis_before.all_paths else 0)
        
        # Estimate success reduction
        success_reduction = min(0.8, coverage_percentage / 100)  # Cap at 80% reduction
        
        return {
            "baseline_success": baseline_result.success_probability,
            "success_reduction": success_reduction,
            "paths_blocked": paths_blocked,
            "total_paths": len(path_analysis_before.all_paths),
            "coverage_percentage": coverage_percentage,
            "value_function_impact": baseline_avg_value
        }
    
    def _get_mitigation_costs(self) -> Dict[str, float]:
        """
        Get mitigation costs for techniques.
        
        Returns:
            Technique ID to cost mapping
        """
        costs = {}
        
        with self.driver.session() as session:
            # Query mitigation costs (could be based on number of mitigations, complexity, etc.)
            query = """
                MATCH (t:AttackPattern)<-[:MITIGATES]-(m:Mitigation)
                WITH t.stix_id as tech_id, count(m) as mitigation_count
                RETURN tech_id, 
                       CASE 
                           WHEN mitigation_count = 0 THEN 5.0
                           WHEN mitigation_count <= 2 THEN 2.0
                           ELSE 1.0
                       END as cost
            """
            
            result = session.run(query)
            for record in result:
                costs[record["tech_id"]] = record["cost"]
        
        return costs
    
    def _get_technique_name(self, technique_id: str) -> str:
        """
        Get technique name from ID.
        
        Args:
            technique_id: Technique STIX ID
            
        Returns:
            Technique name
        """
        with self.driver.session() as session:
            query = """
                MATCH (t:AttackPattern {stix_id: $tech_id})
                RETURN t.name as name
            """
            
            result = session.run(query, {"tech_id": technique_id})
            record = result.single()
            
            return record["name"] if record else technique_id
    
    def recommend_mitigations(
        self,
        interdiction_plan: InterdictionPlan
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Recommend specific mitigations for interdiction plan.
        
        Args:
            interdiction_plan: Interdiction plan
            
        Returns:
            Mitigation recommendations per technique
        """
        recommendations = {}
        
        with self.driver.session() as session:
            for node in interdiction_plan.selected_nodes:
                query = """
                    MATCH (t:AttackPattern {stix_id: $tech_id})<-[:MITIGATES]-(m:Mitigation)
                    RETURN m.stix_id as mitigation_id,
                           m.name as name,
                           m.description as description
                    LIMIT 5
                """
                
                result = session.run(query, {"tech_id": node.technique_id})
                
                mitigations = []
                for record in result:
                    mitigations.append({
                        "mitigation_id": record["mitigation_id"],
                        "name": record["name"],
                        "description": record["description"][:200] if record["description"] else None
                    })
                
                recommendations[node.technique_id] = mitigations
        
        return recommendations
    
    def close(self):
        """Close connections."""
        if self.driver:
            self.driver.close()
        if self.graph_analyzer:
            self.graph_analyzer.close()
        if self.rollout_sim:
            self.rollout_sim.close()
        if self.mdp_solver:
            self.mdp_solver.close()