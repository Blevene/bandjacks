"""MDP value iteration for optimal attacker policy computation."""

import logging
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
import json
import numpy as np
from neo4j import GraphDatabase
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class MDPState:
    """Represents a state in the MDP."""
    technique_id: str
    value: float = 0.0
    best_action: Optional[str] = None  # Next technique to transition to
    is_terminal: bool = False
    is_mitigated: bool = False


@dataclass
class MDPPolicy:
    """Optimal policy from MDP value iteration."""
    policy_id: str
    model_id: str
    states: Dict[str, MDPState]
    value_function: Dict[str, float]
    policy_mapping: Dict[str, str]  # state -> best_action
    convergence_iterations: int
    convergence_delta: float
    parameters: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class MDPConfig:
    """Configuration for MDP solver."""
    discount_factor: float = 0.95  # γ - future reward discount
    convergence_threshold: float = 1e-4  # Value iteration convergence
    max_iterations: int = 1000
    reward_terminal: float = 10.0  # Reward for reaching goal
    reward_step: float = -0.1  # Step cost (negative reward)
    reward_mitigated: float = -5.0  # Penalty for hitting mitigation
    terminal_techniques: Set[str] = field(default_factory=set)
    terminal_tactics: Set[str] = field(default_factory=set)
    mitigated_techniques: Set[str] = field(default_factory=set)
    blocked_edges: Set[Tuple[str, str]] = field(default_factory=set)


@dataclass
class MitigationTransform:
    """Describes mitigation effects on the graph."""
    removed_nodes: Set[str] = field(default_factory=set)
    removed_edges: Set[Tuple[str, str]] = field(default_factory=set)
    penalized_nodes: Dict[str, float] = field(default_factory=dict)  # node -> penalty
    penalized_edges: Dict[Tuple[str, str], float] = field(default_factory=dict)  # edge -> penalty


class MDPAttackerPolicy:
    """Computes optimal attacker policy using value iteration over PTG."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize MDP solver.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self._ptg_cache = {}
        self._tactic_cache = {}
    
    def compute_policy(
        self,
        model_id: str,
        config: Optional[MDPConfig] = None,
        mitigation: Optional[MitigationTransform] = None
    ) -> MDPPolicy:
        """
        Compute optimal attacker policy using value iteration.
        
        Args:
            model_id: PTG model identifier
            config: MDP configuration
            mitigation: Optional mitigation transform
            
        Returns:
            Optimal attacker policy
        """
        if config is None:
            config = MDPConfig()
        
        logger.info(f"Computing MDP policy for model {model_id}")
        
        # Load PTG
        ptg = self._load_ptg_model(model_id)
        
        # Apply mitigation transforms if provided
        if mitigation:
            ptg = self._apply_mitigation(ptg, mitigation, config)
        
        # Initialize states
        states = self._initialize_states(ptg, config)
        
        # Value iteration
        converged = False
        iteration = 0
        max_delta = float('inf')
        
        while not converged and iteration < config.max_iterations:
            iteration += 1
            delta = 0.0
            
            # Update each state
            for state_id, state in states.items():
                if state.is_terminal or state.is_mitigated:
                    continue
                
                old_value = state.value
                
                # Compute value based on Bellman equation
                best_value = float('-inf')
                best_action = None
                
                # Get possible actions (transitions)
                transitions = ptg.get(state_id, [])
                
                if not transitions:
                    # Dead end - no actions available
                    state.value = config.reward_step
                    state.best_action = None
                else:
                    for transition in transitions:
                        next_state_id = transition["to_technique"]
                        trans_prob = transition["probability"]
                        
                        # Skip blocked edges
                        if (state_id, next_state_id) in config.blocked_edges:
                            continue
                        
                        # Calculate expected value of this action
                        next_state = states.get(next_state_id)
                        if next_state:
                            # Q(s,a) = R(s,a) + γ * P(s'|s,a) * V(s')
                            immediate_reward = self._get_immediate_reward(
                                state_id, next_state_id, next_state, config
                            )
                            
                            future_value = config.discount_factor * trans_prob * next_state.value
                            action_value = immediate_reward + future_value
                            
                            # Track best action
                            if action_value > best_value:
                                best_value = action_value
                                best_action = next_state_id
                
                # Update state value and policy
                if best_action is not None:
                    state.value = best_value
                    state.best_action = best_action
                
                # Track convergence
                delta = max(delta, abs(old_value - state.value))
            
            max_delta = delta
            
            # Check convergence
            if delta < config.convergence_threshold:
                converged = True
                logger.info(f"MDP converged after {iteration} iterations (delta={delta})")
        
        if not converged:
            logger.warning(f"MDP did not converge after {config.max_iterations} iterations")
        
        # Extract policy
        policy_mapping = {}
        value_function = {}
        
        for state_id, state in states.items():
            value_function[state_id] = state.value
            if state.best_action:
                policy_mapping[state_id] = state.best_action
        
        return MDPPolicy(
            policy_id=f"mdp-{model_id[:8]}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            model_id=model_id,
            states=states,
            value_function=value_function,
            policy_mapping=policy_mapping,
            convergence_iterations=iteration,
            convergence_delta=max_delta,
            parameters={
                "discount_factor": config.discount_factor,
                "reward_terminal": config.reward_terminal,
                "reward_step": config.reward_step,
                "reward_mitigated": config.reward_mitigated,
                "terminal_techniques": list(config.terminal_techniques),
                "terminal_tactics": list(config.terminal_tactics),
                "mitigated_techniques": list(config.mitigated_techniques)
            }
        )
    
    def extract_optimal_paths(
        self,
        policy: MDPPolicy,
        starting_techniques: List[str],
        max_depth: int = 10
    ) -> List[List[str]]:
        """
        Extract optimal attack paths from policy.
        
        Args:
            policy: Computed MDP policy
            starting_techniques: Initial techniques
            max_depth: Maximum path length
            
        Returns:
            List of optimal paths
        """
        paths = []
        
        for start in starting_techniques:
            if start not in policy.states:
                continue
            
            path = [start]
            current = start
            visited = {start}
            
            for _ in range(max_depth):
                # Get next action from policy
                next_tech = policy.policy_mapping.get(current)
                if not next_tech:
                    break
                
                # Check for cycles
                if next_tech in visited:
                    break
                
                path.append(next_tech)
                visited.add(next_tech)
                
                # Check if terminal
                state = policy.states.get(next_tech)
                if state and (state.is_terminal or state.is_mitigated):
                    break
                
                current = next_tech
            
            paths.append(path)
        
        return paths
    
    def compare_policies(
        self,
        policy1: MDPPolicy,
        policy2: MDPPolicy
    ) -> Dict[str, Any]:
        """
        Compare two policies (e.g., before/after mitigation).
        
        Args:
            policy1: First policy
            policy2: Second policy
            
        Returns:
            Comparison statistics
        """
        # Value function changes
        common_states = set(policy1.states.keys()) & set(policy2.states.keys())
        
        value_deltas = {}
        for state in common_states:
            v1 = policy1.value_function.get(state, 0)
            v2 = policy2.value_function.get(state, 0)
            value_deltas[state] = v2 - v1
        
        avg_value_change = np.mean(list(value_deltas.values())) if value_deltas else 0
        
        # Policy changes
        policy_changes = {}
        for state in common_states:
            a1 = policy1.policy_mapping.get(state)
            a2 = policy2.policy_mapping.get(state)
            if a1 != a2:
                policy_changes[state] = {"before": a1, "after": a2}
        
        # States affected by mitigation
        states_removed = set(policy1.states.keys()) - set(policy2.states.keys())
        states_added = set(policy2.states.keys()) - set(policy1.states.keys())
        
        # Terminal state value changes
        terminal_value_changes = {}
        for state_id, state in policy1.states.items():
            if state.is_terminal:
                v1 = policy1.value_function.get(state_id, 0)
                v2 = policy2.value_function.get(state_id, 0) if state_id in policy2.states else 0
                terminal_value_changes[state_id] = v2 - v1
        
        return {
            "average_value_change": avg_value_change,
            "num_policy_changes": len(policy_changes),
            "policy_changes": dict(list(policy_changes.items())[:10]),  # Top 10
            "states_removed": list(states_removed)[:10],
            "states_added": list(states_added)[:10],
            "value_deltas": dict(sorted(value_deltas.items(), key=lambda x: abs(x[1]), reverse=True)[:10]),
            "terminal_value_changes": terminal_value_changes,
            "comparison_summary": {
                "mitigation_effective": avg_value_change < 0,
                "percent_policy_changed": len(policy_changes) / len(common_states) * 100 if common_states else 0,
                "convergence_delta": abs(policy1.convergence_delta - policy2.convergence_delta)
            }
        }
    
    def _initialize_states(
        self,
        ptg: Dict[str, List[Dict]],
        config: MDPConfig
    ) -> Dict[str, MDPState]:
        """
        Initialize MDP states from PTG.
        
        Args:
            ptg: PTG transition graph
            config: MDP configuration
            
        Returns:
            Dictionary of states
        """
        states = {}
        
        # Get all techniques in PTG
        all_techniques = set(ptg.keys())
        for transitions in ptg.values():
            for trans in transitions:
                all_techniques.add(trans["to_technique"])
        
        # Initialize each state
        for tech_id in all_techniques:
            state = MDPState(technique_id=tech_id)
            
            # Check if terminal
            if tech_id in config.terminal_techniques:
                state.is_terminal = True
                state.value = config.reward_terminal
            elif config.terminal_tactics:
                tactic = self._get_technique_tactic(tech_id)
                if tactic and tactic in config.terminal_tactics:
                    state.is_terminal = True
                    state.value = config.reward_terminal
            
            # Check if mitigated
            if tech_id in config.mitigated_techniques:
                state.is_mitigated = True
                state.value = config.reward_mitigated
            
            states[tech_id] = state
        
        return states
    
    def _get_immediate_reward(
        self,
        current_state: str,
        next_state: str,
        next_state_obj: MDPState,
        config: MDPConfig
    ) -> float:
        """
        Get immediate reward for transitioning between states.
        
        Args:
            current_state: Current technique ID
            next_state: Next technique ID
            next_state_obj: Next state object
            config: MDP configuration
            
        Returns:
            Immediate reward value
        """
        # Terminal state reward
        if next_state_obj.is_terminal:
            return config.reward_terminal
        
        # Mitigation penalty
        if next_state_obj.is_mitigated:
            return config.reward_mitigated
        
        # Default step cost
        return config.reward_step
    
    def _apply_mitigation(
        self,
        ptg: Dict[str, List[Dict]],
        mitigation: MitigationTransform,
        config: MDPConfig
    ) -> Dict[str, List[Dict]]:
        """
        Apply mitigation transforms to PTG.
        
        Args:
            ptg: Original PTG
            mitigation: Mitigation transforms
            config: MDP configuration
            
        Returns:
            Modified PTG
        """
        modified_ptg = {}
        
        for from_tech, transitions in ptg.items():
            # Skip removed nodes
            if from_tech in mitigation.removed_nodes:
                continue
            
            modified_transitions = []
            
            for trans in transitions:
                to_tech = trans["to_technique"]
                
                # Skip removed nodes
                if to_tech in mitigation.removed_nodes:
                    continue
                
                # Skip removed edges
                if (from_tech, to_tech) in mitigation.removed_edges:
                    continue
                
                # Apply edge penalties
                modified_trans = trans.copy()
                if (from_tech, to_tech) in mitigation.penalized_edges:
                    penalty = mitigation.penalized_edges[(from_tech, to_tech)]
                    modified_trans["probability"] *= (1 - penalty)
                
                # Apply node penalties
                if to_tech in mitigation.penalized_nodes:
                    penalty = mitigation.penalized_nodes[to_tech]
                    modified_trans["probability"] *= (1 - penalty)
                
                if modified_trans["probability"] > 0:
                    modified_transitions.append(modified_trans)
            
            if modified_transitions:
                # Renormalize probabilities
                total_prob = sum(t["probability"] for t in modified_transitions)
                if total_prob > 0:
                    for trans in modified_transitions:
                        trans["probability"] /= total_prob
                
                modified_ptg[from_tech] = modified_transitions
        
        # Update config with mitigated techniques
        config.mitigated_techniques.update(mitigation.removed_nodes)
        config.blocked_edges.update(mitigation.removed_edges)
        
        return modified_ptg
    
    def _load_ptg_model(self, model_id: str) -> Dict[str, List[Dict]]:
        """
        Load PTG model from Neo4j.
        
        Args:
            model_id: Model identifier
            
        Returns:
            PTG as adjacency list
        """
        if model_id in self._ptg_cache:
            return self._ptg_cache[model_id]
        
        ptg = defaultdict(list)
        
        with self.driver.session() as session:
            query = """
                MATCH (t1:AttackPattern)-[r:NEXT_P {model_id: $model_id}]->(t2:AttackPattern)
                RETURN t1.stix_id as from_tech,
                       t2.stix_id as to_tech,
                       r.p as probability,
                       r.features as features
                ORDER BY from_tech, probability DESC
            """
            
            result = session.run(query, {"model_id": model_id})
            
            for record in result:
                from_tech = record["from_tech"]
                transition = {
                    "to_technique": record["to_tech"],
                    "probability": record["probability"],
                    "features": json.loads(record["features"]) if record["features"] else {}
                }
                ptg[from_tech].append(transition)
        
        self._ptg_cache[model_id] = dict(ptg)
        
        logger.info(f"Loaded PTG {model_id} with {len(ptg)} nodes for MDP")
        return dict(ptg)
    
    def _get_technique_tactic(self, technique_id: str) -> Optional[str]:
        """
        Get primary tactic for a technique.
        
        Args:
            technique_id: Technique STIX ID
            
        Returns:
            Primary tactic name or None
        """
        if technique_id in self._tactic_cache:
            return self._tactic_cache[technique_id]
        
        with self.driver.session() as session:
            query = """
                MATCH (t:AttackPattern {stix_id: $tech_id})
                RETURN t.x_mitre_primary_tactic as tactic
            """
            
            result = session.run(query, {"tech_id": technique_id})
            record = result.single()
            
            tactic = record["tactic"] if record else None
            self._tactic_cache[technique_id] = tactic
            
            return tactic
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()