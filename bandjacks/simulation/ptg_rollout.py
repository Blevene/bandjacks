"""PTG-based rollout simulation using transition probabilities."""

import random
import uuid
from typing import Dict, List, Tuple, Optional, Set, Any
from dataclasses import dataclass, field
from collections import Counter, defaultdict
import logging
import json
from datetime import datetime
import numpy as np
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


@dataclass
class RolloutPath:
    """A single rollout path through the PTG."""
    path_id: str
    techniques: List[str]
    probabilities: List[float]
    cumulative_probability: float
    depth: int
    reached_terminal: bool
    terminal_type: Optional[str] = None  # "technique" or "tactic"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass  
class RolloutResult:
    """Results from Monte Carlo rollout simulation."""
    simulation_id: str
    n_rollouts: int
    success_count: int
    success_probability: float
    average_depth: float
    path_distribution: Dict[Tuple[str, ...], int]  # path -> count
    technique_frequency: Dict[str, int]  # technique -> count
    most_common_paths: List[Tuple[List[str], int]]  # top paths with counts
    convergence_history: List[float]  # success prob over time
    parameters: Dict[str, Any]
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class RolloutConfig:
    """Configuration for rollout simulation."""
    n_rollouts: int = 5000
    max_depth: int = 8
    terminal_tactics: Optional[Set[str]] = None
    terminal_techniques: Optional[Set[str]] = None
    convergence_check_interval: int = 500  # Check convergence every N rollouts
    convergence_threshold: float = 0.02  # ±2% stability
    min_probability: float = 0.001  # Min path probability to continue
    random_seed: Optional[int] = None
    track_paths: bool = True
    use_judge_scores: bool = False


class PTGRolloutSimulator:
    """Simulates attack paths using PTG transition probabilities."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize rollout simulator.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self._ptg_cache = {}
        self._technique_tactics_cache = {}
    
    def simulate_rollouts(
        self,
        model_id: str,
        starting_techniques: List[str],
        config: Optional[RolloutConfig] = None
    ) -> RolloutResult:
        """
        Run Monte Carlo rollouts through PTG.
        
        Args:
            model_id: PTG model identifier
            starting_techniques: Initial techniques to start from
            config: Rollout configuration
            
        Returns:
            Rollout simulation results
        """
        if config is None:
            config = RolloutConfig()
            
        if config.random_seed:
            random.seed(config.random_seed)
            np.random.seed(config.random_seed)
        
        # Load PTG model
        ptg = self._load_ptg_model(model_id)
        if not ptg:
            raise ValueError(f"PTG model {model_id} not found")
        
        # Initialize results tracking
        simulation_id = f"rollout-{uuid.uuid4().hex[:8]}"
        paths = []
        path_counter = Counter()
        technique_counter = Counter()
        convergence_history = []
        
        logger.info(f"Starting {config.n_rollouts} rollouts with max_depth={config.max_depth}")
        
        # Run rollouts
        for i in range(config.n_rollouts):
            # Sample starting technique
            start_tech = random.choice(starting_techniques)
            
            # Run single rollout
            path = self._single_rollout(
                ptg=ptg,
                start_technique=start_tech,
                config=config
            )
            
            paths.append(path)
            
            # Track statistics
            if config.track_paths and len(path.techniques) > 1:
                path_tuple = tuple(path.techniques)
                path_counter[path_tuple] += 1
                
            for tech in path.techniques:
                technique_counter[tech] += 1
            
            # Check convergence periodically
            if (i + 1) % config.convergence_check_interval == 0:
                current_success = sum(1 for p in paths if p.reached_terminal) / len(paths)
                convergence_history.append(current_success)
                
                # Check stability if we have enough history
                if len(convergence_history) >= 3:
                    recent = convergence_history[-3:]
                    if max(recent) - min(recent) < config.convergence_threshold:
                        logger.info(f"Converged after {i+1} rollouts (variance < {config.convergence_threshold})")
                        # Could break early here if desired
        
        # Calculate final statistics
        success_count = sum(1 for p in paths if p.reached_terminal)
        success_probability = success_count / len(paths)
        average_depth = sum(p.depth for p in paths) / len(paths)
        
        # Get most common paths
        most_common_paths = [
            (list(path), count) 
            for path, count in path_counter.most_common(10)
        ]
        
        return RolloutResult(
            simulation_id=simulation_id,
            n_rollouts=len(paths),
            success_count=success_count,
            success_probability=success_probability,
            average_depth=average_depth,
            path_distribution=dict(path_counter),
            technique_frequency=dict(technique_counter),
            most_common_paths=most_common_paths,
            convergence_history=convergence_history,
            parameters={
                "model_id": model_id,
                "starting_techniques": starting_techniques,
                "max_depth": config.max_depth,
                "terminal_tactics": list(config.terminal_tactics) if config.terminal_tactics else None,
                "terminal_techniques": list(config.terminal_techniques) if config.terminal_techniques else None,
                "random_seed": config.random_seed
            }
        )
    
    def _single_rollout(
        self,
        ptg: Dict[str, List[Dict]],
        start_technique: str,
        config: RolloutConfig
    ) -> RolloutPath:
        """
        Execute a single rollout through PTG.
        
        Args:
            ptg: PTG transition graph
            start_technique: Starting technique
            config: Rollout configuration
            
        Returns:
            Single rollout path
        """
        path_id = f"path-{uuid.uuid4().hex[:8]}"
        techniques = [start_technique]
        probabilities = [1.0]
        cumulative_prob = 1.0
        current = start_technique
        
        for depth in range(config.max_depth):
            # Check terminal conditions
            if self._is_terminal(current, config):
                return RolloutPath(
                    path_id=path_id,
                    techniques=techniques,
                    probabilities=probabilities,
                    cumulative_probability=cumulative_prob,
                    depth=depth,
                    reached_terminal=True,
                    terminal_type=self._get_terminal_type(current, config)
                )
            
            # Get possible transitions
            transitions = ptg.get(current, [])
            if not transitions:
                # Dead end
                return RolloutPath(
                    path_id=path_id,
                    techniques=techniques,
                    probabilities=probabilities,
                    cumulative_probability=cumulative_prob,
                    depth=depth,
                    reached_terminal=False
                )
            
            # Sample next technique based on probabilities
            next_tech = self._sample_transition(transitions)
            if not next_tech:
                break
                
            # Get transition probability
            trans_prob = next((t["probability"] for t in transitions if t["to_technique"] == next_tech), 0.0)
            
            # Update path
            techniques.append(next_tech)
            probabilities.append(trans_prob)
            cumulative_prob *= trans_prob
            
            # Check minimum probability threshold
            if cumulative_prob < config.min_probability:
                break
                
            current = next_tech
        
        # Check if final technique is terminal
        reached_terminal = self._is_terminal(current, config)
        
        return RolloutPath(
            path_id=path_id,
            techniques=techniques,
            probabilities=probabilities,
            cumulative_probability=cumulative_prob,
            depth=len(techniques) - 1,
            reached_terminal=reached_terminal,
            terminal_type=self._get_terminal_type(current, config) if reached_terminal else None
        )
    
    def _sample_transition(self, transitions: List[Dict]) -> Optional[str]:
        """
        Sample next technique from transitions based on probabilities.
        
        Args:
            transitions: List of possible transitions with probabilities
            
        Returns:
            Selected technique ID or None
        """
        if not transitions:
            return None
            
        # Extract techniques and probabilities
        techniques = [t["to_technique"] for t in transitions]
        probabilities = [t["probability"] for t in transitions]
        
        # Normalize probabilities (should already sum to 1, but ensure)
        prob_sum = sum(probabilities)
        if prob_sum > 0:
            probabilities = [p / prob_sum for p in probabilities]
        else:
            # Uniform if no probabilities
            probabilities = [1.0 / len(techniques)] * len(techniques)
        
        # Sample
        return np.random.choice(techniques, p=probabilities)
    
    def _is_terminal(self, technique: str, config: RolloutConfig) -> bool:
        """
        Check if technique is a terminal node.
        
        Args:
            technique: Technique ID
            config: Rollout configuration
            
        Returns:
            True if terminal
        """
        # Check explicit terminal techniques
        if config.terminal_techniques and technique in config.terminal_techniques:
            return True
            
        # Check terminal tactics
        if config.terminal_tactics:
            tactic = self._get_technique_tactic(technique)
            if tactic and tactic in config.terminal_tactics:
                return True
                
        return False
    
    def _get_terminal_type(self, technique: str, config: RolloutConfig) -> str:
        """
        Get type of terminal reached.
        
        Args:
            technique: Technique ID
            config: Rollout configuration
            
        Returns:
            "technique" or "tactic"
        """
        if config.terminal_techniques and technique in config.terminal_techniques:
            return "technique"
            
        if config.terminal_tactics:
            tactic = self._get_technique_tactic(technique)
            if tactic and tactic in config.terminal_tactics:
                return "tactic"
                
        return "unknown"
    
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
            # Load NEXT_P edges for this model
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
        
        # Cache for reuse
        self._ptg_cache[model_id] = dict(ptg)
        
        logger.info(f"Loaded PTG {model_id} with {len(ptg)} nodes")
        return dict(ptg)
    
    def _get_technique_tactic(self, technique_id: str) -> Optional[str]:
        """
        Get primary tactic for a technique.
        
        Args:
            technique_id: Technique STIX ID
            
        Returns:
            Primary tactic name or None
        """
        if technique_id in self._technique_tactics_cache:
            return self._technique_tactics_cache[technique_id]
            
        with self.driver.session() as session:
            query = """
                MATCH (t:AttackPattern {stix_id: $tech_id})
                RETURN t.x_mitre_primary_tactic as tactic
            """
            
            result = session.run(query, {"tech_id": technique_id})
            record = result.single()
            
            tactic = record["tactic"] if record else None
            self._technique_tactics_cache[technique_id] = tactic
            
            return tactic
    
    def compare_rollouts(
        self,
        results1: RolloutResult,
        results2: RolloutResult
    ) -> Dict[str, Any]:
        """
        Compare two rollout results (e.g., before/after mitigation).
        
        Args:
            results1: First rollout result
            results2: Second rollout result
            
        Returns:
            Comparison statistics
        """
        # Success probability delta
        success_delta = results2.success_probability - results1.success_probability
        success_percent_change = (success_delta / results1.success_probability * 100) if results1.success_probability > 0 else 0
        
        # Depth changes
        depth_delta = results2.average_depth - results1.average_depth
        
        # Top path changes
        top_paths1 = set(path for path, _ in results1.most_common_paths[:5])
        top_paths2 = set(path for path, _ in results2.most_common_paths[:5])
        
        paths_removed = top_paths1 - top_paths2
        paths_added = top_paths2 - top_paths1
        
        # Technique frequency changes
        tech_freq_delta = {}
        all_techniques = set(results1.technique_frequency.keys()) | set(results2.technique_frequency.keys())
        
        for tech in all_techniques:
            freq1 = results1.technique_frequency.get(tech, 0) / results1.n_rollouts
            freq2 = results2.technique_frequency.get(tech, 0) / results2.n_rollouts
            tech_freq_delta[tech] = freq2 - freq1
        
        # Sort by largest changes
        top_increases = sorted(tech_freq_delta.items(), key=lambda x: x[1], reverse=True)[:5]
        top_decreases = sorted(tech_freq_delta.items(), key=lambda x: x[1])[:5]
        
        return {
            "success_probability_delta": success_delta,
            "success_percent_change": success_percent_change,
            "average_depth_delta": depth_delta,
            "top_paths_removed": [tuple(p) for p in paths_removed],
            "top_paths_added": [tuple(p) for p in paths_added],
            "technique_frequency_increases": top_increases,
            "technique_frequency_decreases": top_decreases,
            "comparison_summary": {
                "result1_success": results1.success_probability,
                "result2_success": results2.success_probability,
                "improvement": success_delta < 0,  # Lower success is better for defense
                "significant": abs(success_percent_change) > 5
            }
        }
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()