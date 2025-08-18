"""Attack path simulation engine using graph traversal and probabilistic modeling."""

import random
import heapq
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from neo4j import GraphDatabase
import numpy as np


@dataclass
class SimulationPath:
    """Represents a simulated attack path."""
    path_id: str
    techniques: List[str]
    probabilities: List[float]
    cumulative_probability: float
    total_cost: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SimulationConfig:
    """Configuration for attack simulation."""
    max_depth: int = 5
    max_paths: int = 10
    min_probability: float = 0.1
    use_monte_carlo: bool = False
    monte_carlo_iterations: int = 1000
    consider_defenses: bool = False
    randomness_factor: float = 0.1


class AttackSimulator:
    """Simulates attack paths through the ATT&CK graph."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize the attack simulator.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
        self._transition_cache = {}
        self._technique_cache = {}
    
    def simulate_paths(
        self,
        start_technique: Optional[str] = None,
        start_group: Optional[str] = None,
        target_technique: Optional[str] = None,
        config: Optional[SimulationConfig] = None
    ) -> List[SimulationPath]:
        """
        Simulate attack paths from a starting point.
        
        Args:
            start_technique: Starting technique STIX ID
            start_group: Starting threat group STIX ID
            target_technique: Optional target technique to reach
            config: Simulation configuration
            
        Returns:
            List of simulated attack paths
        """
        if config is None:
            config = SimulationConfig()
        
        # Get starting techniques
        starting_techniques = self._get_starting_techniques(start_technique, start_group)
        
        if not starting_techniques:
            return []
        
        # Use Monte Carlo or deterministic simulation
        if config.use_monte_carlo:
            paths = self._monte_carlo_simulation(
                starting_techniques,
                target_technique,
                config
            )
        else:
            paths = self._deterministic_simulation(
                starting_techniques,
                target_technique,
                config
            )
        
        # Sort by probability and limit results
        paths.sort(key=lambda p: p.cumulative_probability, reverse=True)
        return paths[:config.max_paths]
    
    def _get_starting_techniques(
        self,
        start_technique: Optional[str],
        start_group: Optional[str]
    ) -> List[str]:
        """Get starting techniques from input."""
        techniques = []
        
        with self.driver.session() as session:
            if start_technique:
                # Verify technique exists
                result = session.run(
                    "MATCH (t:AttackPattern {stix_id: $tech_id}) RETURN t.stix_id as id",
                    tech_id=start_technique
                )
                if result.single():
                    techniques.append(start_technique)
            
            elif start_group:
                # Get techniques used by group
                result = session.run(
                    """
                    MATCH (g:IntrusionSet {stix_id: $group_id})-[:USES]->(t:AttackPattern)
                    RETURN DISTINCT t.stix_id as technique_id
                    ORDER BY rand()
                    LIMIT 5
                    """,
                    group_id=start_group
                )
                for record in result:
                    techniques.append(record["technique_id"])
            
            else:
                # Get common initial access techniques
                result = session.run(
                    """
                    MATCH (t:AttackPattern)-[:HAS_TACTIC]->(tac:Tactic)
                    WHERE tac.shortname IN ['initial-access', 'execution']
                    RETURN DISTINCT t.stix_id as technique_id
                    ORDER BY rand()
                    LIMIT 3
                    """
                )
                for record in result:
                    techniques.append(record["technique_id"])
        
        return techniques
    
    def _deterministic_simulation(
        self,
        starting_techniques: List[str],
        target_technique: Optional[str],
        config: SimulationConfig
    ) -> List[SimulationPath]:
        """Deterministic path generation using graph traversal."""
        paths = []
        path_counter = 0
        
        for start_tech in starting_techniques:
            # Use priority queue for best-first search
            # Priority is negative cumulative probability (for max-heap behavior)
            pq = [(-1.0, [start_tech], [1.0], 0)]
            visited_paths = set()
            
            while pq and len(paths) < config.max_paths:
                neg_prob, path, probs, depth = heapq.heappop(pq)
                cumulative_prob = -neg_prob
                
                # Skip if below minimum probability
                if cumulative_prob < config.min_probability:
                    continue
                
                # Create path signature to avoid duplicates
                path_sig = tuple(path)
                if path_sig in visited_paths:
                    continue
                visited_paths.add(path_sig)
                
                current_tech = path[-1]
                
                # Check if we reached target
                if target_technique and current_tech == target_technique:
                    paths.append(SimulationPath(
                        path_id=f"sim-path-{path_counter}",
                        techniques=path,
                        probabilities=probs,
                        cumulative_probability=cumulative_prob,
                        total_cost=self._calculate_path_cost(path),
                        metadata={"method": "deterministic", "target_reached": True}
                    ))
                    path_counter += 1
                    continue
                
                # Check depth limit
                if depth >= config.max_depth:
                    if not target_technique or len(path) > 2:
                        paths.append(SimulationPath(
                            path_id=f"sim-path-{path_counter}",
                            techniques=path,
                            probabilities=probs,
                            cumulative_probability=cumulative_prob,
                            total_cost=self._calculate_path_cost(path),
                            metadata={"method": "deterministic", "depth_limited": True}
                        ))
                        path_counter += 1
                    continue
                
                # Get next techniques
                next_techniques = self._get_next_techniques(current_tech, config)
                
                for next_tech, trans_prob in next_techniques:
                    if next_tech not in path:  # Avoid cycles
                        new_prob = cumulative_prob * trans_prob
                        if new_prob >= config.min_probability:
                            new_path = path + [next_tech]
                            new_probs = probs + [trans_prob]
                            heapq.heappush(pq, (-new_prob, new_path, new_probs, depth + 1))
        
        return paths
    
    def _monte_carlo_simulation(
        self,
        starting_techniques: List[str],
        target_technique: Optional[str],
        config: SimulationConfig
    ) -> List[SimulationPath]:
        """Monte Carlo simulation for probabilistic path generation."""
        path_frequencies = {}
        path_details = {}
        
        for _ in range(config.monte_carlo_iterations):
            # Random starting point
            start_tech = random.choice(starting_techniques)
            path = [start_tech]
            probs = [1.0]
            
            current_tech = start_tech
            for depth in range(config.max_depth):
                # Get next techniques with probabilities
                next_techniques = self._get_next_techniques(current_tech, config)
                
                if not next_techniques:
                    break
                
                # Sample next technique based on probabilities
                techniques, probabilities = zip(*next_techniques)
                
                # Add randomness
                adjusted_probs = self._add_randomness(probabilities, config.randomness_factor)
                
                # Normalize probabilities
                total_prob = sum(adjusted_probs)
                if total_prob > 0:
                    adjusted_probs = [p / total_prob for p in adjusted_probs]
                    next_tech = np.random.choice(techniques, p=adjusted_probs)
                    trans_prob = next_techniques[techniques.index(next_tech)][1]
                    
                    # Avoid cycles
                    if next_tech not in path:
                        path.append(next_tech)
                        probs.append(trans_prob)
                        current_tech = next_tech
                        
                        # Check if target reached
                        if target_technique and current_tech == target_technique:
                            break
                    else:
                        break
            
            # Record path
            path_tuple = tuple(path)
            path_frequencies[path_tuple] = path_frequencies.get(path_tuple, 0) + 1
            
            if path_tuple not in path_details:
                path_details[path_tuple] = probs
        
        # Convert frequencies to paths
        paths = []
        path_counter = 0
        
        for path_tuple, frequency in path_frequencies.items():
            if len(path_tuple) > 1:  # Ignore single-node paths
                probs = path_details[path_tuple]
                cumulative_prob = np.prod(probs) * (frequency / config.monte_carlo_iterations)
                
                if cumulative_prob >= config.min_probability:
                    paths.append(SimulationPath(
                        path_id=f"mc-path-{path_counter}",
                        techniques=list(path_tuple),
                        probabilities=probs,
                        cumulative_probability=cumulative_prob,
                        total_cost=self._calculate_path_cost(list(path_tuple)),
                        metadata={
                            "method": "monte_carlo",
                            "frequency": frequency,
                            "iterations": config.monte_carlo_iterations
                        }
                    ))
                    path_counter += 1
        
        return paths
    
    def _get_next_techniques(
        self,
        current_technique: str,
        config: SimulationConfig
    ) -> List[Tuple[str, float]]:
        """Get possible next techniques with transition probabilities."""
        
        # Check cache
        cache_key = f"{current_technique}_{config.consider_defenses}"
        if cache_key in self._transition_cache:
            return self._transition_cache[cache_key]
        
        next_techniques = []
        
        with self.driver.session() as session:
            # Get historical transitions from flows
            flow_query = """
                MATCH (a1:AttackAction {attack_pattern_ref: $current})-[n:NEXT]->(a2:AttackAction)
                WITH a2.attack_pattern_ref as next_tech, avg(n.p) as avg_prob, count(*) as frequency
                RETURN next_tech, avg_prob, frequency
                ORDER BY avg_prob DESC
            """
            
            flow_result = session.run(flow_query, current=current_technique)
            flow_transitions = {}
            
            for record in flow_result:
                if record["next_tech"]:
                    flow_transitions[record["next_tech"]] = {
                        "prob": record["avg_prob"] or 0.5,
                        "frequency": record["frequency"] or 1
                    }
            
            # Get tactic-based transitions
            tactic_query = """
                MATCH (t1:AttackPattern {stix_id: $current})-[:HAS_TACTIC]->(tac1:Tactic)
                WITH tac1.shortname as current_tactic
                MATCH (t2:AttackPattern)-[:HAS_TACTIC]->(tac2:Tactic)
                WHERE tac2.shortname IN 
                    CASE current_tactic
                        WHEN 'initial-access' THEN ['execution', 'persistence']
                        WHEN 'execution' THEN ['persistence', 'privilege-escalation', 'defense-evasion']
                        WHEN 'persistence' THEN ['privilege-escalation', 'defense-evasion']
                        WHEN 'privilege-escalation' THEN ['defense-evasion', 'credential-access', 'discovery']
                        WHEN 'defense-evasion' THEN ['credential-access', 'discovery']
                        WHEN 'credential-access' THEN ['discovery', 'lateral-movement']
                        WHEN 'discovery' THEN ['lateral-movement', 'collection']
                        WHEN 'lateral-movement' THEN ['collection', 'command-and-control']
                        WHEN 'collection' THEN ['command-and-control', 'exfiltration']
                        WHEN 'command-and-control' THEN ['exfiltration', 'impact']
                        WHEN 'exfiltration' THEN ['impact']
                        ELSE []
                    END
                AND t2.stix_id <> $current
                RETURN DISTINCT t2.stix_id as next_tech, tac2.shortname as next_tactic
                LIMIT 20
            """
            
            tactic_result = session.run(tactic_query, current=current_technique)
            
            for record in tactic_result:
                next_tech = record["next_tech"]
                
                # Calculate probability
                if next_tech in flow_transitions:
                    # Use historical probability with boost
                    prob = flow_transitions[next_tech]["prob"]
                    freq_boost = min(flow_transitions[next_tech]["frequency"] / 10, 0.2)
                    prob = min(prob + freq_boost, 0.95)
                else:
                    # Use tactic-based heuristic
                    base_prob = 0.3
                    # Adjust based on tactic progression
                    if record["next_tactic"] in ['lateral-movement', 'exfiltration', 'impact']:
                        base_prob *= 0.8  # Later tactics less likely
                    prob = base_prob
                
                # Consider defenses if enabled
                if config.consider_defenses:
                    defense_reduction = self._get_defense_reduction(next_tech)
                    prob *= (1 - defense_reduction)
                
                if prob > 0.05:  # Minimum threshold
                    next_techniques.append((next_tech, prob))
        
        # Sort by probability
        next_techniques.sort(key=lambda x: x[1], reverse=True)
        
        # Cache result
        self._transition_cache[cache_key] = next_techniques[:10]  # Limit cache size
        
        return next_techniques[:10]
    
    def _get_defense_reduction(self, technique: str) -> float:
        """Get defense reduction factor for a technique."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (t:AttackPattern {stix_id: $tech_id})
                OPTIONAL MATCH (d:D3fendTechnique)-[:COUNTERS]->(t)
                RETURN count(d) as defense_count
                """,
                tech_id=technique
            )
            
            record = result.single()
            defense_count = record["defense_count"] if record else 0
            
            # Each defense reduces probability by 15%, max 75% reduction
            return min(defense_count * 0.15, 0.75)
    
    def _calculate_path_cost(self, path: List[str]) -> float:
        """Calculate the cost/complexity of an attack path."""
        if not path:
            return 0.0
        
        # Base cost per technique
        base_cost = len(path) * 1.0
        
        # Additional cost for complex techniques
        complexity_cost = 0.0
        
        with self.driver.session() as session:
            for tech in path:
                # Check if it's a sub-technique (higher complexity)
                result = session.run(
                    """
                    MATCH (t:AttackPattern {stix_id: $tech_id})
                    RETURN t.x_mitre_is_subtechnique as is_sub
                    """,
                    tech_id=tech
                )
                record = result.single()
                if record and record["is_sub"]:
                    complexity_cost += 0.5
        
        return base_cost + complexity_cost
    
    def _add_randomness(self, probabilities: List[float], factor: float) -> List[float]:
        """Add controlled randomness to probabilities."""
        adjusted = []
        for prob in probabilities:
            # Add random noise
            noise = random.uniform(-factor, factor)
            adjusted_prob = prob + noise
            # Keep within bounds
            adjusted_prob = max(0.01, min(0.99, adjusted_prob))
            adjusted.append(adjusted_prob)
        return adjusted
    
    def get_transition_matrix(
        self,
        techniques: Optional[List[str]] = None,
        limit: int = 50
    ) -> Dict[str, Any]:
        """
        Get transition probability matrix between techniques.
        
        Args:
            techniques: Specific techniques to analyze (None for top techniques)
            limit: Maximum number of techniques
            
        Returns:
            Transition matrix and metadata
        """
        with self.driver.session() as session:
            if not techniques:
                # Get most common techniques
                result = session.run(
                    """
                    MATCH (a:AttackAction)
                    WITH a.attack_pattern_ref as tech, count(*) as frequency
                    RETURN tech
                    ORDER BY frequency DESC
                    LIMIT $limit
                    """,
                    limit=limit
                )
                techniques = [r["tech"] for r in result if r["tech"]]
            
            # Build transition matrix
            matrix = {}
            for from_tech in techniques:
                matrix[from_tech] = {}
                
                # Get transitions
                result = session.run(
                    """
                    MATCH (a1:AttackAction {attack_pattern_ref: $from_tech})-[n:NEXT]->(a2:AttackAction)
                    WHERE a2.attack_pattern_ref IN $techniques
                    WITH a2.attack_pattern_ref as to_tech, avg(n.p) as avg_prob
                    RETURN to_tech, avg_prob
                    """,
                    from_tech=from_tech,
                    techniques=techniques
                )
                
                for record in result:
                    matrix[from_tech][record["to_tech"]] = round(record["avg_prob"] or 0, 3)
            
            return {
                "techniques": techniques,
                "matrix": matrix,
                "technique_count": len(techniques),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def whatif_analysis(
        self,
        scenario: Dict[str, Any],
        config: Optional[SimulationConfig] = None
    ) -> Dict[str, Any]:
        """
        Perform what-if analysis for a scenario.
        
        Args:
            scenario: Scenario definition with constraints
            config: Simulation configuration
            
        Returns:
            Analysis results with paths and recommendations
        """
        if config is None:
            config = SimulationConfig()
        
        # Extract scenario parameters
        compromised_techniques = scenario.get("compromised", [])
        blocked_techniques = scenario.get("blocked", [])
        target_assets = scenario.get("targets", [])
        
        # Simulate paths avoiding blocked techniques
        paths = []
        
        for start_tech in compromised_techniques:
            sim_paths = self.simulate_paths(
                start_technique=start_tech,
                config=config
            )
            
            # Filter out paths with blocked techniques
            for path in sim_paths:
                if not any(tech in blocked_techniques for tech in path.techniques):
                    paths.append(path)
        
        # Analyze impact
        reachable_targets = set()
        critical_paths = []
        
        for path in paths:
            # Check if path reaches critical targets
            for tech in path.techniques:
                with self.driver.session() as session:
                    result = session.run(
                        """
                        MATCH (t:AttackPattern {stix_id: $tech_id})-[:HAS_TACTIC]->(tac:Tactic)
                        WHERE tac.shortname IN ['exfiltration', 'impact']
                        RETURN count(*) as is_critical
                        """,
                        tech_id=tech
                    )
                    record = result.single()
                    if record and record["is_critical"] > 0:
                        critical_paths.append(path)
                        reachable_targets.update(target_assets)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(paths, blocked_techniques)
        
        return {
            "scenario": scenario,
            "possible_paths": len(paths),
            "critical_paths": len(critical_paths),
            "reachable_targets": list(reachable_targets),
            "highest_probability_path": paths[0] if paths else None,
            "recommendations": recommendations,
            "analysis_timestamp": datetime.utcnow().isoformat()
        }
    
    def _generate_recommendations(
        self,
        paths: List[SimulationPath],
        blocked_techniques: List[str]
    ) -> List[Dict[str, Any]]:
        """Generate defensive recommendations based on simulation."""
        recommendations = []
        
        # Find common techniques across paths
        technique_frequency = {}
        for path in paths:
            for tech in path.techniques:
                if tech not in blocked_techniques:
                    technique_frequency[tech] = technique_frequency.get(tech, 0) + 1
        
        # Recommend blocking high-frequency techniques
        sorted_techs = sorted(technique_frequency.items(), key=lambda x: x[1], reverse=True)
        
        for tech, frequency in sorted_techs[:5]:
            impact = frequency / len(paths) if paths else 0
            recommendations.append({
                "technique": tech,
                "action": "block",
                "impact": round(impact * 100, 2),
                "rationale": f"Appears in {frequency} of {len(paths)} possible paths"
            })
        
        return recommendations
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()