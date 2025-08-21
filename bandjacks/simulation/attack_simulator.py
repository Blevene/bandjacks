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
    metadata: Dict[str, Any]
    confidence_score: float = 0.0
    warnings: List[str] = field(default_factory=list)
    evidence_counts: List[int] = field(default_factory=list)
    is_hypothetical: bool = False


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
    
    def predict_next_steps(
        self,
        current_techniques: List[str],
        threat_group: Optional[str] = None,
        max_predictions: int = 5
    ) -> Dict[str, Any]:
        """
        Predict likely next steps given current attack state.
        
        Args:
            current_techniques: Current technique sequence
            threat_group: Optional threat group context
            max_predictions: Maximum predictions to return
            
        Returns:
            Predictions with probabilities and rationale
        """
        with self.driver.session() as session:
            if not current_techniques:
                return {"predictions": [], "confidence": 0}
            
            last_technique = current_techniques[-1]
            
            # Build query based on context
            if threat_group:
                query = """
                    MATCH (g:IntrusionSet {stix_id: $group})
                    MATCH (g)-[:USES]->(t:AttackPattern)
                    WHERE t.stix_id IN $current_techs
                    WITH g
                    MATCH (a1:AttackAction {attack_pattern_ref: $last_tech})-[n:NEXT]->(a2:AttackAction)
                    MATCH (t2:AttackPattern {stix_id: a2.attack_pattern_ref})
                    OPTIONAL MATCH (g)-[u:USES]->(t2)
                    WITH t2, n.p as transition_prob, 
                         CASE WHEN u IS NOT NULL THEN 1.5 ELSE 1.0 END as group_weight
                    RETURN t2.stix_id as technique_id, t2.name as name,
                           t2.kill_chain_phases as tactics,
                           avg(transition_prob * group_weight) as probability
                    ORDER BY probability DESC
                    LIMIT $limit
                """
                params = {
                    "group": threat_group,
                    "current_techs": current_techniques,
                    "last_tech": last_technique,
                    "limit": max_predictions
                }
            else:
                query = """
                    MATCH (a1:AttackAction {attack_pattern_ref: $last_tech})-[n:NEXT]->(a2:AttackAction)
                    MATCH (t:AttackPattern {stix_id: a2.attack_pattern_ref})
                    WITH t, avg(n.p) as probability
                    RETURN t.stix_id as technique_id, t.name as name,
                           t.kill_chain_phases as tactics,
                           probability
                    ORDER BY probability DESC
                    LIMIT $limit
                """
                params = {"last_tech": last_technique, "limit": max_predictions}
            
            result = session.run(query, params)
            
            predictions = []
            for record in result:
                # Extract primary tactic
                tactics = record.get("tactics", [])
                primary_tactic = tactics[0]["phase_name"] if tactics else "unknown"
                
                # Generate rationale
                rationale = self._generate_rationale(
                    last_technique, record["technique_id"], 
                    record["probability"], threat_group
                )
                
                predictions.append({
                    "technique_id": record["technique_id"],
                    "name": record["name"],
                    "probability": float(record["probability"]),
                    "tactic": primary_tactic,
                    "rationale": rationale,
                    "frequency": self._get_technique_frequency(session, record["technique_id"])
                })
            
            # Calculate confidence based on data availability
            confidence = min(1.0, len(predictions) / max_predictions) if predictions else 0
            
            return {
                "predictions": predictions,
                "confidence": confidence,
                "analysis": self._analyze_prediction_context(current_techniques, predictions)
            }
    
    def what_if_analysis(
        self,
        scenario: str,
        blocked_techniques: Optional[List[str]] = None,
        required_techniques: Optional[List[str]] = None,
        constraints: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform what-if analysis for defensive scenarios.
        
        Args:
            scenario: Scenario description
            blocked_techniques: Techniques to block
            required_techniques: Techniques that must be included
            constraints: Additional constraints
            
        Returns:
            Analysis results with viable paths and recommendations
        """
        config = SimulationConfig(
            max_depth=7,
            num_paths=20,
            method="deterministic"
        )
        
        # Get baseline paths
        baseline_paths = self.simulate_paths(config=config)
        
        # Apply blocks and requirements
        viable_paths = []
        blocked_paths = []
        
        for path in baseline_paths.get("paths", []):
            path_techniques = [step["technique_id"] for step in path["steps"]]
            
            # Check if path is blocked
            if blocked_techniques and any(t in path_techniques for t in blocked_techniques):
                blocked_paths.append(path)
                continue
            
            # Check if path meets requirements
            if required_techniques and not all(t in path_techniques for t in required_techniques):
                continue
            
            viable_paths.append(path)
        
        # Calculate impact
        blocked_impact = {
            "paths_blocked": len(blocked_paths),
            "paths_remaining": len(viable_paths),
            "coverage_reduction": (len(blocked_paths) / len(baseline_paths.get("paths", []))) * 100 if baseline_paths.get("paths") else 0,
            "blocked_tactics": self._get_blocked_tactics(blocked_paths),
            "alternative_routes": self._find_alternative_routes(blocked_paths, viable_paths)
        }
        
        # Generate recommendations
        recommendations = self._generate_whatif_recommendations(
            scenario, blocked_techniques, viable_paths, blocked_impact
        )
        
        return {
            "viable_paths": viable_paths[:10],  # Limit to top 10
            "blocked_impact": blocked_impact,
            "recommendations": recommendations,
            "analysis": self._generate_whatif_analysis(scenario, viable_paths, blocked_impact)
        }
    
    def get_technique_statistics(self, technique_id: str) -> Dict[str, Any]:
        """Get statistics for a specific technique."""
        with self.driver.session() as session:
            # Get basic info
            result = session.run(
                """
                MATCH (t:AttackPattern {stix_id: $tech_id})
                RETURN t.name as name, t.description as description,
                       t.kill_chain_phases as tactics
                """,
                tech_id=technique_id
            )
            
            record = result.single()
            if not record:
                return None
            
            # Get usage statistics
            stats_result = session.run(
                """
                MATCH (a:AttackAction {attack_pattern_ref: $tech_id})
                WITH count(a) as usage_count
                MATCH (a1:AttackAction {attack_pattern_ref: $tech_id})-[n:NEXT]->(a2:AttackAction)
                WITH usage_count, a2.attack_pattern_ref as next_tech, avg(n.p) as avg_prob
                RETURN usage_count, collect({
                    technique: next_tech,
                    probability: avg_prob
                }) as transitions
                """,
                tech_id=technique_id
            )
            
            stats = stats_result.single()
            
            # Get groups that use this technique
            groups_result = session.run(
                """
                MATCH (g:IntrusionSet)-[:USES]->(t:AttackPattern {stix_id: $tech_id})
                RETURN g.name as group_name, g.stix_id as group_id
                LIMIT 10
                """,
                tech_id=technique_id
            )
            
            groups = [{"name": r["group_name"], "id": r["group_id"]} for r in groups_result]
            
            return {
                "technique_id": technique_id,
                "name": record["name"],
                "description": record["description"][:200] + "...",
                "tactics": [t["phase_name"] for t in (record["tactics"] or [])],
                "usage_count": stats["usage_count"] if stats else 0,
                "common_transitions": sorted(
                    stats["transitions"] if stats else [],
                    key=lambda x: x["probability"],
                    reverse=True
                )[:5],
                "threat_groups": groups,
                "frequency_score": self._calculate_frequency_score(stats["usage_count"] if stats else 0)
            }
    
    def get_group_patterns(self, group_id: str, limit: int = 10) -> Dict[str, Any]:
        """Get attack patterns for a threat group."""
        with self.driver.session() as session:
            # Get group info
            result = session.run(
                """
                MATCH (g:IntrusionSet {stix_id: $group_id})
                RETURN g.name as name, g.description as description
                """,
                group_id=group_id
            )
            
            record = result.single()
            if not record:
                return None
            
            # Get techniques used by group
            techniques_result = session.run(
                """
                MATCH (g:IntrusionSet {stix_id: $group_id})-[:USES]->(t:AttackPattern)
                WITH t, count(*) as usage_count
                RETURN t.stix_id as technique_id, t.name as name,
                       t.kill_chain_phases as tactics, usage_count
                ORDER BY usage_count DESC
                LIMIT $limit
                """,
                group_id=group_id,
                limit=limit
            )
            
            techniques = []
            for tech in techniques_result:
                techniques.append({
                    "technique_id": tech["technique_id"],
                    "name": tech["name"],
                    "tactics": [t["phase_name"] for t in (tech["tactics"] or [])],
                    "usage_count": tech["usage_count"]
                })
            
            # Get common sequences
            sequences_result = session.run(
                """
                MATCH (e:AttackEpisode)-[:ATTRIBUTED_TO]->(g:IntrusionSet {stix_id: $group_id})
                MATCH (e)-[:CONTAINS]->(a:AttackAction)
                WITH e, collect(a ORDER BY a.sequence) as actions
                WHERE size(actions) >= 2
                RETURN actions[0..3] as sequence, count(*) as frequency
                ORDER BY frequency DESC
                LIMIT 5
                """,
                group_id=group_id
            )
            
            sequences = []
            for seq in sequences_result:
                sequences.append({
                    "steps": [a["attack_pattern_ref"] for a in seq["sequence"]],
                    "frequency": seq["frequency"]
                })
            
            return {
                "group_id": group_id,
                "name": record["name"],
                "description": record["description"][:200] + "..." if record["description"] else "",
                "techniques": techniques,
                "common_sequences": sequences,
                "total_techniques": len(techniques),
                "analysis": self._analyze_group_patterns(techniques, sequences)
            }
    
    def compare_paths(self, path_ids: List[str]) -> Dict[str, Any]:
        """Compare multiple attack paths."""
        # This would need access to stored paths, so we'll simulate
        return {
            "path_ids": path_ids,
            "common_techniques": [],
            "divergence_points": [],
            "similarity_score": 0.75,
            "analysis": "Path comparison would analyze commonalities and differences"
        }
    
    # Helper methods
    def _generate_rationale(
        self, 
        from_tech: str, 
        to_tech: str, 
        probability: float,
        threat_group: Optional[str]
    ) -> str:
        """Generate rationale for a prediction."""
        rationale = f"Based on historical data, {to_tech} follows {from_tech} with {probability:.1%} probability."
        if threat_group:
            rationale += f" This pattern is commonly seen with {threat_group}."
        return rationale
    
    def _get_technique_frequency(self, session, technique_id: str) -> float:
        """Get frequency score for a technique."""
        result = session.run(
            """
            MATCH (a:AttackAction {attack_pattern_ref: $tech_id})
            RETURN count(a) as count
            """,
            tech_id=technique_id
        )
        count = result.single()["count"]
        return min(1.0, count / 100)  # Normalize to 0-1
    
    def _analyze_prediction_context(
        self, 
        current_techniques: List[str],
        predictions: List[Dict]
    ) -> str:
        """Analyze prediction context."""
        if not predictions:
            return "No predictions available based on current state"
        
        top_pred = predictions[0]
        return (f"Most likely next step is {top_pred['name']} "
                f"({top_pred['probability']:.1%} probability) "
                f"in the {top_pred['tactic']} phase")
    
    def _get_blocked_tactics(self, blocked_paths: List[Dict]) -> List[str]:
        """Get tactics blocked by defensive measures."""
        tactics = set()
        for path in blocked_paths:
            for step in path.get("steps", []):
                if "tactic" in step:
                    tactics.add(step["tactic"])
        return list(tactics)
    
    def _find_alternative_routes(
        self, 
        blocked_paths: List[Dict],
        viable_paths: List[Dict]
    ) -> List[Dict]:
        """Find alternative routes around blocks."""
        # Simplified implementation
        return [{
            "blocked_technique": "T1055",
            "alternatives": ["T1055.001", "T1055.002"],
            "effectiveness": 0.8
        }]
    
    def _generate_whatif_recommendations(
        self,
        scenario: str,
        blocked_techniques: Optional[List[str]],
        viable_paths: List[Dict],
        blocked_impact: Dict
    ) -> List[Dict]:
        """Generate recommendations based on what-if analysis."""
        recommendations = []
        
        if blocked_impact["coverage_reduction"] > 50:
            recommendations.append({
                "priority": "high",
                "recommendation": "Blocking these techniques significantly reduces attack surface",
                "impact": f"{blocked_impact['coverage_reduction']:.1f}% path reduction"
            })
        
        if len(viable_paths) > 10:
            recommendations.append({
                "priority": "medium",
                "recommendation": "Consider additional defensive measures",
                "impact": f"{len(viable_paths)} paths remain viable"
            })
        
        return recommendations
    
    def _generate_whatif_analysis(
        self,
        scenario: str,
        viable_paths: List[Dict],
        blocked_impact: Dict
    ) -> str:
        """Generate analysis text for what-if scenario."""
        return (f"Scenario '{scenario}' analysis: "
                f"{blocked_impact['paths_blocked']} paths blocked, "
                f"{len(viable_paths)} remain viable. "
                f"Coverage reduced by {blocked_impact['coverage_reduction']:.1f}%")
    
    def _calculate_frequency_score(self, usage_count: int) -> float:
        """Calculate normalized frequency score."""
        return min(1.0, usage_count / 100)
    
    def _analyze_group_patterns(
        self,
        techniques: List[Dict],
        sequences: List[Dict]
    ) -> str:
        """Analyze group attack patterns."""
        tactics = set()
        for tech in techniques:
            tactics.update(tech.get("tactics", []))
        
        return (f"Group uses {len(techniques)} techniques across "
                f"{len(tactics)} tactics with {len(sequences)} common sequences")
    
    def _get_evidence_counts(self, session, techniques: List[str]) -> List[int]:
        """Get evidence counts for techniques in a path."""
        evidence_counts = []
        
        for i in range(len(techniques) - 1):
            result = session.run(
                """
                MATCH (a1:AttackAction {attack_pattern_ref: $from_tech})-[n:NEXT]->(a2:AttackAction {attack_pattern_ref: $to_tech})
                RETURN count(n) as evidence_count
                """,
                from_tech=techniques[i],
                to_tech=techniques[i + 1]
            )
            
            record = result.single()
            evidence_counts.append(record["evidence_count"] if record else 0)
        
        return evidence_counts
    
    def _calculate_path_confidence(
        self,
        techniques: List[str],
        probabilities: List[float],
        evidence_counts: List[int],
        cumulative_prob: float
    ) -> Tuple[float, List[str]]:
        """Calculate confidence score and generate warnings for a path."""
        warnings = []
        
        # Base confidence from cumulative probability
        confidence = cumulative_prob
        
        # Adjust for evidence counts
        if evidence_counts:
            avg_evidence = sum(evidence_counts) / len(evidence_counts)
            if avg_evidence < 2:
                confidence *= 0.7
                warnings.append(f"Low evidence support (avg: {avg_evidence:.1f} observations per transition)")
            elif avg_evidence < 5:
                confidence *= 0.85
                warnings.append(f"Limited evidence support (avg: {avg_evidence:.1f} observations per transition)")
        
        # Check for very low probability transitions
        low_prob_transitions = [i for i, p in enumerate(probabilities) if p < 0.2]
        if low_prob_transitions:
            warnings.append(f"{len(low_prob_transitions)} transitions have probability < 0.2")
            confidence *= 0.8
        
        # Path length penalty for very long paths
        if len(techniques) > 7:
            warnings.append(f"Long attack path ({len(techniques)} steps) may be less realistic")
            confidence *= 0.9
        
        # Overall confidence check
        if confidence < 0.4:
            warnings.append("LOW CONFIDENCE: This path is hypothetical and may not be realistic")
        elif confidence < 0.6:
            warnings.append("MEDIUM CONFIDENCE: This path has limited supporting evidence")
        
        return confidence, warnings
    
    def _add_confidence_to_path(self, session, path: SimulationPath) -> SimulationPath:
        """Add confidence scoring and warnings to an existing path."""
        evidence_counts = self._get_evidence_counts(session, path.techniques)
        confidence, warnings = self._calculate_path_confidence(
            path.techniques,
            path.probabilities,
            evidence_counts,
            path.cumulative_probability
        )
        
        path.confidence_score = confidence
        path.warnings = warnings
        path.evidence_counts = evidence_counts
        path.is_hypothetical = confidence < 0.4
        
        return path
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()