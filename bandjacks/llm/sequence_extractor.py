"""Flow sequence extraction and pairwise statistics calculation."""

import uuid
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import json
import logging
from datetime import datetime
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


@dataclass
class TechniquePair:
    """Represents a technique transition pair."""
    from_technique: str
    to_technique: str
    from_tactic: Optional[str] = None
    to_tactic: Optional[str] = None
    count: int = 1
    flows: List[str] = field(default_factory=list)
    evidence_sources: List[str] = field(default_factory=list)


@dataclass 
class FlowSequence:
    """Extracted sequence from an attack flow."""
    flow_id: str
    episode_id: str
    intrusion_set_id: Optional[str] = None
    techniques: List[str] = field(default_factory=list)
    pairs: List[TechniquePair] = field(default_factory=list)
    flow_type: str = "sequential"  # or "co-occurrence"
    confidence: float = 1.0


@dataclass
class PairwiseStatistics:
    """Statistical analysis of technique pairs per scope."""
    scope: str  # intrusion_set_id or "global"
    scope_type: str  # "intrusion-set" or "global" 
    technique_counts: Dict[str, int] = field(default_factory=dict)
    pair_counts: Dict[Tuple[str, str], int] = field(default_factory=dict)
    conditional_probs: Dict[Tuple[str, str], float] = field(default_factory=dict)
    asymmetry_scores: Dict[Tuple[str, str], float] = field(default_factory=dict)
    total_flows: int = 0
    total_techniques: int = 0
    total_pairs: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)


class SequenceExtractor:
    """Extract technique sequences and compute pairwise statistics from attack flows."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize sequence extractor.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username  
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.technique_cache = {}
        
    def extract_all_sequences(self, include_cooccurrence: bool = True) -> List[FlowSequence]:
        """
        Extract sequences from all attack flows in Neo4j.
        
        Args:
            include_cooccurrence: Whether to include co-occurrence flows
            
        Returns:
            List of extracted flow sequences
        """
        sequences = []
        
        with self.driver.session() as session:
            # Get all attack episodes with their flows
            query = """
                MATCH (e:AttackEpisode)
                OPTIONAL MATCH (e)-[:ATTRIBUTED_TO]->(g:IntrusionSet)
                RETURN e.episode_id as episode_id, 
                       e.flow_id as flow_id,
                       e.flow_type as flow_type,
                       e.sequence_inferred as sequence_inferred,
                       g.stix_id as intrusion_set_id,
                       e.created as created_at
                ORDER BY e.created DESC
            """
            
            result = session.run(query)
            
            for record in result:
                episode_id = record["episode_id"]
                flow_id = record["flow_id"]
                flow_type = record["flow_type"] or "sequential"
                sequence_inferred = record["sequence_inferred"]
                intrusion_set_id = record["intrusion_set_id"]
                
                # Skip co-occurrence flows if not requested
                if not include_cooccurrence and flow_type == "co-occurrence":
                    continue
                
                # Extract sequence for this flow
                sequence = self._extract_flow_sequence(
                    session, episode_id, flow_id, intrusion_set_id, flow_type
                )
                
                if sequence and len(sequence.techniques) > 1:
                    sequences.append(sequence)
                    
        logger.info(f"Extracted {len(sequences)} flow sequences")
        return sequences
    
    def _extract_flow_sequence(
        self,
        session, 
        episode_id: str,
        flow_id: str,
        intrusion_set_id: Optional[str],
        flow_type: str
    ) -> Optional[FlowSequence]:
        """Extract technique sequence from a single flow episode."""
        
        # Get actions for this episode in order
        query = """
            MATCH (e:AttackEpisode {episode_id: $episode_id})-[:CONTAINS]->(a:AttackAction)
            RETURN a.action_id as action_id,
                   a.attack_pattern_ref as technique_id,
                   a.order as order,
                   a.confidence as confidence,
                   a.evidence as evidence
            ORDER BY COALESCE(a.order, 999), a.action_id
        """
        
        result = session.run(query, episode_id=episode_id)
        actions = list(result)
        
        if len(actions) < 2:
            return None
            
        # Build technique sequence
        techniques = []
        confidences = []
        
        for action in actions:
            technique_id = action["technique_id"]
            if technique_id and technique_id not in techniques:  # Avoid duplicates
                techniques.append(technique_id)
                confidences.append(action["confidence"] or 50.0)
        
        if len(techniques) < 2:
            return None
        
        # Create technique pairs
        pairs = []
        for i in range(len(techniques) - 1):
            from_tech = techniques[i]
            to_tech = techniques[i + 1]
            
            # Get tactic information
            from_tactic = self._get_primary_tactic(session, from_tech)
            to_tactic = self._get_primary_tactic(session, to_tech)
            
            pair = TechniquePair(
                from_technique=from_tech,
                to_technique=to_tech,
                from_tactic=from_tactic,
                to_tactic=to_tactic,
                flows=[flow_id],
                evidence_sources=[episode_id]
            )
            pairs.append(pair)
        
        # Calculate overall confidence
        avg_confidence = sum(confidences) / len(confidences) if confidences else 50.0
        
        sequence = FlowSequence(
            flow_id=flow_id,
            episode_id=episode_id,
            intrusion_set_id=intrusion_set_id,
            techniques=techniques,
            pairs=pairs,
            flow_type=flow_type,
            confidence=avg_confidence / 100.0  # Normalize to 0-1
        )
        
        return sequence
    
    def _get_primary_tactic(self, session, technique_id: str) -> Optional[str]:
        """Get primary tactic for a technique (cached)."""
        if technique_id in self.technique_cache:
            return self.technique_cache[technique_id]
        
        query = """
            MATCH (t:AttackPattern {stix_id: $technique_id})-[:HAS_TACTIC]->(tac:Tactic)
            RETURN tac.shortname as tactic
            LIMIT 1
        """
        
        result = session.run(query, technique_id=technique_id)
        record = result.single()
        
        tactic = record["tactic"] if record else None
        self.technique_cache[technique_id] = tactic
        
        return tactic
    
    def compute_pairwise_statistics(
        self, 
        sequences: List[FlowSequence],
        scope: str = "global",
        scope_type: str = "global"
    ) -> PairwiseStatistics:
        """
        Compute pairwise transition statistics for a set of sequences.
        
        Args:
            sequences: List of flow sequences
            scope: Scope identifier (intrusion_set_id or "global")
            scope_type: Type of scope ("intrusion-set" or "global")
            
        Returns:
            Pairwise statistics for the scope
        """
        technique_counts = Counter()
        pair_counts = Counter()
        
        # Filter sequences by scope
        if scope_type == "intrusion-set" and scope != "global":
            sequences = [s for s in sequences if s.intrusion_set_id == scope]
        
        # Count techniques and pairs
        for sequence in sequences:
            for technique in sequence.techniques:
                technique_counts[technique] += 1
            
            for pair in sequence.pairs:
                pair_key = (pair.from_technique, pair.to_technique)
                pair_counts[pair_key] += 1
        
        # Calculate conditional probabilities with Laplace smoothing
        conditional_probs = {}
        asymmetry_scores = {}
        
        vocabulary_size = len(technique_counts)
        
        for (from_tech, to_tech), count in pair_counts.items():
            # P(to_tech | from_tech) with Laplace smoothing
            numerator = count + 1  # Add 1 for smoothing
            denominator = technique_counts[from_tech] + vocabulary_size
            conditional_probs[(from_tech, to_tech)] = numerator / denominator
            
            # Calculate asymmetry: |P(j|i) - P(i|j)|
            reverse_count = pair_counts.get((to_tech, from_tech), 0)
            reverse_prob = (reverse_count + 1) / (technique_counts[to_tech] + vocabulary_size)
            
            asymmetry = abs(conditional_probs[(from_tech, to_tech)] - reverse_prob)
            asymmetry_scores[(from_tech, to_tech)] = asymmetry
        
        stats = PairwiseStatistics(
            scope=scope,
            scope_type=scope_type,
            technique_counts=dict(technique_counts),
            pair_counts=dict(pair_counts),
            conditional_probs=conditional_probs,
            asymmetry_scores=asymmetry_scores,
            total_flows=len(sequences),
            total_techniques=len(technique_counts),
            total_pairs=len(pair_counts)
        )
        
        logger.info(f"Computed statistics for {scope}: {stats.total_pairs} pairs from {stats.total_flows} flows")
        return stats
    
    def extract_by_intrusion_set(self, sequences: List[FlowSequence]) -> Dict[str, PairwiseStatistics]:
        """Extract pairwise statistics grouped by intrusion set."""
        intrusion_sets = set()
        
        # Collect all intrusion sets
        for sequence in sequences:
            if sequence.intrusion_set_id:
                intrusion_sets.add(sequence.intrusion_set_id)
        
        # Compute statistics for each intrusion set
        intrusion_set_stats = {}
        
        for intrusion_set_id in intrusion_sets:
            stats = self.compute_pairwise_statistics(
                sequences, 
                scope=intrusion_set_id,
                scope_type="intrusion-set"
            )
            intrusion_set_stats[intrusion_set_id] = stats
        
        # Also compute global statistics
        global_stats = self.compute_pairwise_statistics(
            sequences,
            scope="global", 
            scope_type="global"
        )
        intrusion_set_stats["global"] = global_stats
        
        return intrusion_set_stats
    
    def find_ambiguous_pairs(
        self, 
        stats: PairwiseStatistics,
        ambiguity_threshold: float = 0.15,
        min_count: int = 3
    ) -> List[Tuple[str, str]]:
        """
        Find technique pairs that are ambiguous in direction.
        
        Args:
            stats: Pairwise statistics to analyze
            ambiguity_threshold: Maximum asymmetry score for ambiguous pairs
            min_count: Minimum pair count to consider
            
        Returns:
            List of ambiguous technique pairs
        """
        ambiguous_pairs = []
        
        for (from_tech, to_tech), asymmetry in stats.asymmetry_scores.items():
            pair_count = stats.pair_counts.get((from_tech, to_tech), 0)
            
            if asymmetry <= ambiguity_threshold and pair_count >= min_count:
                ambiguous_pairs.append((from_tech, to_tech))
        
        logger.info(f"Found {len(ambiguous_pairs)} ambiguous pairs (threshold={ambiguity_threshold})")
        return ambiguous_pairs
    
    def export_statistics_to_neo4j(
        self, 
        stats_dict: Dict[str, PairwiseStatistics],
        model_version: str = None
    ) -> str:
        """
        Export pairwise statistics to Neo4j for persistence.
        
        Args:
            stats_dict: Dictionary of scope -> statistics
            model_version: Version identifier for this model
            
        Returns:
            Model ID for the exported statistics
        """
        model_id = f"seq-model-{uuid.uuid4().hex[:8]}"
        model_version = model_version or datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        
        with self.driver.session() as session:
            # Create sequence model metadata
            create_model_query = """
                CREATE (m:SequenceModel {
                    model_id: $model_id,
                    version: $version,
                    created_at: datetime(),
                    scope_count: $scope_count,
                    total_flows: $total_flows,
                    total_pairs: $total_pairs,
                    params: $params
                })
                RETURN m.model_id as model_id
            """
            
            total_flows = sum(s.total_flows for s in stats_dict.values())
            total_pairs = sum(s.total_pairs for s in stats_dict.values())
            
            session.run(create_model_query, {
                "model_id": model_id,
                "version": model_version,
                "scope_count": len(stats_dict),
                "total_flows": total_flows,
                "total_pairs": total_pairs,
                "params": json.dumps({
                    "laplace_smoothing": True,
                    "ambiguity_threshold": 0.15,
                    "min_count": 3
                })
            })
            
            # Store statistics for each scope
            for scope, stats in stats_dict.items():
                self._store_scope_statistics(session, model_id, scope, stats)
        
        logger.info(f"Exported sequence model {model_id} with {len(stats_dict)} scopes")
        return model_id
    
    def _store_scope_statistics(
        self, 
        session,
        model_id: str, 
        scope: str,
        stats: PairwiseStatistics
    ):
        """Store statistics for a specific scope."""
        
        # Create scope statistics node
        create_scope_query = """
            MATCH (m:SequenceModel {model_id: $model_id})
            CREATE (s:SequenceStatistics {
                scope: $scope,
                scope_type: $scope_type,
                model_id: $model_id,
                total_flows: $total_flows,
                total_techniques: $total_techniques,
                total_pairs: $total_pairs,
                created_at: datetime(),
                technique_counts: $technique_counts,
                conditional_probs: $conditional_probs,
                asymmetry_scores: $asymmetry_scores
            })
            CREATE (m)-[:HAS_SCOPE]->(s)
            RETURN s.scope as scope
        """
        
        session.run(create_scope_query, {
            "model_id": model_id,
            "scope": scope,
            "scope_type": stats.scope_type,
            "total_flows": stats.total_flows,
            "total_techniques": stats.total_techniques,
            "total_pairs": stats.total_pairs,
            "technique_counts": json.dumps(stats.technique_counts),
            "conditional_probs": json.dumps({f"{k[0]}→{k[1]}": v for k, v in stats.conditional_probs.items()}),
            "asymmetry_scores": json.dumps({f"{k[0]}→{k[1]}": v for k, v in stats.asymmetry_scores.items()})
        })
        
        logger.debug(f"Stored statistics for scope {scope}: {stats.total_pairs} pairs")
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()


def extract_sequences_from_flows(
    neo4j_uri: str,
    neo4j_user: str, 
    neo4j_password: str,
    include_cooccurrence: bool = True
) -> Dict[str, PairwiseStatistics]:
    """
    Convenience function to extract sequences and compute statistics.
    
    Args:
        neo4j_uri: Neo4j connection URI
        neo4j_user: Neo4j username
        neo4j_password: Neo4j password
        include_cooccurrence: Whether to include co-occurrence flows
        
    Returns:
        Dictionary mapping scope -> pairwise statistics
    """
    extractor = SequenceExtractor(neo4j_uri, neo4j_user, neo4j_password)
    
    try:
        # Extract all sequences
        sequences = extractor.extract_all_sequences(include_cooccurrence)
        
        # Compute statistics by intrusion set
        stats_dict = extractor.extract_by_intrusion_set(sequences)
        
        return stats_dict
        
    finally:
        extractor.close()