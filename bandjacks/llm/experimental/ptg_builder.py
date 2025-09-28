"""Probabilistic Temporal Graph (PTG) builder with feature fusion."""

import uuid
import json
import math
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import logging
import numpy as np
from neo4j import GraphDatabase

from .sequence_extractor import PairwiseStatistics, SequenceExtractor
from bandjacks.llm.tactic_priors import TacticPriors, get_technique_tactic_prior

logger = logging.getLogger(__name__)


@dataclass
class PTGEdge:
    """Represents a PTG edge with probability and features."""
    from_technique: str
    to_technique: str
    probability: float
    features: Dict[str, Any] = field(default_factory=dict)
    rationale: Optional[str] = None
    evidence_count: int = 0
    judge_score: Optional[float] = None


@dataclass
class PTGNode:
    """Represents a PTG node (technique)."""
    technique_id: str
    name: str
    primary_tactic: Optional[str] = None
    outgoing_edges: List[PTGEdge] = field(default_factory=list)
    total_probability: float = 0.0
    
    
@dataclass
class PTGModel:
    """Complete PTG model for a scope."""
    model_id: str
    scope: str
    scope_type: str
    version: str
    nodes: Dict[str, PTGNode] = field(default_factory=dict)
    edges: List[PTGEdge] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    statistics: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass  
class PTGParameters:
    """Parameters for PTG construction."""
    alpha: float = 1.0  # Weight for conditional probability
    beta: float = 0.5   # Weight for tactic priors
    gamma: float = 0.3  # Weight for software bias (future)
    delta: float = 0.7  # Weight for observed NEXT edges
    epsilon: float = 1.0  # Weight for judge scores
    kmax_outgoing: int = 5  # Maximum outgoing edges per node
    min_probability: float = 0.01  # Minimum edge probability
    use_judge: bool = False  # Whether to use LLM judge


class PTGBuilder:
    """Builds Probabilistic Temporal Graphs from pairwise statistics."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize PTG builder.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.tactic_priors = TacticPriors()
        self.technique_cache = {}
        
    def build_ptg(
        self,
        stats: PairwiseStatistics,
        parameters: PTGParameters = None,
        judge_scores: Dict[Tuple[str, str], float] = None
    ) -> PTGModel:
        """
        Build PTG from pairwise statistics.
        
        Args:
            stats: Pairwise statistics for the scope
            parameters: PTG construction parameters
            judge_scores: Optional LLM judge scores for ambiguous pairs
            
        Returns:
            Complete PTG model
        """
        if parameters is None:
            parameters = PTGParameters()
            
        model_id = f"ptg-{uuid.uuid4().hex[:8]}"
        
        logger.info(f"Building PTG {model_id} for scope {stats.scope}")
        
        # Get technique-to-tactic mapping
        tactic_mapping = self._get_tactic_mapping(list(stats.technique_counts.keys()))
        
        # Get observed NEXT edges from Neo4j
        observed_edges = self._get_observed_next_edges(stats.scope, stats.scope_type)
        
        # Build nodes
        nodes = {}
        for technique_id in stats.technique_counts.keys():
            nodes[technique_id] = PTGNode(
                technique_id=technique_id,
                name=self._get_technique_name(technique_id),
                primary_tactic=tactic_mapping.get(technique_id)
            )
        
        # Build edges with feature fusion
        edges = []
        
        for from_tech in stats.technique_counts.keys():
            tech_edges = []
            
            # Calculate scores for all possible next techniques
            for to_tech in stats.technique_counts.keys():
                if from_tech == to_tech:
                    continue  # Skip self-loops
                
                edge_score = self._calculate_edge_score(
                    from_tech, to_tech, stats, tactic_mapping,
                    parameters, observed_edges, judge_scores
                )
                
                # Always include edges for softmax normalization
                # We'll filter by min_probability after normalization
                tech_edges.append((to_tech, edge_score, self._build_features(
                    from_tech, to_tech, stats, tactic_mapping, 
                    parameters, observed_edges, judge_scores
                )))
            
            # Apply softmax normalization and keep top-K
            if tech_edges:
                probabilities = self._softmax_normalize([score for _, score, _ in tech_edges])
                
                # Sort by probability and take top-K
                normalized_edges = list(zip(
                    [tech for tech, _, _ in tech_edges],
                    probabilities,
                    [features for _, _, features in tech_edges]
                ))
                
                normalized_edges.sort(key=lambda x: x[1], reverse=True)
                top_edges = normalized_edges[:parameters.kmax_outgoing]
                
                # Create PTG edges
                for to_tech, prob, features in top_edges:
                    if prob >= parameters.min_probability:
                        edge = PTGEdge(
                            from_technique=from_tech,
                            to_technique=to_tech,
                            probability=prob,
                            features=features,
                            evidence_count=stats.pair_counts.get((from_tech, to_tech), 0),
                            judge_score=judge_scores.get((from_tech, to_tech)) if judge_scores else None,
                            rationale=self._generate_edge_rationale(
                                from_tech, to_tech, prob, features
                            )
                        )
                        
                        edges.append(edge)
                        nodes[from_tech].outgoing_edges.append(edge)
                        nodes[from_tech].total_probability += prob
        
        # Build model
        model = PTGModel(
            model_id=model_id,
            scope=stats.scope,
            scope_type=stats.scope_type,
            version=datetime.utcnow().strftime("%Y%m%d-%H%M%S"),
            nodes=nodes,
            edges=edges,
            parameters=parameters.__dict__,
            statistics={
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "avg_outgoing_edges": sum(len(n.outgoing_edges) for n in nodes.values()) / len(nodes),
                "source_flows": stats.total_flows,
                "source_pairs": stats.total_pairs
            }
        )
        
        logger.info(f"Built PTG {model_id}: {len(nodes)} nodes, {len(edges)} edges")
        return model
        
    def _calculate_edge_score(
        self,
        from_tech: str,
        to_tech: str,
        stats: PairwiseStatistics,
        tactic_mapping: Dict[str, str],
        parameters: PTGParameters,
        observed_edges: Dict[Tuple[str, str], float],
        judge_scores: Optional[Dict[Tuple[str, str], float]]
    ) -> float:
        """Calculate weighted score for a potential edge."""
        
        # Component 1: Conditional probability (with Laplace smoothing)
        pair_count = stats.pair_counts.get((from_tech, to_tech), 0)
        from_count = stats.technique_counts[from_tech]
        vocab_size = len(stats.technique_counts)
        
        conditional_prob = (pair_count + 1) / (from_count + vocab_size)
        
        # Component 2: Tactic prior
        tactic_prior = get_technique_tactic_prior(from_tech, to_tech, tactic_mapping)
        
        # Component 3: Observed edge weight
        observed_weight = observed_edges.get((from_tech, to_tech), 0.0)
        
        # Component 4: Judge score (if available)
        judge_weight = 0.0
        if judge_scores and (from_tech, to_tech) in judge_scores:
            judge_weight = judge_scores[(from_tech, to_tech)]
        
        # Feature fusion with logit transform
        logit_score = (
            parameters.alpha * self._logit(conditional_prob) +
            parameters.beta * self._logit(tactic_prior) +
            parameters.delta * observed_weight +
            parameters.epsilon * judge_weight
        )
        
        return logit_score
    
    def _logit(self, p: float) -> float:
        """Safe logit transform."""
        p = max(1e-8, min(1-1e-8, p))  # Clamp to avoid infinity
        return math.log(p / (1 - p))
    
    def _softmax_normalize(self, scores: List[float]) -> List[float]:
        """Apply softmax normalization to scores."""
        if not scores:
            return []
            
        # Subtract max for numerical stability
        max_score = max(scores)
        exp_scores = [math.exp(s - max_score) for s in scores]
        
        total = sum(exp_scores)
        if total == 0:
            return [1.0 / len(scores)] * len(scores)  # Uniform if all zero
        
        return [exp_s / total for exp_s in exp_scores]
    
    def _build_features(
        self,
        from_tech: str,
        to_tech: str,
        stats: PairwiseStatistics,
        tactic_mapping: Dict[str, str],
        parameters: PTGParameters,
        observed_edges: Dict[Tuple[str, str], float],
        judge_scores: Optional[Dict[Tuple[str, str], float]]
    ) -> Dict[str, Any]:
        """Build feature vector for an edge."""
        
        pair_count = stats.pair_counts.get((from_tech, to_tech), 0)
        conditional_prob = stats.conditional_probs.get((from_tech, to_tech), 0.0)
        asymmetry = stats.asymmetry_scores.get((from_tech, to_tech), 0.0)
        
        features = {
            "pair_count": pair_count,
            "conditional_prob": conditional_prob,
            "tactic_prior": get_technique_tactic_prior(from_tech, to_tech, tactic_mapping),
            "asymmetry": asymmetry,
            "observed_edge": observed_edges.get((from_tech, to_tech), 0.0),
            "from_tactic": tactic_mapping.get(from_tech),
            "to_tactic": tactic_mapping.get(to_tech),
            "weights": {
                "alpha": parameters.alpha,
                "beta": parameters.beta,
                "delta": parameters.delta,
                "epsilon": parameters.epsilon if parameters.use_judge else 0.0
            }
        }
        
        if judge_scores and (from_tech, to_tech) in judge_scores:
            features["judge_score"] = judge_scores[(from_tech, to_tech)]
            # Mark confidence level based on judge score
            # Judge returns 0.1 for unknown verdicts (low confidence)
            if features["judge_score"] <= 0.1:
                features["confidence_level"] = "low"
                features["needs_validation"] = True
            elif features["judge_score"] >= 0.7:
                features["confidence_level"] = "high"
                features["needs_validation"] = False
            else:
                features["confidence_level"] = "medium"
                features["needs_validation"] = False
        
        return features
    
    def _generate_edge_rationale(
        self,
        from_tech: str,
        to_tech: str,
        probability: float,
        features: Dict[str, Any]
    ) -> str:
        """Generate human-readable rationale for an edge."""
        
        rationale_parts = []
        
        # Primary evidence
        if features["pair_count"] > 0:
            rationale_parts.append(f"observed in {features['pair_count']} flow(s)")
        
        # Tactic progression
        if features.get("from_tactic") and features.get("to_tactic"):
            from_tactic = features["from_tactic"]
            to_tactic = features["to_tactic"]
            tactic_rationale = self.tactic_priors.get_transition_rationale(from_tactic, to_tactic)
            rationale_parts.append(f"tactic progression: {tactic_rationale}")
        
        # Judge input
        if "judge_score" in features:
            judge_score = features["judge_score"]
            if judge_score > 0.5:
                rationale_parts.append("LLM judge supports this direction")
            elif judge_score < -0.5:
                rationale_parts.append("LLM judge questions this direction")
            elif judge_score <= 0.1:
                rationale_parts.append("LLM judge returned unknown (insufficient evidence)")
        
        # Confidence assessment based on features
        if features.get("confidence_level"):
            confidence = f"{features['confidence_level']} confidence"
            if features.get("needs_validation"):
                confidence += " (needs validation)"
        elif probability > 0.7:
            confidence = "high confidence"
        elif probability > 0.4:
            confidence = "moderate confidence"
        else:
            confidence = "low confidence"
        
        rationale = f"Transition probability {probability:.3f} ({confidence}). " + "; ".join(rationale_parts)
        
        return rationale
    
    def _get_tactic_mapping(self, technique_ids: List[str]) -> Dict[str, str]:
        """Get technique -> primary tactic mapping."""
        tactic_mapping = {}
        
        with self.driver.session() as session:
            query = """
                MATCH (t:AttackPattern)-[:HAS_TACTIC]->(tac:Tactic)
                WHERE t.stix_id IN $technique_ids
                WITH t.stix_id as technique_id, collect(tac.shortname) as tactics
                RETURN technique_id, tactics[0] as primary_tactic
            """
            
            result = session.run(query, technique_ids=technique_ids)
            
            for record in result:
                tactic_mapping[record["technique_id"]] = record["primary_tactic"]
        
        return tactic_mapping
    
    def _get_technique_name(self, technique_id: str) -> str:
        """Get technique name (cached)."""
        if technique_id in self.technique_cache:
            return self.technique_cache[technique_id]
        
        with self.driver.session() as session:
            query = "MATCH (t:AttackPattern {stix_id: $tech_id}) RETURN t.name as name"
            result = session.run(query, tech_id=technique_id)
            record = result.single()
            
            name = record["name"] if record else "Unknown"
            self.technique_cache[technique_id] = name
            
        return name
    
    def _get_observed_next_edges(
        self,
        scope: str,
        scope_type: str
    ) -> Dict[Tuple[str, str], float]:
        """Get existing NEXT edges from Neo4j for this scope."""
        observed_edges = {}
        
        with self.driver.session() as session:
            if scope_type == "intrusion-set" and scope != "global":
                # Scope to specific intrusion set
                query = """
                    MATCH (e:AttackEpisode)-[:ATTRIBUTED_TO]->(g:IntrusionSet {stix_id: $scope})
                    MATCH (e)-[:CONTAINS]->(a1:AttackAction)-[n:NEXT]->(a2:AttackAction)
                    WITH a1.attack_pattern_ref as from_tech, 
                         a2.attack_pattern_ref as to_tech,
                         avg(n.p) as avg_prob
                    RETURN from_tech, to_tech, avg_prob
                """
                result = session.run(query, scope=scope)
            else:
                # Global scope
                query = """
                    MATCH (a1:AttackAction)-[n:NEXT]->(a2:AttackAction)
                    WITH a1.attack_pattern_ref as from_tech,
                         a2.attack_pattern_ref as to_tech,
                         avg(n.p) as avg_prob
                    RETURN from_tech, to_tech, avg_prob
                """
                result = session.run(query)
            
            for record in result:
                from_tech = record["from_tech"]
                to_tech = record["to_tech"]
                if from_tech and to_tech:
                    observed_edges[(from_tech, to_tech)] = record["avg_prob"] or 0.5
        
        logger.debug(f"Found {len(observed_edges)} observed NEXT edges for scope {scope}")
        return observed_edges
    
    def persist_ptg(self, model: PTGModel) -> bool:
        """
        Persist PTG model to Neo4j.
        
        Args:
            model: PTG model to persist
            
        Returns:
            True if successful
        """
        try:
            with self.driver.session() as session:
                # Create sequence model node
                create_model_query = """
                    CREATE (m:SequenceModel {
                        model_id: $model_id,
                        scope: $scope,
                        scope_type: $scope_type,
                        version: $version,
                        created_at: datetime(),
                        total_nodes: $total_nodes,
                        total_edges: $total_edges,
                        parameters: $parameters,
                        statistics: $statistics
                    })
                    RETURN m.model_id as model_id
                """
                
                session.run(create_model_query, {
                    "model_id": model.model_id,
                    "scope": model.scope,
                    "scope_type": model.scope_type,
                    "version": model.version,
                    "total_nodes": model.statistics["total_nodes"],
                    "total_edges": model.statistics["total_edges"],
                    "parameters": json.dumps(model.parameters),
                    "statistics": json.dumps(model.statistics)
                })
                
                # Create NEXT_P edges between techniques
                for edge in model.edges:
                    create_edge_query = """
                        MATCH (t1:AttackPattern {stix_id: $from_tech})
                        MATCH (t2:AttackPattern {stix_id: $to_tech})
                        MERGE (t1)-[r:NEXT_P {
                            model_id: $model_id,
                            p: $probability,
                            features: $features,
                            rationale: $rationale,
                            evidence_count: $evidence_count,
                            created_at: datetime()
                        }]->(t2)
                        RETURN r
                    """
                    
                    session.run(create_edge_query, {
                        "model_id": model.model_id,
                        "from_tech": edge.from_technique,
                        "to_tech": edge.to_technique,
                        "probability": edge.probability,
                        "features": json.dumps(edge.features),
                        "rationale": edge.rationale,
                        "evidence_count": edge.evidence_count
                    })
                
                logger.info(f"Persisted PTG {model.model_id} with {len(model.edges)} NEXT_P edges")
                return True
                
        except Exception as e:
            logger.error(f"Failed to persist PTG {model.model_id}: {e}")
            return False
    
    def load_ptg(self, model_id: str) -> Optional[PTGModel]:
        """
        Load PTG model from Neo4j.
        
        Args:
            model_id: Model identifier
            
        Returns:
            PTG model if found
        """
        with self.driver.session() as session:
            # Load model metadata
            model_query = """
                MATCH (m:SequenceModel {model_id: $model_id})
                RETURN m.model_id as model_id,
                       m.scope as scope,
                       m.scope_type as scope_type,
                       m.version as version,
                       m.parameters as parameters,
                       m.statistics as statistics,
                       m.created_at as created_at
            """
            
            result = session.run(model_query, model_id=model_id)
            record = result.single()
            
            if not record:
                return None
            
            # Load edges
            edges_query = """
                MATCH (t1:AttackPattern)-[r:NEXT_P {model_id: $model_id}]->(t2:AttackPattern)
                RETURN t1.stix_id as from_tech,
                       t2.stix_id as to_tech,
                       r.p as probability,
                       r.features as features,
                       r.rationale as rationale,
                       r.evidence_count as evidence_count
            """
            
            edges_result = session.run(edges_query, model_id=model_id)
            
            edges = []
            nodes = {}
            
            for edge_record in edges_result:
                from_tech = edge_record["from_tech"]
                to_tech = edge_record["to_tech"]
                
                # Ensure nodes exist
                if from_tech not in nodes:
                    nodes[from_tech] = PTGNode(
                        technique_id=from_tech,
                        name=self._get_technique_name(from_tech)
                    )
                
                if to_tech not in nodes:
                    nodes[to_tech] = PTGNode(
                        technique_id=to_tech,
                        name=self._get_technique_name(to_tech)
                    )
                
                # Create edge
                edge = PTGEdge(
                    from_technique=from_tech,
                    to_technique=to_tech,
                    probability=edge_record["probability"],
                    features=json.loads(edge_record["features"] or "{}"),
                    rationale=edge_record["rationale"],
                    evidence_count=edge_record["evidence_count"] or 0
                )
                
                edges.append(edge)
                nodes[from_tech].outgoing_edges.append(edge)
                nodes[from_tech].total_probability += edge.probability
            
            # Reconstruct model
            model = PTGModel(
                model_id=record["model_id"],
                scope=record["scope"],
                scope_type=record["scope_type"],
                version=record["version"],
                nodes=nodes,
                edges=edges,
                parameters=json.loads(record["parameters"] or "{}"),
                statistics=json.loads(record["statistics"] or "{}"),
                created_at=record["created_at"]
            )
            
            return model
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()


def build_ptg_for_scope(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    scope: str,
    scope_type: str = "global",
    parameters: PTGParameters = None,
    opensearch_url: str = None,
    opensearch_index: str = None
) -> Optional[PTGModel]:
    """
    Convenience function to build PTG for a specific scope.
    
    Args:
        neo4j_uri: Neo4j connection URI
        neo4j_user: Neo4j username
        neo4j_password: Neo4j password
        scope: Scope identifier  
        scope_type: Type of scope
        parameters: PTG parameters
        opensearch_url: OpenSearch URL for evidence (required if use_judge=True)
        opensearch_index: OpenSearch index (required if use_judge=True)
        
    Returns:
        Built PTG model or None if failed
    """
    extractor = SequenceExtractor(neo4j_uri, neo4j_user, neo4j_password)
    builder = PTGBuilder(neo4j_uri, neo4j_user, neo4j_password)
    
    try:
        # Extract sequences
        sequences = extractor.extract_all_sequences(include_cooccurrence=True)
        
        # Compute statistics for scope
        if scope_type == "intrusion-set":
            stats = extractor.compute_pairwise_statistics(sequences, scope, scope_type)
        else:
            stats = extractor.compute_pairwise_statistics(sequences, "global", "global")
        
        judge_scores = None
        
        # If judge is enabled, get judge verdicts for ambiguous pairs
        if parameters and parameters.use_judge:
            logger.info("Judge integration enabled - processing ambiguous pairs")
            
            # Import here to avoid circular dependency
            from .judge_client import JudgeClient, JudgeConfig
            from .judge_cache import JudgeVerdictCache
            from .evidence_pack import EvidencePackBuilder
            from .triage import PairTriage, TriageConfig
            from .judge_integration import JudgeScoreConverter
            
            # Initialize components
            judge_cache = JudgeVerdictCache(neo4j_uri, neo4j_user, neo4j_password)
            judge_client = JudgeClient(config=JudgeConfig(enable_caching=True), cache=judge_cache)
            
            if opensearch_url and opensearch_index:
                evidence_builder = EvidencePackBuilder(
                    neo4j_uri, neo4j_user, neo4j_password,
                    opensearch_url, opensearch_index
                )
            else:
                logger.warning("OpenSearch not configured - judge will use limited evidence")
                evidence_builder = EvidencePackBuilder(
                    neo4j_uri, neo4j_user, neo4j_password
                )
            
            # Find ambiguous pairs
            ambiguous_pairs = extractor.find_ambiguous_pairs(
                stats, 
                ambiguity_threshold=0.15,
                min_count=3
            )
            
            logger.info(f"Found {len(ambiguous_pairs)} ambiguous pairs for judging")
            
            # Get judge verdicts
            verdicts = []
            score_converter = JudgeScoreConverter()
            judge_scores = {}
            
            for from_tech, to_tech in ambiguous_pairs[:50]:  # Limit to 50 pairs
                try:
                    # Build evidence pack
                    evidence_pack = evidence_builder.build_evidence_pack(
                        from_technique=from_tech,
                        to_technique=to_tech,
                        stats=stats,
                        top_k_evidence=3
                    )
                    
                    # Get verdict
                    verdict = judge_client.judge_pair(evidence_pack)
                    verdicts.append(verdict)
                    
                    # Convert to score
                    judge_score = score_converter.convert_verdict_to_score(verdict)
                    judge_scores[(from_tech, to_tech)] = judge_score.score
                    
                except Exception as e:
                    logger.warning(f"Failed to judge pair {from_tech} -> {to_tech}: {e}")
            
            logger.info(f"Obtained {len(verdicts)} judge verdicts")
        
        # Build PTG with optional judge scores
        model = builder.build_ptg(stats, parameters, judge_scores)
        
        # Persist to Neo4j
        success = builder.persist_ptg(model)
        
        if success:
            logger.info(f"Successfully built and persisted PTG {model.model_id}")
            return model
        else:
            logger.error(f"Failed to persist PTG {model.model_id}")
            return None
            
    except Exception as e:
        logger.error(f"Failed to build PTG for scope {scope}: {e}")
        return None
        
    finally:
        extractor.close()
        builder.close()