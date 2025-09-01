"""Sequence analysis service for intrusion sets."""

import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from neo4j import GraphDatabase

from bandjacks.llm.sequence_extractor import SequenceExtractor
from bandjacks.llm.ptg_builder import PTGBuilder, PTGParameters, build_ptg_for_scope
from bandjacks.llm.judge_client import JudgeClient, JudgeConfig, JudgeVerdict, VerdictType
from bandjacks.llm.judge_cache import JudgeVerdictCache
from bandjacks.llm.evidence_pack import EvidencePackBuilder
from bandjacks.llm.sequence_proposal import (
    SequenceProposalBuilder, TransitionValidator, AnalystReviewFormatter
)

logger = logging.getLogger(__name__)


@dataclass
class SequenceAnalysisResult:
    """Results from sequence analysis."""
    intrusion_set_id: str
    intrusion_set_name: str
    generated_at: datetime = field(default_factory=datetime.utcnow)
    
    # PTG Model
    ptg_model_id: Optional[str] = None
    techniques_count: int = 0
    transitions_count: int = 0
    
    # Validation Results  
    validated_transitions: List[Dict] = field(default_factory=list)
    uncertain_transitions: List[Dict] = field(default_factory=list)
    unknown_count: int = 0
    
    # Sequence Proposals
    sequence_proposals: List[Dict] = field(default_factory=list)
    
    # Statistics
    statistics: Dict[str, Any] = field(default_factory=dict)
    
    # Report
    markdown_report: Optional[str] = None
    

class SequenceAnalyzer:
    """Service for analyzing attack sequences for intrusion sets."""
    
    def __init__(
        self,
        neo4j_uri: str,
        neo4j_user: str,
        neo4j_password: str,
        opensearch_url: Optional[str] = None
    ):
        """
        Initialize sequence analyzer.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            opensearch_url: Optional OpenSearch URL for evidence retrieval
        """
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        self.opensearch_url = opensearch_url
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        
    def analyze_intrusion_set(
        self,
        intrusion_set_id: str,
        use_judge: bool = True,
        max_transitions_to_judge: int = 100,
        min_confidence: float = 0.4,
        max_sequences: int = 20
    ) -> SequenceAnalysisResult:
        """
        Perform comprehensive sequence analysis for an intrusion set.
        
        Args:
            intrusion_set_id: STIX ID of the intrusion set
            use_judge: Whether to use LLM judge for validation
            max_transitions_to_judge: Maximum transitions to validate
            min_confidence: Minimum confidence for sequence proposals
            max_sequences: Maximum sequences to generate
            
        Returns:
            Analysis results
        """
        logger.info(f"Starting sequence analysis for {intrusion_set_id}")
        
        # Get intrusion set details
        intrusion_set_name = self._get_intrusion_set_name(intrusion_set_id)
        if not intrusion_set_name:
            raise ValueError(f"Intrusion set {intrusion_set_id} not found")
        
        result = SequenceAnalysisResult(
            intrusion_set_id=intrusion_set_id,
            intrusion_set_name=intrusion_set_name
        )
        
        try:
            # Step 1: Build or get PTG model
            logger.info("Building PTG model...")
            ptg_model = self._build_or_get_ptg(intrusion_set_id, use_judge)
            if ptg_model:
                result.ptg_model_id = ptg_model.get("model_id")
                result.techniques_count = ptg_model.get("total_nodes", 0)
                result.transitions_count = ptg_model.get("total_edges", 0)
            
            # Step 2: Get top transitions
            transitions = self._get_top_transitions(intrusion_set_id, max_transitions_to_judge)
            
            # Step 3: Judge transitions if enabled
            if use_judge and transitions:
                logger.info(f"Judging {len(transitions)} transitions...")
                verdicts = self._judge_transitions(
                    transitions,
                    intrusion_set_id,
                    max_transitions_to_judge
                )
                
                # Categorize verdicts
                validated, uncertain, unknown = self._categorize_verdicts(verdicts)
                result.validated_transitions = validated
                result.uncertain_transitions = uncertain
                result.unknown_count = unknown
            
            # Step 4: Generate sequence proposals
            logger.info("Generating sequence proposals...")
            proposals = self._generate_proposals(
                intrusion_set_id,
                intrusion_set_name,
                min_confidence,
                max_sequences
            )
            result.sequence_proposals = proposals
            
            # Step 5: Calculate statistics
            result.statistics = self._calculate_statistics(result)
            
            # Step 6: Generate markdown report
            result.markdown_report = self._generate_markdown_report(result)
            
        except Exception as e:
            logger.error(f"Error analyzing {intrusion_set_id}: {e}")
            raise
            
        return result
    
    def _get_intrusion_set_name(self, intrusion_set_id: str) -> Optional[str]:
        """Get intrusion set name from Neo4j."""
        with self.driver.session() as session:
            query = """
                MATCH (g:IntrusionSet {stix_id: $intrusion_set_id})
                RETURN g.name as name
                LIMIT 1
            """
            result = session.run(query, intrusion_set_id=intrusion_set_id)
            record = result.single()
            return record["name"] if record else None
    
    def _build_or_get_ptg(self, intrusion_set_id: str, use_judge: bool) -> Optional[Dict]:
        """Build or retrieve PTG model."""
        # Check if recent model exists
        with self.driver.session() as session:
            query = """
                MATCH (m:SequenceModel {scope: $scope})
                WHERE datetime() - duration({hours: 24}) < m.created_at
                RETURN m.model_id as model_id,
                       m.parameters as parameters,
                       m.statistics as statistics,
                       m.created_at as created_at
                ORDER BY m.created_at DESC
                LIMIT 1
            """
            result = session.run(query, scope=intrusion_set_id)
            record = result.single()
            
            if record:
                logger.info(f"Using existing PTG model {record['model_id']}")
                return {
                    "model_id": record["model_id"],
                    "total_nodes": json.loads(record["statistics"]).get("total_nodes", 0),
                    "total_edges": json.loads(record["statistics"]).get("total_edges", 0)
                }
        
        # Build new model
        logger.info("Building new PTG model...")
        try:
            model = build_ptg_for_scope(
                scope=intrusion_set_id,
                scope_type="intrusion-set",
                neo4j_uri=self.neo4j_uri,
                neo4j_user=self.neo4j_user,
                neo4j_password=self.neo4j_password,
                opensearch_url=self.opensearch_url,
                use_judge=use_judge
            )
            
            if model:
                return {
                    "model_id": model.model_id,
                    "total_nodes": len(model.nodes),
                    "total_edges": len(model.edges)
                }
        except Exception as e:
            logger.error(f"Failed to build PTG model: {e}")
        
        return None
    
    def _get_top_transitions(self, intrusion_set_id: str, limit: int) -> List[List[str]]:
        """Get top probability transitions from PTG model."""
        transitions = []
        
        with self.driver.session() as session:
            query = """
                MATCH (m:SequenceModel {scope: $scope})
                MATCH (t1:AttackPattern)-[r:NEXT_P {model_id: m.model_id}]->(t2:AttackPattern)
                RETURN t1.stix_id as from_tech, t2.stix_id as to_tech, r.p as probability
                ORDER BY r.p DESC
                LIMIT $limit
            """
            result = session.run(query, scope=intrusion_set_id, limit=limit)
            
            for record in result:
                transitions.append([record["from_tech"], record["to_tech"]])
        
        return transitions
    
    def _judge_transitions(
        self,
        transitions: List[List[str]],
        intrusion_set_id: str,
        max_to_judge: int
    ) -> List[JudgeVerdict]:
        """Judge transitions using LLM."""
        # Initialize judge components
        judge_cache = JudgeVerdictCache(
            self.neo4j_uri,
            self.neo4j_user,
            self.neo4j_password
        )
        
        judge_config = JudgeConfig(
            enable_caching=True,
            max_retries=2
        )
        
        judge_client = JudgeClient(config=judge_config, cache=judge_cache)
        
        evidence_builder = EvidencePackBuilder(
            neo4j_uri=self.neo4j_uri,
            neo4j_user=self.neo4j_user,
            neo4j_password=self.neo4j_password,
            opensearch_url=self.opensearch_url
        )
        
        # Judge transitions in batches
        verdicts = []
        batch_size = 5
        
        for i in range(0, min(len(transitions), max_to_judge), batch_size):
            batch = transitions[i:i + batch_size]
            
            for trans in batch:
                try:
                    # Build evidence pack
                    evidence_pack = evidence_builder.build_evidence_pack(
                        from_technique=trans[0],
                        to_technique=trans[1],
                        stats=None,  # Will be populated from Neo4j
                        top_k_evidence=3
                    )
                    
                    # Judge the pair
                    verdict = judge_client.judge_pair(evidence_pack)
                    verdicts.append(verdict)
                    
                except Exception as e:
                    logger.warning(f"Failed to judge {trans[0]} -> {trans[1]}: {e}")
        
        return verdicts
    
    def _categorize_verdicts(self, verdicts: List[JudgeVerdict]) -> Tuple[List[Dict], List[Dict], int]:
        """Categorize judge verdicts."""
        validator = TransitionValidator()
        validated_edges, uncertain_edges = validator.categorize_transitions(verdicts)
        
        # Convert to dictionaries with technique details
        validated = []
        for edge in validated_edges:
            validated.append({
                "from_technique": edge.from_technique,
                "to_technique": edge.to_technique,
                "confidence": edge.transition_confidence,
                "verdict": edge.verdict
            })
        
        uncertain = []
        for edge in uncertain_edges:
            uncertain.append({
                "from_technique": edge.from_technique,
                "to_technique": edge.to_technique,
                "transition_confidence": edge.transition_confidence,
                "judge_confidence": edge.judge_confidence
            })
        
        unknown_count = len([v for v in verdicts if v.verdict == VerdictType.UNKNOWN])
        
        return validated, uncertain, unknown_count
    
    def _generate_proposals(
        self,
        intrusion_set_id: str,
        intrusion_set_name: str,
        min_confidence: float,
        max_sequences: int
    ) -> List[Dict]:
        """Generate sequence proposals."""
        builder = SequenceProposalBuilder(
            self.neo4j_uri,
            self.neo4j_user,
            self.neo4j_password
        )
        
        try:
            # Get validated transitions from Neo4j
            with self.driver.session() as session:
                # This would need to be enhanced to get actual validated transitions
                # For now, returning empty list
                return []
                
        finally:
            builder.close()
    
    def _calculate_statistics(self, result: SequenceAnalysisResult) -> Dict[str, Any]:
        """Calculate analysis statistics."""
        total_transitions = len(result.validated_transitions) + len(result.uncertain_transitions) + result.unknown_count
        
        stats = {
            "techniques_analyzed": result.techniques_count,
            "transitions_evaluated": total_transitions,
            "validated_count": len(result.validated_transitions),
            "uncertain_count": len(result.uncertain_transitions),
            "unknown_count": result.unknown_count,
            "sequence_proposals": len(result.sequence_proposals)
        }
        
        if total_transitions > 0:
            stats["validation_rate"] = len(result.validated_transitions) / total_transitions
            stats["uncertainty_rate"] = result.unknown_count / total_transitions
        
        return stats
    
    def _generate_markdown_report(self, result: SequenceAnalysisResult) -> str:
        """Generate markdown report."""
        lines = []
        lines.append(f"# Sequence Analysis: {result.intrusion_set_name}")
        lines.append(f"\nGenerated: {result.generated_at.strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(f"\n## Summary")
        lines.append(f"- Techniques: {result.techniques_count}")
        lines.append(f"- Transitions Evaluated: {result.statistics.get('transitions_evaluated', 0)}")
        lines.append(f"- Validated: {len(result.validated_transitions)}")
        lines.append(f"- Uncertain: {len(result.uncertain_transitions)}")
        lines.append(f"- Proposals: {len(result.sequence_proposals)}")
        
        if result.validated_transitions:
            lines.append(f"\n## Validated Transitions")
            for trans in result.validated_transitions[:10]:
                lines.append(f"- {trans['from_technique'][:30]}... → {trans['to_technique'][:30]}...")
                lines.append(f"  - Confidence: {trans['confidence']:.1%}")
        
        return "\n".join(lines)
    
    def close(self):
        """Close connections."""
        if self.driver:
            self.driver.close()