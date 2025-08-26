"""Integration layer for converting LLM judge verdicts into PTG features."""

import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime

from .judge_client import JudgeVerdict, VerdictType
from .triage import TriagedPair, PairTriage
from .evidence_pack import EvidencePackBuilder
from .ptg_builder import PTGBuilder, PTGParameters
from .sequence_extractor import PairwiseStatistics

logger = logging.getLogger(__name__)


@dataclass
class JudgeScore:
    """Numerical score derived from judge verdict."""
    from_technique: str
    to_technique: str
    score: float  # -1.0 to 1.0 (negative = reverse direction)
    confidence: float  # 0.0 to 1.0
    verdict_type: VerdictType
    evidence_strength: float  # Based on evidence count and quality
    
    
class JudgeScoreConverter:
    """Converts judge verdicts to numerical scores for PTG integration."""
    
    def __init__(self, confidence_weight: float = 0.8, evidence_weight: float = 0.2):
        """
        Initialize score converter.
        
        Args:
            confidence_weight: Weight for judge confidence in score calculation
            evidence_weight: Weight for evidence strength in score calculation
        """
        self.confidence_weight = confidence_weight
        self.evidence_weight = evidence_weight
    
    def convert_verdict_to_score(
        self,
        verdict: JudgeVerdict,
        evidence_pack_size: int = 0
    ) -> JudgeScore:
        """
        Convert a single judge verdict to numerical score.
        
        Args:
            verdict: Judge verdict from LLM
            evidence_pack_size: Number of evidence snippets used
            
        Returns:
            Numerical score for PTG integration
        """
        # Base score from verdict type and confidence
        base_score = self._verdict_to_base_score(verdict.verdict, verdict.confidence)
        
        # Evidence strength based on citation count and evidence quality
        evidence_strength = self._calculate_evidence_strength(
            verdict.evidence_ids, evidence_pack_size
        )
        
        # Final score combines base score with evidence strength
        final_score = base_score * (
            self.confidence_weight * verdict.confidence +
            self.evidence_weight * evidence_strength
        )
        
        # Clamp to valid range
        final_score = max(-1.0, min(1.0, final_score))
        
        return JudgeScore(
            from_technique=verdict.from_technique,
            to_technique=verdict.to_technique,
            score=final_score,
            confidence=verdict.confidence,
            verdict_type=verdict.verdict,
            evidence_strength=evidence_strength
        )
    
    def batch_convert_verdicts(
        self,
        verdicts: List[JudgeVerdict],
        evidence_pack_sizes: Optional[Dict[Tuple[str, str], int]] = None
    ) -> Dict[Tuple[str, str], JudgeScore]:
        """
        Convert multiple verdicts to score dictionary.
        
        Args:
            verdicts: List of judge verdicts
            evidence_pack_sizes: Optional evidence pack sizes by pair
            
        Returns:
            Dictionary mapping (from_tech, to_tech) -> JudgeScore
        """
        scores = {}
        
        for verdict in verdicts:
            pair_key = (verdict.from_technique, verdict.to_technique)
            
            evidence_size = 0
            if evidence_pack_sizes and pair_key in evidence_pack_sizes:
                evidence_size = evidence_pack_sizes[pair_key]
            
            score = self.convert_verdict_to_score(verdict, evidence_size)
            scores[pair_key] = score
            
        logger.info(f"Converted {len(verdicts)} verdicts to numerical scores")
        return scores
    
    def _verdict_to_base_score(self, verdict: VerdictType, confidence: float) -> float:
        """Convert verdict type to base directional score."""
        if verdict == VerdictType.FORWARD:  # i->j
            return 1.0 * confidence
        elif verdict == VerdictType.REVERSE:  # j->i  
            return -1.0 * confidence
        elif verdict == VerdictType.BIDIRECTIONAL:
            # Bidirectional gets positive score but lower magnitude
            return 0.5 * confidence
        else:  # UNKNOWN
            return 0.0
    
    def _calculate_evidence_strength(
        self,
        evidence_ids: List[str],
        total_evidence_available: int
    ) -> float:
        """Calculate strength of evidence citations."""
        if total_evidence_available == 0:
            return 0.0
        
        # Evidence strength based on citation coverage
        citation_coverage = len(evidence_ids) / max(total_evidence_available, 1)
        
        # Normalize to 0-1 range with diminishing returns
        return min(1.0, citation_coverage * 2.0)


class PTGJudgeIntegrator:
    """High-level integrator for PTG construction with LLM judge."""
    
    def __init__(
        self,
        neo4j_uri: str,
        neo4j_user: str, 
        neo4j_password: str,
        opensearch_url: str,
        opensearch_index: str
    ):
        """
        Initialize PTG judge integrator.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            opensearch_url: OpenSearch URL
            opensearch_index: OpenSearch index
        """
        self.ptg_builder = PTGBuilder(neo4j_uri, neo4j_user, neo4j_password)
        self.evidence_builder = EvidencePackBuilder(
            neo4j_uri, neo4j_user, neo4j_password,
            opensearch_url, opensearch_index
        )
        self.score_converter = JudgeScoreConverter()
        
    def build_ptg_with_judge(
        self,
        stats: PairwiseStatistics,
        triaged_pairs: List[TriagedPair],
        verdicts: List[JudgeVerdict],
        parameters: Optional[PTGParameters] = None
    ) -> Any:  # PTGModel
        """
        Build PTG with integrated judge scores.
        
        Args:
            stats: Pairwise statistics
            triaged_pairs: Pairs that were triaged for judging
            verdicts: Judge verdicts for the triaged pairs
            parameters: PTG construction parameters
            
        Returns:
            PTG model with judge integration
        """
        if parameters is None:
            parameters = PTGParameters(use_judge=True, epsilon=1.0)
        
        # Convert verdicts to numerical scores
        evidence_sizes = {}
        for pair in triaged_pairs:
            key = (pair.from_technique, pair.to_technique)
            # Estimate evidence size from evidence pack hash if available
            evidence_sizes[key] = 5  # Default reasonable estimate
            
        judge_scores_dict = self.score_converter.batch_convert_verdicts(
            verdicts, evidence_sizes
        )
        
        # Convert to format expected by PTG builder
        ptg_judge_scores = {}
        for (from_tech, to_tech), judge_score in judge_scores_dict.items():
            ptg_judge_scores[(from_tech, to_tech)] = judge_score.score
        
        # Build PTG with judge scores
        ptg_model = self.ptg_builder.build_ptg(
            stats=stats,
            parameters=parameters,
            judge_scores=ptg_judge_scores
        )
        
        # Enhance model with judge metadata
        ptg_model.parameters["judge_integration"] = {
            "total_verdicts": len(verdicts),
            "forward_verdicts": len([v for v in verdicts if v.verdict == VerdictType.FORWARD]),
            "reverse_verdicts": len([v for v in verdicts if v.verdict == VerdictType.REVERSE]),
            "bidirectional_verdicts": len([v for v in verdicts if v.verdict == VerdictType.BIDIRECTIONAL]),
            "unknown_verdicts": len([v for v in verdicts if v.verdict == VerdictType.UNKNOWN]),
            "avg_confidence": sum(v.confidence for v in verdicts) / len(verdicts) if verdicts else 0.0,
            "judge_enabled": True
        }
        
        logger.info(
            f"Built PTG {ptg_model.model_id} with {len(verdicts)} judge verdicts integrated"
        )
        
        return ptg_model
    
    def build_ptg_without_judge(
        self,
        stats: PairwiseStatistics,
        parameters: Optional[PTGParameters] = None
    ) -> Any:  # PTGModel
        """
        Build PTG without judge integration (baseline).
        
        Args:
            stats: Pairwise statistics
            parameters: PTG construction parameters
            
        Returns:
            PTG model without judge scores
        """
        if parameters is None:
            parameters = PTGParameters(use_judge=False, epsilon=0.0)
        
        ptg_model = self.ptg_builder.build_ptg(
            stats=stats,
            parameters=parameters,
            judge_scores=None
        )
        
        ptg_model.parameters["judge_integration"] = {
            "judge_enabled": False,
            "baseline_model": True
        }
        
        logger.info(f"Built baseline PTG {ptg_model.model_id} without judge integration")
        return ptg_model
    
    def analyze_judge_impact(
        self,
        baseline_model: Any,  # PTGModel
        judge_model: Any     # PTGModel  
    ) -> Dict[str, Any]:
        """
        Analyze the impact of judge integration on PTG structure.
        
        Args:
            baseline_model: PTG without judge scores
            judge_model: PTG with judge scores
            
        Returns:
            Impact analysis results
        """
        baseline_edges = {(e.from_technique, e.to_technique): e.probability 
                         for e in baseline_model.edges}
        judge_edges = {(e.from_technique, e.to_technique): e.probability 
                      for e in judge_model.edges}
        
        # Calculate probability changes
        probability_changes = []
        new_edges = []
        removed_edges = []
        
        for pair, judge_prob in judge_edges.items():
            if pair in baseline_edges:
                baseline_prob = baseline_edges[pair]
                change = judge_prob - baseline_prob
                probability_changes.append({
                    "pair": f"{pair[0]}->{pair[1]}",
                    "baseline_prob": baseline_prob,
                    "judge_prob": judge_prob,
                    "change": change,
                    "percent_change": (change / baseline_prob) * 100 if baseline_prob > 0 else 0
                })
            else:
                new_edges.append({
                    "pair": f"{pair[0]}->{pair[1]}",
                    "probability": judge_prob
                })
        
        for pair, baseline_prob in baseline_edges.items():
            if pair not in judge_edges:
                removed_edges.append({
                    "pair": f"{pair[0]}->{pair[1]}",
                    "probability": baseline_prob
                })
        
        # Sort by absolute change
        probability_changes.sort(key=lambda x: abs(x["change"]), reverse=True)
        
        analysis = {
            "edge_changes": {
                "total_baseline_edges": len(baseline_edges),
                "total_judge_edges": len(judge_edges),
                "new_edges": len(new_edges),
                "removed_edges": len(removed_edges),
                "modified_edges": len(probability_changes)
            },
            "top_probability_increases": [
                change for change in probability_changes if change["change"] > 0
            ][:10],
            "top_probability_decreases": [
                change for change in probability_changes if change["change"] < 0
            ][:10],
            "new_edges_added": new_edges[:10],
            "edges_removed": removed_edges[:10],
            "summary": {
                "avg_probability_change": sum(c["change"] for c in probability_changes) / len(probability_changes) if probability_changes else 0,
                "max_increase": max((c["change"] for c in probability_changes), default=0),
                "max_decrease": min((c["change"] for c in probability_changes), default=0)
            }
        }
        
        return analysis
    
    def close(self):
        """Close connections."""
        if hasattr(self.ptg_builder, 'close'):
            self.ptg_builder.close()
        if hasattr(self.evidence_builder, 'close'):
            self.evidence_builder.close()


def integrate_judge_scores_into_ptg(
    stats: PairwiseStatistics,
    verdicts: List[JudgeVerdict],
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    opensearch_url: str,
    opensearch_index: str,
    parameters: Optional[PTGParameters] = None
) -> Tuple[Any, Dict[str, Any]]:  # PTGModel, analysis
    """
    Convenience function for complete judge integration workflow.
    
    Args:
        stats: Pairwise statistics
        verdicts: Judge verdicts
        neo4j_uri: Neo4j connection URI
        neo4j_user: Neo4j username
        neo4j_password: Neo4j password
        opensearch_url: OpenSearch URL
        opensearch_index: OpenSearch index
        parameters: PTG construction parameters
        
    Returns:
        Tuple of (PTG model with judge scores, impact analysis)
    """
    integrator = PTGJudgeIntegrator(
        neo4j_uri, neo4j_user, neo4j_password,
        opensearch_url, opensearch_index
    )
    
    try:
        # Build baseline and judge models
        baseline_model = integrator.build_ptg_without_judge(stats, parameters)
        
        # Mock triaged pairs from verdicts for integration
        triaged_pairs = [
            type('MockTriagedPair', (), {
                'from_technique': v.from_technique,
                'to_technique': v.to_technique
            })() for v in verdicts
        ]
        
        judge_model = integrator.build_ptg_with_judge(
            stats, triaged_pairs, verdicts, parameters
        )
        
        # Analyze impact
        impact_analysis = integrator.analyze_judge_impact(baseline_model, judge_model)
        
        return judge_model, impact_analysis
        
    finally:
        integrator.close()