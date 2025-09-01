"""Triage system for filtering ambiguous technique pairs for LLM judging."""

import logging
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from bandjacks.llm.sequence_extractor import SequenceExtractor, PairwiseStatistics
from bandjacks.llm.evidence_pack import EvidencePackBuilder, EvidencePack

logger = logging.getLogger(__name__)


@dataclass
class TriageConfig:
    """Configuration for ambiguous pair triage."""
    ambiguity_threshold: float = 0.15  # τ - maximum asymmetry for ambiguous pairs
    min_count: int = 3  # c_min - minimum co-occurrence count
    max_pairs_per_scope: int = 50  # Budget control
    exclude_subtechniques: bool = False  # Focus on parent techniques
    exclude_same_tactic: bool = True  # Skip pairs within same tactic
    min_confidence: float = 0.1  # Minimum confidence threshold
    max_evidence_age_days: int = 365  # Evidence freshness limit


@dataclass
class TriagedPair:
    """A technique pair that needs LLM judging."""
    from_technique: str
    to_technique: str
    scope: str  # intrusion_set_id or "global"
    scope_type: str  # "intrusion-set" or "global"
    
    # Statistical features
    asymmetry_score: float
    forward_prob: float  # P(to|from)
    reverse_prob: float  # P(from|to)
    co_occurrence_count: int
    
    # Contextual features
    from_tactic: Optional[str] = None
    to_tactic: Optional[str] = None
    tactic_distance: Optional[int] = None  # Distance in kill chain
    
    # Triage metadata
    priority_score: float = 0.0  # Higher = more important to judge
    evidence_pack_hash: Optional[str] = None  # For caching
    triaged_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Calculate derived fields."""
        self.priority_score = self._calculate_priority()
    
    def _calculate_priority(self) -> float:
        """Calculate priority score for judging this pair."""
        # Base score from asymmetry (lower asymmetry = higher priority)
        priority = 1.0 - self.asymmetry_score
        
        # Boost pairs with higher co-occurrence
        priority += min(self.co_occurrence_count / 10.0, 1.0)
        
        # Boost cross-tactic transitions (more interesting)
        if self.from_tactic != self.to_tactic and self.tactic_distance:
            priority += 0.3 * (1.0 / max(self.tactic_distance, 1))
        
        # Boost pairs with balanced probabilities
        balance = 1.0 - abs(self.forward_prob - self.reverse_prob)
        priority += 0.2 * balance
        
        return priority


class PairTriage:
    """Triage system for identifying technique pairs that need LLM judging."""
    
    def __init__(
        self,
        sequence_extractor: SequenceExtractor,
        evidence_builder: EvidencePackBuilder,
        config: Optional[TriageConfig] = None
    ):
        """
        Initialize triage system.
        
        Args:
            sequence_extractor: For extracting pairwise statistics
            evidence_builder: For building evidence packs
            config: Triage configuration
        """
        self.extractor = sequence_extractor
        self.evidence_builder = evidence_builder
        self.config = config or TriageConfig()
        
        # Kill chain ordering for tactic distance calculation
        self.tactic_order = {
            "reconnaissance": 0,
            "resource-development": 1,
            "initial-access": 2,
            "execution": 3,
            "persistence": 4,
            "privilege-escalation": 5,
            "defense-evasion": 6,
            "credential-access": 7,
            "discovery": 8,
            "lateral-movement": 9,
            "collection": 10,
            "command-and-control": 11,
            "exfiltration": 12,
            "impact": 13
        }
        
    def triage_all_scopes(
        self,
        stats_dict: Dict[str, PairwiseStatistics]
    ) -> Dict[str, List[TriagedPair]]:
        """
        Triage ambiguous pairs across all scopes.
        
        Args:
            stats_dict: Dictionary mapping scope -> pairwise statistics
            
        Returns:
            Dictionary mapping scope -> list of triaged pairs
        """
        all_triaged = {}
        total_pairs = 0
        
        for scope, stats in stats_dict.items():
            triaged_pairs = self.triage_scope(stats)
            all_triaged[scope] = triaged_pairs
            total_pairs += len(triaged_pairs)
            
            logger.info(f"Triaged {len(triaged_pairs)} pairs for scope {scope}")
        
        logger.info(f"Total triaged pairs across all scopes: {total_pairs}")
        return all_triaged
    
    def triage_scope(self, stats: PairwiseStatistics) -> List[TriagedPair]:
        """
        Triage ambiguous pairs for a single scope.
        
        Args:
            stats: Pairwise statistics for the scope
            
        Returns:
            List of triaged pairs sorted by priority
        """
        candidates = []
        
        # Find all candidate pairs using existing ambiguity detection
        ambiguous_pairs = self.extractor.find_ambiguous_pairs(
            stats,
            ambiguity_threshold=self.config.ambiguity_threshold,
            min_count=self.config.min_count
        )
        
        logger.debug(f"Found {len(ambiguous_pairs)} ambiguous pairs for {stats.scope}")
        
        for from_tech, to_tech in ambiguous_pairs:
            # Apply additional filters
            if self._should_skip_pair(from_tech, to_tech, stats):
                continue
            
            # Create triaged pair with full context
            triaged_pair = self._create_triaged_pair(
                from_tech, to_tech, stats
            )
            
            if triaged_pair:
                candidates.append(triaged_pair)
        
        # Sort by priority score (descending) and apply budget limit
        candidates.sort(key=lambda p: p.priority_score, reverse=True)
        
        # Apply budget constraint
        max_pairs = self.config.max_pairs_per_scope
        selected_pairs = candidates[:max_pairs]
        
        if len(candidates) > max_pairs:
            logger.info(
                f"Budget limit applied: selected {max_pairs} of {len(candidates)} "
                f"candidates for scope {stats.scope}"
            )
        
        return selected_pairs
    
    def _should_skip_pair(
        self,
        from_tech: str,
        to_tech: str,
        stats: PairwiseStatistics
    ) -> bool:
        """Check if a pair should be skipped during triage."""
        
        # Skip subtechniques if configured
        if self.config.exclude_subtechniques:
            if "." in from_tech or "." in to_tech:
                return True
        
        # Get tactics for the techniques
        with self.extractor.driver.session() as session:
            from_tactic = self._get_primary_tactic(session, from_tech)
            to_tactic = self._get_primary_tactic(session, to_tech)
        
        # Skip same-tactic pairs if configured
        if self.config.exclude_same_tactic and from_tactic == to_tactic:
            return True
        
        # Skip pairs with very low probabilities
        forward_prob = stats.conditional_probs.get((from_tech, to_tech), 0.0)
        reverse_prob = stats.conditional_probs.get((to_tech, from_tech), 0.0)
        
        if max(forward_prob, reverse_prob) < self.config.min_confidence:
            return True
        
        return False
    
    def _create_triaged_pair(
        self,
        from_tech: str,
        to_tech: str,
        stats: PairwiseStatistics
    ) -> Optional[TriagedPair]:
        """Create a TriagedPair with full context."""
        
        # Get statistical features
        asymmetry = stats.asymmetry_scores.get((from_tech, to_tech), 0.0)
        forward_prob = stats.conditional_probs.get((from_tech, to_tech), 0.0)
        reverse_prob = stats.conditional_probs.get((to_tech, from_tech), 0.0)
        count = stats.pair_counts.get((from_tech, to_tech), 0)
        
        # Get tactic information
        with self.extractor.driver.session() as session:
            from_tactic = self._get_primary_tactic(session, from_tech)
            to_tactic = self._get_primary_tactic(session, to_tech)
        
        # Calculate tactic distance
        tactic_distance = self._calculate_tactic_distance(from_tactic, to_tactic)
        
        pair = TriagedPair(
            from_technique=from_tech,
            to_technique=to_tech,
            scope=stats.scope,
            scope_type=stats.scope_type,
            asymmetry_score=asymmetry,
            forward_prob=forward_prob,
            reverse_prob=reverse_prob,
            co_occurrence_count=count,
            from_tactic=from_tactic,
            to_tactic=to_tactic,
            tactic_distance=tactic_distance
        )
        
        return pair
    
    def _get_primary_tactic(self, session, technique_id: str) -> Optional[str]:
        """Get primary tactic for a technique (uses extractor's cache)."""
        return self.extractor._get_primary_tactic(session, technique_id)
    
    def _calculate_tactic_distance(self, tactic1: Optional[str], tactic2: Optional[str]) -> Optional[int]:
        """Calculate distance between tactics in kill chain."""
        if not tactic1 or not tactic2 or tactic1 not in self.tactic_order or tactic2 not in self.tactic_order:
            return None
        
        return abs(self.tactic_order[tactic1] - self.tactic_order[tactic2])
    
    def build_evidence_packs_for_batch(
        self,
        triaged_pairs: List[TriagedPair],
        batch_size: int = 10
    ) -> List[Tuple[TriagedPair, EvidencePack]]:
        """
        Build evidence packs for a batch of triaged pairs.
        
        Args:
            triaged_pairs: Pairs needing evidence packs
            batch_size: Number of pairs to process in parallel
            
        Returns:
            List of (pair, evidence_pack) tuples
        """
        results = []
        
        for i in range(0, len(triaged_pairs), batch_size):
            batch = triaged_pairs[i:i + batch_size]
            batch_results = []
            
            for pair in batch:
                try:
                    # Build evidence pack for this pair
                    evidence_pack = self.evidence_builder.build_evidence_pack(
                        pair.from_technique,
                        pair.to_technique,
                        scope=pair.scope if pair.scope != "global" else None
                    )
                    
                    # Update pair with evidence pack hash
                    pair.evidence_pack_hash = evidence_pack.retrieval_hash
                    
                    batch_results.append((pair, evidence_pack))
                    
                except Exception as e:
                    logger.error(f"Failed to build evidence pack for {pair.from_technique}->{pair.to_technique}: {e}")
                    continue
            
            results.extend(batch_results)
            logger.debug(f"Built evidence packs for batch {i//batch_size + 1}: {len(batch_results)} pairs")
        
        logger.info(f"Built evidence packs for {len(results)} of {len(triaged_pairs)} triaged pairs")
        return results
    
    def filter_by_budget(
        self,
        all_triaged: Dict[str, List[TriagedPair]],
        max_total_pairs: int = 200,
        prioritize_global: bool = True
    ) -> Dict[str, List[TriagedPair]]:
        """
        Apply budget constraints across all scopes.
        
        Args:
            all_triaged: All triaged pairs by scope
            max_total_pairs: Maximum total pairs to judge
            prioritize_global: Whether to prioritize global scope
            
        Returns:
            Filtered pairs within budget
        """
        # Flatten all pairs with scope priority
        all_pairs = []
        
        for scope, pairs in all_triaged.items():
            for pair in pairs:
                # Add scope priority boost
                priority_boost = 0.0
                if prioritize_global and scope == "global":
                    priority_boost = 0.5
                elif scope != "global":
                    # Slight boost for intrusion-set specific pairs
                    priority_boost = 0.1
                
                pair.priority_score += priority_boost
                all_pairs.append(pair)
        
        # Sort by priority globally
        all_pairs.sort(key=lambda p: p.priority_score, reverse=True)
        
        # Select top pairs within budget
        selected_pairs = all_pairs[:max_total_pairs]
        
        # Group back by scope
        filtered_by_scope = defaultdict(list)
        for pair in selected_pairs:
            filtered_by_scope[pair.scope].append(pair)
        
        # Log budget application results
        original_total = sum(len(pairs) for pairs in all_triaged.values())
        final_total = len(selected_pairs)
        
        logger.info(f"Budget filter: {final_total} of {original_total} pairs selected")
        for scope, pairs in filtered_by_scope.items():
            original_count = len(all_triaged[scope])
            logger.info(f"  {scope}: {len(pairs)} of {original_count} pairs")
        
        return dict(filtered_by_scope)
    
    def get_triage_summary(
        self,
        all_triaged: Dict[str, List[TriagedPair]]
    ) -> Dict[str, Any]:
        """
        Generate summary statistics for triage results.
        
        Args:
            all_triaged: All triaged pairs by scope
            
        Returns:
            Summary statistics
        """
        total_pairs = sum(len(pairs) for pairs in all_triaged.values())
        
        if total_pairs == 0:
            return {"total_pairs": 0}
        
        # Aggregate statistics
        all_pairs = [pair for pairs in all_triaged.values() for pair in pairs]
        
        avg_asymmetry = sum(p.asymmetry_score for p in all_pairs) / total_pairs
        avg_priority = sum(p.priority_score for p in all_pairs) / total_pairs
        avg_count = sum(p.co_occurrence_count for p in all_pairs) / total_pairs
        
        # Tactic distribution
        tactic_pairs = defaultdict(int)
        for pair in all_pairs:
            if pair.from_tactic and pair.to_tactic:
                key = f"{pair.from_tactic}->{pair.to_tactic}"
                tactic_pairs[key] += 1
        
        # Cross-tactic vs same-tactic
        cross_tactic = sum(1 for p in all_pairs if p.from_tactic != p.to_tactic)
        same_tactic = total_pairs - cross_tactic
        
        summary = {
            "total_pairs": total_pairs,
            "scopes": list(all_triaged.keys()),
            "scope_counts": {scope: len(pairs) for scope, pairs in all_triaged.items()},
            "avg_asymmetry": avg_asymmetry,
            "avg_priority": avg_priority,
            "avg_co_occurrence": avg_count,
            "cross_tactic_pairs": cross_tactic,
            "same_tactic_pairs": same_tactic,
            "top_tactic_transitions": dict(sorted(tactic_pairs.items(), key=lambda x: x[1], reverse=True)[:10]),
            "config": {
                "ambiguity_threshold": self.config.ambiguity_threshold,
                "min_count": self.config.min_count,
                "max_pairs_per_scope": self.config.max_pairs_per_scope
            }
        }
        
        return summary


def triage_pairs_for_judging(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    opensearch_url: str,
    opensearch_index: str,
    config: Optional[TriageConfig] = None,
    build_evidence_packs: bool = False
) -> Dict[str, Any]:
    """
    Convenience function to perform complete triage workflow.
    
    Args:
        neo4j_uri: Neo4j connection URI
        neo4j_user: Neo4j username
        neo4j_password: Neo4j password
        opensearch_url: OpenSearch URL
        opensearch_index: OpenSearch index name
        config: Triage configuration
        build_evidence_packs: Whether to build evidence packs
        
    Returns:
        Complete triage results with summary
    """
    # Initialize components
    extractor = SequenceExtractor(neo4j_uri, neo4j_user, neo4j_password)
    
    evidence_builder = None
    if build_evidence_packs:
        evidence_builder = EvidencePackBuilder(
            neo4j_uri, neo4j_user, neo4j_password,
            opensearch_url, opensearch_index
        )
    
    triage = PairTriage(extractor, evidence_builder, config)
    
    try:
        # Extract sequences and compute statistics
        sequences = extractor.extract_all_sequences(include_cooccurrence=True)
        stats_dict = extractor.extract_by_intrusion_set(sequences)
        
        # Triage all scopes
        all_triaged = triage.triage_all_scopes(stats_dict)
        
        # Apply global budget constraints
        budget_filtered = triage.filter_by_budget(all_triaged, max_total_pairs=200)
        
        # Build evidence packs if requested
        evidence_packs = {}
        if build_evidence_packs and evidence_builder:
            for scope, pairs in budget_filtered.items():
                pack_results = triage.build_evidence_packs_for_batch(pairs)
                evidence_packs[scope] = pack_results
        
        # Generate summary
        summary = triage.get_triage_summary(budget_filtered)
        
        results = {
            "triaged_pairs": budget_filtered,
            "summary": summary,
            "evidence_packs": evidence_packs if evidence_packs else None
        }
        
        return results
        
    finally:
        extractor.close()
        if evidence_builder:
            evidence_builder.close()