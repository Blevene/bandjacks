"""Base class for consolidators with shared deduplication and evidence extraction logic."""

from typing import List, Dict, Any, Optional, Tuple
import re
import logging

logger = logging.getLogger(__name__)


class ConsolidatorBase:
    """Base class for consolidators with shared deduplication logic."""
    
    def __init__(self):
        """Initialize consolidator with configuration-based deduplication."""
        # Import here to avoid circular imports
        try:
            from bandjacks.services.api.settings import settings
            self.use_semantic_dedup = settings.enable_semantic_dedup
            self.dedup_threshold = settings.semantic_dedup_threshold
            self.entity_threshold = settings.entity_dedup_threshold
            
            if self.use_semantic_dedup:
                from bandjacks.llm.semantic_dedup import SemanticDeduplicator
                self.semantic_dedup = SemanticDeduplicator(
                    similarity_threshold=self.dedup_threshold,
                    entity_threshold=self.entity_threshold
                )
                logger.info(f"Semantic deduplication enabled (technique threshold: {self.dedup_threshold}, entity threshold: {self.entity_threshold})")
            else:
                logger.info("Using Jaccard-based deduplication")
        except ImportError:
            # Fallback if settings not available (e.g., during testing)
            self.use_semantic_dedup = False
            logger.debug("Settings not available, defaulting to Jaccard deduplication")
    
    def _merge_evidence_intelligently(self, evidence_list: List[str]) -> List[str]:
        """
        Merge evidence using semantic or Jaccard deduplication based on config.
        
        Args:
            evidence_list: List of evidence strings
            
        Returns:
            Deduplicated list of evidence
        """
        if not evidence_list:
            return []
        
        # First pass: exact deduplication
        unique_evidence = self._exact_dedup(evidence_list)
        
        # Second pass: semantic or Jaccard
        if self.use_semantic_dedup and hasattr(self, 'semantic_dedup'):
            return self.semantic_dedup.deduplicate_evidence(unique_evidence)
        else:
            return self._jaccard_dedup(unique_evidence)
    
    def _exact_dedup(self, evidence_list: List[str]) -> List[str]:
        """
        Remove exact duplicates (case-insensitive, normalized).
        
        Args:
            evidence_list: List of evidence strings
            
        Returns:
            List with exact duplicates removed
        """
        seen_normalized = set()
        unique = []
        
        for ev in evidence_list:
            if not ev or not isinstance(ev, str):
                continue
            # Normalize: lowercase, strip whitespace, collapse spaces
            normalized = " ".join(ev.lower().strip().split())
            if normalized not in seen_normalized:
                unique.append(ev)
                seen_normalized.add(normalized)
        
        return unique
    
    def _jaccard_dedup(self, evidence_list: List[str]) -> List[str]:
        """
        Jaccard-based deduplication (existing approach).
        
        Args:
            evidence_list: List of evidence strings
            
        Returns:
            Deduplicated list using Jaccard similarity
        """
        final_evidence = []
        
        for i, ev1 in enumerate(evidence_list):
            is_duplicate = False
            ev1_words = set(ev1.lower().split())
            
            for ev2 in final_evidence:
                ev2_words = set(ev2.lower().split())
                
                # Calculate Jaccard similarity
                intersection = len(ev1_words & ev2_words)
                union = len(ev1_words | ev2_words)
                
                if union > 0:
                    similarity = intersection / union
                    # If evidence is >85% similar, consider it a duplicate
                    if similarity > 0.85:
                        is_duplicate = True
                        # Keep the longer evidence (more context)
                        if len(ev1) > len(ev2):
                            final_evidence[final_evidence.index(ev2)] = ev1
                        break
            
            if not is_duplicate:
                final_evidence.append(ev1)
        
        # Sort by length (longer evidence first) to preserve more context
        final_evidence.sort(key=len, reverse=True)
        
        return final_evidence
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate Jaccard similarity between two text strings.
        
        Args:
            text1: First text
            text2: Second text
            
        Returns:
            Similarity score between 0 and 1
        """
        if not text1 or not text2:
            return 0.0
        
        # Tokenize
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())
        
        # Calculate Jaccard similarity
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        
        if union == 0:
            return 0.0
        
        return intersection / union