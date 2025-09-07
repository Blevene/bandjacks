"""Thread-safe accumulator for progressive context sharing during chunk processing."""

import threading
import logging
import os
from typing import Dict, List, Set, Optional, Any
from collections import defaultdict
from dataclasses import dataclass, field
import time

logger = logging.getLogger(__name__)


@dataclass
class TechniqueContext:
    """Stores accumulated context for a technique."""
    technique_id: str
    name: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    chunk_ids: Set[int] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    claim_count: int = 0


class ThreadSafeAccumulator:
    """
    Thread-safe accumulator for sharing technique discoveries across chunks.
    
    Features:
    - Thread-safe operations using locks
    - Confidence aggregation across multiple discoveries
    - Evidence accumulation from different chunks
    - Early termination signaling
    - Context hints generation for new chunks
    """
    
    def __init__(
        self,
        early_termination_threshold: float = None,
        max_context_hints: int = None,
        confidence_boost: float = None,
        min_techniques_for_termination: int = None,
        enable_early_termination: bool = None
    ):
        """
        Initialize the accumulator.
        
        Args:
            early_termination_threshold: Confidence level to trigger early termination
            max_context_hints: Maximum number of hints to provide to new chunks
            confidence_boost: Boost to apply when technique found multiple times
            min_techniques_for_termination: Minimum techniques required before considering early termination
            enable_early_termination: Whether to enable early termination at all
        """
        self.techniques: Dict[str, TechniqueContext] = {}
        self.lock = threading.Lock()
        self.should_terminate = threading.Event()
        
        # Read from settings (which gets values from environment)
        from bandjacks.services.api.settings import settings
        
        self.early_termination_threshold = early_termination_threshold if early_termination_threshold is not None else settings.early_termination_threshold
        self.max_context_hints = max_context_hints if max_context_hints is not None else settings.max_context_hints
        self.confidence_boost = confidence_boost if confidence_boost is not None else settings.confidence_boost
        self.min_techniques_for_termination = min_techniques_for_termination if min_techniques_for_termination is not None else settings.min_techniques_for_termination
        self.enable_early_termination = enable_early_termination if enable_early_termination is not None else settings.enable_early_termination
        
        # Statistics
        self.chunks_processed = 0
        self.total_techniques = 0
        self.high_confidence_count = 0
        
    def add_technique(
        self,
        technique_id: str,
        name: str,
        confidence: float,
        evidence: List[str],
        chunk_id: int
    ) -> bool:
        """
        Add or update a technique discovery.
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            name: Technique name
            confidence: Confidence score (0-100)
            evidence: List of evidence strings
            chunk_id: ID of chunk that found this technique
            
        Returns:
            True if this triggers early termination
        """
        with self.lock:
            if technique_id in self.techniques:
                # Update existing technique
                tech = self.techniques[technique_id]
                
                # Aggregate confidence (max + boost for multiple discoveries)
                old_confidence = tech.confidence
                tech.confidence = min(100, max(tech.confidence, confidence) + self.confidence_boost)
                
                # Add new evidence (avoid duplicates)
                for e in evidence:
                    if e not in tech.evidence:
                        tech.evidence.append(e)
                
                # Track chunk
                tech.chunk_ids.add(chunk_id)
                tech.claim_count += 1
                
                logger.debug(
                    f"Updated {technique_id}: confidence {old_confidence:.1f} → {tech.confidence:.1f} "
                    f"(found in {len(tech.chunk_ids)} chunks)"
                )
                
            else:
                # New technique discovery
                self.techniques[technique_id] = TechniqueContext(
                    technique_id=technique_id,
                    name=name,
                    confidence=confidence,
                    evidence=evidence.copy(),
                    chunk_ids={chunk_id},
                    claim_count=1
                )
                self.total_techniques += 1
                
                logger.debug(f"New technique {technique_id}: {name} (confidence: {confidence:.1f})")
            
            # Check for early termination
            if confidence >= self.early_termination_threshold:
                self.high_confidence_count += 1
                
            # Only consider early termination if enabled and we have enough techniques
            if (self.enable_early_termination and 
                len(self.techniques) >= self.min_techniques_for_termination and
                self.high_confidence_count >= self.min_techniques_for_termination):
                
                avg_confidence = sum(t.confidence for t in self.techniques.values()) / len(self.techniques)
                if avg_confidence >= self.early_termination_threshold:
                    logger.info(
                        f"Early termination triggered: {len(self.techniques)} techniques found "
                        f"({self.high_confidence_count} high-confidence), avg confidence {avg_confidence:.1f}"
                    )
                    self.should_terminate.set()
                    return True
                    
            return False
    
    def get_context_hints(self) -> Dict[str, Any]:
        """
        Get context hints for a new chunk.
        
        Returns:
            Dictionary with discovered techniques and hints
        """
        with self.lock:
            if not self.techniques:
                return {"discovered_techniques": [], "hint_count": 0}
            
            # Sort by confidence and recency
            sorted_techniques = sorted(
                self.techniques.values(),
                key=lambda t: (t.confidence, -t.first_seen),
                reverse=True
            )
            
            # Take top techniques as hints
            hints = []
            for tech in sorted_techniques[:self.max_context_hints]:
                hints.append({
                    "technique_id": tech.technique_id,
                    "name": tech.name,
                    "confidence": tech.confidence,
                    "found_in_chunks": len(tech.chunk_ids)
                })
            
            return {
                "discovered_techniques": hints,
                "hint_count": len(hints),
                "total_found": len(self.techniques),
                "avg_confidence": sum(t.confidence for t in self.techniques.values()) / len(self.techniques)
            }
    
    def mark_chunk_complete(self, chunk_id: int):
        """Mark a chunk as completed."""
        with self.lock:
            self.chunks_processed += 1
            logger.debug(f"Chunk {chunk_id} complete. Total processed: {self.chunks_processed}")
    
    def should_stop_processing(self) -> bool:
        """Check if processing should stop early."""
        return self.should_terminate.is_set()
    
    def get_accumulated_techniques(self) -> Dict[str, Dict[str, Any]]:
        """
        Get all accumulated techniques.
        
        Returns:
            Dictionary mapping technique IDs to their accumulated data
        """
        with self.lock:
            result = {}
            for tech_id, tech in self.techniques.items():
                result[tech_id] = {
                    "name": tech.name,
                    "confidence": tech.confidence,
                    "evidence": tech.evidence,
                    "chunk_ids": list(tech.chunk_ids),
                    "claim_count": tech.claim_count
                }
            return result
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get accumulator statistics.
        
        Returns:
            Dictionary with processing statistics
        """
        with self.lock:
            if not self.techniques:
                return {
                    "chunks_processed": self.chunks_processed,
                    "total_techniques": 0,
                    "high_confidence_count": 0,
                    "avg_confidence": 0,
                    "techniques_per_chunk": 0
                }
            
            return {
                "chunks_processed": self.chunks_processed,
                "total_techniques": len(self.techniques),
                "high_confidence_count": self.high_confidence_count,
                "avg_confidence": sum(t.confidence for t in self.techniques.values()) / len(self.techniques),
                "techniques_per_chunk": len(self.techniques) / max(1, self.chunks_processed),
                "multi_chunk_techniques": sum(1 for t in self.techniques.values() if len(t.chunk_ids) > 1)
            }