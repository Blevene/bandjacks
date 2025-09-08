"""Entity consolidator agent for claim-based entity consolidation."""

import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from bandjacks.llm.memory import WorkingMemory

logger = logging.getLogger(__name__)


@dataclass
class EntityClaim:
    """Represents a claim about an entity from text."""
    entity_id: str  # Unique identifier for the entity
    name: str
    entity_type: str  # group, malware, tool, target, campaign
    quotes: List[str] = field(default_factory=list)
    line_refs: List[int] = field(default_factory=list)
    confidence: float = 50.0
    evidence_score: float = 50.0
    chunk_id: Optional[int] = None
    context: str = "primary_mention"  # primary_mention, alias, related


class EntityConsolidatorAgent:
    """
    Consolidates entity claims from multiple chunks into entities with evidence.
    
    This agent mirrors the ConsolidatorAgent but for entities, ensuring:
    - Entity claims are merged across chunks
    - Evidence is deduplicated intelligently
    - Confidence is boosted for multi-chunk discoveries
    - Aliases are properly tracked
    """
    
    def __init__(self):
        self.name = "EntityConsolidatorAgent"
        
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        """
        Consolidate entity claims into entities with substantiated evidence.
        
        Args:
            mem: Working memory containing entity_claims
            config: Configuration dict
        """
        if not hasattr(mem, 'entity_claims') or not mem.entity_claims:
            logger.info("No entity claims to consolidate")
            if not hasattr(mem, 'consolidated_entities'):
                mem.consolidated_entities = {}
            return
            
        logger.info(f"Consolidating {len(mem.entity_claims)} entity claims")
        
        # Group claims by entity ID
        entity_groups = {}
        for claim in mem.entity_claims:
            if isinstance(claim, dict):
                entity_id = claim.get('entity_id', '')
                if not entity_id:
                    # Generate ID from name and type if missing
                    entity_id = f"{claim.get('entity_type', 'unknown')}_{claim.get('name', 'unknown').lower().replace(' ', '_')}"
                    claim['entity_id'] = entity_id
                    
                if entity_id not in entity_groups:
                    entity_groups[entity_id] = []
                entity_groups[entity_id].append(claim)
        
        # Consolidate each entity
        consolidated = {}
        
        for entity_id, claims in entity_groups.items():
            if not claims:
                continue
                
            # Get basic info from first claim
            first_claim = claims[0]
            entity_name = first_claim.get('name', '')
            entity_type = first_claim.get('entity_type', '')
            
            # Collect all evidence
            all_quotes = []
            all_line_refs = []
            chunk_ids = set()
            contexts = set()
            
            for claim in claims:
                # Collect quotes
                quotes = claim.get('quotes', [])
                if isinstance(quotes, list):
                    all_quotes.extend(quotes)
                elif isinstance(quotes, str) and quotes:
                    all_quotes.append(quotes)
                    
                # Collect line references
                line_refs = claim.get('line_refs', [])
                if isinstance(line_refs, list):
                    all_line_refs.extend(line_refs)
                    
                # Track chunks
                chunk_id = claim.get('chunk_id')
                if chunk_id is not None:
                    chunk_ids.add(chunk_id)
                    
                # Track contexts
                context = claim.get('context', 'primary_mention')
                contexts.add(context)
            
            # Deduplicate evidence intelligently
            unique_evidence = self._merge_evidence_intelligently(all_quotes)
            
            # Calculate consolidated confidence
            max_confidence = max((c.get('confidence', 50) for c in claims), default=50)
            
            # Boost confidence for multiple chunks (5% per additional chunk, max 20%)
            chunk_boost = min(20, len(chunk_ids) * 5) if len(chunk_ids) > 1 else 0
            
            # Boost confidence for multiple evidence pieces (2% per piece, max 10%)
            evidence_boost = min(10, len(unique_evidence) * 2)
            
            final_confidence = min(100, max_confidence + chunk_boost + evidence_boost)
            
            # Check if this is an alias
            is_alias = 'alias' in contexts
            
            # Create consolidated entity
            consolidated[entity_id] = {
                "entity_id": entity_id,
                "name": entity_name,
                "type": entity_type,
                "confidence": final_confidence,
                "evidence": unique_evidence[:10],  # Keep top 10 evidence pieces
                "line_refs": sorted(set(all_line_refs))[:50],  # Keep top 50 line refs
                "chunks_found": sorted(chunk_ids),
                "claim_count": len(claims),
                "is_alias": is_alias,
                "contexts": list(contexts)
            }
            
            logger.debug(
                f"Consolidated entity {entity_name} ({entity_type}): "
                f"{len(claims)} claims, {len(chunk_ids)} chunks, "
                f"confidence {max_confidence:.1f} → {final_confidence:.1f}"
            )
        
        # Store consolidated entities
        mem.consolidated_entities = consolidated
        
        # Also update mem.entities for backward compatibility
        if not hasattr(mem, 'entities') or not isinstance(mem.entities, dict):
            mem.entities = {"entities": [], "extraction_status": "success"}
        
        # Convert consolidated entities to standard format
        entity_list = []
        for entity_id, entity_data in consolidated.items():
            entity_dict = {
                "name": entity_data["name"],
                "type": entity_data["type"],
                "confidence": entity_data["confidence"],
                "mentions": [
                    {
                        "quote": quote,
                        "line_refs": entity_data["line_refs"][:10],  # Sample of line refs
                        "context": "consolidated"
                    }
                    for quote in entity_data["evidence"][:3]  # Top 3 evidence pieces
                ]
            }
            
            # Add alias flag if applicable
            if entity_data.get("is_alias"):
                entity_dict["is_alias"] = True
                
            entity_list.append(entity_dict)
        
        mem.entities["entities"] = entity_list
        
        logger.info(
            f"Entity consolidation complete: {len(consolidated)} unique entities from {len(mem.entity_claims)} claims"
        )
    
    def _merge_evidence_intelligently(self, evidence_list: List[str]) -> List[str]:
        """
        Merge evidence quotes intelligently, removing duplicates and near-duplicates.
        
        Args:
            evidence_list: List of evidence quotes
            
        Returns:
            Deduplicated list of evidence
        """
        if not evidence_list:
            return []
        
        # Normalize and deduplicate
        seen_normalized = set()
        unique_evidence = []
        
        for evidence in evidence_list:
            if not evidence or not isinstance(evidence, str):
                continue
                
            # Normalize for comparison (lowercase, remove extra spaces)
            normalized = ' '.join(evidence.lower().split())
            
            # Skip if we've seen this exact normalized version
            if normalized in seen_normalized:
                continue
                
            # Check for near duplicates (>85% similar using simple overlap)
            is_duplicate = False
            for seen in seen_normalized:
                similarity = self._calculate_similarity(normalized, seen)
                if similarity > 0.85:
                    is_duplicate = True
                    break
            
            if not is_duplicate:
                unique_evidence.append(evidence)
                seen_normalized.add(normalized)
        
        # Sort by length (longer evidence usually more informative)
        unique_evidence.sort(key=len, reverse=True)
        
        return unique_evidence
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity between two text strings using Jaccard similarity.
        
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
        
        # Jaccard similarity
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        if not union:
            return 0.0
            
        return len(intersection) / len(union)