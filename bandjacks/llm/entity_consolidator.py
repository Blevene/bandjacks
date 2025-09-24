"""Entity consolidator agent for claim-based entity consolidation."""

import re
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.consolidator_base import ConsolidatorBase

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


class EntityConsolidatorAgent(ConsolidatorBase):
    """
    Consolidates entity claims from multiple chunks into entities with evidence.
    
    This agent mirrors the ConsolidatorAgent but for entities, ensuring:
    - Entity claims are merged across chunks
    - Evidence is deduplicated intelligently
    - Confidence is boosted for multi-chunk discoveries
    - Aliases are properly tracked
    """
    
    def __init__(self):
        super().__init__()
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
        
        # Optionally deduplicate entire entities based on similarity (e.g., APT29 vs Cozy Bear)
        if self.use_semantic_dedup and hasattr(self, 'semantic_dedup'):
            try:
                from bandjacks.services.api.settings import settings
                if settings.deduplicate_entities:
                    original_count = len(mem.consolidated_entities)
                    mem.consolidated_entities = self.semantic_dedup.deduplicate_entities(mem.consolidated_entities)
                    if len(mem.consolidated_entities) < original_count:
                        logger.info(f"Semantic entity deduplication: {original_count} → {len(mem.consolidated_entities)} entities")
            except Exception as e:
                logger.warning(f"Entity deduplication failed: {e}")
        
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
    
    # Methods inherited from ConsolidatorBase:
    # - _merge_evidence_intelligently() - uses semantic or Jaccard based on config
    # - _exact_dedup() - removes exact duplicates
    # - _jaccard_dedup() - Jaccard-based deduplication
    # - _calculate_similarity() - Jaccard similarity calculation

    @classmethod
    def consolidate_entities(cls, entities_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Consolidate entities by merging aliases and duplicate mentions.

        This function:
        1. Detects aliases from evidence quotes (e.g., "APT29, also known as Cozy Bear")
        2. Merges entities that are aliases of each other
        3. Combines evidence from multiple mentions
        4. Boosts confidence for frequently mentioned entities

        Args:
            entities_data: Dictionary with 'entities' key containing list of entity dicts

        Returns:
            Consolidated entities data with aliases merged
        """
        if not isinstance(entities_data, dict) or "entities" not in entities_data:
            return entities_data

        entities = entities_data.get("entities", [])
        if not entities:
            return entities_data

        # Build alias relationships from evidence
        alias_map = {}  # Maps alias names to primary names
        primary_entities = {}  # Maps primary names to their entity data

        # First pass: identify aliases from evidence
        for entity in entities:
            if not isinstance(entity, dict):
                continue

            entity_name = entity.get("name", "").strip()
            if not entity_name:
                continue

            # Check mentions for alias patterns
            for mention in entity.get("mentions", []):
                quote = mention.get("quote", "")
                context = mention.get("context", "")

                # If this mention is marked as an alias
                if context == "alias":
                    # Try to find the primary entity from the quote
                    primary = cls._extract_primary_from_alias_quote(quote, entity_name)
                    if primary and primary != entity_name:
                        alias_map[entity_name.lower()] = primary
                        logger.debug(f"Identified {entity_name} as alias of {primary}")

                # Look for "also known as" patterns in quotes
                elif "also known as" in quote.lower() or ", aka " in quote.lower():
                    aliases = cls._extract_aliases_from_quote(quote)
                    if aliases:
                        # Determine which is primary and which are aliases
                        names_in_quote = [n for n in aliases if n.lower() in quote.lower()]
                        if len(names_in_quote) >= 2:
                            # Usually the first name is primary
                            primary = names_in_quote[0]
                            for alias in names_in_quote[1:]:
                                if alias.lower() != primary.lower():
                                    alias_map[alias.lower()] = primary
                                    logger.debug(f"Found alias relationship: {alias} -> {primary}")

        # Second pass: group entities by their canonical name
        entity_groups = {}  # Key: (canonical_name, type) -> Value: list of entities

        for entity in entities:
            if not isinstance(entity, dict):
                continue

            entity_name = entity.get("name", "").strip()
            entity_type = entity.get("type", "")

            if not entity_name:
                continue

            # Find canonical name (resolve through alias map)
            canonical_name = alias_map.get(entity_name.lower(), entity_name)

            # Check if canonical name itself has an alias (transitive)
            while canonical_name.lower() in alias_map and alias_map[canonical_name.lower()] != canonical_name:
                canonical_name = alias_map[canonical_name.lower()]

            key = (canonical_name.lower(), entity_type)
            if key not in entity_groups:
                entity_groups[key] = []
            entity_groups[key].append(entity)

        # Third pass: merge entity groups
        consolidated = []

        for (canonical_name_lower, entity_type), group in entity_groups.items():
            if not group:
                continue

            # Find the best primary name (prefer non-lowercase version)
            primary_name = group[0]["name"]
            for entity in group:
                if entity["name"].lower() == canonical_name_lower:
                    # Prefer the original casing
                    if not entity["name"].islower() or primary_name.islower():
                        primary_name = entity["name"]

            # Collect all unique names (including aliases)
            all_names = set()
            for entity in group:
                all_names.add(entity["name"])

            # Remove primary name from aliases
            aliases = sorted([n for n in all_names if n != primary_name])

            # Merge mentions from all entities in group
            merged_mentions = []
            seen_quotes = set()

            for entity in group:
                for mention in entity.get("mentions", []):
                    # Use first 100 chars of quote as key to detect duplicates
                    quote_key = mention.get("quote", "")[:100]
                    if quote_key and quote_key not in seen_quotes:
                        merged_mentions.append(mention)
                        seen_quotes.add(quote_key)

            # Calculate consolidated confidence
            max_confidence = max((e.get("confidence", 50) for e in group), default=50)
            # Boost confidence based on multiple mentions
            confidence_boost = min(20, len(merged_mentions) * 5)
            final_confidence = min(100, max_confidence + confidence_boost)

            # Create consolidated entity
            consolidated_entity = {
                "name": primary_name,
                "type": entity_type,
                "confidence": final_confidence,
                "mentions": merged_mentions
            }

            # Add aliases if present
            if aliases:
                consolidated_entity["aliases"] = aliases

            consolidated.append(consolidated_entity)

        # Sort by confidence (highest first) for consistent output
        consolidated.sort(key=lambda x: x.get("confidence", 0), reverse=True)

        result = {
            "entities": consolidated,
            "extraction_status": entities_data.get("extraction_status", "completed")
        }

        # Preserve any other keys from original data
        for key in entities_data:
            if key not in result:
                result[key] = entities_data[key]

        logger.info(f"Consolidated {len(entities)} entities into {len(consolidated)} unique entities")

        return result

    @staticmethod
    def _extract_primary_from_alias_quote(quote: str, alias_name: str) -> str:
        """
        Extract the primary entity name from a quote containing an alias.

        Patterns handled:
        - "APT29, also known as Cozy Bear"
        - "APT29 (aka Cozy Bear)"
        - "Cozy Bear (APT29)"
        """
        quote_lower = quote.lower()
        alias_lower = alias_name.lower()

        # Pattern: "X, also known as Y" or "X (aka Y)"
        patterns = [
            r'([^,]+),\s*also known as\s+' + re.escape(alias_lower),
            r'([^,]+),\s*aka\s+' + re.escape(alias_lower),
            r'([^(]+)\s*\(aka\s+' + re.escape(alias_lower) + r'\)',
        ]

        for pattern in patterns:
            match = re.search(pattern, quote, re.IGNORECASE)
            if match:
                primary = match.group(1).strip()
                # Clean up the primary name
                primary = re.sub(r'^(The|the)\s+', '', primary)
                if primary and primary.lower() != alias_lower:
                    return primary

        # Pattern: "Y (X)" where Y is the alias
        if f"{alias_name} (" in quote:
            match = re.search(re.escape(alias_name) + r'\s*\(([^)]+)\)', quote, re.IGNORECASE)
            if match:
                primary = match.group(1).strip()
                if primary and primary.lower() != alias_lower:
                    return primary

        return ""

    @staticmethod
    def _extract_aliases_from_quote(quote: str) -> List[str]:
        """
        Extract all entity names that appear to be aliases from a quote.

        Returns list of names found in alias relationships.
        """
        names = []

        # Pattern: "X, also known as Y"
        match = re.search(r'([^,]+),\s*also known as\s+([^,\\.]+)', quote, re.IGNORECASE)
        if match:
            names.extend([match.group(1).strip(), match.group(2).strip()])

        # Pattern: "X (aka Y)" or "X, aka Y"
        match = re.search(r'([^,(]+)[\s,]*\(?\s*aka\s+([^,)\.]+)', quote, re.IGNORECASE)
        if match:
            names.extend([match.group(1).strip(), match.group(2).strip()])

        # Clean up names
        cleaned = []
        for name in names:
            # Remove leading "the"
            name = re.sub(r'^(The|the)\s+', '', name)
            # Remove trailing punctuation
            name = name.rstrip('.,;:')
            if name and len(name) > 2:  # Skip very short names
                cleaned.append(name)

        return cleaned