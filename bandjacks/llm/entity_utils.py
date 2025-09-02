"""Entity utility functions for extraction pipeline."""

import re
import logging
from typing import Dict, List, Any, Set, Tuple

logger = logging.getLogger(__name__)


def consolidate_entities(entities_data: Dict[str, Any]) -> Dict[str, Any]:
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
                primary = _extract_primary_from_alias_quote(quote, entity_name)
                if primary and primary != entity_name:
                    alias_map[entity_name.lower()] = primary
                    logger.debug(f"Identified {entity_name} as alias of {primary}")
            
            # Look for "also known as" patterns in quotes
            elif "also known as" in quote.lower() or ", aka " in quote.lower():
                aliases = _extract_aliases_from_quote(quote)
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