from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class WorkingMemory:
    """Shared CTI-grade working state for agentic extraction.

    Holds spans, retrieval candidates, verified claims, consolidated techniques,
    and caches for graph lookups. Designed to be deterministic and easily
    serializable for debugging and tests.
    """

    document_text: str = ""
    line_index: List[str] = field(default_factory=list)

    # Structured entities from entity extraction agent
    # Format: {
    #   "entities": [
    #     {
    #       "name": str,
    #       "type": str,
    #       "confidence": int (0-100),
    #       "mentions": [
    #         {
    #           "quote": str,
    #           "line_refs": List[int],
    #           "context": str (primary_mention/alias/coreference)
    #         }
    #       ]
    #     }
    #   ],
    #   "extraction_status": str
    # }
    entities: Dict[str, Any] = field(
        default_factory=lambda: {
            "entities": [],
            "extraction_status": "not_attempted"
        }
    )

    # Span candidates likely to contain TTPs: {text, line_refs}
    spans: List[Dict[str, Any]] = field(default_factory=list)

    # Retrieval/free-propose candidates per span index
    # span_idx -> [{external_id, name, score, meta, source}]
    candidates: Dict[int, List[Dict[str, Any]]] = field(default_factory=dict)

    # Verified claims (post-mapping and evidence checks)
    # [{span_idx, external_id, name, quotes, line_refs, confidence, source}]
    claims: List[Dict[str, Any]] = field(default_factory=list)

    # Consolidated techniques map: id -> {name, confidence, evidence, line_refs, tactic?}
    techniques: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Cache for graph lookups keyed by external_id or stix_id
    graph_cache: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Notes/metrics for observability
    notes: List[str] = field(default_factory=list)

    # Extensible metadata for pipeline enhancements (pair suggestions, etc.)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Entity claims from EntityExtractionAgent
    entity_claims: List[Dict[str, Any]] = field(default_factory=list)

    # Consolidated entities from EntityConsolidatorAgent
    consolidated_entities: Dict[str, Any] = field(default_factory=dict)

    # Inferred kill-chain suggestions from KillChainSuggestionsAgent
    inferred_suggestions: List[Dict[str, Any]] = field(default_factory=list)

    # Errors accumulated during extraction stages
    extraction_errors: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entities": self.entities,
            "spans": self.spans,
            "candidates": self.candidates,
            "claims": self.claims,
            "techniques": self.techniques,
            "notes": self.notes,
            "entity_claims": self.entity_claims,
            "consolidated_entities": self.consolidated_entities,
            "inferred_suggestions": self.inferred_suggestions,
            "extraction_errors": self.extraction_errors,
        }

    def add_entity(self, entity_type: str, name: str, evidence: str = "", 
                   confidence: int = 75, context: str = "primary_mention") -> None:
        """Add a normalized entity to the structured entities list if not present."""
        norm = (name or "").strip()
        if not norm:
            return
        
        # Get current entities list
        current_entities = self.entities.get("entities", [])
        
        # Check if entity already exists (case-insensitive)
        for entity in current_entities:
            if isinstance(entity, dict) and entity.get("name", "").lower() == norm.lower():
                # Entity exists, add mention if we have evidence
                if evidence and "mentions" in entity:
                    entity["mentions"].append({
                        "quote": evidence,
                        "line_refs": [],  # Would need to calculate
                        "context": context
                    })
                    # Update confidence if higher
                    entity["confidence"] = max(entity.get("confidence", 75), confidence)
                return
        
        # Add new entity with new structure
        new_entity = {
            "name": name,
            "type": entity_type,
            "confidence": confidence,
            "mentions": []
        }
        
        # Add evidence as first mention if provided
        if evidence:
            new_entity["mentions"].append({
                "quote": evidence,
                "line_refs": [],  # Would need to calculate
                "context": context
            })
        
        current_entities.append(new_entity)
        self.entities["entities"] = current_entities


