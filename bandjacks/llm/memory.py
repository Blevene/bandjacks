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

    entities: Dict[str, List[str]] = field(
        default_factory=lambda: {
            "threat_actors": [],
            "malware": [],
            "tools": [],
            "campaigns": [],
            "infrastructure": [],
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entities": self.entities,
            "spans": self.spans,
            "candidates": self.candidates,
            "claims": self.claims,
            "techniques": self.techniques,
            "notes": self.notes,
        }

    def add_entity(self, kind: str, name: str) -> None:
        """Add a normalized entity name to the specified kind if not present."""
        norm = (name or "").strip()
        if not norm:
            return
        current = self.entities.get(kind, [])
        if norm.lower() not in [e.lower() for e in current]:
            current.append(name)
            self.entities[kind] = current


