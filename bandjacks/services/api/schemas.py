"""Pydantic schemas for API requests and responses."""

from typing import Any, List, Optional, Dict, Literal
from pydantic import BaseModel, Field

class VersionRef(BaseModel):
    version: str
    url: str
    modified: Optional[str] = None

class CatalogItem(BaseModel):
    name: str
    key: str
    versions: List[VersionRef]

class UpsertProvenance(BaseModel):
    collection: str
    version: str
    modified: Optional[str] = None
    url: str
    adm_spec: Optional[str] = None
    adm_sha: Optional[str] = None

class UpsertResult(BaseModel):
    inserted: int = 0
    updated: int = 0
    rejected: List[Dict[str, Any]] = Field(default_factory=list)
    provenance: UpsertProvenance
    trace_id: Optional[str] = None


# Sprint 2 Schemas
class ChunkingParams(BaseModel):
    """Parameters for text chunking."""
    target_chars: int = 1200
    overlap: int = 150


class ProposeRequest(BaseModel):
    """Request for mapper proposal."""
    source_id: str
    source_type: Literal["pdf", "html", "md", "json", "csv"]
    content_url: Optional[str] = None
    inline_text: Optional[str] = None
    max_candidates: int = 5
    chunking: ChunkingParams = Field(default_factory=ChunkingParams)
    engine: Literal["vector", "llm", "hybrid"] = "vector"


class ProposalStats(BaseModel):
    """Statistics from proposal generation."""
    chunks: int
    candidates_total: int
    techniques_found: int = 0
    groups_found: int = 0
    software_found: int = 0
    relationships_proposed: int = 0


class ProposalResponse(BaseModel):
    """Response from mapper proposal."""
    proposal_id: str
    bundle: Dict[str, Any]
    stats: ProposalStats


class ReviewDecision(BaseModel):
    """Review decision for mapping or object."""
    object_id: str
    decision: Literal["accept", "edit", "reject"]
    note: Optional[str] = None
    fields_patch: Optional[Dict[str, Any]] = None


class ReviewResponse(BaseModel):
    """Response from review submission."""
    status: str = "recorded"
    object_id: str
    ts: str


class TtxQuery(BaseModel):
    """Text-to-technique search query."""
    text: str
    top_k: int = Field(10, ge=1, le=50)
    kb_types: Optional[List[str]] = Field(None, description="Filter by kb_type, e.g., ['AttackPattern'] or ['IntrusionSet','Software']")


class STIXObject(BaseModel):
    """STIX object with provenance."""
    object: Dict[str, Any]
    provenance: Dict[str, Any]
    relationships: List[Dict[str, Any]] = Field(default_factory=list)