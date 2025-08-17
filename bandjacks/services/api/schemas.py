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


# Sprint 3 Flow Schemas
class FlowBuildRequest(BaseModel):
    """Request to build an attack flow."""
    source_id: Optional[str] = Field(None, description="Report or bundle ID")
    extraction: Optional[Dict[str, Any]] = Field(None, description="LLM extraction results")
    bundle: Optional[Dict[str, Any]] = Field(None, description="STIX bundle")
    strict: bool = Field(True, description="Enforce strict validation")
    use_llm_synthesis: bool = Field(True, description="Use AttackFlowSynthesizer for LLM-based flow generation")


class FlowStep(BaseModel):
    """Individual step in an attack flow."""
    order: int = Field(..., ge=1, description="Step order (1-based)")
    action_id: str = Field(..., description="Unique action identifier")
    attack_pattern_ref: str = Field(..., description="STIX ID of the technique")
    name: str = Field(..., description="Technique name")
    description: str = Field(..., description="What happened in this step")
    confidence: float = Field(..., ge=0, le=100, description="Confidence percentage")
    evidence: Optional[List[Dict[str, Any]]] = Field(None, description="Supporting evidence")
    reason: Optional[str] = Field(None, description="Why this step is here")
    timestamp: Optional[str] = Field(None, description="When this occurred")


class FlowEdge(BaseModel):
    """Edge between flow steps."""
    source: str = Field(..., description="Source action_id")
    target: str = Field(..., description="Target action_id")
    probability: float = Field(..., ge=0.1, le=1.0, description="Transition probability")
    rationale: str = Field(..., description="Reason for this edge")


class FlowBuildResponse(BaseModel):
    """Response from flow build."""
    flow_id: str = Field(..., description="Unique flow identifier")
    episode_id: str = Field(..., description="Attack episode ID")
    name: str = Field(..., description="Flow name")
    source_id: Optional[str] = Field(None, description="Source document/bundle ID")
    steps: List[FlowStep] = Field(..., description="Ordered flow steps")
    edges: List[FlowEdge] = Field(..., description="Transitions between steps")
    stats: Dict[str, Any] = Field(..., description="Flow statistics")
    llm_synthesized: bool = Field(..., description="Whether LLM synthesis was used")
    created_at: str = Field(..., description="Creation timestamp")


class FlowSearchRequest(BaseModel):
    """Request to search for flows."""
    flow_id: Optional[str] = Field(None, description="Find similar to this flow")
    text: Optional[str] = Field(None, description="Search by text description")
    top_k: int = Field(10, ge=1, le=50, description="Number of results")


class FlowSearchResult(BaseModel):
    """Individual flow search result."""
    flow_id: str
    episode_id: str
    name: str
    score: float
    preview: str
    steps_count: int
    tactics: List[str]
    created_at: str


class FlowSearchResponse(BaseModel):
    """Response from flow search."""
    results: List[FlowSearchResult]
    query_type: Literal["flow_similarity", "text_search"]
    total_results: int


class FlowGetResponse(BaseModel):
    """Response from getting a single flow."""
    flow_id: str
    episode_id: str
    name: str
    source_id: Optional[str]
    created_at: str
    strategy: Optional[str]
    llm_synthesized: bool
    steps: List[FlowStep]
    edges: List[FlowEdge]
    metadata: Dict[str, Any]