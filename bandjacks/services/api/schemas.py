"""Pydantic schemas for API requests and responses."""

from typing import Any, List, Optional, Dict, Literal, Union
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
    trace_id: Optional[str] = Field(None, description="Request trace ID for debugging")


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
    trace_id: Optional[str] = Field(None, description="Request trace ID")


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
    trace_id: Optional[str] = Field(None, description="Request trace ID")


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
    trace_id: Optional[str] = Field(None, description="Request trace ID")


# Sprint 3 Flow Schemas
class FlowBuildRequest(BaseModel):
    """Request to build an attack flow."""
    source_id: Optional[str] = Field(None, description="Report or bundle ID")
    extraction: Optional[Dict[str, Any]] = Field(None, description="LLM extraction results")
    bundle: Optional[Dict[str, Any]] = Field(None, description="STIX bundle")
    strict: bool = Field(True, description="Enforce strict validation")
    use_llm_synthesis: bool = Field(True, description="Use AttackFlowSynthesizer for LLM-based flow generation")
    intrusion_set_id: Optional[str] = Field(None, description="Build from an Intrusion Set (group) by stix_id")
    techniques: Optional[List[str]] = Field(None, description="List of technique identifiers (STIX IDs like 'attack-pattern--...' or ATT&CK IDs like 'T1059.001')")
    campaign_id: Optional[str] = Field(None, description="Build from a Campaign by stix_id")
    report_id: Optional[str] = Field(None, description="Build from a Report by stix_id")
    flow_mode: Optional[Literal["sequential","cooccurrence"]] = Field("sequential", description="Sequence steps by inferred order or as co-occurrence (unordered with low p)")


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
    trace_id: Optional[str] = Field(None, description="Request trace ID")


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
    trace_id: Optional[str] = Field(None, description="Request trace ID")


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
    trace_id: Optional[str] = Field(None, description="Request trace ID")


# Granular Feedback Schemas (1-5 scale)
class QualityScore(BaseModel):
    """Granular quality score for an object or result."""
    object_id: str = Field(..., description="STIX ID or object identifier")
    accuracy: int = Field(..., ge=1, le=5, description="Accuracy score (1=poor, 5=excellent)")
    relevance: int = Field(..., ge=1, le=5, description="Relevance score (1=irrelevant, 5=highly relevant)")
    completeness: int = Field(..., ge=1, le=5, description="Completeness score (1=incomplete, 5=comprehensive)")
    clarity: int = Field(..., ge=1, le=5, description="Clarity score (1=unclear, 5=very clear)")
    overall: Optional[int] = Field(None, ge=1, le=5, description="Overall score (optional, computed if not provided)")
    comment: Optional[str] = Field(None, description="Optional comment explaining the scores")
    analyst_id: Optional[str] = Field(None, description="Analyst providing the feedback")


class QualityFeedback(BaseModel):
    """Submit quality feedback with granular scoring."""
    scores: List[QualityScore] = Field(..., description="Quality scores for one or more objects")
    context: Optional[str] = Field(None, description="Context for the feedback (e.g., query_id, flow_id)")
    session_id: Optional[str] = Field(None, description="Session identifier for grouping feedback")


class QualityFeedbackResponse(BaseModel):
    """Response from quality feedback submission."""
    feedback_id: str
    scores_recorded: int
    average_overall: float
    message: str
    trace_id: Optional[str] = Field(None, description="Request trace ID")


# Drift Detection Schemas
class DriftMetric(BaseModel):
    """Individual drift metric."""
    metric_name: str = Field(..., description="Name of the metric")
    current_value: float = Field(..., description="Current metric value")
    baseline_value: float = Field(..., description="Baseline metric value")
    drift_percentage: float = Field(..., description="Percentage drift from baseline")
    is_significant: bool = Field(..., description="Whether drift is statistically significant")
    threshold: float = Field(..., description="Significance threshold")
    timestamp: str = Field(..., description="When the metric was measured")


class DriftAlert(BaseModel):
    """Alert for significant drift detection."""
    alert_id: str = Field(..., description="Unique alert identifier")
    alert_type: Literal["version", "schema", "performance", "quality"] = Field(..., description="Type of drift")
    severity: Literal["low", "medium", "high", "critical"] = Field(..., description="Alert severity")
    description: str = Field(..., description="Human-readable alert description")
    metrics: List[DriftMetric] = Field(..., description="Metrics involved in the drift")
    recommended_action: str = Field(..., description="Suggested remediation")
    created_at: str = Field(..., description="When alert was created")
    acknowledged: bool = Field(False, description="Whether alert has been acknowledged")


class DriftStatus(BaseModel):
    """Overall drift status."""
    status: Literal["stable", "minor_drift", "major_drift", "critical"] = Field(..., description="Overall status")
    active_alerts: int = Field(..., description="Number of active alerts")
    last_analysis: str = Field(..., description="Last drift analysis timestamp")
    metrics: Dict[str, DriftMetric] = Field(..., description="Current drift metrics by category")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


# ============================================================================
# MISSING RESPONSE MODELS - Added for OpenAPI Compliance
# ============================================================================

class TtxSearchResponse(BaseModel):
    """Response from text-to-technique search."""
    results: List[Dict[str, Any]] = Field(..., description="Search results with scores")
    query: str = Field(..., description="Original search query")
    total_results: int = Field(..., description="Total number of results found")
    trace_id: Optional[str] = Field(None, description="Request trace ID")
    
    class Config:
        schema_extra = {
            "example": {
                "results": [
                    {
                        "external_id": "T1566.001",
                        "name": "Spearphishing Attachment",
                        "score": 0.95,
                        "description": "Adversaries may send spearphishing emails...",
                        "kb_type": "AttackPattern"
                    }
                ],
                "query": "phishing emails with attachments",
                "total_results": 5,
                "trace_id": "abc-123"
            }
        }


class GraphNeighborsResponse(BaseModel):
    """Response for graph neighbor queries."""
    node_id: str = Field(..., description="ID of the queried node")
    neighbors: List[Dict[str, Any]] = Field(..., description="List of neighboring nodes")
    relationships: List[Dict[str, Any]] = Field(..., description="Relationships to neighbors")
    total_neighbors: int = Field(..., description="Total number of neighbors")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class GraphPathResponse(BaseModel):
    """Response for graph path finding."""
    source_id: str = Field(..., description="Source node ID")
    target_id: str = Field(..., description="Target node ID")
    paths: List[List[Dict[str, Any]]] = Field(..., description="List of paths between nodes")
    shortest_path_length: Optional[int] = Field(None, description="Length of shortest path")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class GraphSubgraphResponse(BaseModel):
    """Response for subgraph extraction."""
    nodes: List[Dict[str, Any]] = Field(..., description="Nodes in the subgraph")
    edges: List[Dict[str, Any]] = Field(..., description="Edges in the subgraph")
    stats: Dict[str, int] = Field(..., description="Subgraph statistics")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class QueryHistoryResponse(BaseModel):
    """Response for query history retrieval."""
    queries: List[Dict[str, Any]] = Field(..., description="List of past queries")
    total_queries: int = Field(..., description="Total number of queries in history")
    user_id: Optional[str] = Field(None, description="User ID if authenticated")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class SaveQueryResponse(BaseModel):
    """Response for saving a query."""
    query_id: str = Field(..., description="ID of the saved query")
    message: str = Field(..., description="Success message")
    saved_at: str = Field(..., description="Timestamp when query was saved")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class FeedbackPendingResponse(BaseModel):
    """Response for pending feedback retrieval."""
    pending_items: List[Dict[str, Any]] = Field(..., description="Items awaiting feedback")
    total_pending: int = Field(..., description="Total number of pending items")
    categories: Dict[str, int] = Field(..., description="Pending counts by category")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class FeedbackStatisticsResponse(BaseModel):
    """Response for feedback statistics."""
    total_feedback: int = Field(..., description="Total feedback received")
    average_scores: Dict[str, float] = Field(..., description="Average scores by metric")
    feedback_by_type: Dict[str, int] = Field(..., description="Feedback counts by type")
    recent_trends: Dict[str, Any] = Field(..., description="Recent feedback trends")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class FeedbackApplyResponse(BaseModel):
    """Response for applying feedback."""
    feedback_id: str = Field(..., description="ID of the applied feedback")
    changes_made: List[str] = Field(..., description="List of changes applied")
    status: str = Field(..., description="Application status")
    message: str = Field(..., description="Result message")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class ProvenanceValidationResponse(BaseModel):
    """Response for provenance validation history."""
    object_id: str = Field(..., description="Object being validated")
    validation_history: List[Dict[str, Any]] = Field(..., description="Validation events")
    current_status: str = Field(..., description="Current validation status")
    last_validated: Optional[str] = Field(None, description="Last validation timestamp")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class ProvenanceTraceResponse(BaseModel):
    """Response for trace-based provenance lookup."""
    trace_id: str = Field(..., description="The trace ID queried")
    objects_affected: List[str] = Field(..., description="Objects involved in this trace")
    operations: List[Dict[str, Any]] = Field(..., description="Operations performed")
    timeline: List[Dict[str, Any]] = Field(..., description="Timeline of events")
    trace_id_response: Optional[str] = Field(None, description="Response trace ID")


class LLMToStixResponse(BaseModel):
    """Response for LLM to STIX conversion."""
    bundle: Dict[str, Any] = Field(..., description="Generated STIX bundle")
    objects_created: int = Field(..., description="Number of STIX objects created")
    validation_status: str = Field(..., description="STIX validation status")
    warnings: List[str] = Field(default_factory=list, description="Validation warnings")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class TechniqueStatisticsResponse(BaseModel):
    """Response for technique statistics."""
    technique_id: str = Field(..., description="Technique ID")
    usage_count: int = Field(..., description="Number of times used")
    group_associations: List[str] = Field(..., description="Associated threat groups")
    common_precursors: List[str] = Field(..., description="Common preceding techniques")
    common_successors: List[str] = Field(..., description="Common following techniques")
    confidence_avg: float = Field(..., description="Average confidence score")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class GroupPatternsResponse(BaseModel):
    """Response for group attack patterns."""
    group_id: str = Field(..., description="Threat group ID")
    group_name: str = Field(..., description="Threat group name")
    common_patterns: List[Dict[str, Any]] = Field(..., description="Common attack patterns")
    unique_patterns: List[Dict[str, Any]] = Field(..., description="Unique patterns for this group")
    pattern_sequences: List[List[str]] = Field(..., description="Common sequences of techniques")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class ComparePathsResponse(BaseModel):
    """Response for comparing attack paths."""
    paths: List[Dict[str, Any]] = Field(..., description="Paths being compared")
    similarities: Dict[str, Any] = Field(..., description="Similarities between paths")
    differences: Dict[str, Any] = Field(..., description="Differences between paths")
    recommendations: List[str] = Field(..., description="Defensive recommendations")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class CatalogTacticsResponse(BaseModel):
    """Response for tactics catalog."""
    tactics: List[Dict[str, str]] = Field(..., description="List of ATT&CK tactics")
    total: int = Field(..., description="Total number of tactics")
    version: str = Field(..., description="ATT&CK version")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class AnalyticsStatisticsResponse(BaseModel):
    """Response for analytics statistics."""
    total_techniques: int = Field(..., description="Total techniques in knowledge base")
    total_groups: int = Field(..., description="Total threat groups")
    total_software: int = Field(..., description="Total malware/tools")
    coverage_percentage: float = Field(..., description="Overall coverage percentage")
    most_common_techniques: List[Dict[str, Any]] = Field(..., description="Most frequently seen techniques")
    recent_additions: List[Dict[str, Any]] = Field(..., description="Recently added items")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class AnalyticsReportResponse(BaseModel):
    """Response for analytics report generation."""
    report_type: str = Field(..., description="Type of report generated")
    report_id: str = Field(..., description="Unique report ID")
    content: Dict[str, Any] = Field(..., description="Report content")
    generated_at: str = Field(..., description="Generation timestamp")
    format: str = Field(..., description="Report format (json, pdf, html)")
    download_url: Optional[str] = Field(None, description="URL to download report")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class ReviewQueueActionResponse(BaseModel):
    """Response for review queue actions (approve/reject/batch)."""
    action: str = Field(..., description="Action performed")
    candidate_ids: List[str] = Field(..., description="Affected candidate IDs")
    success_count: int = Field(..., description="Number of successful operations")
    failed_count: int = Field(0, description="Number of failed operations")
    errors: List[Dict[str, str]] = Field(default_factory=list, description="Error details for failures")
    message: str = Field(..., description="Result message")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class CandidateArchiveResponse(BaseModel):
    """Response for archiving old candidates."""
    archived_count: int = Field(..., description="Number of candidates archived")
    cutoff_date: str = Field(..., description="Date used as cutoff for archiving")
    archived_ids: List[str] = Field(..., description="IDs of archived candidates")
    message: str = Field(..., description="Result message")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


# ============================================================================
# ERROR RESPONSE MODELS
# ============================================================================

class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    detail: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    trace_id: Optional[str] = Field(None, description="Request trace ID for debugging")
    
    class Config:
        schema_extra = {
            "example": {
                "error": "ValidationError",
                "message": "Invalid request parameters",
                "detail": {"field": "top_k", "issue": "Must be between 1 and 50"},
                "trace_id": "abc-123"
            }
        }


# ============================================================================
# PAGINATION MODELS
# ============================================================================

class PaginationParams(BaseModel):
    """Common pagination parameters."""
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(20, ge=1, le=100, description="Items per page")
    sort_by: Optional[str] = Field(None, description="Field to sort by")
    sort_order: Literal["asc", "desc"] = Field("desc", description="Sort order")


class PaginatedResponse(BaseModel):
    """Base class for paginated responses."""
    items: List[Any] = Field(..., description="Page items")
    total: int = Field(..., description="Total number of items")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Items per page")
    total_pages: int = Field(..., description="Total number of pages")
    has_next: bool = Field(..., description="Whether there is a next page")
    has_prev: bool = Field(..., description="Whether there is a previous page")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


# ============================================================================
# QUERY ENDPOINT RESPONSE MODELS
# ============================================================================

class QuerySuggestionResponse(BaseModel):
    """Response for query autocomplete suggestions."""
    suggestions: List[Dict[str, str]] = Field(..., description="List of autocomplete suggestions")
    partial_query: str = Field(..., description="Original partial query")
    total_suggestions: int = Field(..., description="Number of suggestions returned")
    trace_id: Optional[str] = Field(None, description="Request trace ID")
    
    class Config:
        schema_extra = {
            "example": {
                "suggestions": [
                    {"text": "lateral movement", "type": "AttackPattern"},
                    {"text": "groups using", "type": "pattern"}
                ],
                "partial_query": "lateral",
                "total_suggestions": 2,
                "trace_id": "abc-123"
            }
        }


# ============================================================================
# FLOW ENDPOINT RESPONSE MODELS  
# ============================================================================

class FlowListResponse(BaseModel):
    """Response for listing attack flows."""
    flows: List[Dict[str, Any]] = Field(..., description="List of attack flows")
    total: int = Field(..., description="Total number of flows")
    page: int = Field(1, description="Current page number")
    page_size: int = Field(20, description="Items per page")
    filters_applied: Optional[Dict[str, Any]] = Field(None, description="Filters that were applied")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class FlowDeleteResponse(BaseModel):
    """Response for deleting an attack flow."""
    flow_id: str = Field(..., description="ID of the deleted flow")
    deleted: bool = Field(..., description="Whether deletion was successful")
    message: str = Field(..., description="Result message")
    cleanup_performed: List[str] = Field(default_factory=list, description="Cleanup actions performed")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


# ============================================================================
# SEQUENCE ANALYSIS RESPONSE MODELS
# ============================================================================

class ValidatedTransition(BaseModel):
    """A validated technique transition."""
    from_technique: str = Field(..., description="Source technique STIX ID")
    from_name: Optional[str] = Field(None, description="Source technique name")
    to_technique: str = Field(..., description="Target technique STIX ID")
    to_name: Optional[str] = Field(None, description="Target technique name")
    confidence: float = Field(..., description="Transition confidence score")
    verdict: str = Field(..., description="Judge verdict (forward/reverse/bidirectional)")
    features: Optional[Dict[str, Any]] = Field(None, description="Feature vector used for scoring")


class UncertainTransition(BaseModel):
    """An uncertain technique transition needing review."""
    from_technique: str = Field(..., description="Source technique STIX ID")
    to_technique: str = Field(..., description="Target technique STIX ID")
    transition_confidence: float = Field(..., description="Transition probability")
    judge_confidence: float = Field(..., description="Judge model confidence")
    reason: Optional[str] = Field(None, description="Reason for uncertainty")


class SequenceProposal(BaseModel):
    """A proposed attack sequence."""
    sequence_id: str = Field(..., description="Unique sequence identifier")
    techniques: List[str] = Field(..., description="Ordered list of technique IDs")
    technique_names: Optional[List[str]] = Field(None, description="Ordered list of technique names")
    edges: List[ValidatedTransition] = Field(..., description="Transitions in the sequence")
    overall_confidence: float = Field(..., description="Overall sequence confidence")
    validation_status: str = Field(..., description="Validation status")
    created_at: Optional[str] = Field(None, description="Creation timestamp")


class PTGModelInfo(BaseModel):
    """PTG model information."""
    model_id: Optional[str] = Field(None, description="Model identifier")
    techniques_count: int = Field(0, description="Number of techniques in model")
    transitions_count: int = Field(0, description="Number of transitions in model")
    parameters: Optional[Dict[str, Any]] = Field(None, description="Model parameters used")


class SequenceAnalysisResponse(BaseModel):
    """Response for sequence analysis."""
    intrusion_set_id: str = Field(..., description="Intrusion set STIX ID")
    intrusion_set_name: str = Field(..., description="Intrusion set name")
    generated_at: str = Field(..., description="Analysis timestamp")
    
    # PTG Model
    ptg_model: PTGModelInfo = Field(..., description="PTG model information")
    
    # Validation Results
    validation_results: Dict[str, Any] = Field(..., description="Validation results")
    validated_transitions: List[ValidatedTransition] = Field(default_factory=list, description="High confidence transitions")
    uncertain_transitions: List[UncertainTransition] = Field(default_factory=list, description="Transitions needing review")
    unknown_count: int = Field(0, description="Number of unknown verdicts")
    
    # Sequence Proposals
    sequence_proposals: List[SequenceProposal] = Field(default_factory=list, description="Generated sequence proposals")
    
    # Statistics
    statistics: Dict[str, Any] = Field(default_factory=dict, description="Analysis statistics")
    
    # Report
    markdown_report: Optional[str] = Field(None, description="Human-readable markdown report")
    
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class SequenceReportResponse(BaseModel):
    """Response for sequence analysis report."""
    intrusion_set_id: str = Field(..., description="Intrusion set STIX ID")
    intrusion_set_name: str = Field(..., description="Intrusion set name")
    report: str = Field(..., description="Markdown formatted report")
    generated_at: str = Field(..., description="Report generation timestamp")
    statistics: Dict[str, Any] = Field(default_factory=dict, description="Analysis statistics")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class SequenceListResponse(BaseModel):
    """Response for listing analyzed sequences."""
    sequences: List[Dict[str, Any]] = Field(..., description="List of analyzed intrusion sets")
    total: int = Field(..., description="Total number of analyzed sets")
    page: int = Field(1, description="Current page number")
    page_size: int = Field(20, description="Items per page")
    filters_applied: Optional[Dict[str, Any]] = Field(None, description="Applied filters")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


# ============================================================================
# DEFENSE ENDPOINT RESPONSE MODELS
# ============================================================================

class DefenseInitializeResponse(BaseModel):
    """Response for D3FEND initialization."""
    status: str = Field(..., description="Initialization status")
    d3fend_version: str = Field(..., description="D3FEND ontology version loaded")
    techniques_loaded: int = Field(..., description="Number of D3FEND techniques loaded")
    relationships_created: int = Field(..., description="Number of COUNTERS relationships created")
    artifacts_mapped: int = Field(..., description="Number of digital artifacts mapped")
    message: str = Field(..., description="Result message")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class DefenseTechniquesResponse(BaseModel):
    """Response for listing D3FEND techniques."""
    techniques: List[Dict[str, Any]] = Field(..., description="List of D3FEND defensive techniques")
    total: int = Field(..., description="Total number of techniques")
    categories: Dict[str, int] = Field(..., description="Techniques by category")
    d3fend_version: str = Field(..., description="D3FEND ontology version")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class DefenseCoverageResponse(BaseModel):
    """Response for defense coverage analysis."""
    attack_pattern_id: str = Field(..., description="ATT&CK technique being analyzed")
    attack_pattern_name: str = Field(..., description="Name of the ATT&CK technique")
    defensive_techniques: List[Dict[str, Any]] = Field(..., description="Applicable D3FEND techniques")
    coverage_score: float = Field(..., ge=0, le=100, description="Coverage percentage")
    gaps: List[str] = Field(..., description="Identified coverage gaps")
    recommendations: List[str] = Field(..., description="Defensive recommendations")
    trace_id: Optional[str] = Field(None, description="Request trace ID")


# ============================================================================
# SEQUENCE MODELING & PTG ENDPOINT SCHEMAS (Sprint 8)
# ============================================================================

class SequenceExtractionResponse(BaseModel):
    """Response for sequence extraction from attack flows."""
    sequences_extracted: int = Field(..., description="Number of sequences extracted")
    scopes_analyzed: int = Field(..., description="Number of scopes analyzed") 
    scope_summaries: List[Dict[str, Any]] = Field(..., description="Summary statistics per scope")
    ambiguous_pairs_total: int = Field(..., description="Total ambiguous pairs across scopes")
    model_id: Optional[str] = Field(None, description="Model ID if exported to Neo4j")
    parameters: Dict[str, Any] = Field(..., description="Extraction parameters used")
    extracted_at: str = Field(..., description="ISO timestamp of extraction")


class PTGBuildRequest(BaseModel):
    """Request to build a Probabilistic Temporal Graph."""
    scope: str = Field(..., description="Scope identifier (intrusion_set_id or 'global')")
    scope_type: str = Field("global", description="Scope type: 'intrusion-set' or 'global'")
    background: bool = Field(False, description="Run PTG build in background")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="PTG construction parameters")


class PTGBuildResponse(BaseModel):
    """Response for PTG build operation.""" 
    model_id: str = Field(..., description="Generated PTG model ID")
    scope: str = Field(..., description="Scope that was processed")
    scope_type: str = Field(..., description="Type of scope")
    status: str = Field(..., description="Build status: building|completed|failed")
    message: str = Field(..., description="Status message")
    total_nodes: int = Field(..., description="Number of technique nodes")
    total_edges: int = Field(..., description="Number of NEXT_P edges created")
    parameters: Dict[str, Any] = Field(..., description="Parameters used")
    statistics: Optional[Dict[str, Any]] = Field(None, description="Model statistics")
    created_at: str = Field(..., description="ISO timestamp")


class PTGModelResponse(BaseModel):
    """Response for PTG model retrieval."""
    model_id: str = Field(..., description="PTG model identifier")
    scope: str = Field(..., description="Model scope")
    scope_type: str = Field(..., description="Scope type")
    version: str = Field(..., description="Model version")
    nodes: Dict[str, Dict[str, Any]] = Field(..., description="Technique nodes with metadata")
    edges: List[Dict[str, Any]] = Field(..., description="NEXT_P edges with probabilities")
    parameters: Dict[str, Any] = Field(..., description="Model construction parameters")
    statistics: Dict[str, Any] = Field(..., description="Model statistics")
    filters_applied: Dict[str, Any] = Field(..., description="Filters applied to response")
    created_at: str = Field(..., description="ISO timestamp")


class SequenceStatisticsResponse(BaseModel):
    """Response for pairwise sequence statistics."""
    scope: str = Field(..., description="Statistics scope")
    scope_type: str = Field(..., description="Scope type")
    total_flows: int = Field(..., description="Number of flows analyzed")
    total_techniques: int = Field(..., description="Number of unique techniques")
    total_pairs: int = Field(..., description="Number of technique pairs")
    top_techniques: Dict[str, int] = Field(..., description="Most frequent techniques")
    top_pairs: Optional[Dict[str, float]] = Field(None, description="Top transitions by probability")
    asymmetry_scores: Optional[Dict[str, float]] = Field(None, description="Directional asymmetry scores")
    created_at: str = Field(..., description="ISO timestamp")