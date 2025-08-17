"""Review queue management endpoints for candidate nodes."""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import Dict, Any, List, Optional, Literal
from pydantic import BaseModel, Field
from bandjacks.services.api.deps import get_neo4j_session
from bandjacks.services.api.settings import settings
from bandjacks.store.candidate_store import CandidateStore


router = APIRouter(prefix="/review_queue", tags=["review_queue"])


class CandidateResponse(BaseModel):
    """Candidate node response."""
    id: str
    stix_id: str
    type: str
    name: str
    description: Optional[str]
    source_report: str
    extraction_confidence: float
    status: str
    created_at: str
    stix_object: Dict[str, Any]
    provenance: Dict[str, Any]


class ApprovalRequest(BaseModel):
    """Request to approve a candidate."""
    reviewer_id: str = Field(..., description="ID of the reviewer")
    merge_to_graph: bool = Field(True, description="Whether to merge to main graph")
    notes: Optional[str] = Field(None, description="Optional approval notes")


class RejectionRequest(BaseModel):
    """Request to reject a candidate."""
    reviewer_id: str = Field(..., description="ID of the reviewer")
    reason: str = Field(..., description="Reason for rejection")


class BatchApprovalRequest(BaseModel):
    """Request to approve multiple candidates."""
    candidate_ids: List[str] = Field(..., description="List of candidate IDs")
    reviewer_id: str = Field(..., description="ID of the reviewer")
    merge_to_graph: bool = Field(True, description="Whether to merge to main graph")


class QueueStatsResponse(BaseModel):
    """Review queue statistics."""
    total_candidates: int
    by_status: Dict[str, int]
    by_type: Dict[str, int]
    confidence_stats: Dict[str, Dict[str, float]]
    recent_24h: int
    pending_review: int
    auto_approved: int


@router.get("/queue", response_model=List[CandidateResponse])
async def get_review_queue(
    status: Optional[Literal["pending", "under_review", "auto_approved", "approved", "rejected"]] = Query(
        None,
        description="Filter by status"
    ),
    entity_type: Optional[str] = Query(None, description="Filter by STIX type"),
    min_confidence: Optional[float] = Query(None, ge=0, le=100, description="Minimum confidence"),
    limit: int = Query(50, ge=1, le=200, description="Maximum results"),
    offset: int = Query(0, ge=0, description="Pagination offset")
) -> List[CandidateResponse]:
    """
    Get candidates from the review queue.
    
    Returns a list of candidate nodes pending review, with optional filters.
    """
    store = CandidateStore(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        candidates = store.get_queue(
            status=status,
            entity_type=entity_type,
            min_confidence=min_confidence,
            limit=limit,
            offset=offset
        )
        
        return [CandidateResponse(**c) for c in candidates]
    
    finally:
        store.close()


@router.get("/queue/{candidate_id}", response_model=CandidateResponse)
async def get_candidate(candidate_id: str) -> CandidateResponse:
    """
    Get a specific candidate by ID.
    
    Returns detailed information about a candidate node.
    """
    store = CandidateStore(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        candidate = store.get_candidate(candidate_id)
        
        if not candidate:
            raise HTTPException(status_code=404, detail=f"Candidate {candidate_id} not found")
        
        return CandidateResponse(**candidate)
    
    finally:
        store.close()


@router.post("/approve/{candidate_id}")
async def approve_candidate(
    candidate_id: str,
    request: ApprovalRequest
) -> Dict[str, Any]:
    """
    Approve a candidate and optionally merge to main graph.
    
    This marks the candidate as approved and can automatically merge it
    into the main knowledge graph as a proper entity.
    """
    store = CandidateStore(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        result = store.approve_candidate(
            candidate_id=candidate_id,
            reviewer_id=request.reviewer_id,
            merge_to_graph=request.merge_to_graph
        )
        
        return {
            "status": "success",
            "candidate_id": candidate_id,
            "approved": True,
            "merged": result.get("merged", False),
            "merged_stix_id": result.get("merged_stix_id"),
            "message": f"Candidate approved{' and merged to graph' if result.get('merged') else ''}"
        }
    
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Approval failed: {str(e)}")
    finally:
        store.close()


@router.post("/reject/{candidate_id}")
async def reject_candidate(
    candidate_id: str,
    request: RejectionRequest
) -> Dict[str, Any]:
    """
    Reject a candidate with a reason.
    
    This marks the candidate as rejected and moves it to the archive.
    """
    store = CandidateStore(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        result = store.reject_candidate(
            candidate_id=candidate_id,
            reviewer_id=request.reviewer_id,
            reason=request.reason
        )
        
        return {
            "status": "success",
            "candidate_id": candidate_id,
            "rejected": True,
            "reason": request.reason,
            "message": "Candidate rejected and archived"
        }
    
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Rejection failed: {str(e)}")
    finally:
        store.close()


@router.post("/batch/approve")
async def batch_approve(
    request: BatchApprovalRequest
) -> Dict[str, Any]:
    """
    Approve multiple candidates in batch.
    
    Efficient batch operation for approving multiple candidates at once.
    """
    store = CandidateStore(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        results = store.batch_approve(
            candidate_ids=request.candidate_ids,
            reviewer_id=request.reviewer_id,
            merge_to_graph=request.merge_to_graph
        )
        
        return {
            "status": "success",
            "total_processed": len(request.candidate_ids),
            "approved_count": len(results["approved"]),
            "merged_count": len(results["merged"]),
            "failed_count": len(results["failed"]),
            "approved": results["approved"],
            "merged": results["merged"],
            "failed": results["failed"]
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch approval failed: {str(e)}")
    finally:
        store.close()


@router.put("/status/{candidate_id}")
async def update_candidate_status(
    candidate_id: str,
    status: Literal["pending", "under_review", "approved", "rejected"],
    reviewer_id: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, Any]:
    """
    Update the status of a candidate.
    
    Allows changing the workflow state of a candidate without full approval/rejection.
    """
    store = CandidateStore(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        success = store.update_status(
            candidate_id=candidate_id,
            status=status,
            reviewer_id=reviewer_id,
            reason=reason
        )
        
        if success:
            return {
                "status": "success",
                "candidate_id": candidate_id,
                "new_status": status,
                "message": f"Status updated to {status}"
            }
        else:
            raise HTTPException(status_code=404, detail=f"Candidate {candidate_id} not found")
    
    finally:
        store.close()


@router.get("/stats", response_model=QueueStatsResponse)
async def get_queue_statistics() -> QueueStatsResponse:
    """
    Get review queue statistics.
    
    Returns aggregate statistics about the review queue including
    counts by status, type, and confidence levels.
    """
    store = CandidateStore(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        stats = store.get_statistics()
        return QueueStatsResponse(**stats)
    
    finally:
        store.close()


@router.post("/from_extraction")
async def create_candidates_from_extraction(
    stix_bundle: Dict[str, Any],
    source_report: str,
    extraction_metadata: Dict[str, Any],
    auto_approve_threshold: float = 95.0
) -> Dict[str, Any]:
    """
    Create candidate nodes from an extraction bundle.
    
    This is called by the extraction pipeline to submit candidates
    for review before merging into the main graph.
    """
    store = CandidateStore(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        candidate_ids = []
        auto_approved = []
        
        # Process each object in the bundle
        for stix_object in stix_bundle.get("objects", []):
            # Skip certain types that don't need review
            if stix_object.get("type") in ["report", "relationship"]:
                continue
            
            # Get confidence from object or metadata
            confidence = stix_object.get("x_bj_confidence", 
                                        extraction_metadata.get("confidence", 50))
            
            # Create extraction metadata for this object
            object_metadata = extraction_metadata.copy()
            object_metadata["confidence"] = confidence
            object_metadata["provenance"] = stix_object.get("x_bj_provenance", {})
            
            # Create candidate
            candidate_id = store.create_candidate(
                stix_object=stix_object,
                source_report=source_report,
                extraction_metadata=object_metadata,
                auto_approve_threshold=auto_approve_threshold
            )
            
            candidate_ids.append(candidate_id)
            
            if confidence >= auto_approve_threshold:
                auto_approved.append(candidate_id)
        
        return {
            "status": "success",
            "candidates_created": len(candidate_ids),
            "auto_approved_count": len(auto_approved),
            "candidate_ids": candidate_ids,
            "auto_approved_ids": auto_approved,
            "message": f"Created {len(candidate_ids)} candidates from extraction"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create candidates: {str(e)}")
    finally:
        store.close()


@router.delete("/archive/old")
async def archive_old_candidates(
    days_old: int = 30,
    status_filter: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Archive old candidates to keep the queue manageable.
    
    Moves old candidates to an archive status based on age and status.
    """
    if not status_filter:
        status_filter = ["rejected", "approved"]
    
    store = CandidateStore(
        settings.neo4j_uri,
        settings.neo4j_user,
        settings.neo4j_password
    )
    
    try:
        with store.driver.session() as session:
            query = """
                MATCH (c:CandidateNode)
                WHERE c.created_at < datetime() - duration({days: $days})
                  AND c.status IN $statuses
                REMOVE c:CandidateNode
                SET c:ArchivedCandidate,
                    c.archived_at = datetime()
                RETURN count(c) as archived_count
            """
            
            result = session.run(
                query,
                days=days_old,
                statuses=status_filter
            )
            
            record = result.single()
            archived = record["archived_count"] if record else 0
            
            return {
                "status": "success",
                "archived_count": archived,
                "message": f"Archived {archived} candidates older than {days_old} days"
            }
    
    finally:
        store.close()