"""Candidate attack pattern review API endpoints."""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

from bandjacks.services.api.deps import get_neo4j_session
from bandjacks.services.api.settings import settings
from bandjacks.store.candidate_store import CandidateStore
from bandjacks.loaders.embedder import encode


router = APIRouter(prefix="/review/candidates", tags=["candidates"])


class CandidatePattern(BaseModel):
    """Candidate attack pattern."""
    id: str = Field(..., description="Candidate pattern ID")
    name: str = Field(..., description="Pattern name")
    description: str = Field(..., description="Pattern description")
    source_text: str = Field(..., description="Source text excerpt")
    source_report: str = Field(..., description="Source report ID")
    confidence: float = Field(..., ge=0.0, le=100.0, description="Extraction confidence")
    status: str = Field(..., description="Review status")
    created_at: Optional[str] = Field(None, description="Creation timestamp")
    reviewed_by: Optional[str] = Field(None, description="Reviewer ID")
    has_embedding: bool = Field(False, description="Has vector embedding")


class CreateCandidateRequest(BaseModel):
    """Request to create a candidate pattern."""
    name: str = Field(..., description="Technique name")
    description: str = Field(..., description="Technique description")
    source_text: str = Field(..., description="Original text that led to extraction")
    source_report: str = Field(..., description="Source report ID")
    confidence: float = Field(50.0, ge=0.0, le=100.0, description="Confidence score")
    extraction_method: str = Field("manual", description="Extraction method")
    extraction_model: Optional[str] = Field(None, description="Model used for extraction")
    generate_embedding: bool = Field(True, description="Generate vector embedding")


class ApproveRequest(BaseModel):
    """Request to approve a candidate pattern."""
    reviewer_id: str = Field(..., description="Reviewer ID")
    attack_id: Optional[str] = Field(None, description="STIX ID to assign")
    external_id: Optional[str] = Field(None, description="MITRE ID (e.g., T9999.001)")
    notes: Optional[str] = Field(None, description="Approval notes")


class RejectRequest(BaseModel):
    """Request to reject a candidate pattern."""
    reviewer_id: str = Field(..., description="Reviewer ID")
    reason: str = Field(..., description="Rejection reason")


class SimilarPattern(BaseModel):
    """Similar existing attack pattern."""
    id: str = Field(..., description="Attack pattern STIX ID")
    name: str = Field(..., description="Pattern name")
    description: str = Field(..., description="Pattern description")
    external_id: Optional[str] = Field(None, description="MITRE ATT&CK ID")
    similarity_score: float = Field(..., ge=0.0, le=1.0, description="Similarity score")


@router.get("/",
    summary="List Candidate Patterns",
    description="""
    List candidate attack patterns awaiting review.
    
    Filter by status, confidence, or search by name.
    Results are ordered by confidence and creation date.
    """,
    response_model=List[CandidatePattern]
)
async def list_candidates(
    status: Optional[str] = Query(None, description="Filter by status (pending, approved, rejected)"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=100.0, description="Minimum confidence"),
    limit: int = Query(50, ge=1, le=200, description="Maximum results"),
    neo4j_session=Depends(get_neo4j_session)
) -> List[CandidatePattern]:
    """List candidate attack patterns for review."""
    
    try:
        store = CandidateStore(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        patterns = store.get_candidate_patterns(
            status=status,
            min_confidence=min_confidence,
            limit=limit
        )
        
        store.close()
        
        return [CandidatePattern(**p) for p in patterns]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list candidates: {str(e)}")


@router.post("/",
    summary="Create Candidate Pattern",
    description="""
    Create a new candidate attack pattern from extraction.
    
    This is typically used when the extractor identifies a potentially
    novel technique that doesn't match existing ATT&CK patterns.
    """,
    response_model=Dict[str, Any]
)
async def create_candidate(
    request: CreateCandidateRequest,
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """Create a new candidate attack pattern."""
    
    try:
        store = CandidateStore(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Generate embedding if requested
        embedding = None
        if request.generate_embedding:
            combined_text = f"{request.name} {request.description}"
            embedding = encode(combined_text)
        
        # Create candidate
        candidate_id = store.create_candidate_attack_pattern(
            name=request.name,
            description=request.description,
            source_text=request.source_text,
            source_report=request.source_report,
            extraction_metadata={
                "method": request.extraction_method,
                "model": request.extraction_model,
                "confidence": request.confidence
            },
            embedding=embedding
        )
        
        store.close()
        
        return {
            "candidate_id": candidate_id,
            "status": "created",
            "has_embedding": embedding is not None,
            "confidence": request.confidence
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create candidate: {str(e)}")


@router.get("/{candidate_id}",
    summary="Get Candidate Details",
    description="""
    Get detailed information about a specific candidate pattern.
    
    Returns full details including source text and extraction metadata.
    """,
    response_model=CandidatePattern
)
async def get_candidate(
    candidate_id: str,
    neo4j_session=Depends(get_neo4j_session)
) -> CandidatePattern:
    """Get specific candidate pattern details."""
    
    try:
        with neo4j_session as session:
            query = """
                MATCH (c:CandidateAttackPattern {candidate_id: $candidate_id})
                RETURN c.candidate_id as id,
                       c.name as name,
                       c.description as description,
                       c.source_text as source_text,
                       c.source_report as source_report,
                       c.confidence as confidence,
                       c.status as status,
                       c.created_at as created_at,
                       c.reviewed_by as reviewed_by,
                       c.has_embedding as has_embedding
            """
            
            result = session.run(query, candidate_id=candidate_id)
            record = result.single()
            
            if not record:
                raise HTTPException(status_code=404, detail=f"Candidate {candidate_id} not found")
            
            return CandidatePattern(
                id=record["id"],
                name=record["name"],
                description=record["description"],
                source_text=record["source_text"],
                source_report=record["source_report"],
                confidence=record["confidence"],
                status=record["status"],
                created_at=record["created_at"].isoformat() if record["created_at"] else None,
                reviewed_by=record["reviewed_by"],
                has_embedding=record["has_embedding"] or False
            )
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get candidate: {str(e)}")


@router.post("/{candidate_id}/approve",
    summary="Approve Candidate Pattern",
    description="""
    Approve a candidate pattern and promote it to a full AttackPattern.
    
    This creates a new AttackPattern node in the knowledge graph and
    updates the candidate status to 'promoted'.
    """,
    response_model=Dict[str, Any]
)
async def approve_candidate(
    candidate_id: str,
    request: ApproveRequest,
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """Approve and promote a candidate pattern."""
    
    try:
        store = CandidateStore(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        result = store.promote_candidate_pattern(
            candidate_id=candidate_id,
            reviewer_id=request.reviewer_id,
            attack_id=request.attack_id,
            external_id=request.external_id
        )
        
        store.close()
        
        return {
            "candidate_id": candidate_id,
            "attack_id": result["attack_id"],
            "name": result["name"],
            "status": "approved",
            "promoted": True,
            "reviewer": request.reviewer_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to approve candidate: {str(e)}")


@router.post("/{candidate_id}/reject",
    summary="Reject Candidate Pattern",
    description="""
    Reject a candidate pattern with a reason.
    
    The candidate is marked as rejected and moved to the archive.
    """,
    response_model=Dict[str, Any]
)
async def reject_candidate(
    candidate_id: str,
    request: RejectRequest,
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """Reject a candidate pattern."""
    
    try:
        with neo4j_session as session:
            # Update candidate status
            query = """
                MATCH (c:CandidateAttackPattern {candidate_id: $candidate_id})
                SET c.status = 'rejected',
                    c.reviewed_by = $reviewer_id,
                    c.reviewed_at = datetime(),
                    c.rejection_reason = $reason
                RETURN c.name as name
            """
            
            result = session.run(
                query,
                candidate_id=candidate_id,
                reviewer_id=request.reviewer_id,
                reason=request.reason
            )
            
            record = result.single()
            if not record:
                raise HTTPException(status_code=404, detail=f"Candidate {candidate_id} not found")
            
            return {
                "candidate_id": candidate_id,
                "name": record["name"],
                "status": "rejected",
                "reviewer": request.reviewer_id,
                "reason": request.reason,
                "timestamp": datetime.utcnow().isoformat()
            }
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reject candidate: {str(e)}")


@router.get("/{candidate_id}/similar",
    summary="Find Similar Patterns",
    description="""
    Find existing attack patterns similar to a candidate.
    
    This helps reviewers determine if the candidate represents a truly
    novel technique or maps to an existing one.
    """,
    response_model=List[SimilarPattern]
)
async def find_similar(
    candidate_id: str,
    threshold: float = Query(0.7, ge=0.0, le=1.0, description="Similarity threshold"),
    neo4j_session=Depends(get_neo4j_session)
) -> List[SimilarPattern]:
    """Find existing patterns similar to a candidate."""
    
    try:
        store = CandidateStore(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        similar = store.find_similar_patterns(
            candidate_id=candidate_id,
            threshold=threshold
        )
        
        store.close()
        
        return [SimilarPattern(**s) for s in similar]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to find similar patterns: {str(e)}")


@router.get("/stats/summary",
    summary="Candidate Statistics",
    description="""
    Get summary statistics for candidate patterns.
    
    Returns counts by status, confidence distributions, and recent activity.
    """,
    response_model=Dict[str, Any]
)
async def get_candidate_stats(
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """Get candidate pattern statistics."""
    
    try:
        with neo4j_session as session:
            # Get counts by status
            status_query = """
                MATCH (c:CandidateAttackPattern)
                RETURN c.status as status, count(*) as count
            """
            
            status_result = session.run(status_query)
            status_counts = {}
            for record in status_result:
                status_counts[record["status"] or "pending"] = record["count"]
            
            # Get confidence distribution
            confidence_query = """
                MATCH (c:CandidateAttackPattern)
                WHERE c.status = 'pending'
                RETURN avg(c.confidence) as avg_confidence,
                       min(c.confidence) as min_confidence,
                       max(c.confidence) as max_confidence,
                       count(*) as count
            """
            
            confidence_result = session.run(confidence_query).single()
            
            # Get recent activity
            recent_query = """
                MATCH (c:CandidateAttackPattern)
                WHERE c.created_at > datetime() - duration('P7D')
                RETURN count(*) as recent_count
            """
            
            recent_result = session.run(recent_query).single()
            
            # Get promotion rate
            promotion_query = """
                MATCH (c:CandidateAttackPattern)
                WHERE c.status IN ['promoted', 'rejected']
                WITH c.status as status, count(*) as count
                WITH collect({status: status, count: count}) as counts
                RETURN 
                    COALESCE([x IN counts WHERE x.status = 'promoted'][0].count, 0) as promoted,
                    COALESCE([x IN counts WHERE x.status = 'rejected'][0].count, 0) as rejected
            """
            
            promotion_result = session.run(promotion_query).single()
            promoted = promotion_result["promoted"] if promotion_result else 0
            rejected = promotion_result["rejected"] if promotion_result else 0
            total_reviewed = promoted + rejected
            
            return {
                "total_candidates": sum(status_counts.values()),
                "by_status": status_counts,
                "pending_review": status_counts.get("pending", 0),
                "confidence_stats": {
                    "average": round(confidence_result["avg_confidence"] or 0, 2),
                    "min": confidence_result["min_confidence"] or 0,
                    "max": confidence_result["max_confidence"] or 0,
                    "count": confidence_result["count"] or 0
                },
                "recent_7_days": recent_result["recent_count"] or 0,
                "promotion_rate": round((promoted / total_reviewed * 100) if total_reviewed > 0 else 0, 2),
                "rejection_rate": round((rejected / total_reviewed * 100) if total_reviewed > 0 else 0, 2)
            }
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")