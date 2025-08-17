"""Feedback collection and management endpoints."""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List, Optional, Literal
from pydantic import BaseModel, Field
from datetime import datetime
import uuid
import json
from bandjacks.services.api.deps import get_neo4j_session


router = APIRouter(prefix="/feedback", tags=["feedback"])


class RelevanceFeedback(BaseModel):
    """Relevance feedback for search results."""
    query_id: Optional[str] = Field(None, description="Associated query ID")
    object_id: str = Field(..., description="STIX ID of the object")
    relevance: Literal["relevant", "irrelevant", "needs_context"] = Field(
        ..., 
        description="Relevance judgment"
    )
    comment: Optional[str] = Field(None, description="Optional comment")
    analyst_id: Optional[str] = Field(None, description="Analyst identifier")


class CorrectionFeedback(BaseModel):
    """Correction feedback for objects or relationships."""
    object_id: str = Field(..., description="STIX ID to correct")
    correction_type: Literal["property", "relationship", "classification"] = Field(
        ...,
        description="Type of correction"
    )
    field: Optional[str] = Field(None, description="Field to correct (for property corrections)")
    old_value: Optional[Any] = Field(None, description="Current value")
    new_value: Any = Field(..., description="Proposed new value")
    rationale: str = Field(..., description="Reason for correction")
    evidence: Optional[str] = Field(None, description="Supporting evidence")
    analyst_id: Optional[str] = Field(None, description="Analyst identifier")


class ValidationFeedback(BaseModel):
    """Validation feedback for extracted entities."""
    object_id: str = Field(..., description="STIX ID to validate")
    validation: Literal["approve", "reject", "needs_review"] = Field(
        ...,
        description="Validation decision"
    )
    confidence_adjustment: Optional[float] = Field(
        None,
        ge=-50,
        le=50,
        description="Confidence adjustment (-50 to +50)"
    )
    reason: Optional[str] = Field(None, description="Reason for decision")
    analyst_id: Optional[str] = Field(None, description="Analyst identifier")


class FeedbackResponse(BaseModel):
    """Response for feedback submission."""
    feedback_id: str
    status: str
    message: str


@router.post("/relevance",
    response_model=FeedbackResponse,
    summary="Submit Relevance Feedback",
    description="""
    Submit relevance feedback for search results.
    
    This feedback is used to:
    - Improve search ranking algorithms
    - Learn query patterns and user preferences
    - Identify gaps in the knowledge base
    - Train machine learning models for better matching
    
    Feedback is stored and aggregated for continuous improvement.
    """,
    responses={
        200: {"description": "Feedback successfully recorded"},
        400: {"description": "Invalid feedback data"},
        500: {"description": "Internal server error"}
    }
)
async def submit_relevance_feedback(
    feedback: RelevanceFeedback,
    neo4j_session=Depends(get_neo4j_session)
) -> FeedbackResponse:
    feedback_id = str(uuid.uuid4())
    
    # Create feedback node
    query = """
        CREATE (f:Feedback {
            id: $id,
            type: 'relevance',
            object_id: $object_id,
            relevance: $relevance,
            comment: $comment,
            analyst_id: $analyst_id,
            query_id: $query_id,
            timestamp: datetime(),
            status: 'recorded'
        })
        WITH f
        MATCH (n {stix_id: $object_id})
        CREATE (f)-[:ON]->(n)
        RETURN f.id as id
    """
    
    result = neo4j_session.run(
        query,
        id=feedback_id,
        object_id=feedback.object_id,
        relevance=feedback.relevance,
        comment=feedback.comment,
        analyst_id=feedback.analyst_id or "anonymous",
        query_id=feedback.query_id
    )
    
    record = result.single()
    
    if record:
        # Update relevance scores on the object
        update_query = """
            MATCH (n {stix_id: $object_id})
            SET n.relevance_positive = coalesce(n.relevance_positive, 0) + $positive,
                n.relevance_negative = coalesce(n.relevance_negative, 0) + $negative,
                n.relevance_neutral = coalesce(n.relevance_neutral, 0) + $neutral,
                n.last_feedback = datetime()
            RETURN n.stix_id as id
        """
        
        positive = 1 if feedback.relevance == "relevant" else 0
        negative = 1 if feedback.relevance == "irrelevant" else 0
        neutral = 1 if feedback.relevance == "needs_context" else 0
        
        neo4j_session.run(
            update_query,
            object_id=feedback.object_id,
            positive=positive,
            negative=negative,
            neutral=neutral
        )
        
        return FeedbackResponse(
            feedback_id=feedback_id,
            status="success",
            message=f"Relevance feedback recorded for {feedback.object_id}"
        )
    else:
        raise HTTPException(status_code=500, detail="Failed to record feedback")


@router.post("/correction", response_model=FeedbackResponse)
async def submit_correction_feedback(
    feedback: CorrectionFeedback,
    neo4j_session=Depends(get_neo4j_session)
) -> FeedbackResponse:
    """
    Submit a correction for an object or relationship.
    
    Corrections require review before being applied to maintain
    data quality and audit trail.
    """
    feedback_id = str(uuid.uuid4())
    
    # Create correction feedback
    query = """
        CREATE (f:Feedback {
            id: $id,
            type: 'correction',
            object_id: $object_id,
            correction_type: $correction_type,
            field: $field,
            old_value: $old_value,
            new_value: $new_value,
            rationale: $rationale,
            evidence: $evidence,
            analyst_id: $analyst_id,
            timestamp: datetime(),
            status: 'pending_review'
        })
        WITH f
        MATCH (n {stix_id: $object_id})
        CREATE (f)-[:ON]->(n)
        RETURN f.id as id, n.name as object_name
    """
    
    result = neo4j_session.run(
        query,
        id=feedback_id,
        object_id=feedback.object_id,
        correction_type=feedback.correction_type,
        field=feedback.field,
        old_value=json.dumps(feedback.old_value) if feedback.old_value else None,
        new_value=json.dumps(feedback.new_value),
        rationale=feedback.rationale,
        evidence=feedback.evidence,
        analyst_id=feedback.analyst_id or "anonymous"
    )
    
    record = result.single()
    
    if record:
        return FeedbackResponse(
            feedback_id=feedback_id,
            status="pending_review",
            message=f"Correction submitted for {record['object_name'] or feedback.object_id}"
        )
    else:
        raise HTTPException(status_code=404, detail=f"Object {feedback.object_id} not found")


@router.post("/validation", response_model=FeedbackResponse)
async def submit_validation_feedback(
    feedback: ValidationFeedback,
    neo4j_session=Depends(get_neo4j_session)
) -> FeedbackResponse:
    """
    Submit validation feedback for extracted entities.
    
    This is used to approve or reject candidates from extraction
    before they are merged into the main knowledge graph.
    """
    feedback_id = str(uuid.uuid4())
    
    # Create validation feedback
    query = """
        CREATE (f:Feedback {
            id: $id,
            type: 'validation',
            object_id: $object_id,
            validation: $validation,
            confidence_adjustment: $confidence_adjustment,
            reason: $reason,
            analyst_id: $analyst_id,
            timestamp: datetime(),
            status: 'recorded'
        })
        WITH f
        MATCH (n {stix_id: $object_id})
        CREATE (f)-[:ON]->(n)
        RETURN f.id as id, n.name as object_name,
               n:CandidateNode as is_candidate
    """
    
    result = neo4j_session.run(
        query,
        id=feedback_id,
        object_id=feedback.object_id,
        validation=feedback.validation,
        confidence_adjustment=feedback.confidence_adjustment,
        reason=feedback.reason,
        analyst_id=feedback.analyst_id or "anonymous"
    )
    
    record = result.single()
    
    if record:
        # If validating a candidate node, update its status
        if record["is_candidate"]:
            if feedback.validation == "approve":
                status = "approved"
            elif feedback.validation == "reject":
                status = "rejected"
            else:
                status = "under_review"
            
            update_query = """
                MATCH (n:CandidateNode {stix_id: $object_id})
                SET n.validation_status = $status,
                    n.validation_timestamp = datetime(),
                    n.validated_by = $analyst_id,
                    n.x_bj_confidence = n.x_bj_confidence + $adjustment
                RETURN n.stix_id as id
            """
            
            neo4j_session.run(
                update_query,
                object_id=feedback.object_id,
                status=status,
                analyst_id=feedback.analyst_id or "anonymous",
                adjustment=feedback.confidence_adjustment or 0
            )
        
        return FeedbackResponse(
            feedback_id=feedback_id,
            status="success",
            message=f"Validation feedback recorded for {feedback.object_id}"
        )
    else:
        raise HTTPException(status_code=404, detail=f"Object {feedback.object_id} not found")


@router.get("/pending")
async def get_pending_feedback(
    feedback_type: Optional[str] = None,
    limit: int = 50,
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """
    Get pending feedback items that need review or action.
    
    Returns corrections pending review and other actionable feedback.
    """
    # Build query based on type filter
    if feedback_type:
        query = """
            MATCH (f:Feedback {type: $type})
            WHERE f.status IN ['pending_review', 'pending']
            OPTIONAL MATCH (f)-[:ON]->(n)
            RETURN f, n.stix_id as object_id, n.name as object_name
            ORDER BY f.timestamp DESC
            LIMIT $limit
        """
        params = {"type": feedback_type, "limit": limit}
    else:
        query = """
            MATCH (f:Feedback)
            WHERE f.status IN ['pending_review', 'pending']
            OPTIONAL MATCH (f)-[:ON]->(n)
            RETURN f, n.stix_id as object_id, n.name as object_name
            ORDER BY f.timestamp DESC
            LIMIT $limit
        """
        params = {"limit": limit}
    
    result = neo4j_session.run(query, **params)
    
    pending_items = []
    for record in result:
        feedback = dict(record["f"])
        
        # Parse JSON fields
        if feedback.get("old_value"):
            try:
                feedback["old_value"] = json.loads(feedback["old_value"])
            except:
                pass
        
        if feedback.get("new_value"):
            try:
                feedback["new_value"] = json.loads(feedback["new_value"])
            except:
                pass
        
        pending_items.append({
            "feedback_id": feedback.get("id"),
            "type": feedback.get("type"),
            "object_id": record["object_id"],
            "object_name": record["object_name"],
            "status": feedback.get("status"),
            "timestamp": feedback.get("timestamp"),
            "analyst_id": feedback.get("analyst_id"),
            "details": feedback
        })
    
    return {
        "pending_count": len(pending_items),
        "items": pending_items
    }


@router.post("/{feedback_id}/apply")
async def apply_feedback(
    feedback_id: str,
    reviewer_id: Optional[str] = None,
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """
    Apply approved feedback (corrections).
    
    This actually modifies the knowledge graph based on the feedback.
    Requires appropriate permissions.
    """
    # Get the feedback
    query = """
        MATCH (f:Feedback {id: $id})
        OPTIONAL MATCH (f)-[:ON]->(n)
        RETURN f, n
    """
    
    result = neo4j_session.run(query, id=feedback_id)
    record = result.single()
    
    if not record:
        raise HTTPException(status_code=404, detail=f"Feedback {feedback_id} not found")
    
    feedback = dict(record["f"])
    target = dict(record["n"]) if record["n"] else None
    
    if feedback["type"] != "correction":
        return {
            "status": "skipped",
            "message": "Only correction feedback can be applied"
        }
    
    if feedback["status"] == "applied":
        return {
            "status": "already_applied",
            "message": "Feedback has already been applied"
        }
    
    if not target:
        raise HTTPException(status_code=404, detail="Target object not found")
    
    # Apply the correction
    if feedback["correction_type"] == "property":
        # Update a property on the node
        field = feedback["field"]
        new_value = json.loads(feedback["new_value"]) if feedback["new_value"] else None
        
        update_query = f"""
            MATCH (n {{stix_id: $object_id}})
            SET n.{field} = $new_value,
                n.last_modified = datetime(),
                n.modified_by = $reviewer
            RETURN n.stix_id as id
        """
        
        neo4j_session.run(
            update_query,
            object_id=target["stix_id"],
            new_value=new_value,
            reviewer=reviewer_id or "system"
        )
        
        # Mark feedback as applied
        neo4j_session.run(
            """
            MATCH (f:Feedback {id: $id})
            SET f.status = 'applied',
                f.applied_timestamp = datetime(),
                f.applied_by = $reviewer
            """,
            id=feedback_id,
            reviewer=reviewer_id or "system"
        )
        
        return {
            "status": "success",
            "message": f"Correction applied to {target['stix_id']}",
            "field_updated": field,
            "new_value": new_value
        }
    
    else:
        return {
            "status": "not_implemented",
            "message": f"Correction type {feedback['correction_type']} not yet implemented"
        }


@router.get("/statistics")
async def get_feedback_statistics(
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """
    Get feedback statistics for monitoring and analysis.
    """
    # Count feedback by type and status
    stats_query = """
        MATCH (f:Feedback)
        RETURN f.type as type, f.status as status, count(*) as count
    """
    
    result = neo4j_session.run(stats_query)
    
    stats_by_type = {}
    for record in result:
        feedback_type = record["type"]
        status = record["status"]
        count = record["count"]
        
        if feedback_type not in stats_by_type:
            stats_by_type[feedback_type] = {}
        
        stats_by_type[feedback_type][status] = count
    
    # Get recent feedback activity
    recent_query = """
        MATCH (f:Feedback)
        WHERE f.timestamp > datetime() - duration('P7D')
        RETURN date(f.timestamp) as date, count(*) as count
        ORDER BY date
    """
    
    recent_result = neo4j_session.run(recent_query)
    
    recent_activity = []
    for record in recent_result:
        recent_activity.append({
            "date": str(record["date"]),
            "count": record["count"]
        })
    
    # Get top contributors
    contributor_query = """
        MATCH (f:Feedback)
        WHERE f.analyst_id IS NOT NULL AND f.analyst_id <> 'anonymous'
        RETURN f.analyst_id as analyst, count(*) as feedback_count
        ORDER BY feedback_count DESC
        LIMIT 10
    """
    
    contributor_result = neo4j_session.run(contributor_query)
    
    top_contributors = []
    for record in contributor_result:
        top_contributors.append({
            "analyst": record["analyst"],
            "feedback_count": record["feedback_count"]
        })
    
    return {
        "feedback_by_type": stats_by_type,
        "recent_activity": recent_activity,
        "top_contributors": top_contributors,
        "total_feedback": sum(
            sum(status_counts.values()) 
            for status_counts in stats_by_type.values()
        )
    }