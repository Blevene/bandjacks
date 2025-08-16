"""Review API routes for analyst decisions."""

from fastapi import APIRouter, HTTPException, Header
from typing import Optional
from bandjacks.services.api.schemas import ReviewDecision, ReviewResponse, STIXObject
from bandjacks.services.api.settings import settings
from bandjacks.store.review_store import ReviewStore

router = APIRouter(tags=["review"])


@router.post("/review/mapping", response_model=ReviewResponse)
async def review_mapping(
    decision: ReviewDecision,
    x_analyst_id: Optional[str] = Header(None)
):
    """
    Record analyst decision on a proposed mapping.
    
    This endpoint is called when an analyst reviews a mapping proposal
    and decides to accept, edit, or reject it.
    """
    try:
        store = ReviewStore(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        result = store.record_mapping_decision(
            object_id=decision.object_id,
            decision=decision.decision,
            note=decision.note,
            fields_patch=decision.fields_patch,
            analyst_id=x_analyst_id
        )
        
        store.close()
        
        return ReviewResponse(
            status="recorded",
            object_id=decision.object_id,
            ts=result["ts"]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to record review: {str(e)}")


@router.post("/review/object", response_model=ReviewResponse)
async def review_object(
    decision: ReviewDecision,
    x_analyst_id: Optional[str] = Header(None)
):
    """
    Record analyst decision on an existing object.
    
    This endpoint is used for reviewing objects already in the graph,
    such as those loaded from ATT&CK or previous mappings.
    """
    try:
        store = ReviewStore(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        result = store.record_object_decision(
            object_id=decision.object_id,
            decision=decision.decision,
            note=decision.note,
            fields_patch=decision.fields_patch,
            analyst_id=x_analyst_id
        )
        
        store.close()
        
        return ReviewResponse(
            status="recorded",
            object_id=decision.object_id,
            ts=result["ts"]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to record review: {str(e)}")


@router.get("/stix/objects/{object_id}", response_model=STIXObject)
async def get_stix_object(object_id: str):
    """
    Retrieve a STIX object with provenance and relationships.
    
    This endpoint fetches an object from the graph along with its
    source provenance and any relationships it participates in.
    """
    try:
        store = ReviewStore(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        result = store.get_object_with_provenance(object_id)
        store.close()
        
        if not result:
            raise HTTPException(status_code=404, detail=f"Object {object_id} not found")
        
        return STIXObject(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve object: {str(e)}")