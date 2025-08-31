"""Entity review endpoints for analyst verification."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from neo4j import Session

from bandjacks.services.api.deps import get_neo4j_session, get_opensearch_client
from bandjacks.store.opensearch_report_store import OpenSearchReportStore
from opensearchpy import OpenSearch
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["entity-review"])


class EntityReviewRequest(BaseModel):
    """Entity review submission."""
    entities: Dict[str, Any] = Field(..., description="Reviewed entities with status")
    reviewer_id: str = Field(..., description="Reviewer identifier")
    timestamp: str = Field(..., description="Review timestamp")
    notes: Optional[str] = Field(None, description="Review notes")


class EntityReviewResponse(BaseModel):
    """Response after entity review submission."""
    success: bool
    message: str
    entities_reviewed: int
    entities_approved: int
    entities_rejected: int


@router.post(
    "/{report_id}/entities/review",
    response_model=EntityReviewResponse,
    summary="Submit Entity Review",
    description="Submit entity review decisions for a report."
)
async def submit_entity_review(
    report_id: str,
    request: EntityReviewRequest,
    os_client: OpenSearch = Depends(get_opensearch_client)
):
    """Submit entity review for a report."""
    
    os_store = OpenSearchReportStore(os_client)
    
    # Get the report
    report = os_store.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    
    # Count review statistics and generate STIX IDs for entities
    import uuid
    entities_reviewed = 0
    entities_approved = 0
    entities_rejected = 0
    
    # Process entities and add STIX IDs if missing
    processed_entities = {}
    stix_type_map = {
        "malware": "malware",
        "software": "tool",
        "threat_actors": "intrusion-set",
        "campaigns": "campaign"
    }
    
    for entity_type in ["malware", "software", "threat_actors", "campaigns"]:
        processed_entities[entity_type] = []
        entities = request.entities.get(entity_type, [])
        for entity in entities:
            if isinstance(entity, dict):
                entities_reviewed += 1
                status = entity.get("review_status")
                if status == "approved":
                    entities_approved += 1
                elif status == "rejected":
                    entities_rejected += 1
                
                # Add STIX ID if missing
                if not entity.get("stix_id"):
                    stix_type = stix_type_map.get(entity_type, "x-unknown")
                    entity["stix_id"] = f"{stix_type}--{uuid.uuid4()}"
                
                processed_entities[entity_type].append(entity)
    
    # Update report with entity review
    try:
        # Update the extraction data with reviewed entities (including STIX IDs)
        update_doc = {
            "doc": {
                "extraction": {
                    **report.get("extraction", {}),
                    "entities": processed_entities,  # Use processed entities with STIX IDs
                    "entity_review": {
                        "reviewer_id": request.reviewer_id,
                        "reviewed_at": request.timestamp,
                        "notes": request.notes,
                        "statistics": {
                            "total_reviewed": entities_reviewed,
                            "approved": entities_approved,
                            "rejected": entities_rejected
                        }
                    }
                },
                "modified": datetime.utcnow().isoformat()
            }
        }
        
        # Update in OpenSearch
        os_client.update(
            index="bandjacks_reports",
            id=report_id,
            body=update_doc
        )
        
        logger.info(f"Entity review submitted for report {report_id}: "
                   f"{entities_approved} approved, {entities_rejected} rejected")
        
        return EntityReviewResponse(
            success=True,
            message="Entity review submitted successfully",
            entities_reviewed=entities_reviewed,
            entities_approved=entities_approved,
            entities_rejected=entities_rejected
        )
        
    except Exception as e:
        logger.error(f"Failed to submit entity review for {report_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save entity review: {str(e)}"
        )


@router.post(
    "/{report_id}/entities/approve",
    summary="Approve and Upsert Entities",
    description="Approve reviewed entities and upsert to graph."
)
async def approve_entities(
    report_id: str,
    os_client: OpenSearch = Depends(get_opensearch_client),
    neo4j_session: Session = Depends(get_neo4j_session)
):
    """Approve entities and upsert to Neo4j graph."""
    
    os_store = OpenSearchReportStore(os_client)
    report = os_store.get_report(report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    
    entities = report.get("extraction", {}).get("entities", {})
    if not entities:
        raise HTTPException(status_code=400, detail="No entities to approve")
    
    # Collect approved entities
    approved_entities = []
    
    for entity_type in ["malware", "software", "threat_actors", "campaigns"]:
        for entity in entities.get(entity_type, []):
            if isinstance(entity, dict) and entity.get("review_status") == "approved":
                approved_entities.append({
                    **entity,
                    "entity_type": entity_type.rstrip("s")  # Remove plural
                })
    
    if not approved_entities:
        raise HTTPException(status_code=400, detail="No approved entities to upsert")
    
    # Upsert to Neo4j
    import uuid
    try:
        for entity in approved_entities:
            entity_type = entity["entity_type"]
            
            # Map entity type to Neo4j labels and STIX types
            label_map = {
                "malware": ("Software", "malware"),  # Neo4j uses Software label for both malware and tools
                "software": ("Software", "tool"), 
                "threat_actor": ("IntrusionSet", "intrusion-set"),
                "campaign": ("Campaign", "campaign")
            }
            
            label, stix_type = label_map.get(entity_type, ("Entity", "x-unknown"))
            
            # Generate STIX ID if not present
            stix_id = entity.get("stix_id")
            if not stix_id:
                stix_id = f"{stix_type}--{uuid.uuid4()}"
            
            # Create or update entity in Neo4j with STIX ID
            query = f"""
                MERGE (e:{label} {{stix_id: $stix_id}})
                SET e.name = $name,
                    e.type = $stix_type,
                    e.verified = true,
                    e.description = $description,
                    e.source_report = $report_id,
                    e.modified = datetime(),
                    e.created = coalesce(e.created, datetime()),
                    e.aliases = $aliases,
                    e.x_bj_confidence = $confidence,
                    e.x_bj_evidence = $evidence
                RETURN e
            """
            
            # For Software nodes, add software_type property
            if label == "Software":
                query = f"""
                    MERGE (e:{label} {{stix_id: $stix_id}})
                    SET e.name = $name,
                        e.type = $stix_type,
                        e.software_type = $stix_type,
                        e.verified = true,
                        e.description = $description,
                        e.source_report = $report_id,
                        e.modified = datetime(),
                        e.created = coalesce(e.created, datetime()),
                        e.aliases = $aliases,
                        e.x_bj_confidence = $confidence,
                        e.x_bj_evidence = $evidence
                    RETURN e
                """
            
            result = neo4j_session.run(
                query,
                stix_id=stix_id,
                name=entity["name"],
                stix_type=stix_type,
                description=entity.get("description", ""),
                report_id=report_id,
                aliases=entity.get("aliases", []),
                confidence=entity.get("confidence", 50.0),
                evidence=str(entity.get("evidence", []))
            )
            
            record = result.single()
            if record:
                logger.info(f"Upserted {label} entity: {entity['name']} ({stix_id})")
        
        # Update report status
        os_client.update(
            index="bandjacks_reports",
            id=report_id,
            body={
                "doc": {
                    "extraction": {
                        **report.get("extraction", {}),
                        "entities_upserted": True,
                        "entities_upserted_at": datetime.utcnow().isoformat()
                    }
                }
            }
        )
        
        return {
            "success": True,
            "message": f"Successfully upserted {len(approved_entities)} entities to graph",
            "entities_upserted": len(approved_entities)
        }
        
    except Exception as e:
        logger.error(f"Failed to upsert entities for {report_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to upsert entities: {str(e)}"
        )