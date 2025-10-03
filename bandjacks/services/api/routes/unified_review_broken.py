"""Unified review endpoint for comprehensive report review."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from neo4j import Session
import logging

from bandjacks.services.api.deps import get_neo4j_session, get_opensearch_client
from bandjacks.store.opensearch_report_store import OpenSearchReportStore
from opensearchpy import OpenSearch
from bandjacks.llm.entity_ignorelist import get_entity_ignorelist

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["unified-review"])


class UnifiedReviewDecision(BaseModel):
    """Individual review decision for any item type."""
    item_id: str
    action: str  # approve, reject, edit
    edited_value: Optional[Dict[str, Any]] = None
    confidence_adjustment: Optional[float] = None
    notes: Optional[str] = None
    add_to_ignorelist: Optional[bool] = False  # For rejected entities
    timestamp: str


class UnifiedReviewSubmission(BaseModel):
    """Complete unified review submission."""
    report_id: str
    reviewer_id: str
    decisions: List[UnifiedReviewDecision]
    global_notes: Optional[str] = None
    review_timestamp: str


class UnifiedReviewResponse(BaseModel):
    """Response after unified review submission."""
    success: bool
    message: str
    items_reviewed: int
    items_approved: int
    items_rejected: int
    items_edited: int
    entities_added_to_ignorelist: Optional[List[str]] = None


class ReviewDecisionUpdate(BaseModel):
    """Update for a single review decision."""
    item_id: str
    action: str  # approve, reject, edit
    edited_value: Optional[Dict[str, Any]] = None
    confidence_adjustment: Optional[float] = None
    notes: Optional[str] = None
    timestamp: str


class ReviewDecisionResponse(BaseModel):
    """Response after updating a review decision."""
    success: bool
    message: str
    updated_item_id: str


@router.post(
    "/{report_id}/unified-review",
    response_model=UnifiedReviewResponse,
    summary="Submit Unified Review",
    description="Submit review decisions for all entities, techniques, and flow steps in one request."
)
async def submit_unified_review(
    report_id: str,
    submission: UnifiedReviewSubmission,
    os_client: OpenSearch = Depends(get_opensearch_client),
    neo4j_session: Session = Depends(get_neo4j_session)
):
    """Submit unified review for a report."""
    
    os_store = OpenSearchReportStore(os_client)
    
    # Get the report
    report = os_store.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    
    # Process decisions
    items_approved = 0
    items_rejected = 0
    items_edited = 0
    entities_added_to_ignorelist = []

    # Group decisions by type
    entity_decisions = []
    technique_decisions = []
    flow_decisions = []

    for decision in submission.decisions:
        if decision.item_id.startswith("entity-"):
            entity_decisions.append(decision)
        elif decision.item_id.startswith("technique-"):
            technique_decisions.append(decision)
        elif decision.item_id.startswith("flow-"):
            flow_decisions.append(decision)

        # Count actions
        if decision.action == "approve":
            items_approved += 1
        elif decision.action == "reject":
            items_rejected += 1
        elif decision.action == "edit":
            items_edited += 1
    
    # Apply entity decisions
    if entity_decisions and report.get("extraction", {}).get("entities"):
        entities = report["extraction"]["entities"]
        
        # Handle new format: {"entities": [{"name": str, "type": str}], "extraction_status": str}
        if isinstance(entities, dict) and "entities" in entities:
            entity_list = entities.get("entities", [])
            
            for decision in entity_decisions:
                # Parse entity ID format: entity-{type}-{index}
                parts = decision.item_id.split("-")
                if len(parts) >= 3:
                    entity_type = parts[1]
                    index = int(parts[2])
                    
                    if index < len(entity_list):
                        entity = entity_list[index]
                        entity["review_status"] = decision.action
                        if decision.notes:
                            entity["review_notes"] = decision.notes
                        if decision.edited_value:
                            entity.update(decision.edited_value)
                        if decision.confidence_adjustment is not None:
                            entity["confidence"] = decision.confidence_adjustment

                        # Note: Adding to ignorelist is now handled immediately in the UI
                        # when the reject dialog is confirmed, not during final submission
    
    # Apply technique decisions
    if technique_decisions and report.get("extraction", {}).get("claims"):
        claims = report["extraction"]["claims"]
        for decision in technique_decisions:
            # Parse technique ID format: technique-{index}
            parts = decision.item_id.split("-")
            if len(parts) >= 2:
                index = int(parts[1])
                
                if index < len(claims):
                    claim = claims[index]
                    # Store review status in metadata
                    if "review_status" not in claim:
                        claim["review_status"] = decision.action
                    if decision.notes:
                        claim["review_notes"] = decision.notes
                    if decision.confidence_adjustment is not None:
                        claim["confidence"] = decision.confidence_adjustment
                    if decision.edited_value:
                        # Handle technique ID changes
                        if "external_id" in decision.edited_value:
                            claim["external_id"] = decision.edited_value["external_id"]
                        if "name" in decision.edited_value:
                            claim["name"] = decision.edited_value["name"]
    
    # Apply flow decisions  
    if flow_decisions and report.get("extraction", {}).get("flow", {}).get("steps"):
        flow_steps = report["extraction"]["flow"]["steps"]
        for decision in flow_decisions:
            # Parse flow ID format: flow-{step_id}
            parts = decision.item_id.split("-", 1)
            if len(parts) >= 2:
                step_id = parts[1]
                
                # Find the matching step (check both step_id and action_id)
                for step in flow_steps:
                    if step.get("step_id") == step_id or step.get("action_id") == step_id:
                        # Store review status
                        step["review_status"] = decision.action
                        if decision.notes:
                            step["review_notes"] = decision.notes
                        if decision.edited_value:
                            step.update(decision.edited_value)
                        break
    
    # Update report with unified review
    try:
        update_doc = {
            "doc": {
                "extraction": report.get("extraction", {}),
                "unified_review": {
                    "reviewer_id": submission.reviewer_id,
                    "reviewed_at": submission.review_timestamp,
                    "global_notes": submission.global_notes,
                    "statistics": {
                        "total_reviewed": len(submission.decisions),
                        "approved": items_approved,
                        "rejected": items_rejected,
                        "edited": items_edited
                    },
                    "decisions": [d.dict() for d in submission.decisions]
                },
                "status": "reviewed",
                "modified": datetime.utcnow().isoformat()
            }
        }
        
        # Update in OpenSearch
        os_client.update(
            index="bandjacks_reports",
            id=report_id,
            body=update_doc
        )
        
        # If there are approved entities, upsert them to Neo4j
        if entity_decisions:
            approved_entities = []
            entities = report.get("extraction", {}).get("entities", {})
            
            # Handle new format
            if isinstance(entities, dict) and "entities" in entities:
                entity_list = entities.get("entities", [])
                
                for decision in entity_decisions:
                    if decision.action == "approve":
                        parts = decision.item_id.split("-")
                        if len(parts) >= 3:
                            entity_type = parts[1]
                            index = int(parts[2])
                            
                            if index < len(entity_list):
                                entity = entity_list[index]
                                approved_entities.append({
                                    **entity,
                                    "entity_type": entity.get("type", "unknown")
                                })
            
            # Upsert approved entities to Neo4j
            if approved_entities:
                _upsert_entities_to_graph(neo4j_session, approved_entities, report_id)
        
        # If there are approved techniques, create relationships
        if technique_decisions:
            approved_techniques = []
            claims = report.get("extraction", {}).get("claims", [])
            
            for decision in technique_decisions:
                if decision.action == "approve":
                    parts = decision.item_id.split("-")
                    if len(parts) >= 2:
                        index = int(parts[1])
                        if index < len(claims):
                            approved_techniques.append(claims[index])
            
            # Create technique relationships in Neo4j
            if approved_techniques:
                _create_technique_relationships(neo4j_session, approved_techniques, report_id)
        
        logger.info(f"Unified review submitted for report {report_id}: "
                   f"{items_approved} approved, {items_rejected} rejected, {items_edited} edited")
        
        message = "Unified review submitted successfully"
        if entities_added_to_ignorelist:
            message += f". {len(entities_added_to_ignorelist)} entities added to ignore list"

        return UnifiedReviewResponse(
            success=True,
            message=message,
            items_reviewed=len(submission.decisions),
            items_approved=items_approved,
            items_rejected=items_rejected,
            items_edited=items_edited,
            entities_added_to_ignorelist=entities_added_to_ignorelist if entities_added_to_ignorelist else None
        )
        
    except Exception as e:
        logger.error(f"Failed to submit unified review for {report_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save unified review: {str(e)}"
        )


@router.patch(
    "/{report_id}/review-decision",
    response_model=ReviewDecisionResponse,
    summary="Update Single Review Decision",
    description="Save a single review decision immediately without full submission."
)
async def update_review_decision(
    report_id: str,
    decision: ReviewDecisionUpdate,
    os_client: OpenSearch = Depends(get_opensearch_client)
):
    """Update a single review decision in the report with retry logic for version conflicts."""
    import time
    from opensearchpy.exceptions import ConflictError

    os_store = OpenSearchReportStore(os_client)

    # Retry logic for version conflicts
    max_retries = 3
    retry_count = 0
    last_error = None

    while retry_count < max_retries:
        try:
            # Get the fresh report on each retry
            report = os_store.get_report(report_id)
            if not report:
                raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

            # Parse item ID to determine type and index
            item_parts = decision.item_id.split("-")
            if len(item_parts) < 2:
                raise HTTPException(status_code=400, detail=f"Invalid item ID format: {decision.item_id}")

            item_type = item_parts[0]

            if item_type == "entity":
            # Update entity review status
            if len(item_parts) < 3:
                raise HTTPException(status_code=400, detail=f"Invalid entity ID format: {decision.item_id}")

            entity_type = item_parts[1]
            index = int(item_parts[2])

            entities = report.get("extraction", {}).get("entities", {})
            if isinstance(entities, dict) and "entities" in entities:
                entity_list = entities.get("entities", [])
                if index < len(entity_list):
                    entity = entity_list[index]
                    entity["review_status"] = decision.action
                    if decision.notes:
                        entity["review_notes"] = decision.notes
                    if decision.edited_value:
                        entity.update(decision.edited_value)
                    if decision.confidence_adjustment is not None:
                        entity["confidence"] = decision.confidence_adjustment
                else:
                    raise HTTPException(status_code=404, detail=f"Entity index {index} not found")
            else:
                raise HTTPException(status_code=404, detail="No entities found in report")

        elif item_type == "technique":
            # Update technique review status
            index = int(item_parts[1])
            claims = report.get("extraction", {}).get("claims", [])

            if index < len(claims):
                claim = claims[index]
                claim["review_status"] = decision.action
                if decision.notes:
                    claim["review_notes"] = decision.notes
                if decision.confidence_adjustment is not None:
                    claim["confidence"] = decision.confidence_adjustment
                if decision.edited_value:
                    if "external_id" in decision.edited_value:
                        claim["external_id"] = decision.edited_value["external_id"]
                    if "name" in decision.edited_value:
                        claim["name"] = decision.edited_value["name"]
            else:
                raise HTTPException(status_code=404, detail=f"Technique index {index} not found")

        elif item_type == "flow":
            # Update flow step review status
            step_id = "-".join(item_parts[1:])
            flow_steps = report.get("extraction", {}).get("flow", {}).get("steps", [])

            step_found = False
            for step in flow_steps:
                # Check both step_id and action_id (different field names in different versions)
                if step.get("step_id") == step_id or step.get("action_id") == step_id:
                    step["review_status"] = decision.action
                    if decision.notes:
                        step["review_notes"] = decision.notes
                    if decision.edited_value:
                        step.update(decision.edited_value)
                    step_found = True
                    break

            if not step_found:
                # Log available step IDs for debugging
                available_ids = [f"{step.get('action_id', step.get('step_id', 'no-id'))}" for step in flow_steps]
                logger.error(f"Flow step {step_id} not found. Available: {available_ids}")
                raise HTTPException(status_code=404, detail=f"Flow step {step_id} not found")

            else:
                raise HTTPException(status_code=400, detail=f"Unknown item type: {item_type}")

            # Update the report in OpenSearch
            update_doc = {
                "doc": {
                    "extraction": report.get("extraction", {}),
                    "modified": datetime.utcnow().isoformat()
                }
            }

            os_client.update(
                index="bandjacks_reports",
                id=report_id,
                body=update_doc
            )

            logger.info(f"Updated review decision for {decision.item_id} in report {report_id}")

            return ReviewDecisionResponse(
                success=True,
                message=f"Review decision saved for {decision.item_id}",
                updated_item_id=decision.item_id
            )

        except ConflictError as e:
            # Version conflict - retry with fresh data
            retry_count += 1
            last_error = e
            if retry_count < max_retries:
                logger.warning(f"Version conflict for {decision.item_id}, retrying ({retry_count}/{max_retries})...")
                time.sleep(0.1 * retry_count)  # Exponential backoff
                continue
            else:
                logger.error(f"Failed to update review decision after {max_retries} retries: {e}")
                raise HTTPException(
                    status_code=409,
                    detail=f"Version conflict after {max_retries} retries. Please refresh and try again."
                )

        except HTTPException:
            # Re-raise HTTP exceptions
            raise

        except Exception as e:
            logger.error(f"Failed to update review decision for {report_id}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to save review decision: {str(e)}"
            )

    # Should not reach here
    if last_error:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save review decision: {str(last_error)}"
        )


def _upsert_entities_to_graph(session: Session, entities: List[Dict], report_id: str):
    """Helper to upsert entities to Neo4j - only called after review approval."""
    import uuid
    
    for entity in entities:
        entity_type = entity.get("entity_type", "unknown")
        
        # Map entity type to Neo4j labels and STIX types
        label_map = {
            "malware": ("Software", "malware"),
            "software": ("Software", "tool"),
            "tool": ("Software", "tool"),
            "threat_actor": ("IntrusionSet", "intrusion-set"),
            "group": ("IntrusionSet", "intrusion-set"),  # Handle 'group' type
            "intrusion-set": ("IntrusionSet", "intrusion-set"),
            "campaign": ("Campaign", "campaign")
        }
        
        label, stix_type = label_map.get(entity_type.lower(), ("Entity", "x-unknown"))
        
        # Use resolved STIX ID if available, otherwise generate new one
        stix_id = entity.get("resolved_stix_id") or entity.get("stix_id")
        if not stix_id:
            stix_id = f"{stix_type}--{uuid.uuid4()}"
            logger.info(f"Creating new entity {entity.get('name')} with ID {stix_id}")
        
        # Create or update entity
        query = f"""
            MERGE (e:{label} {{stix_id: $stix_id}})
            SET e.name = $name,
                e.type = $stix_type,
                e.verified = true,
                e.description = $description,
                e.source_report = $report_id,
                e.modified = datetime(),
                e.created = coalesce(e.created, datetime()),
                e.x_bj_confidence = $confidence
            RETURN e
        """
        
        session.run(
            query,
            stix_id=stix_id,
            name=entity.get("name", "Unknown"),
            stix_type=stix_type,
            description=entity.get("description", ""),
            report_id=report_id,
            confidence=entity.get("confidence", 50.0)
        )


def _create_technique_relationships(session: Session, techniques: List[Dict], report_id: str):
    """Helper to create technique relationships in Neo4j."""
    
    # Get or create report node
    session.run("""
        MERGE (r:Report {stix_id: $report_id})
        SET r.modified = datetime()
    """, report_id=report_id)
    
    # Create relationships to techniques
    for technique in techniques:
        external_id = technique.get("external_id")
        if external_id:
            session.run("""
                MATCH (r:Report {stix_id: $report_id})
                MATCH (t:AttackPattern {external_id: $external_id})
                MERGE (r)-[rel:EXTRACTED_TECHNIQUE {
                    confidence: $confidence,
                    evidence_score: $evidence_score,
                    reviewed: true,
                    review_timestamp: datetime()
                }]->(t)
            """,
            report_id=report_id,
            external_id=external_id,
            confidence=technique.get("confidence", 0),
            evidence_score=technique.get("evidence_score", 0)
            )