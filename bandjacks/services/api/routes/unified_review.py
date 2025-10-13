"""Unified review endpoint for comprehensive report review."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Path, Body, Query
from pydantic import BaseModel, Field
from neo4j import Session
import logging
import uuid

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
    graph_stats: Optional[Dict[str, Any]] = None


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


class GraphNode(BaseModel):
    """Represents a node that would be created in Neo4j."""
    id: str
    label: str
    properties: Dict[str, Any]
    action: str = "create"  # create, update, or link


class GraphEdge(BaseModel):
    """Represents an edge that would be created in Neo4j."""
    source_id: str
    target_id: str
    relationship_type: str
    properties: Dict[str, Any]
    action: str = "create"  # create or update


class GraphSimulationResponse(BaseModel):
    """Response containing simulated graph changes."""
    success: bool
    message: str
    summary: Dict[str, int]  # e.g., {"nodes_to_create": 10, "edges_to_create": 20}
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    attack_chains: Optional[List[Dict[str, Any]]] = None


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
        
        # Track graph statistics
        entity_stats = {"created": 0, "updated": 0}
        technique_stats = {"created": 0, "updated": 0, "skipped": 0}
        flow_stats = {"episodes": 0, "actions": 0, "edges": 0, "skipped": 0}

        # If there are approved entities, upsert them to Neo4j
        if entity_decisions:
            logger.info(f"Processing {len(entity_decisions)} entity decisions")
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
                logger.info(f"Upserting {len(approved_entities)} approved entities to Neo4j")
                entity_stats = _upsert_entities_to_graph(neo4j_session, approved_entities, report_id)
                logger.info(f"Entity upsert stats: {entity_stats}")
            else:
                logger.info("No approved entities to upsert")

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
                logger.info(f"Creating relationships for {len(approved_techniques)} approved techniques")
                technique_stats = _create_technique_relationships(neo4j_session, approved_techniques, report_id)
                logger.info(f"Technique relationship stats: {technique_stats}")
            else:
                logger.info("No approved techniques to create relationships for")

        # If there are approved flow steps, create attack flow graph
        if flow_decisions:
            logger.info(f"Processing {len(flow_decisions)} flow decisions")
            approved_flow_steps = []
            flow_steps = report.get("extraction", {}).get("flow", {}).get("steps", [])

            for decision in flow_decisions:
                if decision.action == "approve":
                    # Parse flow ID format: flow-{step_id}
                    parts = decision.item_id.split("-", 1)
                    if len(parts) >= 2:
                        step_id = parts[1]

                        # Find the matching step
                        for step in flow_steps:
                            if step.get("step_id") == step_id or step.get("action_id") == step_id:
                                approved_flow_steps.append(step)
                                break

            # Create attack flow graph in Neo4j
            if approved_flow_steps:
                logger.info(f"Creating attack flow graph with {len(approved_flow_steps)} approved steps")
                flow_stats = _create_attack_flow_graph(neo4j_session, approved_flow_steps, report_id)
                logger.info(f"Attack flow creation stats: {flow_stats}")
            else:
                logger.info("No approved flow steps to create graph for")

        logger.info(f"Unified review submitted for report {report_id}: "
                   f"{items_approved} approved, {items_rejected} rejected, {items_edited} edited")

        entities_added_to_ignorelist = []  # Note: This is handled immediately in the UI now

        # Update report with graph upsert timestamp if we pushed anything to the graph
        logger.info(f"Final stats - Entities: {entity_stats}, Techniques: {technique_stats}, Flow: {flow_stats}")
        if (entity_stats.get("created", 0) > 0 or entity_stats.get("updated", 0) > 0 or
            technique_stats.get("created", 0) > 0 or technique_stats.get("updated", 0) > 0 or
            flow_stats.get("episodes", 0) > 0 or flow_stats.get("actions", 0) > 0):
            # Store graph upsert timestamp
            graph_timestamp = datetime.utcnow().isoformat()
            os_store.client.update(
                index=os_store.index_name,
                id=report_id,
                body={
                    "doc": {
                        "graph_upserted_at": graph_timestamp
                    }
                }
            )
            logger.info(f"Updated graph_upserted_at timestamp for report {report_id}")

        # Build detailed message with graph statistics
        message_parts = ["Unified review submitted successfully"]

        if entity_stats["created"] > 0 or entity_stats["updated"] > 0:
            message_parts.append(f"Entities: {entity_stats['created']} created, {entity_stats['updated']} updated")

        if technique_stats["created"] > 0 or technique_stats["updated"] > 0:
            message_parts.append(f"Techniques: {technique_stats['created']} linked, {technique_stats['updated']} updated")

        message = ". ".join(message_parts)

        # Compile comprehensive graph statistics
        graph_stats = {
            "entities": entity_stats,
            "techniques": technique_stats,
            "flow": flow_stats,
            "total_nodes_created": entity_stats["created"] + flow_stats.get("episodes", 0) + flow_stats.get("actions", 0),
            "total_nodes_updated": entity_stats["updated"],
            "total_edges_created": technique_stats["created"] + flow_stats.get("edges", 0),
            "total_edges_updated": technique_stats["updated"],
            "duplicates_consolidated": technique_stats.get("skipped", 0) + flow_stats.get("skipped", 0)
        }

        return UnifiedReviewResponse(
            success=True,
            message=message,
            items_reviewed=len(submission.decisions),
            items_approved=items_approved,
            items_rejected=items_rejected,
            items_edited=items_edited,
            entities_added_to_ignorelist=entities_added_to_ignorelist if entities_added_to_ignorelist else None,
            graph_stats=graph_stats
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
    """Update a single review decision in the report."""

    os_store = OpenSearchReportStore(os_client)

    # Get the report
    report = os_store.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    # Parse item ID to determine type and index
    item_parts = decision.item_id.split("-")
    if len(item_parts) < 2:
        raise HTTPException(status_code=400, detail=f"Invalid item ID format: {decision.item_id}")

    item_type = item_parts[0]

    try:
        if item_type == "entity":
            # Update entity review status
            if len(item_parts) < 3:
                raise HTTPException(status_code=400, detail=f"Invalid entity ID format: {decision.item_id}")

            entity_type = item_parts[1]
            index = int(item_parts[2])

            entities = report.get("extraction", {}).get("entities", {})
            logger.info(f"Entity structure type: {type(entities)}, has 'entities' key: {'entities' in entities if isinstance(entities, dict) else 'N/A'}")
            if isinstance(entities, dict) and "entities" in entities:
                entity_list = entities.get("entities", [])
                if index < len(entity_list):
                    entity = entity_list[index]
                    # Map action to review_status format expected by frontend
                    status_map = {
                        "approve": "approved",
                        "reject": "rejected",
                        "edit": "edited"
                    }
                    entity["review_status"] = status_map.get(decision.action, decision.action)
                    logger.info(f"Setting entity {index} review_status to: {entity['review_status']} (from action: {decision.action})")
                    if decision.notes:
                        entity["review_notes"] = decision.notes
                    if decision.edited_value:
                        # Handle entity type change if present
                        if "category" in decision.edited_value:
                            entity["type"] = decision.edited_value["category"]
                            if "metadata" in decision.edited_value and "entity_type" in decision.edited_value["metadata"]:
                                # Update metadata entity_type as well
                                if "metadata" not in entity:
                                    entity["metadata"] = {}
                                entity["metadata"]["entity_type"] = decision.edited_value["metadata"]["entity_type"]
                        entity.update(decision.edited_value)
                    if decision.confidence_adjustment is not None:
                        entity["confidence"] = decision.confidence_adjustment
                    logger.info(f"Entity {index} after update: review_status={entity.get('review_status')}")
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
                # Map action to review_status format expected by frontend
                status_map = {
                    "approve": "approved",
                    "reject": "rejected",
                    "edit": "edited"
                }
                claim["review_status"] = status_map.get(decision.action, decision.action)
                logger.info(f"Setting technique {index} review_status to: {claim['review_status']} (from action: {decision.action})")
                if decision.notes:
                    claim["review_notes"] = decision.notes
                if decision.confidence_adjustment is not None:
                    claim["confidence"] = decision.confidence_adjustment
                if decision.edited_value:
                    if "external_id" in decision.edited_value:
                        claim["external_id"] = decision.edited_value["external_id"]
                    if "name" in decision.edited_value:
                        claim["name"] = decision.edited_value["name"]
                logger.info(f"Technique {index} after update: review_status={claim.get('review_status')}")
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
                    # Map action to review_status format expected by frontend
                    status_map = {
                        "approve": "approved",
                        "reject": "rejected",
                        "edit": "edited"
                    }
                    step["review_status"] = status_map.get(decision.action, decision.action)
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
        # Debug: Log what we're about to save
        extraction_data = report.get("extraction", {})
        if item_type == "technique" and extraction_data.get("claims"):
            if index < len(extraction_data["claims"]):
                logger.info(f"About to save technique {index} with review_status={extraction_data['claims'][index].get('review_status')}")
        elif item_type == "entity" and extraction_data.get("entities", {}).get("entities"):
            entity_list = extraction_data["entities"]["entities"]
            if index < len(entity_list):
                logger.info(f"About to save entity {index} with review_status={entity_list[index].get('review_status')}")

        update_doc = {
            "doc": {
                "extraction": extraction_data,
                "modified": datetime.utcnow().isoformat()
            }
        }

        os_client.update(
            index="bandjacks_reports",
            id=report_id,
            body=update_doc
        )

        logger.info(f"Updated review decision for {decision.item_id} (action={decision.action}) in report {report_id}")

        return ReviewDecisionResponse(
            success=True,
            message=f"Review decision saved for {decision.item_id}",
            updated_item_id=decision.item_id
        )

    except Exception as e:
        logger.error(f"Failed to update review decision for {report_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save review decision: {str(e)}"
        )


def _upsert_entities_to_graph(session: Session, entities: List[Dict], report_id: str) -> Dict[str, int]:
    """Helper to upsert entities to Neo4j with evidence tracking - only called after review approval.
    Returns statistics about created/updated nodes.
    """
    import uuid

    logger.info(f"_upsert_entities_to_graph called with {len(entities)} entities for report {report_id}")

    stats = {"created": 0, "updated": 0}

    for entity in entities:
        logger.debug(f"Processing entity: {entity}")
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

        # Extract evidence mentions if available
        evidence_mentions = []
        metadata = entity.get("metadata", {})
        if metadata.get("mentions"):
            # Limit to 10 mentions, each truncated to 200 chars
            evidence_mentions = [
                mention[:200] for mention in metadata.get("mentions", [])[:10]
            ]

        # Extract line references if available
        line_refs = metadata.get("line_refs", [])[:20]  # Limit to 20 line refs

        # Create extraction metadata string
        extraction_meta = {
            "confidence": entity.get("confidence", 50.0),
            "source_report": report_id,
            "extraction_method": metadata.get("extraction_method", "llm"),
            "entity_category": entity.get("type", entity_type)
        }

        # Create or update entity with evidence
        query = f"""
            MERGE (e:{label} {{stix_id: $stix_id}})
            ON CREATE SET
                e.name = $name,
                e.type = $stix_type,
                e.verified = true,
                e.description = $description,
                e.source_report = $report_id,
                e.created = datetime(),
                e.modified = datetime(),
                e.x_bj_confidence = $confidence,
                e.evidence_mentions = $evidence_mentions,
                e.line_refs = $line_refs,
                e.extraction_metadata = $extraction_metadata
            ON MATCH SET
                e.modified = datetime(),
                e.x_bj_confidence = CASE
                    WHEN e.x_bj_confidence < $confidence
                    THEN $confidence
                    ELSE e.x_bj_confidence
                END,
                e.evidence_mentions = CASE
                    WHEN size($evidence_mentions) > 0
                    THEN $evidence_mentions
                    ELSE e.evidence_mentions
                END,
                e.line_refs = CASE
                    WHEN size($line_refs) > 0
                    THEN $line_refs
                    ELSE e.line_refs
                END
            RETURN e, e.created = datetime() as was_created
        """

        logger.debug(f"Executing Neo4j MERGE for entity {stix_id} ({label})")
        result = session.run(
            query,
            stix_id=stix_id,
            name=entity.get("name", "Unknown"),
            stix_type=stix_type,
            description=entity.get("description", ""),
            report_id=report_id,
            confidence=entity.get("confidence", 50.0),
            evidence_mentions=evidence_mentions,
            line_refs=line_refs,
            extraction_metadata=str(extraction_meta)  # Convert dict to string for storage
        )

        record = result.single()
        if record and record["was_created"]:
            stats["created"] += 1
            logger.info(f"Created entity {stix_id} in Neo4j")
        else:
            stats["updated"] += 1
            logger.info(f"Updated entity {stix_id} in Neo4j")

        # Create relationships from Report to Entity
        # First ensure Report node exists
        session.run("""
            MERGE (r:Report {stix_id: $report_id})
            ON CREATE SET r.created = datetime()
            ON MATCH SET r.modified = datetime()
        """, report_id=report_id)

        # Determine relationship type based on entity type
        rel_type_map = {
            "malware": "EXTRACTED_MALWARE",
            "software": "MENTIONS_TOOL",
            "tool": "MENTIONS_TOOL",
            "threat_actor": "IDENTIFIED_ACTOR",
            "group": "IDENTIFIED_ACTOR",
            "intrusion-set": "IDENTIFIED_ACTOR",
            "campaign": "DESCRIBES_CAMPAIGN"
        }

        specific_rel_type = rel_type_map.get(entity_type.lower(), "EXTRACTED_ENTITY")

        # Create both generic and specific relationships
        # Generic EXTRACTED_ENTITY relationship
        session.run(f"""
            MATCH (r:Report {{stix_id: $report_id}})
            MATCH (e:{label} {{stix_id: $stix_id}})
            MERGE (r)-[rel:EXTRACTED_ENTITY]->(e)
            ON CREATE SET
                rel.created = datetime(),
                rel.confidence = $confidence,
                rel.extraction_method = $extraction_method,
                rel.reviewed = true,
                rel.evidence_count = size($evidence_mentions),
                rel.line_refs = $line_refs
            ON MATCH SET
                rel.modified = datetime(),
                rel.confidence = CASE
                    WHEN rel.confidence < $confidence
                    THEN $confidence
                    ELSE rel.confidence
                END
        """,
        report_id=report_id,
        stix_id=stix_id,
        confidence=entity.get("confidence", 50.0),
        extraction_method=metadata.get("extraction_method", "llm"),
        evidence_mentions=evidence_mentions,
        line_refs=line_refs)

        # Specific typed relationship if different from generic
        if specific_rel_type != "EXTRACTED_ENTITY":
            session.run(f"""
                MATCH (r:Report {{stix_id: $report_id}})
                MATCH (e:{label} {{stix_id: $stix_id}})
                MERGE (r)-[rel:{specific_rel_type}]->(e)
                ON CREATE SET
                    rel.created = datetime(),
                    rel.confidence = $confidence,
                    rel.extraction_method = $extraction_method,
                    rel.reviewed = true,
                    rel.entity_type = $entity_type,
                    rel.evidence_count = size($evidence_mentions),
                    rel.line_refs = $line_refs
                ON MATCH SET
                    rel.modified = datetime(),
                    rel.confidence = CASE
                        WHEN rel.confidence < $confidence
                        THEN $confidence
                        ELSE rel.confidence
                    END
            """,
            report_id=report_id,
            stix_id=stix_id,
            confidence=entity.get("confidence", 50.0),
            extraction_method=metadata.get("extraction_method", "llm"),
            entity_type=entity_type,
            evidence_mentions=evidence_mentions,
            line_refs=line_refs)

            logger.debug(f"Created {specific_rel_type} relationship from Report to {label}")

    logger.info(f"Entity upsert complete. Stats: {stats}")
    return stats


def _create_technique_relationships(session: Session, techniques: List[Dict], report_id: str) -> Dict[str, int]:
    """Helper to create technique relationships in Neo4j with evidence tracking.
    Returns statistics about created/updated relationships.
    """
    logger.info(f"_create_technique_relationships called with {len(techniques)} techniques for report {report_id}")

    stats = {"created": 0, "updated": 0, "skipped": 0}

    # Get or create report node
    session.run("""
        MERGE (r:Report {stix_id: $report_id})
        SET r.modified = datetime()
    """, report_id=report_id)

    # Group techniques by external_id to consolidate duplicates and merge evidence
    technique_map = {}
    for idx, technique in enumerate(techniques):
        external_id = technique.get("external_id")
        if external_id:
            if external_id not in technique_map:
                technique_map[external_id] = {
                    **technique,
                    "claim_ids": [f"technique-{idx}"],
                    "all_evidence": technique.get("evidence", [])
                }
            else:
                # Merge with existing, keeping higher confidence and combining evidence
                existing = technique_map[external_id]
                if technique.get("confidence", 0) > existing.get("confidence", 0):
                    technique_map[external_id]["confidence"] = technique.get("confidence", 0)

                # Combine evidence from multiple claims
                technique_map[external_id]["claim_ids"].append(f"technique-{idx}")
                technique_map[external_id]["all_evidence"].extend(technique.get("evidence", []))

    # Create unique relationships to techniques with evidence
    for external_id, technique in technique_map.items():
        # Extract and process evidence
        evidence_texts = []
        line_numbers = []

        for ev in technique.get("all_evidence", []):
            if isinstance(ev, dict):
                quote = ev.get("quote", "")
                if quote:
                    # Limit each evidence to 500 chars
                    evidence_texts.append(quote[:500])
                line_refs = ev.get("line_refs", [])
                if line_refs:
                    line_numbers.extend(line_refs)
            elif isinstance(ev, str):
                evidence_texts.append(ev[:500])

        # Deduplicate evidence while preserving order
        seen = set()
        unique_evidence = []
        for txt in evidence_texts[:10]:  # Limit to 10 pieces
            if txt not in seen:
                seen.add(txt)
                unique_evidence.append(txt)

        # Deduplicate line numbers
        unique_lines = list(set(line_numbers))[:20]  # Limit to 20 line refs

        # Create source summary from description
        source_summary = technique.get("description", "")[:200]

        # Join claim IDs
        claim_ids_str = ",".join(technique.get("claim_ids", []))[:100]  # Limit length

        result = session.run("""
            MATCH (r:Report {stix_id: $report_id})
            MATCH (t:AttackPattern {external_id: $external_id})
            MERGE (r)-[rel:EXTRACTED_TECHNIQUE]->(t)
            ON CREATE SET
                rel.confidence = $confidence,
                rel.evidence_score = $evidence_score,
                rel.reviewed = true,
                rel.review_timestamp = datetime(),
                rel.created = datetime(),
                rel.evidence_texts = $evidence_texts,
                rel.line_numbers = $line_numbers,
                rel.source_summary = $source_summary,
                rel.claim_ids = $claim_ids,
                rel.technique_name = $technique_name
            ON MATCH SET
                rel.confidence = CASE
                    WHEN rel.confidence < $confidence
                    THEN $confidence
                    ELSE rel.confidence
                END,
                rel.evidence_score = CASE
                    WHEN rel.evidence_score < $evidence_score
                    THEN $evidence_score
                    ELSE rel.evidence_score
                END,
                rel.modified = datetime(),
                rel.evidence_texts = $evidence_texts,
                rel.line_numbers = $line_numbers,
                rel.source_summary = $source_summary,
                rel.claim_ids = $claim_ids,
                rel.technique_name = $technique_name
            RETURN rel.created = datetime() as was_created
        """,
        report_id=report_id,
        external_id=external_id,
        confidence=technique.get("confidence", 0),
        evidence_score=technique.get("evidence_score", 0),
        evidence_texts=unique_evidence,
        line_numbers=unique_lines,
        source_summary=source_summary,
        claim_ids=claim_ids_str,
        technique_name=technique.get("name", external_id)
        )

        record = result.single()
        if record:
            if record["was_created"]:
                stats["created"] += 1
            else:
                stats["updated"] += 1
        else:
            stats["skipped"] += 1

    return stats


def _create_attack_flow_graph(session: Session, flow_steps: List[Dict], report_id: str) -> Dict[str, int]:
    """Helper to create attack flow graph in Neo4j with AttackEpisode and AttackAction nodes.
    Returns statistics about created nodes and relationships.
    """
    import uuid

    logger.info(f"_create_attack_flow_graph called with {len(flow_steps)} flow steps for report {report_id}")

    stats = {"episodes": 0, "actions": 0, "edges": 0, "skipped": 0}

    if not flow_steps:
        logger.info("No flow steps to process")
        return stats

    # Create or get AttackEpisode for this report
    episode_id = f"episode--{report_id.split('--')[1]}"

    result = session.run("""
        MERGE (ep:AttackEpisode {episode_id: $episode_id})
        ON CREATE SET
            ep.stix_id = $episode_id,
            ep.report_id = $report_id,
            ep.source_report = $report_id,
            ep.flow_id = $flow_id,
            ep.name = $report_name,
            ep.description = 'Attack flow extracted from report',
            ep.created = datetime(),
            ep.modified = datetime(),
            ep.confidence = $avg_confidence
        ON MATCH SET
            ep.modified = datetime(),
            ep.confidence = CASE
                WHEN ep.confidence < $avg_confidence
                THEN $avg_confidence
                ELSE ep.confidence
            END
        RETURN ep.created = datetime() as was_created
    """,
        episode_id=episode_id,
        report_id=report_id,
        flow_id=f"flow--{report_id.split('--')[1]}",
        report_name=f"Attack flow from {report_id}",
        avg_confidence=sum(s.get("confidence", 80) for s in flow_steps) / len(flow_steps)
    )

    if result.single()["was_created"]:
        stats["episodes"] += 1
        logger.info(f"Created AttackEpisode {episode_id}")
    else:
        logger.info(f"Updated existing AttackEpisode {episode_id}")

    # Create HAS_FLOW relationship from Report to AttackEpisode
    # First ensure Report node exists
    session.run("""
        MERGE (r:Report {stix_id: $report_id})
        ON CREATE SET r.created = datetime()
        ON MATCH SET r.modified = datetime()
    """, report_id=report_id)

    # Create HAS_FLOW relationship
    session.run("""
        MATCH (r:Report {stix_id: $report_id})
        MATCH (e:AttackEpisode {episode_id: $episode_id})
        MERGE (r)-[rel:HAS_FLOW]->(e)
        ON CREATE SET
            rel.created = datetime(),
            rel.flow_type = 'sequential',
            rel.step_count = $step_count,
            rel.avg_confidence = $avg_confidence,
            rel.extraction_timestamp = datetime()
        ON MATCH SET
            rel.modified = datetime(),
            rel.step_count = $step_count,
            rel.avg_confidence = CASE
                WHEN rel.avg_confidence < $avg_confidence
                THEN $avg_confidence
                ELSE rel.avg_confidence
            END
    """,
    report_id=report_id,
    episode_id=episode_id,
    step_count=len(flow_steps),
    avg_confidence=sum(s.get("confidence", 80) for s in flow_steps) / len(flow_steps))

    logger.info(f"Created/updated HAS_FLOW relationship from Report to AttackEpisode")

    # Create AttackAction nodes for each approved flow step
    action_nodes = []
    for i, step in enumerate(flow_steps):
        # Generate unique action ID
        step_id = step.get("step_id") or step.get("action_id") or f"step-{i}"
        action_id = f"action--{report_id.split('--')[1]}-{step_id}"

        # Get technique reference - check multiple possible field names
        technique_ref = step.get("attack_pattern_ref") or step.get("technique_ref") or step.get("technique_id") or ""
        technique_name = step.get("name") or step.get("technique_name") or f"Step {i+1}"

        # Create AttackAction node
        result = session.run("""
            MERGE (aa:AttackAction {action_id: $action_id})
            ON CREATE SET
                aa.stix_id = $action_id,
                aa.report_id = $report_id,
                aa.source_report = $report_id,
                aa.episode_id = $episode_id,
                aa.attack_pattern_ref = $technique_ref,
                aa.technique_ref = $technique_ref,
                aa.name = $technique_name,
                aa.description = $description,
                aa.order = $order,
                aa.sequence = $order,
                aa.confidence = $confidence,
                aa.evidence = $evidence,
                aa.created = datetime(),
                aa.modified = datetime()
            ON MATCH SET
                aa.modified = datetime(),
                aa.confidence = CASE
                    WHEN aa.confidence < $confidence
                    THEN $confidence
                    ELSE aa.confidence
                END
            RETURN aa.created = datetime() as was_created
        """,
            action_id=action_id,
            report_id=report_id,
            episode_id=episode_id,
            technique_ref=technique_ref,
            technique_name=technique_name,
            description=step.get("description", "")[:500],
            order=step.get("order", i + 1),
            confidence=step.get("confidence", 80),
            evidence=step.get("evidence") or step.get("rationale") or step.get("reason") or ""
        )

        if result.single()["was_created"]:
            stats["actions"] += 1
            logger.info(f"Created AttackAction {action_id} for technique {technique_ref}")
        else:
            logger.info(f"Updated AttackAction {action_id}")

        action_nodes.append({
            "action_id": action_id,
            "technique_ref": technique_ref,
            "sequence": i
        })

        # Link AttackAction to AttackEpisode
        session.run("""
            MATCH (ep:AttackEpisode {episode_id: $episode_id})
            MATCH (aa:AttackAction {action_id: $action_id})
            MERGE (ep)-[:CONTAINS]->(aa)
        """, episode_id=episode_id, action_id=action_id)

        # Link AttackAction to AttackPattern if technique exists
        if technique_ref:
            # Extract just the technique ID if it's a full STIX ID
            if technique_ref.startswith("attack-pattern--"):
                # Use STIX ID directly
                session.run("""
                    MATCH (aa:AttackAction {action_id: $action_id})
                    MATCH (t:AttackPattern {stix_id: $technique_ref})
                    MERGE (aa)-[:USES_TECHNIQUE]->(t)
                """, action_id=action_id, technique_ref=technique_ref)
            else:
                # Use external_id (e.g., T1566.001)
                session.run("""
                    MATCH (aa:AttackAction {action_id: $action_id})
                    MATCH (t:AttackPattern {external_id: $technique_ref})
                    MERGE (aa)-[:USES_TECHNIQUE]->(t)
                """, action_id=action_id, technique_ref=technique_ref)

    # Create NEXT relationships between sequential AttackActions
    for i in range(len(action_nodes) - 1):
        current = action_nodes[i]
        next_node = action_nodes[i + 1]

        # Calculate probability based on sequence distance and confidence
        probability = 0.9 - (0.1 * i / max(1, len(action_nodes) - 1))  # Decay probability slightly

        result = session.run("""
            MATCH (a1:AttackAction {action_id: $current_id})
            MATCH (a2:AttackAction {action_id: $next_id})
            MERGE (a1)-[r:NEXT]->(a2)
            ON CREATE SET
                r.probability = $probability,
                r.sequence_delta = 1,
                r.created = datetime(),
                r.source = 'review_approved'
            ON MATCH SET
                r.probability = CASE
                    WHEN r.probability < $probability
                    THEN $probability
                    ELSE r.probability
                END,
                r.modified = datetime()
            RETURN r.created = datetime() as was_created
        """,
            current_id=current["action_id"],
            next_id=next_node["action_id"],
            probability=probability
        )

        if result.single()["was_created"]:
            stats["edges"] += 1
            logger.info(f"Created NEXT edge from {current['technique_ref']} to {next_node['technique_ref']}")

    logger.info(f"Attack flow graph creation complete. Stats: {stats}")
    return stats


@router.post(
    "/{report_id}/graph-simulation",
    response_model=GraphSimulationResponse,
    summary="Simulate Graph Changes",
    description="Simulate what Neo4j graph nodes and edges would be created from review decisions without actually creating them."
)
async def simulate_graph_changes(
    report_id: str,
    submission: UnifiedReviewSubmission,
    os_client: OpenSearch = Depends(get_opensearch_client),
    neo4j_session: Session = Depends(get_neo4j_session)
):
    """Simulate graph changes that would result from review submission."""

    os_store = OpenSearchReportStore(os_client)

    # Get the report
    report = os_store.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    nodes = []
    edges = []
    attack_chains = []

    # Simulate Report node
    report_node = GraphNode(
        id=f"report--{report_id}",
        label="Report",
        properties={
            "report_id": report_id,
            "name": report.get("name", "Unknown Report"),
            "reviewed_at": submission.review_timestamp,
            "review_status": "completed",
            "approved_techniques_count": sum(1 for d in submission.decisions if d.item_id.startswith("technique-") and d.action == "approve"),
            "approved_entities_count": sum(1 for d in submission.decisions if d.item_id.startswith("entity-") and d.action == "approve")
        }
    )
    nodes.append(report_node)

    # Simulate AttackEpisode node
    episode_id = f"episode--{uuid.uuid4()}"
    episode_node = GraphNode(
        id=episode_id,
        label="AttackEpisode",
        properties={
            "episode_id": episode_id,
            "name": f"Campaign from {report.get('name', 'Unknown Report')}",
            "report_id": report_id,
            "created_at": submission.review_timestamp,
            "source": "reviewed_extraction",
            "technique_count": sum(1 for d in submission.decisions if d.item_id.startswith("technique-") and d.action == "approve")
        }
    )
    nodes.append(episode_node)

    # Add edge from Episode to Report
    edges.append(GraphEdge(
        source_id=episode_id,
        target_id=f"report--{report_id}",
        relationship_type="DERIVED_FROM",
        properties={}
    ))

    # Process approved entities
    entities = report.get("extraction", {}).get("entities", {})
    if isinstance(entities, dict) and "entities" in entities:
        entity_list = entities.get("entities", [])

        for decision in submission.decisions:
            if decision.item_id.startswith("entity-") and decision.action == "approve":
                parts = decision.item_id.split("-")
                if len(parts) >= 3:
                    entity_type = parts[1]
                    index = int(parts[2])

                    if index < len(entity_list):
                        entity = entity_list[index]

                        # Map entity type to Neo4j label
                        label_map = {
                            "malware": "Software",
                            "software": "Software",
                            "tool": "Software",
                            "threat_actor": "IntrusionSet",
                            "group": "IntrusionSet",
                            "intrusion-set": "IntrusionSet",
                            "campaign": "Campaign"
                        }

                        label = label_map.get(entity_type.lower(), "Entity")
                        entity_id = entity.get("resolved_stix_id") or f"{entity_type}--{uuid.uuid4()}"

                        nodes.append(GraphNode(
                            id=entity_id,
                            label=label,
                            properties={
                                "stix_id": entity_id,
                                "name": entity.get("name", "Unknown"),
                                "type": entity.get("type", entity_type),
                                "description": entity.get("description", ""),
                                "confidence": entity.get("confidence", 50.0),
                                "source_report": report_id
                            },
                            action="create" if not entity.get("resolved_stix_id") else "update"
                        ))

    # Process approved techniques
    claims = report.get("extraction", {}).get("claims", [])
    technique_nodes = []

    for decision in submission.decisions:
        if decision.item_id.startswith("technique-") and decision.action == "approve":
            parts = decision.item_id.split("-")
            if len(parts) >= 2:
                index = int(parts[1])

                if index < len(claims):
                    claim = claims[index]
                    external_id = claim.get("external_id")

                    if external_id:
                        # Create AttackPattern node reference
                        technique_id = f"attack-pattern--{external_id.lower()}"
                        nodes.append(GraphNode(
                            id=technique_id,
                            label="AttackPattern",
                            properties={
                                "external_id": external_id,
                                "name": claim.get("name", external_id),
                                "confidence_from_report": claim.get("confidence", 0)
                            },
                            action="link"  # These already exist, we're just linking to them
                        ))

                        # Create AttackAction node
                        action_id = f"action--{uuid.uuid4()}"
                        nodes.append(GraphNode(
                            id=action_id,
                            label="AttackAction",
                            properties={
                                "action_id": action_id,
                                "name": claim.get("name", external_id),
                                "technique_ref": technique_id,
                                "confidence": claim.get("confidence", 0),
                                "evidence_score": claim.get("evidence_score", 0),
                                "report_source": report_id
                            }
                        ))

                        # Add edges
                        edges.append(GraphEdge(
                            source_id=f"report--{report_id}",
                            target_id=technique_id,
                            relationship_type="EXTRACTED_TECHNIQUE",
                            properties={
                                "confidence": claim.get("confidence", 0),
                                "review_status": "approved",
                                "extracted_at": submission.review_timestamp
                            }
                        ))

                        edges.append(GraphEdge(
                            source_id=episode_id,
                            target_id=action_id,
                            relationship_type="CONTAINS",
                            properties={}
                        ))

                        edges.append(GraphEdge(
                            source_id=action_id,
                            target_id=technique_id,
                            relationship_type="USES",
                            properties={}
                        ))

                        technique_nodes.append((action_id, claim))

    # Simulate attack flow edges (simplified)
    if len(technique_nodes) > 1:
        # Create NEXT edges based on kill chain progression
        tactic_order = [
            "reconnaissance", "initial-access", "execution", "persistence",
            "privilege-escalation", "defense-evasion", "credential-access",
            "discovery", "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact"
        ]

        # Sort techniques by tactic order (simplified)
        for i in range(len(technique_nodes) - 1):
            source_action, source_claim = technique_nodes[i]
            target_action, target_claim = technique_nodes[i + 1]

            edges.append(GraphEdge(
                source_id=source_action,
                target_id=target_action,
                relationship_type="NEXT",
                properties={
                    "probability": 0.8,  # Simplified probability
                    "inferred": True
                }
            ))

        # Create attack chain summary
        chain = {
            "chain_id": f"chain--{uuid.uuid4()}",
            "techniques": [claim.get("external_id") for _, claim in technique_nodes],
            "description": "Inferred attack chain from reviewed techniques"
        }
        attack_chains.append(chain)

    # Calculate summary statistics
    summary = {
        "nodes_to_create": sum(1 for n in nodes if n.action == "create"),
        "nodes_to_update": sum(1 for n in nodes if n.action == "update"),
        "nodes_to_link": sum(1 for n in nodes if n.action == "link"),
        "edges_to_create": len(edges),
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "approved_entities": sum(1 for d in submission.decisions if d.item_id.startswith("entity-") and d.action == "approve"),
        "approved_techniques": sum(1 for d in submission.decisions if d.item_id.startswith("technique-") and d.action == "approve"),
        "approved_flow_steps": sum(1 for d in submission.decisions if d.item_id.startswith("flow-") and d.action == "approve")
    }

    return GraphSimulationResponse(
        success=True,
        message=f"Graph simulation complete for report {report_id}",
        summary=summary,
        nodes=nodes,
        edges=edges,
        attack_chains=attack_chains if attack_chains else None
    )


@router.post(
    "/{report_id}/graph-upsert",
    response_model=UnifiedReviewResponse,
    description="Push already-reviewed report data to Neo4j graph"
)
async def upsert_to_graph(
    report_id: str = Path(..., description="Report STIX ID"),
    submission: UnifiedReviewSubmission = Body(..., description="Review decisions to push to graph"),
    db: Session = Depends(get_neo4j_session)
):
    """
    Upsert approved items from an already-reviewed report to the Neo4j graph.
    This is identical to the graph operations in unified-review but without the
    report modification steps.
    """
    # Fetch report to get extraction data
    report = await fetch_report(report_id)

    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    # Process the review decisions to create nodes and edges
    entity_stats = await _create_entities(report_id, submission, report, db)
    technique_stats = await _create_technique_links(report_id, submission, report, db)

    # Update report with graph upsert timestamp if we pushed anything to the graph
    if (entity_stats.get("created", 0) > 0 or entity_stats.get("updated", 0) > 0 or
        technique_stats.get("created", 0) > 0 or technique_stats.get("updated", 0) > 0):
        # Store graph upsert timestamp
        os_client = get_opensearch_client()
        store = OpenSearchReportStore(os_client)
        report["graph_upserted_at"] = datetime.utcnow().isoformat()
        store.index_report(report)
        logger.info(f"Updated graph_upserted_at timestamp for report {report_id}")

    # Return statistics about what was created
    return UnifiedReviewResponse(
        success=True,
        report_id=report_id,
        message=f"Successfully pushed approved items to Neo4j graph",
        stats={
            "entities": entity_stats,
            "techniques": technique_stats,
            "total_nodes_created": entity_stats["created"],
            "total_nodes_updated": entity_stats["updated"],
            "total_edges_created": technique_stats["created"],
            "total_edges_updated": technique_stats["updated"],
            "duplicates_consolidated": technique_stats.get("skipped", 0)
        }
    )

@router.get(
    "/evidence/{node_id}",
    summary="Get Evidence for Node",
    description="Retrieve evidence for a technique or entity from the graph"
)
async def get_node_evidence(
    node_id: str = Path(..., description="Node ID (technique external_id or entity stix_id)"),
    node_type: str = Query("technique", description="Node type: 'technique' or 'entity'"),
    neo4j_session: Session = Depends(get_neo4j_session)
):
    """Retrieve evidence for a technique or entity from the Neo4j graph."""
    try:
        if node_type == "technique":
            # Query for technique evidence from EXTRACTED_TECHNIQUE relationships
            query = """
            MATCH (r:Report)-[rel:EXTRACTED_TECHNIQUE]->(t:AttackPattern)
            WHERE t.external_id = $node_id OR t.stix_id = $node_id
            RETURN
                r.stix_id as report_id,
                r.name as report_name,
                rel.evidence_texts as evidence_texts,
                rel.line_numbers as line_numbers,
                rel.source_summary as source_summary,
                rel.claim_ids as claim_ids,
                rel.confidence as confidence,
                rel.technique_name as technique_name,
                t.name as technique_full_name,
                t.external_id as technique_id
            ORDER BY rel.confidence DESC
            """
            results = neo4j_session.run(query, node_id=node_id)

            evidence_records = []
            for record in results:
                evidence_records.append({
                    "report_id": record["report_id"],
                    "report_name": record["report_name"],
                    "evidence_texts": record["evidence_texts"] or [],
                    "line_numbers": record["line_numbers"] or [],
                    "source_summary": record["source_summary"],
                    "claim_ids": record["claim_ids"],
                    "confidence": record["confidence"],
                    "technique_name": record["technique_name"] or record["technique_full_name"],
                    "technique_id": record["technique_id"]
                })

            return {
                "node_id": node_id,
                "node_type": "technique",
                "evidence_count": len(evidence_records),
                "evidence": evidence_records
            }

        elif node_type == "entity":
            # Query for entity evidence from node properties
            query = """
            MATCH (e)
            WHERE e.stix_id = $node_id
            RETURN
                e.stix_id as entity_id,
                e.name as entity_name,
                e.type as entity_type,
                e.evidence_mentions as evidence_mentions,
                e.line_refs as line_refs,
                e.source_report as source_report,
                e.description as description,
                e.x_bj_confidence as confidence,
                e.extraction_metadata as extraction_metadata
            """
            result = neo4j_session.run(query, node_id=node_id).single()

            if not result:
                raise HTTPException(status_code=404, detail=f"Entity {node_id} not found")

            return {
                "node_id": node_id,
                "node_type": "entity",
                "entity_name": result["entity_name"],
                "entity_type": result["entity_type"],
                "evidence": {
                    "evidence_mentions": result["evidence_mentions"] or [],
                    "line_refs": result["line_refs"] or [],
                    "source_report": result["source_report"],
                    "description": result["description"],
                    "confidence": result["confidence"],
                    "extraction_metadata": result["extraction_metadata"]
                }
            }

        else:
            raise HTTPException(status_code=400, detail=f"Invalid node type: {node_type}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve evidence for {node_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve evidence: {str(e)}"
        )
