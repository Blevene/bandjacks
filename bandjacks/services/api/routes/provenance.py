"""Provenance and lineage API endpoints."""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from neo4j import GraphDatabase

from ....config import get_settings
from ....loaders.evidence_retriever import EvidenceRetriever, EvidenceSnippet

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/provenance", tags=["provenance"])

# Get settings
settings = get_settings()


class ProvenanceSource(BaseModel):
    """Source document or data for an object."""
    source_id: str
    source_type: str
    collection: Optional[str]
    version: Optional[str]
    url: Optional[str]
    modified: Optional[str]
    confidence: float
    extraction_method: Optional[str]
    evidence_text: Optional[str] = None
    evidence_ids: Optional[List[str]] = None


class ProvenanceRelation(BaseModel):
    """Relationship in provenance chain."""
    relation_type: str
    direction: str  # "incoming" or "outgoing"
    target_id: str
    target_type: str
    target_name: str
    confidence: Optional[float]
    evidence_count: Optional[int]
    properties: Dict[str, Any]


class ProvenanceResponse(BaseModel):
    """Complete provenance information for an object."""
    object_id: str
    object_type: str
    object_name: str
    created: str
    modified: str
    sources: List[ProvenanceSource]
    relations: List[ProvenanceRelation]
    confidence_score: Optional[float]
    validation_status: Optional[str]
    warnings: List[str]
    lineage_depth: int


class LineageNode(BaseModel):
    """Node in lineage graph."""
    id: str
    type: str
    name: str
    confidence: Optional[float]
    depth: int


class LineageEdge(BaseModel):
    """Edge in lineage graph."""
    source: str
    target: str
    relation_type: str
    confidence: Optional[float]


class LineageGraph(BaseModel):
    """Full lineage graph."""
    root_id: str
    nodes: List[LineageNode]
    edges: List[LineageEdge]
    max_depth: int
    total_nodes: int


def get_neo4j_driver():
    """Get Neo4j driver instance."""
    if not settings.neo4j_password:
        raise ValueError(
            "NEO4J_PASSWORD environment variable is required. "
            "Please set it in your .env file or environment variables."
        )
    return GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password)
    )


@router.get("/{object_id}", response_model=ProvenanceResponse)
async def get_provenance(
    object_id: str,
    include_relations: bool = Query(True, description="Include related objects"),
    max_depth: int = Query(2, ge=1, le=5, description="Maximum relation depth")
) -> ProvenanceResponse:
    """
    Get complete provenance information for any object.
    
    Returns source documents, extraction metadata, relationships, and confidence scores.
    This endpoint provides full transparency into how an object was created and validated.
    """
    driver = get_neo4j_driver()
    
    try:
        with driver.session() as session:
            # Get object details
            object_data = _get_object_details(session, object_id)
            if not object_data:
                raise HTTPException(status_code=404, detail=f"Object {object_id} not found")
            
            # Get source information
            sources = _get_object_sources(session, object_id, object_data["type"])
            
            # Get relationships if requested
            relations = []
            if include_relations:
                relations = _get_object_relations(session, object_id, max_depth)
            
            # Calculate aggregate confidence
            confidence_score = _calculate_aggregate_confidence(sources, relations)
            
            # Generate warnings
            warnings = _generate_provenance_warnings(
                object_data, sources, relations, confidence_score
            )
            
            return ProvenanceResponse(
                object_id=object_id,
                object_type=object_data["type"],
                object_name=object_data.get("name", "Unknown"),
                created=object_data.get("created", datetime.utcnow().isoformat()),
                modified=object_data.get("modified", datetime.utcnow().isoformat()),
                sources=sources,
                relations=relations,
                confidence_score=confidence_score,
                validation_status=object_data.get("validation_status"),
                warnings=warnings,
                lineage_depth=max_depth if relations else 0
            )
            
    except Exception as e:
        logger.error(f"Failed to get provenance for {object_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        driver.close()


@router.get("/{object_id}/lineage", response_model=LineageGraph)
async def get_lineage_graph(
    object_id: str,
    max_depth: int = Query(3, ge=1, le=10, description="Maximum graph depth"),
    direction: str = Query("both", description="Traversal direction: upstream, downstream, both")
) -> LineageGraph:
    """
    Get the full lineage graph for an object.
    
    Returns a graph structure showing all connected objects and their relationships,
    useful for visualization and impact analysis.
    """
    driver = get_neo4j_driver()
    
    try:
        with driver.session() as session:
            # Build lineage graph
            nodes, edges = _build_lineage_graph(
                session, object_id, max_depth, direction
            )
            
            if not nodes:
                raise HTTPException(status_code=404, detail=f"Object {object_id} not found")
            
            return LineageGraph(
                root_id=object_id,
                nodes=nodes,
                edges=edges,
                max_depth=max_depth,
                total_nodes=len(nodes)
            )
            
    except Exception as e:
        logger.error(f"Failed to get lineage for {object_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        driver.close()


@router.get("/{object_id}/reviews")
async def get_review_provenance(
    object_id: str,
    include_all_types: bool = Query(True, description="Include all review types")
) -> Dict[str, Any]:
    """
    Get complete review provenance for an object.
    
    Returns all review decisions, timestamps, reviewers, and rationales
    for maintaining audit trail and understanding decision history.
    """
    driver = get_neo4j_driver()
    
    try:
        with driver.session() as session:
            # Get review provenance
            query = """
                MATCH (rp:ReviewProvenance)
                WHERE rp.object_id = $object_id
                RETURN rp {
                    .*,
                    age_days: duration.inDays(rp.timestamp, datetime()).days
                } as review
                ORDER BY rp.timestamp DESC
            """
            
            result = session.run(query, object_id=object_id)
            
            reviews = []
            for record in result:
                review = dict(record["review"])
                reviews.append({
                    "provenance_id": review.get("provenance_id"),
                    "review_type": review.get("review_type"),
                    "reviewer_id": review.get("reviewer_id"),
                    "timestamp": review.get("timestamp"),
                    "decision": review.get("decision"),
                    "rationale": review.get("rationale"),
                    "confidence_before": review.get("confidence_before"),
                    "confidence_after": review.get("confidence_after"),
                    "field_changed": review.get("field_changed"),
                    "old_value": review.get("old_value"),
                    "new_value": review.get("new_value"),
                    "evidence": review.get("evidence"),
                    "trace_id": review.get("trace_id"),
                    "age_days": review.get("age_days")
                })
            
            # Group by review type
            reviews_by_type = {}
            for review in reviews:
                review_type = review["review_type"]
                if review_type not in reviews_by_type:
                    reviews_by_type[review_type] = []
                reviews_by_type[review_type].append(review)
            
            # Calculate review statistics
            total_reviews = len(reviews)
            unique_reviewers = len(set(r["reviewer_id"] for r in reviews if r["reviewer_id"]))
            
            decisions = {}
            for review in reviews:
                decision = review.get("decision")
                if decision:
                    decisions[decision] = decisions.get(decision, 0) + 1
            
            return {
                "object_id": object_id,
                "total_reviews": total_reviews,
                "unique_reviewers": unique_reviewers,
                "decision_summary": decisions,
                "reviews_by_type": reviews_by_type if include_all_types else {},
                "recent_reviews": reviews[:10],  # Last 10 reviews
                "oldest_review": reviews[-1]["timestamp"] if reviews else None,
                "newest_review": reviews[0]["timestamp"] if reviews else None
            }
            
    except Exception as e:
        logger.error(f"Failed to get review provenance for {object_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        driver.close()


@router.get("/{object_id}/validation")
async def get_validation_history(
    object_id: str,
    include_feedback: bool = Query(True, description="Include review feedback")
) -> Dict[str, Any]:
    """
    Get validation and review history for an object.
    
    Returns all validation checks, review decisions, and feedback associated
    with the object's creation and updates.
    """
    driver = get_neo4j_driver()
    
    try:
        with driver.session() as session:
            # Get validation history
            validation_data = _get_validation_history(session, object_id)
            
            # Get review feedback if requested
            feedback = []
            if include_feedback:
                feedback = _get_review_feedback(session, object_id)
            
            return {
                "object_id": object_id,
                "validations": validation_data,
                "feedback": feedback,
                "current_status": _determine_validation_status(validation_data, feedback)
            }
            
    except Exception as e:
        logger.error(f"Failed to get validation history for {object_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        driver.close()


@router.post("/trace/{trace_id}")
async def get_trace_provenance(
    trace_id: str,
    include_intermediate: bool = Query(True, description="Include intermediate objects")
) -> Dict[str, Any]:
    """
    Get provenance for all objects created in a specific trace/session.
    
    Useful for understanding what was created during a specific operation
    or API call.
    """
    driver = get_neo4j_driver()
    
    try:
        with driver.session() as session:
            # Get all objects with this trace_id
            objects = _get_trace_objects(session, trace_id, include_intermediate)
            
            if not objects:
                raise HTTPException(status_code=404, detail=f"No objects found for trace {trace_id}")
            
            return {
                "trace_id": trace_id,
                "object_count": len(objects),
                "objects": objects,
                "timeline": _build_trace_timeline(objects)
            }
            
    except Exception as e:
        logger.error(f"Failed to get trace provenance for {trace_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        driver.close()


# Helper functions

def _get_object_details(session, object_id: str) -> Optional[Dict[str, Any]]:
    """Get basic object details."""
    # Try different ID fields
    for id_field in ["stix_id", "flow_id", "candidate_id", "d3fend_id"]:
        result = session.run(
            f"""
            MATCH (n)
            WHERE n.{id_field} = $object_id
            RETURN n.name as name, n.type as type, 
                   n.created as created, n.modified as modified,
                   n.validation_status as validation_status,
                   labels(n) as labels
            LIMIT 1
            """,
            object_id=object_id
        )
        
        record = result.single()
        if record:
            return {
                "name": record["name"],
                "type": record["labels"][0] if record["labels"] else record["type"],
                "created": record["created"],
                "modified": record["modified"],
                "validation_status": record["validation_status"]
            }
    
    return None


def _get_object_sources(session, object_id: str, object_type: str) -> List[ProvenanceSource]:
    """Get source information for an object."""
    sources = []
    
    # Initialize evidence retriever
    evidence_retriever = None
    try:
        evidence_retriever = EvidenceRetriever(
            opensearch_url=getattr(settings, 'opensearch_url', 'http://localhost:9200')
        )
    except Exception as e:
        logger.warning(f"Could not initialize evidence retriever: {e}")
    
    # Get direct source properties
    result = session.run(
        """
        MATCH (n)
        WHERE n.stix_id = $object_id OR n.flow_id = $object_id 
           OR n.candidate_id = $object_id OR n.d3fend_id = $object_id
        RETURN n.source_collection as collection,
               n.source_version as version,
               n.source_url as url,
               n.source_modified as modified,
               n.source_report as report,
               n.extraction_method as method,
               n.confidence_score as confidence,
               n.evidence_ids as evidence_ids
        """,
        object_id=object_id
    )
    
    record = result.single()
    if record and (record["collection"] or record["report"]):
        evidence_text = None
        evidence_ids = record.get("evidence_ids", [])
        
        # Retrieve evidence text if available
        if evidence_retriever and evidence_ids:
            evidence_snippets = []
            for eid in evidence_ids[:3]:  # Limit to first 3 evidence IDs
                snippet = evidence_retriever.get_evidence_by_id(eid)
                if snippet:
                    evidence_snippets.append(snippet.text)
            if evidence_snippets:
                evidence_text = " ... ".join(evidence_snippets)
        
        sources.append(ProvenanceSource(
            source_id=record["report"] or f"{record['collection']}-{record['version']}",
            source_type="report" if record["report"] else "attack-release",
            collection=record["collection"],
            version=record["version"],
            url=record["url"],
            modified=record["modified"],
            confidence=record["confidence"] or 1.0,
            extraction_method=record["method"],
            evidence_text=evidence_text,
            evidence_ids=evidence_ids
        ))
    
    # Get extraction sources with evidence
    result = session.run(
        """
        MATCH (n)<-[:EXTRACTED_FROM]-(doc)
        WHERE n.stix_id = $object_id OR n.flow_id = $object_id
        RETURN doc.document_id as doc_id, doc.name as doc_name,
               doc.type as doc_type, doc.url as doc_url,
               doc.extraction_id as extraction_id
        """,
        object_id=object_id
    )
    
    for record in result:
        evidence_text = None
        evidence_ids = []
        
        # Get evidence for this extraction
        if evidence_retriever and record.get("extraction_id"):
            evidence_snippets = evidence_retriever.get_evidence_for_extraction(
                record["extraction_id"],
                min_confidence=0.6
            )
            if evidence_snippets:
                evidence_ids = [s.evidence_id for s in evidence_snippets[:3]]
                evidence_text = " ... ".join([s.text for s in evidence_snippets[:3]])
        
        sources.append(ProvenanceSource(
            source_id=record["doc_id"],
            source_type=record["doc_type"] or "document",
            collection=None,
            version=None,
            url=record["doc_url"],
            modified=None,
            confidence=0.8,
            extraction_method="llm_extraction",
            evidence_text=evidence_text,
            evidence_ids=evidence_ids
        ))
    
    # Clean up
    if evidence_retriever:
        evidence_retriever.close()
    
    return sources


def _get_object_relations(session, object_id: str, max_depth: int) -> List[ProvenanceRelation]:
    """Get relationships for an object."""
    relations = []
    
    # Get incoming relationships
    result = session.run(
        """
        MATCH (source)-[r]->(target)
        WHERE (target.stix_id = $object_id OR target.flow_id = $object_id 
               OR target.candidate_id = $object_id)
        AND NOT type(r) IN ['EXTRACTED_FROM', 'REVIEWED_BY']
        RETURN type(r) as rel_type, source.stix_id as source_id,
               source.name as source_name, labels(source)[0] as source_type,
               r.confidence as confidence, r.evidence_count as evidence_count,
               properties(r) as props
        LIMIT 50
        """,
        object_id=object_id
    )
    
    for record in result:
        relations.append(ProvenanceRelation(
            relation_type=record["rel_type"],
            direction="incoming",
            target_id=record["source_id"],
            target_type=record["source_type"],
            target_name=record["source_name"] or "Unknown",
            confidence=record["confidence"],
            evidence_count=record["evidence_count"],
            properties=record["props"] or {}
        ))
    
    # Get outgoing relationships
    result = session.run(
        """
        MATCH (source)-[r]->(target)
        WHERE (source.stix_id = $object_id OR source.flow_id = $object_id 
               OR source.candidate_id = $object_id)
        AND NOT type(r) IN ['EXTRACTED_FROM', 'REVIEWED_BY']
        RETURN type(r) as rel_type, target.stix_id as target_id,
               target.name as target_name, labels(target)[0] as target_type,
               r.confidence as confidence, r.evidence_count as evidence_count,
               properties(r) as props
        LIMIT 50
        """,
        object_id=object_id
    )
    
    for record in result:
        relations.append(ProvenanceRelation(
            relation_type=record["rel_type"],
            direction="outgoing",
            target_id=record["target_id"],
            target_type=record["target_type"],
            target_name=record["target_name"] or "Unknown",
            confidence=record["confidence"],
            evidence_count=record["evidence_count"],
            properties=record["props"] or {}
        ))
    
    return relations


def _calculate_aggregate_confidence(
    sources: List[ProvenanceSource],
    relations: List[ProvenanceRelation]
) -> float:
    """Calculate aggregate confidence score."""
    if not sources and not relations:
        return 0.0
    
    # Weight sources more heavily than relations
    source_weight = 0.7
    relation_weight = 0.3
    
    source_conf = sum(s.confidence for s in sources) / len(sources) if sources else 0
    relation_conf = sum(r.confidence or 0.5 for r in relations) / len(relations) if relations else 0
    
    if sources and relations:
        return source_weight * source_conf + relation_weight * relation_conf
    elif sources:
        return source_conf
    else:
        return relation_conf


def _generate_provenance_warnings(
    object_data: Dict,
    sources: List[ProvenanceSource],
    relations: List[ProvenanceRelation],
    confidence: float
) -> List[str]:
    """Generate warnings about provenance issues."""
    warnings = []
    
    if confidence < 0.5:
        warnings.append(f"Low confidence score: {confidence:.2f}")
    
    if not sources:
        warnings.append("No source documents found")
    
    if any(s.confidence < 0.6 for s in sources):
        warnings.append("Some sources have low confidence")
    
    sparse_relations = [r for r in relations if (r.evidence_count or 1) < 2]
    if sparse_relations:
        warnings.append(f"{len(sparse_relations)} relationships have limited evidence")
    
    if object_data.get("validation_status") == "pending":
        warnings.append("Object pending validation")
    
    return warnings


def _build_lineage_graph(
    session,
    root_id: str,
    max_depth: int,
    direction: str
) -> tuple[List[LineageNode], List[LineageEdge]]:
    """Build complete lineage graph."""
    nodes = []
    edges = []
    visited = set()
    
    # BFS traversal
    queue = [(root_id, 0)]
    
    while queue:
        current_id, depth = queue.pop(0)
        
        if current_id in visited or depth > max_depth:
            continue
        
        visited.add(current_id)
        
        # Get node details
        node_data = _get_object_details(session, current_id)
        if node_data:
            nodes.append(LineageNode(
                id=current_id,
                type=node_data["type"],
                name=node_data.get("name", "Unknown"),
                confidence=None,  # Could calculate if needed
                depth=depth
            ))
        
        if depth < max_depth:
            # Get connected nodes based on direction
            if direction in ["upstream", "both"]:
                # Get sources
                result = session.run(
                    """
                    MATCH (source)-[r]->(target)
                    WHERE target.stix_id = $node_id OR target.flow_id = $node_id
                    RETURN source.stix_id as id, type(r) as rel_type,
                           r.confidence as confidence
                    """,
                    node_id=current_id
                )
                
                for record in result:
                    if record["id"]:
                        edges.append(LineageEdge(
                            source=record["id"],
                            target=current_id,
                            relation_type=record["rel_type"],
                            confidence=record["confidence"]
                        ))
                        queue.append((record["id"], depth + 1))
            
            if direction in ["downstream", "both"]:
                # Get targets
                result = session.run(
                    """
                    MATCH (source)-[r]->(target)
                    WHERE source.stix_id = $node_id OR source.flow_id = $node_id
                    RETURN target.stix_id as id, type(r) as rel_type,
                           r.confidence as confidence
                    """,
                    node_id=current_id
                )
                
                for record in result:
                    if record["id"]:
                        edges.append(LineageEdge(
                            source=current_id,
                            target=record["id"],
                            relation_type=record["rel_type"],
                            confidence=record["confidence"]
                        ))
                        queue.append((record["id"], depth + 1))
    
    return nodes, edges


def _get_validation_history(session, object_id: str) -> List[Dict[str, Any]]:
    """Get validation history for an object."""
    result = session.run(
        """
        MATCH (n)-[:VALIDATED_BY]->(v:Validation)
        WHERE n.stix_id = $object_id OR n.flow_id = $object_id
        RETURN v.timestamp as timestamp, v.validator as validator,
               v.result as result, v.errors as errors, v.spec_version as spec
        ORDER BY v.timestamp DESC
        """,
        object_id=object_id
    )
    
    validations = []
    for record in result:
        validations.append({
            "timestamp": record["timestamp"],
            "validator": record["validator"],
            "result": record["result"],
            "errors": record["errors"],
            "spec_version": record["spec"]
        })
    
    return validations


def _get_review_feedback(session, object_id: str) -> List[Dict[str, Any]]:
    """Get review feedback for an object."""
    result = session.run(
        """
        MATCH (n)<-[:REVIEWED]-(f:Feedback)
        WHERE n.stix_id = $object_id OR n.flow_id = $object_id
        RETURN f.timestamp as timestamp, f.reviewer as reviewer,
               f.decision as decision, f.score as score,
               f.comment as comment
        ORDER BY f.timestamp DESC
        """,
        object_id=object_id
    )
    
    feedback = []
    for record in result:
        feedback.append({
            "timestamp": record["timestamp"],
            "reviewer": record["reviewer"],
            "decision": record["decision"],
            "score": record["score"],
            "comment": record["comment"]
        })
    
    return feedback


def _determine_validation_status(
    validations: List[Dict],
    feedback: List[Dict]
) -> str:
    """Determine current validation status."""
    if not validations and not feedback:
        return "unvalidated"
    
    # Check latest validation
    if validations and validations[0]["result"] == "failed":
        return "invalid"
    
    # Check feedback consensus
    if feedback:
        approvals = sum(1 for f in feedback if f["decision"] == "approved")
        rejections = sum(1 for f in feedback if f["decision"] == "rejected")
        
        if rejections > approvals:
            return "rejected"
        elif approvals > 0:
            return "approved"
    
    return "validated" if validations else "pending"


def _get_trace_objects(session, trace_id: str, include_intermediate: bool) -> List[Dict[str, Any]]:
    """Get all objects created in a trace."""
    query = """
        MATCH (n)
        WHERE n.trace_id = $trace_id
    """
    
    if not include_intermediate:
        query += " AND NOT n:Intermediate"
    
    query += """
        RETURN n.stix_id as id, labels(n)[0] as type,
               n.name as name, n.created as created
        ORDER BY n.created
    """
    
    result = session.run(query, trace_id=trace_id)
    
    objects = []
    for record in result:
        objects.append({
            "id": record["id"],
            "type": record["type"],
            "name": record["name"],
            "created": record["created"]
        })
    
    return objects


def _build_trace_timeline(objects: List[Dict]) -> List[Dict[str, Any]]:
    """Build timeline of object creation."""
    timeline = []
    
    for obj in objects:
        timeline.append({
            "timestamp": obj["created"],
            "event": f"Created {obj['type']}",
            "object_id": obj["id"],
            "object_name": obj["name"]
        })
    
    return sorted(timeline, key=lambda x: x["timestamp"]) if timeline else []