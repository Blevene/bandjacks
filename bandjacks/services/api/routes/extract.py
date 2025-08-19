"""API endpoints for CTI extraction with provenance tracking."""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
import hashlib
from datetime import datetime
import os

from bandjacks.services.api.deps import get_neo4j_session, get_opensearch_client
from bandjacks.loaders.parse_text import extract_text
from bandjacks.loaders.chunker import split_into_chunks
from bandjacks.llm.extractor import LLMExtractor
from bandjacks.llm.stix_builder import STIXBuilder
from bandjacks.llm.entity_resolver import EntityResolver
from bandjacks.llm.provenance_tracker import ProvenanceTracker
from bandjacks.loaders.attack_upsert import upsert_to_graph_and_vectors


router = APIRouter(prefix="/extract", tags=["extraction"])


class ExtractionRequest(BaseModel):
    """Request for report extraction."""
    source_url: Optional[str] = Field(None, description="URL of source document")
    source_type: str = Field("report", description="Type of source (report, blog, pdf, etc)")
    content: str = Field(..., description="Text content to extract from")
    title: Optional[str] = Field(None, description="Optional title for the report")
    method: str = Field("llm", description="Extraction method (llm, agentic_v2, vector, hybrid)")
    confidence_threshold: float = Field(50.0, description="Minimum confidence for extraction")
    auto_ingest: bool = Field(False, description="Automatically ingest to graph if True")


class ExtractionResponse(BaseModel):
    """Response from extraction."""
    extraction_id: str
    source_id: str
    bundle: Dict[str, Any]
    stats: Dict[str, Any]
    provenance: Dict[str, Any]
    ingested: bool = False


@router.post("/report", response_model=ExtractionResponse)
async def extract_report(
    request: ExtractionRequest,
    neo4j_session=Depends(get_neo4j_session),
    opensearch_client=Depends(get_opensearch_client)
) -> ExtractionResponse:
    """
    Extract CTI from a report with full provenance tracking.
    
    This endpoint:
    1. Registers the source document with hash-based ID
    2. Chunks the text for processing
    3. Extracts entities and relationships using LLM
    4. Resolves entities to existing KB entries
    5. Builds STIX 2.1 bundle with provenance
    6. Optionally ingests to Neo4j graph
    """
    
    # Initialize components
    provenance_tracker = ProvenanceTracker()
    
    # Register source document
    source_id = provenance_tracker.register_source(
        content=request.content,
        url=request.source_url,
        title=request.title,
        source_type=request.source_type,
        metadata={
            "content_length": len(request.content),
            "extraction_requested_at": datetime.utcnow().isoformat() + "Z"
        }
    )
    
    # Start extraction run
    extraction_id = provenance_tracker.start_extraction(
        source_id=source_id,
        method=request.method,
        model=os.getenv("PRIMARY_LLM", "gemini-2.5-flash"),
        parameters={
            "confidence_threshold": request.confidence_threshold,
            "auto_ingest": request.auto_ingest
        }
    )
    
    try:
        # Agentic v2 path
        if request.method == "agentic_v2":
            from bandjacks.llm.agentic_v2 import run_agentic_v2

            neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
            neo4j_user = os.getenv("NEO4J_USER", "neo4j")
            neo4j_password = os.getenv("NEO4J_PASSWORD", "password")

            result = run_agentic_v2(
                report_text=request.content,
                config={
                    "neo4j_uri": neo4j_uri,
                    "neo4j_user": neo4j_user,
                    "neo4j_password": neo4j_password,
                    "model": os.getenv("PRIMARY_LLM", "gemini-2.0-flash"),
                    "title": request.title,
                    "url": request.source_url,
                },
            )

            bundle = result["bundle"]
            stats = {
                "claims_extracted": len(result.get("techniques", {})),
                "stix_objects_created": len(bundle.get("objects", [])),
                "mode": "agentic_v2",
            }

            provenance_tracker.complete_extraction(extraction_id, stats)

            ingested = False
            if request.auto_ingest and bundle.get("objects"):
                filtered_objects = [
                    obj for obj in bundle["objects"] if obj.get("x_bj_confidence", 100) >= request.confidence_threshold
                ]
                if filtered_objects:
                    bundle["objects"] = filtered_objects
                    inserted, updated = upsert_to_graph_and_vectors(
                        bundle=bundle,
                        collection="extracted",
                        version=datetime.utcnow().strftime("%Y%m%d"),
                        neo4j_uri=neo4j_uri,
                        neo4j_user=neo4j_user,
                        neo4j_password=neo4j_password,
                        os_url=os.getenv("OPENSEARCH_URL", "http://localhost:9200"),
                        os_index="bandjacks_attack_nodes-v1",
                        provenance={
                            "id": extraction_id,
                            "method": request.method,
                            "model": os.getenv("PRIMARY_LLM", "gemini-2.0-flash"),
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                        },
                    )
                    stats["objects_inserted"] = inserted
                    stats["objects_updated"] = updated
                    ingested = True

            return ExtractionResponse(
                extraction_id=extraction_id,
                source_id=source_id,
                bundle=bundle,
                stats=stats,
                provenance=provenance_tracker.create_stix_provenance_extension(
                    object_id=bundle["id"],
                    source_id=source_id,
                    extraction_id=extraction_id,
                    confidence=stats.get("avg_confidence", 50),
                    evidence=f"Agentic v2 extraction",
                    line_refs=[],
                ),
                ingested=ingested,
            )

        # Initialize LLM extractor (legacy)
        extractor = LLMExtractor(model=os.getenv("PRIMARY_LLM", "gemini/gemini-2.0-flash-exp"))
        
        # Extract from document - this handles chunking internally
        # Use reasonable chunk size that LLM can process effectively
        extraction_output = extractor.extract_document(
            source_id=source_id,
            source_type=request.source_type,
            inline_text=request.content,
            chunking_params={"target_chars": 2500, "overlap": 300}
        )
        
        # Aggregate results from all chunks
        all_claims = []
        all_entities = {}
        
        if "chunks" in extraction_output:
            for chunk_result in extraction_output["chunks"]:
                # Aggregate claims
                if "claims" in chunk_result:
                    all_claims.extend(chunk_result["claims"])
                
                # Merge entities
                if "entities" in chunk_result:
                    for entity_type, entities in chunk_result["entities"].items():
                        if entity_type not in all_entities:
                            all_entities[entity_type] = []
                        if isinstance(entities, list):
                            all_entities[entity_type].extend(entities)
        
        # Build extraction results
        extraction_results = {
            "claims": all_claims,
            "entities": all_entities,
            "metadata": extraction_output.get("metadata", {})
        }
        
        # Initialize entity resolver
        neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        neo4j_user = os.getenv("NEO4J_USER", "neo4j")
        neo4j_password = os.getenv("NEO4J_PASSWORD", "password")
        
        entity_resolver = EntityResolver(neo4j_uri, neo4j_user, neo4j_password)
        
        # Build STIX bundle
        stix_builder = STIXBuilder(entity_resolver)
        
        source_metadata = {
            "id": source_id,
            "url": request.source_url,
            "title": request.title,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "hash": hashlib.sha256(request.content.encode()).hexdigest()
        }
        
        extraction_metadata = {
            "id": extraction_id,
            "method": request.method,
            "model": os.getenv("PRIMARY_LLM", "gemini-2.5-flash"),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        bundle = stix_builder.build_bundle(
            extraction_results=extraction_results,
            source_metadata=source_metadata,
            extraction_metadata=extraction_metadata
        )
        
        # Calculate statistics
        stats = {
            "chunks_processed": len(extraction_output.get("chunks", [])),
            "claims_extracted": len(all_claims),
            "entities_found": {k: len(v) for k, v in all_entities.items()},
            "stix_objects_created": len(bundle.get("objects", [])),
            "confidence_threshold": request.confidence_threshold
        }
        
        # Complete extraction tracking
        provenance_tracker.complete_extraction(extraction_id, stats)
        
        # Optionally ingest to graph
        ingested = False
        if request.auto_ingest and bundle.get("objects"):
            # Filter by confidence threshold
            filtered_objects = []
            for obj in bundle["objects"]:
                if obj.get("x_bj_confidence", 100) >= request.confidence_threshold:
                    filtered_objects.append(obj)
            
            if filtered_objects:
                bundle["objects"] = filtered_objects
                
                # Ingest to Neo4j and OpenSearch
                inserted, updated = upsert_to_graph_and_vectors(
                    bundle=bundle,
                    collection="extracted",
                    version=datetime.utcnow().strftime("%Y%m%d"),
                    neo4j_uri=neo4j_uri,
                    neo4j_user=neo4j_user,
                    neo4j_password=neo4j_password,
                    os_url=os.getenv("OPENSEARCH_URL", "http://localhost:9200"),
                    os_index="bandjacks_attack_nodes-v1",
                    provenance=extraction_metadata
                )
                
                stats["objects_inserted"] = inserted
                stats["objects_updated"] = updated
                ingested = True
        
        # Close entity resolver
        entity_resolver.close()
        
        # Build response
        return ExtractionResponse(
            extraction_id=extraction_id,
            source_id=source_id,
            bundle=bundle,
            stats=stats,
            provenance=provenance_tracker.create_stix_provenance_extension(
                object_id=bundle["id"],
                source_id=source_id,
                extraction_id=extraction_id,
                confidence=stats.get("avg_confidence", 50),
                evidence=f"Extracted from {len(extraction_output.get('chunks', []))} chunks",
                line_refs=[]
            ),
            ingested=ingested
        )
        
    except Exception as e:
        # Track failure
        provenance_tracker.complete_extraction(extraction_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"Extraction failed: {str(e)}")


@router.get("/provenance/{object_id}")
async def get_object_provenance(
    object_id: str,
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """
    Get complete provenance history for a STIX object.
    
    This traces the object back through all extraction sources.
    """
    # Query for object and its provenance
    result = neo4j_session.run("""
        MATCH (n {stix_id: $object_id})
        OPTIONAL MATCH (n)-[e:EXTRACTED_FROM]->(r:Report)
        RETURN n, collect({
            report: r,
            confidence: e.confidence,
            evidence: e.evidence
        }) as sources
    """, object_id=object_id)
    
    record = result.single()
    if not record:
        raise HTTPException(status_code=404, detail=f"Object {object_id} not found")
    
    node = dict(record["n"])
    sources = record["sources"]
    
    # Parse stored provenance
    x_bj_sources = node.get("x_bj_sources", [])
    if x_bj_sources and isinstance(x_bj_sources[0], str):
        import json
        x_bj_sources = [json.loads(s) for s in x_bj_sources]
    
    return {
        "object_id": object_id,
        "object_type": node.get("type"),
        "name": node.get("name"),
        "provenance_sources": x_bj_sources,
        "extracted_from": [
            {
                "report_id": s["report"]["stix_id"] if s["report"] else None,
                "report_name": s["report"]["name"] if s["report"] else None,
                "confidence": s["confidence"],
                "evidence": s["evidence"]
            }
            for s in sources if s["report"]
        ],
        "source_collection": node.get("source_collection"),
        "source_version": node.get("source_version")
    }