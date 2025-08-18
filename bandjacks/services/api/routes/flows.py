"""Attack flow generation, retrieval, and search endpoints."""

from fastapi import APIRouter, HTTPException, Depends, Query
from typing import Dict, Any, List, Optional
from opensearchpy import OpenSearch
import json

from bandjacks.services.api.deps import get_neo4j_session, get_opensearch_client
from bandjacks.services.api.settings import settings
from bandjacks.services.api.schemas import (
    FlowBuildRequest, FlowBuildResponse, FlowSearchRequest, 
    FlowSearchResponse, FlowGetResponse, FlowStep, FlowEdge,
    FlowSearchResult
)
from bandjacks.llm.flow_builder import FlowBuilder
from bandjacks.loaders.opensearch_index import upsert_flow_embedding
from bandjacks.loaders.embedder import encode


router = APIRouter(prefix="/flows", tags=["flows"])


@router.post("/build",
    response_model=FlowBuildResponse,
    summary="Build Attack Flow",
    description="""
    Build an attack flow from various sources.
    
    This endpoint can create flows from:
    - **Extraction results**: Use LLM synthesis from extraction data
    - **STIX bundles**: Deterministic flow from STIX objects
    - **Stored sources**: Build from reports or bundles in the knowledge base
    
    The flow is persisted in Neo4j as AttackEpisode/AttackAction nodes
    and indexed in OpenSearch for similarity search.
    """,
    responses={
        200: {"description": "Flow successfully built"},
        400: {"description": "Invalid request parameters"},
        404: {"description": "Source not found"},
        500: {"description": "Internal server error"}
    }
)
async def build_flow(
    source_id: Optional[str] = Query(None, description="Source report or bundle ID"),
    strict: bool = Query(True, description="Enforce strict validation"),
    request: Optional[FlowBuildRequest] = None,
    neo4j_session=Depends(get_neo4j_session),
    opensearch_client=Depends(get_opensearch_client)
) -> FlowBuildResponse:
    """Build an attack flow from extraction, bundle, or source."""
    
    # Initialize flow builder
    builder = FlowBuilder(
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=settings.neo4j_password
    )
    
    try:
        # Determine source and build flow
        if request and request.extraction:
            # Use LLM synthesis from extraction
            flow_data = builder.build_from_extraction(
                extraction_data=request.extraction,
                source_id=request.source_id or source_id
            )
            
        elif request and request.bundle:
            # Deterministic from bundle
            flow_data = builder.build_from_bundle(
                bundle=request.bundle,
                source_id=request.source_id or source_id
            )
            
        elif source_id:
            # Load from stored source
            flow_data = builder.build_from_source(source_id)
            
        else:
            raise HTTPException(
                status_code=400,
                detail="Must provide source_id, extraction data, or STIX bundle"
            )
        
        # Persist to Neo4j
        success = builder.persist_to_neo4j(flow_data)
        if not success:
            raise HTTPException(
                status_code=500,
                detail="Failed to persist flow to database"
            )
        
        # Generate embedding and index in OpenSearch
        try:
            flow_embedding = builder.generate_flow_embedding(flow_data)
            upsert_flow_embedding(
                os_url=settings.opensearch_url,
                index="attack_flows",
                doc=flow_embedding
            )
        except Exception as e:
            print(f"Warning: Failed to index flow in OpenSearch: {e}")
            # Continue without failing the request
        
        # Format response
        steps = []
        for action in flow_data["actions"]:
            steps.append(FlowStep(
                order=action["order"],
                action_id=action["action_id"],
                attack_pattern_ref=action["attack_pattern_ref"],
                name=action["name"],
                description=action["description"],
                confidence=action["confidence"],
                evidence=action.get("evidence"),
                reason=action.get("reason"),
                timestamp=action.get("timestamp")
            ))
        
        edges = []
        for edge in flow_data["edges"]:
            edges.append(FlowEdge(
                source=edge["source"],
                target=edge["target"],
                probability=edge["probability"],
                rationale=edge["rationale"]
            ))
        
        return FlowBuildResponse(
            flow_id=flow_data["flow_id"],
            episode_id=flow_data["episode_id"],
            name=flow_data["name"],
            source_id=flow_data.get("source_id"),
            steps=steps,
            edges=edges,
            stats=flow_data["stats"],
            llm_synthesized=flow_data.get("llm_synthesized", False),
            created_at=flow_data["created_at"]
        )
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Flow build failed: {str(e)}")
    finally:
        builder.close()


@router.get("/{flow_id}",
    response_model=FlowGetResponse,
    summary="Get Attack Flow",
    description="""
    Retrieve a specific attack flow by ID.
    
    Returns complete flow details including:
    - Episode metadata
    - Ordered attack actions  
    - NEXT edges with probabilities
    - Source provenance
    """,
    responses={
        200: {"description": "Flow details retrieved"},
        404: {"description": "Flow not found"},
        500: {"description": "Internal server error"}
    }
)
async def get_flow(
    flow_id: str,
    neo4j_session=Depends(get_neo4j_session)
) -> FlowGetResponse:
    """Get a specific flow by ID."""
    
    try:
        # Query Neo4j for the episode
        episode_query = """
            MATCH (e:AttackEpisode {flow_id: $flow_id})
            RETURN e.episode_id as episode_id, e.name as name, 
                   e.source_id as source_id, e.created as created_at,
                   e.strategy as strategy, e.llm_synthesized as llm_synthesized
        """
        
        episode_result = neo4j_session.run(episode_query, flow_id=flow_id)
        episode_record = episode_result.single()
        
        if not episode_record:
            raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found")
        
        # Get all actions for this episode
        actions_query = """
            MATCH (e:AttackEpisode {flow_id: $flow_id})-[:CONTAINS]->(a:AttackAction)
            RETURN a.action_id as action_id, a.order as order,
                   a.attack_pattern_ref as attack_pattern_ref,
                   a.confidence as confidence, a.description as description,
                   a.evidence as evidence, a.rationale as rationale,
                   a.timestamp as timestamp
            ORDER BY a.order
        """
        
        actions_result = neo4j_session.run(actions_query, flow_id=flow_id)
        
        steps = []
        action_names = {}  # Cache for technique names
        
        for action_record in actions_result:
            action_id = action_record["action_id"]
            
            # Get technique name
            if action_record["attack_pattern_ref"] not in action_names:
                tech_query = """
                    MATCH (t:AttackPattern {stix_id: $tech_id})
                    RETURN t.name as name
                """
                tech_result = neo4j_session.run(
                    tech_query, 
                    tech_id=action_record["attack_pattern_ref"]
                )
                tech_record = tech_result.single()
                technique_name = tech_record["name"] if tech_record else "Unknown"
                action_names[action_record["attack_pattern_ref"]] = technique_name
            else:
                technique_name = action_names[action_record["attack_pattern_ref"]]
            
            # Parse evidence JSON
            evidence = None
            if action_record["evidence"]:
                try:
                    evidence = json.loads(action_record["evidence"])
                except:
                    evidence = []
            
            steps.append(FlowStep(
                order=action_record["order"],
                action_id=action_id,
                attack_pattern_ref=action_record["attack_pattern_ref"],
                name=technique_name,
                description=action_record["description"] or "",
                confidence=action_record["confidence"] or 50.0,
                evidence=evidence,
                reason=action_record["rationale"],
                timestamp=action_record["timestamp"].isoformat() if action_record["timestamp"] else None
            ))
        
        # Get NEXT edges
        edges_query = """
            MATCH (e:AttackEpisode {flow_id: $flow_id})-[:CONTAINS]->(a1:AttackAction)
            MATCH (a1)-[n:NEXT]->(a2:AttackAction)
            RETURN a1.action_id as source, a2.action_id as target,
                   n.p as probability, n.rationale as rationale
        """
        
        edges_result = neo4j_session.run(edges_query, flow_id=flow_id)
        
        edges = []
        for edge_record in edges_result:
            edges.append(FlowEdge(
                source=edge_record["source"],
                target=edge_record["target"],
                probability=edge_record["probability"] or 0.5,
                rationale=edge_record["rationale"] or ""
            ))
        
        return FlowGetResponse(
            flow_id=flow_id,
            episode_id=episode_record["episode_id"],
            name=episode_record["name"] or "Unknown Flow",
            source_id=episode_record["source_id"],
            created_at=episode_record["created_at"].isoformat() if episode_record["created_at"] else "",
            strategy=episode_record["strategy"],
            llm_synthesized=episode_record["llm_synthesized"] or False,
            steps=steps,
            edges=edges,
            metadata={
                "steps_count": len(steps),
                "edges_count": len(edges),
                "avg_confidence": sum(s.confidence for s in steps) / len(steps) if steps else 0
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve flow: {str(e)}")


@router.post("/search",
    response_model=FlowSearchResponse,
    summary="Search Attack Flows",
    description="""
    Search for similar attack flows.
    
    Search modes:
    - **By flow_id**: Find flows similar to an existing flow
    - **By text**: Find flows matching a text description
    
    Uses vector similarity search on flow embeddings.
    """,
    responses={
        200: {"description": "Search results returned"},
        400: {"description": "Invalid search parameters"},
        502: {"description": "Search service unavailable"},
        500: {"description": "Internal server error"}
    }
)
async def search_flows(
    request: FlowSearchRequest,
    opensearch_client=Depends(get_opensearch_client)
) -> FlowSearchResponse:
    """Search for similar flows."""
    
    if not request.flow_id and not request.text:
        raise HTTPException(
            status_code=400,
            detail="Must provide either flow_id or text for search"
        )
    
    try:
        query_vector = None
        query_type = ""
        
        if request.flow_id:
            # Search by flow similarity
            query_type = "flow_similarity"
            
            # Get the embedding of the reference flow
            response = opensearch_client.get(
                index="attack_flows",
                id=request.flow_id,
                _source=["flow_embedding"]
            )
            
            if response["found"]:
                query_vector = response["_source"]["flow_embedding"]
            else:
                raise HTTPException(
                    status_code=404,
                    detail=f"Flow {request.flow_id} not found"
                )
                
        elif request.text:
            # Search by text
            query_type = "text_search"
            
            # Generate embedding for the search text
            query_vector = encode(request.text)
            if query_vector is None:
                raise HTTPException(
                    status_code=500,
                    detail="Failed to generate embedding for search text"
                )
        
        # Perform KNN search
        search_body = {
            "size": request.top_k,
            "query": {
                "knn": {
                    "flow_embedding": {
                        "vector": query_vector,
                        "k": request.top_k
                    }
                }
            },
            "_source": [
                "flow_id", "episode_id", "name", "created", 
                "steps_count", "tactics", "avg_confidence", "flow_text"
            ]
        }
        
        # Exclude the query flow itself if searching by flow_id
        if request.flow_id:
            search_body["query"] = {
                "bool": {
                    "must": [search_body["query"]],
                    "must_not": [
                        {"term": {"flow_id": request.flow_id}}
                    ]
                }
            }
        
        response = opensearch_client.search(
            index="attack_flows",
            body=search_body
        )
        
        # Format results
        results = []
        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            
            # Generate preview from flow text
            flow_text = source.get("flow_text", "")
            preview = flow_text[:200] + "..." if len(flow_text) > 200 else flow_text
            
            results.append(FlowSearchResult(
                flow_id=source["flow_id"],
                episode_id=source["episode_id"],
                name=source["name"],
                score=hit["_score"],
                preview=preview,
                steps_count=source.get("steps_count", 0),
                tactics=source.get("tactics", []),
                created_at=source.get("created", "")
            ))
        
        return FlowSearchResponse(
            results=results,
            query_type=query_type,
            total_results=len(results)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        if "index_not_found_exception" in str(e):
            raise HTTPException(
                status_code=502,
                detail="Flow search index not available"
            )
        raise HTTPException(
            status_code=500,
            detail=f"Flow search failed: {str(e)}"
        )


@router.get("/",
    summary="List Attack Flows",
    description="List all attack flows with optional filtering."
)
async def list_flows(
    limit: int = Query(20, ge=1, le=100, description="Maximum flows to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    source_id: Optional[str] = Query(None, description="Filter by source"),
    llm_synthesized: Optional[bool] = Query(None, description="Filter by synthesis method"),
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """List flows with pagination and filtering."""
    
    try:
        # Build query with filters
        where_clauses = []
        params = {"limit": limit, "offset": offset}
        
        if source_id:
            where_clauses.append("e.source_id = $source_id")
            params["source_id"] = source_id
            
        if llm_synthesized is not None:
            where_clauses.append("e.llm_synthesized = $llm_synthesized")
            params["llm_synthesized"] = llm_synthesized
        
        where_clause = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        query = f"""
            MATCH (e:AttackEpisode)
            {where_clause}
            RETURN e.flow_id as flow_id, e.episode_id as episode_id,
                   e.name as name, e.created as created_at,
                   e.source_id as source_id, e.llm_synthesized as llm_synthesized
            ORDER BY e.created DESC
            SKIP $offset
            LIMIT $limit
        """
        
        result = neo4j_session.run(query, **params)
        
        flows = []
        for record in result:
            flows.append({
                "flow_id": record["flow_id"],
                "episode_id": record["episode_id"],
                "name": record["name"],
                "created_at": record["created_at"].isoformat() if record["created_at"] else "",
                "source_id": record["source_id"],
                "llm_synthesized": record["llm_synthesized"] or False
            })
        
        # Get total count
        count_query = f"""
            MATCH (e:AttackEpisode)
            {where_clause}
            RETURN count(e) as total
        """
        
        count_result = neo4j_session.run(count_query, **params)
        total = count_result.single()["total"]
        
        return {
            "flows": flows,
            "total": total,
            "offset": offset,
            "limit": limit
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list flows: {str(e)}")


@router.delete("/{flow_id}",
    summary="Delete Attack Flow",
    description="Delete an attack flow and all associated data."
)
async def delete_flow(
    flow_id: str,
    neo4j_session=Depends(get_neo4j_session),
    opensearch_client=Depends(get_opensearch_client)
) -> Dict[str, Any]:
    """Delete a flow and all its data."""
    
    try:
        # Delete from Neo4j
        delete_query = """
            MATCH (e:AttackEpisode {flow_id: $flow_id})
            OPTIONAL MATCH (e)-[:CONTAINS]->(a:AttackAction)
            OPTIONAL MATCH (a)-[n:NEXT]-()
            DELETE n, a, e
            RETURN count(e) as deleted_episodes, count(a) as deleted_actions
        """
        
        result = neo4j_session.run(delete_query, flow_id=flow_id)
        record = result.single()
        
        if record["deleted_episodes"] == 0:
            raise HTTPException(status_code=404, detail=f"Flow {flow_id} not found")
        
        # Delete from OpenSearch
        try:
            opensearch_client.delete(index="attack_flows", id=flow_id)
        except Exception as e:
            print(f"Warning: Failed to delete flow from OpenSearch: {e}")
        
        return {
            "flow_id": flow_id,
            "deleted": True,
            "deleted_episodes": record["deleted_episodes"],
            "deleted_actions": record["deleted_actions"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete flow: {str(e)}")