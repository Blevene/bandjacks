"""Search endpoints for text-to-technique (TTX) queries and attack flow similarity."""

from typing import Dict, Any, Optional, List
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, Field
from bandjacks.services.api.schemas import TtxQuery, TtxSearchResponse, ErrorResponse
from bandjacks.services.api.settings import settings
from bandjacks.services.api.deps import get_neo4j_session, get_opensearch_client
from bandjacks.loaders.search_nodes import ttx_search_kb
import uuid
import json

router = APIRouter(tags=["search"])


class FlowSearchRequest(BaseModel):
    """Request to search for similar attack flows."""
    flow_id: Optional[str] = Field(None, description="Find flows similar to this flow")
    text: Optional[str] = Field(None, description="Find flows matching this description")
    techniques: Optional[List[str]] = Field(None, description="Find flows containing these techniques")
    top_k: int = Field(10, description="Number of results to return", ge=1, le=100)
    min_score: float = Field(0.5, description="Minimum similarity score", ge=0.0, le=1.0)


class FlowSearchResult(BaseModel):
    """A single flow search result."""
    flow_id: str = Field(..., description="Flow ID")
    name: str = Field(..., description="Flow name")
    description: str = Field(..., description="Flow description")
    similarity_score: float = Field(..., description="Similarity score (0-1)")
    action_count: int = Field(..., description="Number of actions in flow")
    techniques: List[str] = Field(..., description="Techniques used in flow")


class FlowSearchResponse(BaseModel):
    """Response from flow search."""
    results: List[FlowSearchResult] = Field(..., description="Search results")
    query_type: str = Field(..., description="Type of search performed")
    total_results: int = Field(..., description="Total number of results")


@router.post(
    "/search/ttx",
    response_model=TtxSearchResponse,
    status_code=status.HTTP_200_OK,
    summary="Search for ATT&CK Techniques",
    description="""
    Search for MITRE ATT&CK techniques and entities using natural language queries.
    
    This endpoint uses vector similarity search to find techniques that match the
    provided text description. Results are ranked by relevance score.
    
    **Features:**
    - Natural language search
    - Vector similarity matching
    - Optional filtering by entity type
    - Configurable result count
    
    **Use cases:**
    - Find techniques matching threat descriptions
    - Discover similar attack patterns
    - Map threat reports to ATT&CK framework
    """,
    response_description="List of matching techniques with relevance scores",
    operation_id="searchTechniques",
    responses={
        200: {
            "description": "Successful search",
            "model": TtxSearchResponse
        },
        400: {
            "description": "Invalid request parameters",
            "model": ErrorResponse
        },
        502: {
            "description": "Search backend unavailable",
            "model": ErrorResponse
        }
    }
)
async def search_ttx(q: TtxQuery) -> TtxSearchResponse:
    """
    Search for ATT&CK techniques/entities similar to input text with optional kb_type filtering.
    
    Args:
        q: Search query parameters
        
    Returns:
        TtxSearchResponse with matching techniques and scores
        
    Raises:
        HTTPException: If search fails or backend is unavailable
    """
    trace_id = str(uuid.uuid4())
    
    try:
        results = ttx_search_kb(
            os_url=settings.opensearch_url,
            index=settings.os_index_nodes,
            text=q.text,
            top_k=q.top_k,
            kb_types=q.kb_types
        )
        
        return TtxSearchResponse(
            results=results,
            query=q.text,
            total_results=len(results),
            trace_id=trace_id
        )
        
    except ConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "SearchBackendUnavailable",
                "message": f"OpenSearch connection failed: {str(e)}",
                "trace_id": trace_id
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "SearchError",
                "message": f"Search operation failed: {str(e)}",
                "trace_id": trace_id
            }
        )


@router.post(
    "/search/flows",
    response_model=FlowSearchResponse,
    status_code=status.HTTP_200_OK,
    summary="Search Attack Flows",
    description="""
    Search for similar attack flows using various criteria.
    
    This endpoint supports multiple search modes:
    - **By flow_id**: Find flows similar to an existing flow using vector embeddings
    - **By text**: Find flows matching a text description using semantic search
    - **By techniques**: Find flows containing specific ATT&CK techniques
    
    The search uses OpenSearch vector similarity for flow embeddings and
    Neo4j graph queries for technique-based searches.
    
    **Use cases:**
    - Find similar attack patterns
    - Discover flows with specific techniques
    - Search flows by description
    """,
    response_description="List of matching flows with similarity scores",
    operation_id="searchFlows",
    responses={
        200: {
            "description": "Successful search",
            "model": FlowSearchResponse
        },
        400: {
            "description": "Invalid request parameters",
            "model": ErrorResponse
        },
        404: {
            "description": "Reference flow not found",
            "model": ErrorResponse
        },
        502: {
            "description": "Search backend unavailable",
            "model": ErrorResponse
        }
    }
)
async def search_flows(
    request: FlowSearchRequest,
    neo4j_session=Depends(get_neo4j_session),
    opensearch_client=Depends(get_opensearch_client)
) -> FlowSearchResponse:
    """
    Search for similar attack flows.
    
    Args:
        request: Search parameters
        neo4j_session: Neo4j database session
        opensearch_client: OpenSearch client
        
    Returns:
        FlowSearchResponse with matching flows and scores
        
    Raises:
        HTTPException: If search fails or backends are unavailable
    """
    trace_id = str(uuid.uuid4())
    
    try:
        results = []
        query_type = "unknown"
        
        # Search by flow ID (similarity search)
        if request.flow_id:
            query_type = "similarity"
            
            # Get the reference flow's embedding
            try:
                ref_doc = opensearch_client.get(
                    index="attack_flows",
                    id=request.flow_id
                )
                ref_embedding = ref_doc["_source"].get("embedding")
                
                if not ref_embedding:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail={
                            "error": "FlowNotIndexed",
                            "message": f"Flow {request.flow_id} has no embedding",
                            "trace_id": trace_id
                        }
                    )
                
                # Search for similar flows
                search_body = {
                    "size": request.top_k,
                    "query": {
                        "script_score": {
                            "query": {"match_all": {}},
                            "script": {
                                "source": "cosineSimilarity(params.query_vector, 'embedding') + 1.0",
                                "params": {"query_vector": ref_embedding}
                            }
                        }
                    },
                    "_source": ["flow_id", "name", "description", "action_count", "techniques"]
                }
                
                search_result = opensearch_client.search(
                    index="attack_flows",
                    body=search_body
                )
                
                for hit in search_result["hits"]["hits"]:
                    if hit["_id"] != request.flow_id:  # Exclude self
                        score = (hit["_score"] - 1.0)  # Adjust score back
                        if score >= request.min_score:
                            results.append(FlowSearchResult(
                                flow_id=hit["_id"],
                                name=hit["_source"].get("name", "Unnamed"),
                                description=hit["_source"].get("description", ""),
                                similarity_score=score,
                                action_count=hit["_source"].get("action_count", 0),
                                techniques=hit["_source"].get("techniques", [])
                            ))
                            
            except Exception as e:
                if "404" in str(e):
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail={
                            "error": "FlowNotFound",
                            "message": f"Flow {request.flow_id} not found",
                            "trace_id": trace_id
                        }
                    )
                raise
        
        # Search by text description
        elif request.text:
            query_type = "text"
            
            # Use text embedding search
            search_body = {
                "size": request.top_k,
                "query": {
                    "multi_match": {
                        "query": request.text,
                        "fields": ["name^2", "description", "techniques"]
                    }
                },
                "_source": ["flow_id", "name", "description", "action_count", "techniques"]
            }
            
            search_result = opensearch_client.search(
                index="attack_flows",
                body=search_body
            )
            
            max_score = search_result["hits"]["max_score"] or 1.0
            for hit in search_result["hits"]["hits"]:
                normalized_score = hit["_score"] / max_score
                if normalized_score >= request.min_score:
                    results.append(FlowSearchResult(
                        flow_id=hit["_id"],
                        name=hit["_source"].get("name", "Unnamed"),
                        description=hit["_source"].get("description", ""),
                        similarity_score=normalized_score,
                        action_count=hit["_source"].get("action_count", 0),
                        techniques=hit["_source"].get("techniques", [])
                    ))
        
        # Search by techniques
        elif request.techniques:
            query_type = "techniques"
            
            # Query Neo4j for flows containing these techniques
            query = """
                MATCH (e:AttackEpisode)-[:CONTAINS]->(a:AttackAction)
                WHERE a.technique_id IN $techniques
                WITH e, count(DISTINCT a.technique_id) as match_count,
                     collect(DISTINCT a.technique_id) as matched_techniques
                WHERE match_count > 0
                MATCH (e)-[:CONTAINS]->(all_actions:AttackAction)
                RETURN e.flow_id as flow_id,
                       e.name as name,
                       e.description as description,
                       match_count,
                       matched_techniques,
                       count(all_actions) as action_count,
                       collect(DISTINCT all_actions.technique_id) as all_techniques
                ORDER BY match_count DESC
                LIMIT $limit
            """
            
            result = neo4j_session.run(
                query,
                techniques=request.techniques,
                limit=request.top_k
            )
            
            for record in result:
                # Calculate similarity as ratio of matched techniques
                similarity = record["match_count"] / len(request.techniques)
                if similarity >= request.min_score:
                    results.append(FlowSearchResult(
                        flow_id=record["flow_id"],
                        name=record["name"] or "Unnamed",
                        description=record["description"] or "",
                        similarity_score=similarity,
                        action_count=record["action_count"],
                        techniques=record["all_techniques"]
                    ))
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "InvalidRequest",
                    "message": "Must provide flow_id, text, or techniques",
                    "trace_id": trace_id
                }
            )
        
        return FlowSearchResponse(
            results=results,
            query_type=query_type,
            total_results=len(results)
        )
        
    except HTTPException:
        raise
    except ConnectionError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "error": "SearchBackendUnavailable",
                "message": f"Backend connection failed: {str(e)}",
                "trace_id": trace_id
            }
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "SearchError",
                "message": f"Search operation failed: {str(e)}",
                "trace_id": trace_id
            }
        )