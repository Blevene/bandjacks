"""Natural language query endpoints for hybrid search."""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from bandjacks.services.api.deps import get_neo4j_session, get_opensearch_client
from bandjacks.services.api.settings import settings
from bandjacks.loaders.hybrid_search import HybridSearcher
import json


router = APIRouter(prefix="/query", tags=["query"])


class QueryRequest(BaseModel):
    """Natural language query request."""
    query: str = Field(..., description="Natural language query text")
    top_k: int = Field(20, ge=1, le=100, description="Number of results to return")
    filters: Optional[Dict[str, Any]] = Field(None, description="Optional filters")
    include_context: bool = Field(True, description="Include graph context")
    fusion_weights: Optional[Dict[str, float]] = Field(
        None,
        description="Weights for fusion (vector, graph)"
    )


class QueryResult(BaseModel):
    """Query result with metadata."""
    stix_id: str
    type: str
    name: str
    preview: str
    fusion_score: float
    fusion_rank: int
    source: str
    graph_context: Optional[Dict[str, Any]] = None


class QueryResponse(BaseModel):
    """Query response with results and metadata."""
    query: str
    expanded_query: Optional[str] = None
    result_count: int
    results: List[QueryResult]
    filters_applied: Optional[Dict[str, Any]] = None


@router.post("/search", 
    response_model=QueryResponse,
    summary="Natural Language Search",
    description="""
    Perform natural language search for cyber threat intelligence.
    
    This endpoint implements hybrid search combining:
    - **Vector similarity search** in OpenSearch for semantic matching
    - **Graph pattern matching** in Neo4j for structural relationships
    - **Reciprocal rank fusion** to combine and rank results
    - **Graph context enrichment** with neighboring nodes
    
    The search automatically expands queries with synonyms and related terms
    for improved recall.
    """,
    responses={
        200: {"description": "Successful search with ranked results"},
        400: {"description": "Invalid query parameters"},
        500: {"description": "Internal server error"}
    }
)
async def natural_language_query(
    request: QueryRequest,
    neo4j_session=Depends(get_neo4j_session),
    opensearch_client=Depends(get_opensearch_client)
) -> QueryResponse:
    try:
        # Initialize hybrid searcher
        searcher = HybridSearcher(
            opensearch_url=settings.opensearch_url,
            opensearch_index=settings.os_index_nodes,
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Perform hybrid search
        results = searcher.search(
            query=request.query,
            top_k=request.top_k,
            filters=request.filters,
            include_graph_context=request.include_context,
            fusion_weights=request.fusion_weights
        )
        
        # Get expanded query for transparency
        expanded = searcher._expand_query(request.query)
        
        # Close connections
        searcher.close()
        
        # Format response
        return QueryResponse(
            query=request.query,
            expanded_query=expanded if expanded != request.query else None,
            result_count=len(results),
            results=[QueryResult(**r) for r in results],
            filters_applied=request.filters
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Query failed: {str(e)}")


class ExpansionRequest(BaseModel):
    """Query expansion request."""
    query: str = Field(..., description="Query to expand")


class ExpansionResponse(BaseModel):
    """Query expansion response."""
    original: str
    expanded: str
    suggestions: List[str]


@router.post("/expand",
    response_model=ExpansionResponse,
    summary="Query Expansion",
    description="Get query expansion with synonyms and related terms for improved search."
)
async def expand_query(request: ExpansionRequest) -> ExpansionResponse:
    """Expand query with synonyms and related terms."""
    from bandjacks.loaders.hybrid_search import HybridSearcher
    
    searcher = HybridSearcher(
        opensearch_url=settings.opensearch_url,
        opensearch_index=settings.os_index_nodes,
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=settings.neo4j_password
    )
    
    expanded = searcher._expand_query(request.query)
    searcher.close()
    
    # Generate suggestions
    suggestions = []
    if "lateral" in request.query.lower():
        suggestions.extend(["lateral movement", "pivoting", "remote services"])
    if "cred" in request.query.lower():
        suggestions.extend(["credential dumping", "credential access", "password attacks"])
    if "persist" in request.query.lower():
        suggestions.extend(["persistence", "backdoor", "maintain access"])
    
    return ExpansionResponse(
        original=request.query,
        expanded=expanded,
        suggestions=suggestions[:5]
    )


class SuggestRequest(BaseModel):
    """Query suggestion request."""
    partial_query: str = Field(..., min_length=2, description="Partial query text")
    max_suggestions: int = Field(10, ge=1, le=50, description="Maximum suggestions")


@router.post("/suggest",
    summary="Query Suggestions",
    description="Get autocomplete suggestions based on partial query input."
)
async def query_suggestions(
    request: SuggestRequest,
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    if len(request.partial_query) < 2:
        return {"suggestions": []}
    
    suggestions = []
    
    # Query Neo4j for matching entities
    query = """
        MATCH (n)
        WHERE (n:AttackPattern OR n:IntrusionSet OR n:Software)
          AND toLower(n.name) CONTAINS toLower($partial)
        RETURN DISTINCT n.name as suggestion, n.type as type
        ORDER BY size(n.name)
        LIMIT $limit
    """
    
    result = neo4j_session.run(
        query,
        partial=request.partial_query,
        limit=request.max_suggestions
    )
    
    for record in result:
        suggestions.append({
            "text": record["suggestion"],
            "type": record["type"]
        })
    
    # Add common query patterns
    common_patterns = [
        "groups using",
        "techniques for",
        "mitigations against",
        "software that",
        "vulnerabilities in"
    ]
    
    for pattern in common_patterns:
        if request.partial_query.lower() in pattern:
            suggestions.append({
                "text": pattern,
                "type": "pattern"
            })
    
    return {
        "suggestions": suggestions[:request.max_suggestions]
    }


@router.get("/history")
async def query_history(
    limit: int = 20,
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """
    Get recent query history.
    
    Returns recent queries with their results for analysis
    and quick re-execution.
    """
    # Query for recent queries (if stored)
    query = """
        MATCH (q:Query)
        RETURN q.id as id, q.text as query, q.timestamp as timestamp,
               q.result_count as result_count
        ORDER BY q.timestamp DESC
        LIMIT $limit
    """
    
    result = neo4j_session.run(query, limit=limit)
    
    history = []
    for record in result:
        history.append({
            "id": record["id"],
            "query": record["query"],
            "timestamp": record["timestamp"],
            "result_count": record["result_count"]
        })
    
    return {"history": history}


@router.post("/save")
async def save_query(
    query_text: str,
    results: List[str],
    metadata: Optional[Dict[str, Any]] = None,
    neo4j_session=Depends(get_neo4j_session)
) -> Dict[str, Any]:
    """
    Save a query and its results for future analysis.
    
    This helps build query patterns and improve search over time.
    """
    import uuid
    from datetime import datetime
    
    query_id = str(uuid.uuid4())
    
    # Save query to Neo4j
    cypher = """
        CREATE (q:Query {
            id: $id,
            text: $text,
            timestamp: datetime(),
            result_count: $result_count,
            results: $results,
            metadata: $metadata
        })
        RETURN q.id as id
    """
    
    result = neo4j_session.run(
        cypher,
        id=query_id,
        text=query_text,
        result_count=len(results),
        results=results,
        metadata=json.dumps(metadata) if metadata else None
    )
    
    record = result.single()
    
    return {
        "query_id": record["id"] if record else query_id,
        "saved": True
    }