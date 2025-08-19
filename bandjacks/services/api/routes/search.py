"""Search endpoints for text-to-technique (TTX) queries."""

from fastapi import APIRouter, HTTPException, status
from bandjacks.services.api.schemas import TtxQuery, TtxSearchResponse, ErrorResponse
from bandjacks.services.api.settings import settings
from bandjacks.loaders.search_nodes import ttx_search_kb
import uuid

router = APIRouter(tags=["search"])


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