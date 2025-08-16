"""Search endpoints for text-to-technique (TTX) queries."""

from fastapi import APIRouter, HTTPException
from bandjacks.services.api.schemas import TtxQuery
from bandjacks.services.api.settings import settings
from bandjacks.loaders.search_nodes import ttx_search_kb

router = APIRouter(tags=["search"])


@router.post("/search/ttx")
async def search_ttx(q: TtxQuery):
    """Search for ATT&CK techniques/entities similar to input text with optional kb_type filtering."""
    try:
        results = ttx_search_kb(
            os_url=settings.opensearch_url,
            index=settings.os_index_nodes,
            text=q.text,
            top_k=q.top_k,
            kb_types=q.kb_types
        )
        return {"results": results}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Search failed: {e}")