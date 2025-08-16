"""Search endpoints for text-to-technique (TTX) queries."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from bandjacks.services.api.settings import settings
from bandjacks.loaders.search_nodes import ttx_search

router = APIRouter(tags=["search"])

class TtxQuery(BaseModel):
    """Text-to-technique search query."""
    text: str
    top_k: int = 10

@router.post("/search/ttx")
async def search_ttx(q: TtxQuery):
    """Search for ATT&CK techniques similar to input text."""
    try:
        return {"results": ttx_search(settings.opensearch_url, settings.os_index_nodes, q.text, q.top_k)}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Search failed: {e}")