"""Entity ignorelist management endpoints."""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
import logging

from bandjacks.llm.entity_ignorelist import get_entity_ignorelist

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ignorelist", tags=["ignorelist"])


class AddToIgnorelistRequest(BaseModel):
    """Request to add entity to ignorelist."""
    entity_name: str
    metadata: Optional[Dict[str, Any]] = None


class RemoveFromIgnorelistRequest(BaseModel):
    """Request to remove entity from ignorelist."""
    entity_name: str


class IgnorelistResponse(BaseModel):
    """Response for ignorelist operations."""
    success: bool
    message: str


class IgnorelistStatusResponse(BaseModel):
    """Response with current ignorelist status."""
    user_added: List[Dict[str, Any]]
    total_entries: int


@router.get(
    "/",
    response_model=IgnorelistStatusResponse,
    summary="Get Ignorelist Status",
    description="Get current entity ignorelist with user-added entries."
)
async def get_ignorelist():
    """Get current ignorelist status."""
    try:
        ignorelist = get_entity_ignorelist()
        user_additions = ignorelist.get_user_additions()

        # Count total entries
        total = (
            len(ignorelist.vendors) +
            len(ignorelist.file_extensions) +
            len(ignorelist.generic_terms) +
            len(ignorelist.code_constructs) +
            len(ignorelist.patterns) +
            len(ignorelist.user_added)
        )

        return IgnorelistStatusResponse(
            user_added=user_additions,
            total_entries=total
        )
    except Exception as e:
        logger.error(f"Failed to get ignorelist: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve ignorelist"
        )


@router.post(
    "/add",
    response_model=IgnorelistResponse,
    summary="Add to Ignorelist",
    description="Add an entity to the ignorelist."
)
async def add_to_ignorelist(request: AddToIgnorelistRequest):
    """Add entity to ignorelist."""
    try:
        ignorelist = get_entity_ignorelist()

        if ignorelist.add_to_ignorelist(request.entity_name, request.metadata):
            logger.info(f"Added '{request.entity_name}' to ignorelist via API")
            return IgnorelistResponse(
                success=True,
                message=f"Successfully added '{request.entity_name}' to ignorelist"
            )
        else:
            return IgnorelistResponse(
                success=False,
                message=f"Failed to add '{request.entity_name}' to ignorelist"
            )
    except Exception as e:
        logger.error(f"Failed to add to ignorelist: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add entity to ignorelist: {str(e)}"
        )


@router.delete(
    "/remove",
    response_model=IgnorelistResponse,
    summary="Remove from Ignorelist",
    description="Remove an entity from the ignorelist."
)
async def remove_from_ignorelist(request: RemoveFromIgnorelistRequest):
    """Remove entity from ignorelist."""
    try:
        ignorelist = get_entity_ignorelist()

        if ignorelist.remove_from_ignorelist(request.entity_name):
            logger.info(f"Removed '{request.entity_name}' from ignorelist via API")
            return IgnorelistResponse(
                success=True,
                message=f"Successfully removed '{request.entity_name}' from ignorelist"
            )
        else:
            return IgnorelistResponse(
                success=False,
                message=f"'{request.entity_name}' not found in ignorelist"
            )
    except Exception as e:
        logger.error(f"Failed to remove from ignorelist: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to remove entity from ignorelist: {str(e)}"
        )


@router.post(
    "/reload",
    response_model=IgnorelistResponse,
    summary="Reload Ignorelist",
    description="Reload the ignorelist from disk."
)
async def reload_ignorelist():
    """Reload ignorelist from disk."""
    try:
        ignorelist = get_entity_ignorelist()
        ignorelist.reload()

        return IgnorelistResponse(
            success=True,
            message="Ignorelist reloaded successfully"
        )
    except Exception as e:
        logger.error(f"Failed to reload ignorelist: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reload ignorelist"
        )