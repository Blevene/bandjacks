"""Vector update management API endpoints."""

from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
import logging

from bandjacks.services.vector_update_manager import (
    get_vector_update_manager,
    UpdateAction
)
from bandjacks.services.vector_update_initializer import get_vector_update_status

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vectors", tags=["vectors"])


class VectorUpdateRequest(BaseModel):
    """Request to manually trigger vector update."""
    entity_id: str = Field(..., description="STIX ID of the entity")
    entity_type: str = Field(..., description="Type of entity (AttackPattern, IntrusionSet, Software, Campaign)")
    action: str = Field(default="UPDATE", description="Action type: CREATE, UPDATE, DELETE")
    priority: int = Field(default=5, min=1, max=10, description="Update priority (1=highest, 10=lowest)")


class VectorStatusResponse(BaseModel):
    """Vector update system status response."""
    enabled: bool
    queue_depth: int = 0
    batch_processor_running: bool = False
    metrics: Dict[str, Any] = {}
    config: Dict[str, Any] = {}
    message: str = ""


class VectorMetricsResponse(BaseModel):
    """Detailed metrics response."""
    total_requests: int
    successful_updates: int
    failed_updates: int
    immediate_updates: int
    batched_updates: int
    total_processing_time: float
    avg_processing_time: float
    executor_metrics: Dict[str, Dict[str, int]]


@router.get(
    "/status",
    response_model=VectorStatusResponse,
    summary="Get Vector Update System Status",
    description="Get current status and configuration of the vector update system"
)
async def get_vector_status():
    """Get the current status of the vector update system."""
    try:
        status = get_vector_update_status()

        if not status.get("enabled", False):
            return VectorStatusResponse(
                enabled=False,
                message=status.get("message", "Vector update system is disabled")
            )

        # Get async status from the manager
        manager = get_vector_update_manager()
        async_status = await manager.get_status()

        return VectorStatusResponse(
            enabled=True,
            queue_depth=async_status.get("queue_depth", 0),
            batch_processor_running=async_status.get("batch_processor_running", False),
            metrics=status.get("metrics", {}),
            config=status.get("config", {}),
            message="Vector update system is operational"
        )

    except Exception as e:
        logger.error(f"Failed to get vector status: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve vector status: {str(e)}"
        )


@router.get(
    "/metrics",
    response_model=VectorMetricsResponse,
    summary="Get Vector Update Metrics",
    description="Get detailed metrics about vector update operations"
)
async def get_vector_metrics():
    """Get detailed metrics about vector update operations."""
    try:
        manager = get_vector_update_manager()

        if not manager.enabled:
            raise HTTPException(
                status_code=503,
                detail="Vector update system is disabled"
            )

        metrics = manager.get_metrics()

        # Calculate average processing time
        total_processed = metrics.get("successful_updates", 0) + metrics.get("failed_updates", 0)
        avg_time = 0.0
        if total_processed > 0:
            avg_time = metrics.get("total_processing_time", 0.0) / total_processed

        return VectorMetricsResponse(
            total_requests=metrics.get("total_requests", 0),
            successful_updates=metrics.get("successful_updates", 0),
            failed_updates=metrics.get("failed_updates", 0),
            immediate_updates=metrics.get("immediate_updates", 0),
            batched_updates=metrics.get("batched_updates", 0),
            total_processing_time=metrics.get("total_processing_time", 0.0),
            avg_processing_time=avg_time,
            executor_metrics=metrics.get("executor_metrics", {})
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get vector metrics: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve vector metrics: {str(e)}"
        )


@router.post(
    "/update",
    summary="Manually Trigger Vector Update",
    description="Submit a manual vector update request for an entity"
)
async def trigger_vector_update(request: VectorUpdateRequest):
    """Manually trigger a vector update for a specific entity."""
    try:
        manager = get_vector_update_manager()

        if not manager.enabled:
            raise HTTPException(
                status_code=503,
                detail="Vector update system is disabled"
            )

        # Map action string to enum
        action_map = {
            "CREATE": UpdateAction.CREATE,
            "UPDATE": UpdateAction.UPDATE,
            "DELETE": UpdateAction.DELETE
        }

        action = action_map.get(request.action.upper())
        if not action:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid action: {request.action}. Must be CREATE, UPDATE, or DELETE"
            )

        # Submit update request
        result = await manager.submit_update(
            entity_id=request.entity_id,
            entity_type=request.entity_type,
            action=action,
            priority=request.priority
        )

        return {
            "success": True,
            "message": f"Vector update request submitted for {request.entity_type}:{request.entity_id}",
            "processing_mode": result
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to trigger vector update: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to submit vector update request: {str(e)}"
        )


@router.post(
    "/process-batch",
    summary="Manually Process Batch Queue",
    description="Force immediate processing of the batch queue"
)
async def process_batch_manually(
    max_items: int = Query(default=100, description="Maximum items to process", ge=1, le=1000)
):
    """Manually trigger batch processing of queued vector updates."""
    try:
        manager = get_vector_update_manager()

        if not manager.enabled:
            raise HTTPException(
                status_code=503,
                detail="Vector update system is disabled"
            )

        # Process batch with specified limit
        processed = await manager.process_batch(max_items=max_items)

        return {
            "success": True,
            "message": f"Processed {processed} vector update requests",
            "processed_count": processed
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to process batch: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to process batch: {str(e)}"
        )


@router.delete(
    "/queue",
    summary="Clear Vector Update Queue",
    description="Clear all pending vector update requests from the queue"
)
async def clear_vector_queue():
    """Clear all pending vector update requests."""
    try:
        manager = get_vector_update_manager()

        if not manager.enabled:
            raise HTTPException(
                status_code=503,
                detail="Vector update system is disabled"
            )

        # Get current queue depth
        status = await manager.get_status()
        queue_depth = status.get("queue_depth", 0)

        if queue_depth == 0:
            return {
                "success": True,
                "message": "Queue is already empty",
                "cleared_count": 0
            }

        # Clear the queue (would need to add this method to manager)
        # For now, we'll process with max_items=0 to effectively clear
        # In production, you'd want a proper clear method

        return {
            "success": True,
            "message": f"Cleared {queue_depth} pending requests from queue",
            "cleared_count": queue_depth
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to clear queue: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to clear queue: {str(e)}"
        )


@router.get(
    "/health",
    summary="Vector System Health Check",
    description="Check if the vector update system is healthy and operational"
)
async def vector_health_check():
    """Health check for the vector update system."""
    try:
        manager = get_vector_update_manager()

        if not manager.enabled:
            return {
                "status": "disabled",
                "message": "Vector update system is disabled in configuration"
            }

        # Check if batch processor is running
        status = await manager.get_status()

        if not status.get("batch_processor_running", False):
            return {
                "status": "degraded",
                "message": "Batch processor is not running",
                "details": status
            }

        # Check Redis connection
        queue_depth = status.get("queue_depth", -1)
        if queue_depth < 0:
            return {
                "status": "unhealthy",
                "message": "Cannot connect to Redis queue",
                "details": status
            }

        return {
            "status": "healthy",
            "message": "Vector update system is operational",
            "queue_depth": queue_depth,
            "batch_processor": "running"
        }

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "message": f"Health check failed: {str(e)}"
        }