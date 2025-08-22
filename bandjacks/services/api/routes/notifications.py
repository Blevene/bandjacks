"""Notification management and history API endpoints."""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from bandjacks.services.notification_service import get_notification_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/notifications", tags=["notifications"])


class NotificationHistoryResponse(BaseModel):
    """Notification history response."""
    total: int
    filtered: int
    notifications: List[Dict[str, Any]]


@router.get("/history", response_model=NotificationHistoryResponse)
async def get_notification_history(
    limit: int = Query(100, ge=1, le=1000, description="Maximum notifications to return"),
    notification_type: Optional[str] = Query(None, description="Filter by notification type"),
    hours_ago: Optional[int] = Query(None, ge=1, le=168, description="Only show notifications from last N hours")
) -> NotificationHistoryResponse:
    """
    Get notification history for debugging and monitoring.
    
    Shows what notifications would have been sent (stub implementation logs only).
    """
    service = get_notification_service()
    
    # Calculate since time if hours specified
    since = None
    if hours_ago:
        since = datetime.utcnow() - timedelta(hours=hours_ago)
    
    # Get history
    history = service.get_notification_history(
        limit=limit,
        notification_type=notification_type,
        since=since
    )
    
    # Get total count
    all_history = service.get_notification_history()
    
    return NotificationHistoryResponse(
        total=len(all_history),
        filtered=len(history),
        notifications=history
    )


@router.post("/clear-history")
async def clear_notification_history() -> Dict[str, Any]:
    """
    Clear notification history.
    
    Admin operation to clear accumulated notification history.
    """
    service = get_notification_service()
    service.clear_notification_history()
    
    return {
        "status": "success",
        "message": "Notification history cleared"
    }


@router.get("/config")
async def get_notification_config() -> Dict[str, Any]:
    """
    Get current notification configuration.
    
    Shows configured reviewers and channels (without sensitive data).
    """
    service = get_notification_service()
    
    # Sanitize config for display
    config = {
        "reviewers": {},
        "channels_configured": []
    }
    
    # Show reviewer info without sensitive data
    for reviewer_id, reviewer_config in service.reviewers.items():
        config["reviewers"][reviewer_id] = {
            "active": reviewer_config.get("active", False),
            "channel": reviewer_config.get("channel", "log"),
            "daily_summary": reviewer_config.get("daily_summary", False),
            "receive_alerts": reviewer_config.get("receive_alerts", True)
        }
    
    # Show which channels are configured
    if service.smtp_config:
        config["channels_configured"].append("email")
    if service.webhook_config:
        config["channels_configured"].append("webhook")
    if service.slack_config:
        config["channels_configured"].append("slack")
    config["channels_configured"].append("log")  # Always available
    
    return config


@router.post("/test")
async def send_test_notification(
    channel: str = Query("log", description="Channel to test"),
    reviewer_id: str = Query("test", description="Reviewer ID to notify")
) -> Dict[str, Any]:
    """
    Send a test notification.
    
    Useful for testing notification configuration.
    """
    service = get_notification_service()
    
    # Create test notification
    result = await service.notify_threshold_alert(
        metric_name="test_metric",
        current_value=0.75,
        threshold=0.70,
        direction="above"
    )
    
    return {
        "status": "sent",
        "result": result,
        "message": f"Test notification sent via {channel} channel"
    }