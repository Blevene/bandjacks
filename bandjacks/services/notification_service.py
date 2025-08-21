"""Notification service for reviewer alerts."""

import logging
import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum
import httpx
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


class NotificationType(Enum):
    """Types of notifications."""
    REVIEW_NEEDED = "review_needed"
    REVIEW_COMPLETED = "review_completed"
    HIGH_PRIORITY = "high_priority"
    DAILY_SUMMARY = "daily_summary"
    THRESHOLD_ALERT = "threshold_alert"


class NotificationChannel(Enum):
    """Notification delivery channels."""
    EMAIL = "email"
    WEBHOOK = "webhook"
    SLACK = "slack"
    LOG = "log"  # For testing


class NotificationService:
    """Service for sending notifications to reviewers."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize notification service.
        
        Args:
            config: Notification configuration
        """
        self.config = config or {}
        self.smtp_config = self.config.get("smtp", {})
        self.webhook_config = self.config.get("webhooks", {})
        self.slack_config = self.config.get("slack", {})
        self.reviewers = self.config.get("reviewers", {})
        
        # Default to log channel if not configured
        self.default_channel = NotificationChannel.LOG
    
    async def notify_review_needed(
        self,
        job_id: str,
        item_count: int,
        high_priority_count: int = 0,
        item_types: List[str] = None
    ) -> Dict[str, Any]:
        """
        Notify reviewers that new items need review.
        
        Args:
            job_id: AL sampling job ID
            item_count: Total items needing review
            high_priority_count: Number of high priority items
            item_types: Types of items needing review
            
        Returns:
            Notification result
        """
        notification = {
            "type": NotificationType.REVIEW_NEEDED,
            "job_id": job_id,
            "item_count": item_count,
            "high_priority_count": high_priority_count,
            "item_types": item_types or [],
            "timestamp": datetime.utcnow().isoformat(),
            "message": self._format_review_needed_message(
                item_count, high_priority_count, item_types
            )
        }
        
        # Send to all configured reviewers
        results = []
        for reviewer_id, reviewer_config in self.reviewers.items():
            if reviewer_config.get("active", True):
                channel = NotificationChannel(
                    reviewer_config.get("channel", self.default_channel.value)
                )
                result = await self._send_notification(
                    channel,
                    reviewer_config,
                    notification
                )
                results.append({
                    "reviewer": reviewer_id,
                    "channel": channel.value,
                    "success": result["success"]
                })
        
        return {
            "notification_id": f"notif-{job_id}",
            "sent_to": len(results),
            "results": results
        }
    
    async def notify_review_completed(
        self,
        reviewer_id: str,
        review_id: str,
        decision: str,
        item_type: str
    ) -> Dict[str, Any]:
        """
        Notify that a review has been completed.
        
        Args:
            reviewer_id: ID of the reviewer
            review_id: Review decision ID
            decision: Review decision (accept/edit/reject)
            item_type: Type of item reviewed
            
        Returns:
            Notification result
        """
        notification = {
            "type": NotificationType.REVIEW_COMPLETED,
            "reviewer_id": reviewer_id,
            "review_id": review_id,
            "decision": decision,
            "item_type": item_type,
            "timestamp": datetime.utcnow().isoformat(),
            "message": f"Review {review_id} completed: {decision} for {item_type}"
        }
        
        # Send to admin/supervisor if configured
        admin_config = self.reviewers.get("admin", {})
        if admin_config.get("active", False):
            channel = NotificationChannel(
                admin_config.get("channel", self.default_channel.value)
            )
            result = await self._send_notification(
                channel,
                admin_config,
                notification
            )
            return result
        
        # Just log if no admin configured
        logger.info(f"Review completed: {notification}")
        return {"success": True, "channel": "log"}
    
    async def notify_threshold_alert(
        self,
        metric_name: str,
        current_value: float,
        threshold: float,
        direction: str = "above"
    ) -> Dict[str, Any]:
        """
        Notify when a metric crosses a threshold.
        
        Args:
            metric_name: Name of the metric
            current_value: Current metric value
            threshold: Threshold that was crossed
            direction: "above" or "below"
            
        Returns:
            Notification result
        """
        notification = {
            "type": NotificationType.THRESHOLD_ALERT,
            "metric_name": metric_name,
            "current_value": current_value,
            "threshold": threshold,
            "direction": direction,
            "timestamp": datetime.utcnow().isoformat(),
            "message": f"ALERT: {metric_name} is {direction} threshold: {current_value:.2f} ({direction} {threshold})"
        }
        
        # Send high priority notification
        results = []
        for reviewer_id, reviewer_config in self.reviewers.items():
            if reviewer_config.get("receive_alerts", True):
                channel = NotificationChannel(
                    reviewer_config.get("alert_channel", reviewer_config.get("channel", self.default_channel.value))
                )
                result = await self._send_notification(
                    channel,
                    reviewer_config,
                    notification,
                    priority="high"
                )
                results.append({
                    "reviewer": reviewer_id,
                    "channel": channel.value,
                    "success": result["success"]
                })
        
        return {
            "alert_id": f"alert-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "sent_to": len(results),
            "results": results
        }
    
    async def send_daily_summary(self) -> Dict[str, Any]:
        """
        Send daily summary to all reviewers.
        
        Returns:
            Summary result
        """
        # This would gather metrics from the database
        summary = {
            "type": NotificationType.DAILY_SUMMARY,
            "date": datetime.utcnow().date().isoformat(),
            "timestamp": datetime.utcnow().isoformat(),
            "message": "Daily review summary",
            "stats": {
                "items_reviewed": 0,  # Would query from DB
                "items_pending": 0,   # Would query from DB
                "avg_confidence": 0,  # Would query from DB
            }
        }
        
        results = []
        for reviewer_id, reviewer_config in self.reviewers.items():
            if reviewer_config.get("daily_summary", False):
                channel = NotificationChannel(
                    reviewer_config.get("channel", self.default_channel.value)
                )
                result = await self._send_notification(
                    channel,
                    reviewer_config,
                    summary
                )
                results.append({
                    "reviewer": reviewer_id,
                    "channel": channel.value,
                    "success": result["success"]
                })
        
        return {
            "summary_id": f"summary-{datetime.utcnow().date().isoformat()}",
            "sent_to": len(results),
            "results": results
        }
    
    async def _send_notification(
        self,
        channel: NotificationChannel,
        config: Dict[str, Any],
        notification: Dict[str, Any],
        priority: str = "normal"
    ) -> Dict[str, Any]:
        """
        Send notification via specified channel.
        
        Args:
            channel: Delivery channel
            config: Channel configuration
            notification: Notification content
            priority: Notification priority
            
        Returns:
            Send result
        """
        try:
            if channel == NotificationChannel.EMAIL:
                return await self._send_email(config, notification, priority)
            elif channel == NotificationChannel.WEBHOOK:
                return await self._send_webhook(config, notification, priority)
            elif channel == NotificationChannel.SLACK:
                return await self._send_slack(config, notification, priority)
            else:  # LOG channel
                return self._log_notification(notification, priority)
        except Exception as e:
            logger.error(f"Failed to send notification via {channel.value}: {e}")
            return {"success": False, "channel": channel.value, "error": str(e)}
    
    async def _send_email(
        self,
        config: Dict[str, Any],
        notification: Dict[str, Any],
        priority: str
    ) -> Dict[str, Any]:
        """Send email notification."""
        if not self.smtp_config:
            return {"success": False, "channel": "email", "error": "SMTP not configured"}
        
        try:
            msg = MIMEMultipart()
            msg["From"] = self.smtp_config.get("from_address", "noreply@bandjacks.io")
            msg["To"] = config.get("email")
            msg["Subject"] = f"[Bandjacks] {notification['type'].value.replace('_', ' ').title()}"
            
            if priority == "high":
                msg["X-Priority"] = "1"
            
            body = notification["message"]
            if "stats" in notification:
                body += "\n\nStatistics:\n"
                for key, value in notification["stats"].items():
                    body += f"  {key}: {value}\n"
            
            msg.attach(MIMEText(body, "plain"))
            
            # Would use actual SMTP here
            logger.info(f"Would send email to {config.get('email')}: {msg['Subject']}")
            return {"success": True, "channel": "email"}
            
        except Exception as e:
            return {"success": False, "channel": "email", "error": str(e)}
    
    async def _send_webhook(
        self,
        config: Dict[str, Any],
        notification: Dict[str, Any],
        priority: str
    ) -> Dict[str, Any]:
        """Send webhook notification."""
        webhook_url = config.get("webhook_url")
        if not webhook_url:
            return {"success": False, "channel": "webhook", "error": "Webhook URL not configured"}
        
        try:
            async with httpx.AsyncClient() as client:
                headers = {"Content-Type": "application/json"}
                if priority == "high":
                    headers["X-Priority"] = "high"
                
                response = await client.post(
                    webhook_url,
                    json=notification,
                    headers=headers,
                    timeout=10.0
                )
                
                return {
                    "success": response.status_code < 300,
                    "channel": "webhook",
                    "status_code": response.status_code
                }
        except Exception as e:
            return {"success": False, "channel": "webhook", "error": str(e)}
    
    async def _send_slack(
        self,
        config: Dict[str, Any],
        notification: Dict[str, Any],
        priority: str
    ) -> Dict[str, Any]:
        """Send Slack notification."""
        slack_webhook = config.get("slack_webhook") or self.slack_config.get("webhook_url")
        if not slack_webhook:
            return {"success": False, "channel": "slack", "error": "Slack webhook not configured"}
        
        try:
            # Format for Slack
            slack_message = {
                "text": notification["message"],
                "attachments": []
            }
            
            if priority == "high":
                slack_message["attachments"].append({
                    "color": "danger",
                    "title": "High Priority",
                    "text": notification.get("message", "")
                })
            
            if "stats" in notification:
                fields = []
                for key, value in notification["stats"].items():
                    fields.append({
                        "title": key.replace("_", " ").title(),
                        "value": str(value),
                        "short": True
                    })
                slack_message["attachments"].append({
                    "color": "good",
                    "fields": fields
                })
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    slack_webhook,
                    json=slack_message,
                    timeout=10.0
                )
                
                return {
                    "success": response.status_code == 200,
                    "channel": "slack",
                    "status_code": response.status_code
                }
        except Exception as e:
            return {"success": False, "channel": "slack", "error": str(e)}
    
    def _log_notification(
        self,
        notification: Dict[str, Any],
        priority: str
    ) -> Dict[str, Any]:
        """Log notification (for testing/fallback)."""
        log_level = logging.WARNING if priority == "high" else logging.INFO
        logger.log(
            log_level,
            f"Notification [{notification['type'].value}]: {notification['message']}",
            extra={"notification": notification}
        )
        return {"success": True, "channel": "log"}
    
    def _format_review_needed_message(
        self,
        item_count: int,
        high_priority_count: int,
        item_types: List[str]
    ) -> str:
        """Format review needed message."""
        message = f"{item_count} new items need review"
        
        if high_priority_count > 0:
            message += f" ({high_priority_count} high priority)"
        
        if item_types:
            types_str = ", ".join(item_types)
            message += f"\nTypes: {types_str}"
        
        message += f"\n\nPlease visit the review queue to process these items."
        
        return message


# Singleton instance
_notification_service = None


def get_notification_service(config: Optional[Dict[str, Any]] = None) -> NotificationService:
    """Get or create notification service singleton."""
    global _notification_service
    if _notification_service is None:
        _notification_service = NotificationService(config)
    return _notification_service