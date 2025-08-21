"""Drift detection and monitoring endpoints."""

from fastapi import APIRouter, HTTPException, Request, Query
from typing import List, Optional
from bandjacks.services.api.settings import settings
from bandjacks.services.api.schemas import DriftStatus, DriftAlert, DriftMetric
from bandjacks.monitoring.drift_detector import DriftDetector, DriftThresholds
from datetime import datetime

router = APIRouter(prefix="/drift", tags=["drift"])

# Store alerts in memory (in production, use persistent storage)
_drift_alerts: List[DriftAlert] = []


@router.get("/status",
    response_model=DriftStatus,
    summary="Get Current Drift Status",
    description="""
    Analyze and return the current drift status across all monitored metrics.
    
    Checks for drift in:
    - **Version consistency**: Multiple ATT&CK versions in use
    - **Confidence scores**: Degradation in extraction/mapping confidence
    - **Quality scores**: Decline in user feedback quality ratings
    - **Schema consistency**: Deviations from expected data schema
    
    Returns overall status and detailed metrics for each category.
    """
)
async def get_drift_status(request: Request) -> DriftStatus:
    """Get current drift status across all metrics."""
    try:
        detector = DriftDetector(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        status = detector.get_drift_status()
        
        # Store alerts globally
        global _drift_alerts
        _drift_alerts.extend(detector.alerts)
        
        # Add trace ID
        status.trace_id = getattr(request.state, 'trace_id', None)
        
        detector.close()
        
        return status
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Drift analysis failed: {str(e)}")


@router.post("/analyze",
    response_model=DriftStatus,
    summary="Run Drift Analysis",
    description="""
    Trigger a comprehensive drift analysis with custom thresholds.
    
    This endpoint allows you to run drift detection with specific threshold values
    to identify potential issues in your system.
    """
)
async def analyze_drift(
    request: Request,
    confidence_threshold: float = Query(0.15, ge=0, le=1, description="Threshold for confidence score drift"),
    quality_threshold: float = Query(0.2, ge=0, le=1, description="Threshold for quality score drift"),
    schema_threshold: float = Query(0.1, ge=0, le=1, description="Threshold for schema consistency drift"),
    days_back: int = Query(30, ge=7, le=90, description="Days to look back for baseline")
) -> DriftStatus:
    """Run drift analysis with custom thresholds."""
    try:
        thresholds = DriftThresholds(
            confidence_drop=confidence_threshold,
            quality_drop=quality_threshold,
            schema_change=schema_threshold
        )
        
        detector = DriftDetector(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password,
            thresholds=thresholds
        )
        
        # Run analysis with custom parameters
        status = detector.get_drift_status()
        
        # Store new alerts
        global _drift_alerts
        _drift_alerts.extend(detector.alerts)
        
        # Add trace ID
        status.trace_id = getattr(request.state, 'trace_id', None)
        
        detector.close()
        
        return status
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Drift analysis failed: {str(e)}")


@router.get("/alerts",
    response_model=List[DriftAlert],
    summary="Get Drift Alerts",
    description="""
    Retrieve active drift alerts.
    
    Returns all unacknowledged drift alerts sorted by severity and creation time.
    Use the acknowledge endpoint to mark alerts as reviewed.
    """
)
async def get_drift_alerts(
    acknowledged: Optional[bool] = Query(None, description="Filter by acknowledgment status"),
    severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of alerts to return")
) -> List[DriftAlert]:
    """Get active drift alerts."""
    global _drift_alerts
    
    # Filter alerts
    alerts = _drift_alerts
    
    if acknowledged is not None:
        alerts = [a for a in alerts if a.acknowledged == acknowledged]
    
    if severity:
        alerts = [a for a in alerts if a.severity == severity]
    
    # Sort by severity (critical first) and creation time
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: (severity_order.get(a.severity, 999), a.created_at), reverse=True)
    
    return alerts[:limit]


@router.post("/alerts/{alert_id}/acknowledge",
    summary="Acknowledge Drift Alert",
    description="""
    Mark a drift alert as acknowledged.
    
    Acknowledged alerts remain in the system for audit purposes but are
    typically filtered out from active alert displays.
    """
)
async def acknowledge_alert(alert_id: str) -> dict:
    """Acknowledge a drift alert."""
    global _drift_alerts
    
    for alert in _drift_alerts:
        if alert.alert_id == alert_id:
            alert.acknowledged = True
            return {
                "status": "success",
                "message": f"Alert {alert_id} acknowledged",
                "alert": alert
            }
    
    raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")


@router.delete("/alerts",
    summary="Clear Drift Alerts",
    description="""
    Clear drift alerts from memory.
    
    Use with caution - this removes alert history.
    In production, alerts should be archived rather than deleted.
    """
)
async def clear_alerts(
    acknowledged_only: bool = Query(True, description="Only clear acknowledged alerts")
) -> dict:
    """Clear drift alerts."""
    global _drift_alerts
    
    if acknowledged_only:
        original_count = len(_drift_alerts)
        _drift_alerts = [a for a in _drift_alerts if not a.acknowledged]
        cleared = original_count - len(_drift_alerts)
    else:
        cleared = len(_drift_alerts)
        _drift_alerts = []
    
    return {
        "status": "success",
        "cleared": cleared,
        "remaining": len(_drift_alerts)
    }


@router.get("/metrics/{metric_name}",
    response_model=DriftMetric,
    summary="Get Specific Drift Metric",
    description="""
    Get detailed information about a specific drift metric.
    
    Available metrics:
    - `version`: Version consistency across ATT&CK data
    - `confidence`: Confidence score trends
    - `quality`: Quality feedback score trends
    - `schema`: Schema consistency across node types
    """
)
async def get_drift_metric(
    metric_name: str,
    days_back: int = Query(30, ge=7, le=90, description="Days to look back for baseline")
) -> DriftMetric:
    """Get a specific drift metric."""
    if metric_name not in ["version", "confidence", "quality", "schema"]:
        raise HTTPException(status_code=400, detail=f"Unknown metric: {metric_name}")
    
    try:
        detector = DriftDetector(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        if metric_name == "version":
            metric = detector.analyze_version_drift()
        elif metric_name == "confidence":
            metric = detector.analyze_confidence_drift(days_back=days_back)
        elif metric_name == "quality":
            metric = detector.analyze_quality_drift(days_back=days_back)
        elif metric_name == "schema":
            metric = detector.analyze_schema_drift()
        else:
            raise ValueError(f"Unsupported metric: {metric_name}")
        
        detector.close()
        
        return metric
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Metric analysis failed: {str(e)}")