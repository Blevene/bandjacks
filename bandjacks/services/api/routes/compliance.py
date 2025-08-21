"""Compliance metrics and reporting API endpoints."""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, Request, Query, status
from pydantic import BaseModel, Field

from bandjacks.monitoring.compliance_metrics import (
    ComplianceMetrics,
    get_compliance_metrics,
    get_compliance_report
)
from bandjacks.services.api.middleware.tracing import get_trace_id

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/compliance", tags=["compliance"])


class ComplianceMetricsResponse(BaseModel):
    """Compliance metrics response."""
    adm_violations: Dict[str, int]
    filtering_metrics: Dict[str, Any]
    review_metrics: Dict[str, Any]
    retrain_metrics: Dict[str, Any]
    detection_coverage: Dict[str, Any]
    trace_id: Optional[str] = Field(None, description="Request trace ID")


class ComplianceReportResponse(BaseModel):
    """Compliance report response."""
    timestamp: str
    overall_compliance_score: float
    categories: Dict[str, Dict[str, Any]]
    trends: Dict[str, Any]
    recommendations: List[str]
    trace_id: Optional[str] = Field(None, description="Request trace ID")


@router.get("/metrics",
    response_model=ComplianceMetricsResponse,
    summary="Get Compliance Metrics",
    description="""
    Get current compliance metrics including:
    - ADM validation violations
    - Filtering metrics
    - Review decision metrics
    - Retrain job metrics
    - Detection coverage metrics
    """
)
async def get_metrics(req: Request) -> ComplianceMetricsResponse:
    """Get current compliance metrics."""
    trace_id = get_trace_id()
    
    try:
        metrics = get_compliance_metrics()
        
        return ComplianceMetricsResponse(
            adm_violations=metrics.adm_violations,
            filtering_metrics=metrics.filtering_metrics,
            review_metrics=metrics.review_metrics,
            retrain_metrics=metrics.retrain_metrics,
            detection_coverage=metrics.detection_coverage,
            trace_id=trace_id
        )
    except Exception as e:
        logger.error(f"Failed to get compliance metrics: {e}", extra={"trace_id": trace_id})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve compliance metrics: {str(e)}"
        )


@router.get("/report",
    response_model=ComplianceReportResponse,
    summary="Get Compliance Report",
    description="""
    Get comprehensive compliance report with scores, trends, and recommendations.
    
    The report includes:
    - Overall compliance score
    - Category breakdowns (ADM, Review, Coverage)
    - Trend analysis
    - Actionable recommendations
    """
)
async def get_report(
    req: Request,
    include_trends: bool = Query(True, description="Include trend analysis"),
    include_recommendations: bool = Query(True, description="Include recommendations")
) -> ComplianceReportResponse:
    """Get comprehensive compliance report."""
    trace_id = get_trace_id()
    
    try:
        report = get_compliance_report()
        
        # Filter out trends if not requested
        if not include_trends:
            report["trends"] = {}
        
        # Filter out recommendations if not requested
        if not include_recommendations:
            report["recommendations"] = []
        
        return ComplianceReportResponse(
            timestamp=report["timestamp"],
            overall_compliance_score=report["overall_compliance_score"],
            categories=report["categories"],
            trends=report.get("trends", {}),
            recommendations=report.get("recommendations", []),
            trace_id=trace_id
        )
    except Exception as e:
        logger.error(f"Failed to generate compliance report: {e}", extra={"trace_id": trace_id})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate compliance report: {str(e)}"
        )


@router.post("/reset-metrics",
    summary="Reset Compliance Metrics",
    description="Reset compliance metrics counters (admin operation)."
)
async def reset_metrics(
    req: Request,
    category: Optional[str] = Query(None, description="Specific category to reset")
) -> Dict[str, Any]:
    """Reset compliance metrics."""
    trace_id = get_trace_id()
    
    try:
        metrics = get_compliance_metrics()
        
        if category:
            if category == "adm_violations":
                metrics.adm_violations = {
                    "spec_version_violations": 0,
                    "relationship_type_violations": 0,
                    "missing_required_fields": 0,
                    "invalid_references": 0,
                    "total_violations": 0
                }
            elif category == "filtering":
                metrics.filtering_metrics = {
                    "total_filtered": 0,
                    "filtered_by_type": {},
                    "filtering_rate": 0.0
                }
            elif category == "review":
                metrics.review_metrics = {
                    "total_reviews": 0,
                    "accepts": 0,
                    "edits": 0,
                    "rejects": 0,
                    "approval_rate": 0.0
                }
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid category: {category}"
                )
        else:
            # Reset all metrics
            metrics = ComplianceMetrics()
        
        logger.info(f"Reset compliance metrics", extra={"trace_id": trace_id, "category": category})
        
        return {
            "success": True,
            "category_reset": category or "all",
            "timestamp": datetime.utcnow().isoformat(),
            "trace_id": trace_id
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reset metrics: {e}", extra={"trace_id": trace_id})
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reset metrics: {str(e)}"
        )