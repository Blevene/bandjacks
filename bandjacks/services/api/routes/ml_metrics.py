"""ML metrics and performance monitoring endpoints."""

import logging
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from bandjacks.monitoring.ml_metrics import (
    get_ml_metrics_tracker,
    get_ml_metrics,
    export_dashboard_metrics
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ml-metrics", tags=["ml-metrics"])


class PredictionRecord(BaseModel):
    """Record of a model prediction."""
    model_type: str = Field(..., description="Model type (e.g., technique_mapping)")
    true_label: str = Field(..., description="Ground truth label")
    predicted_label: str = Field(..., description="Model prediction")
    confidence: float = Field(..., ge=0, le=1, description="Confidence score")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


class ReviewRecord(BaseModel):
    """Record of a review decision."""
    item_type: str = Field(..., description="Type of item reviewed")
    decision: str = Field(..., description="Review decision (accept/edit/reject)")
    original_confidence: float = Field(..., ge=0, le=1, description="Original confidence")
    reviewer_id: Optional[str] = Field(None, description="Reviewer identifier")


class CoverageGapRecord(BaseModel):
    """Record of a coverage gap."""
    gap_type: str = Field(..., description="Type of gap (detection/mitigation/d3fend)")
    technique_id: str = Field(..., description="Technique with gap")
    severity: str = Field("medium", description="Gap severity (low/medium/high/critical)")


@router.post("/prediction")
async def record_prediction(record: PredictionRecord) -> Dict[str, Any]:
    """
    Record a model prediction for metrics tracking.
    
    Used to track model performance over time.
    """
    tracker = get_ml_metrics_tracker()
    tracker.record_prediction(
        model_type=record.model_type,
        true_label=record.true_label,
        predicted_label=record.predicted_label,
        confidence=record.confidence,
        metadata=record.metadata
    )
    
    return {
        "status": "recorded",
        "model_type": record.model_type,
        "confidence": record.confidence
    }


@router.post("/review")
async def record_review(record: ReviewRecord) -> Dict[str, Any]:
    """
    Record a review decision for approval rate tracking.
    """
    tracker = get_ml_metrics_tracker()
    tracker.record_review_decision(
        item_type=record.item_type,
        decision=record.decision,
        original_confidence=record.original_confidence,
        reviewer_id=record.reviewer_id
    )
    
    return {
        "status": "recorded",
        "item_type": record.item_type,
        "decision": record.decision
    }


@router.post("/coverage-gap")
async def record_coverage_gap(record: CoverageGapRecord) -> Dict[str, Any]:
    """
    Record a coverage gap for gap rate tracking.
    """
    tracker = get_ml_metrics_tracker()
    tracker.record_coverage_gap(
        gap_type=record.gap_type,
        technique_id=record.technique_id,
        severity=record.severity
    )
    
    return {
        "status": "recorded",
        "gap_type": record.gap_type,
        "technique_id": record.technique_id
    }


@router.get("/precision-recall")
async def get_precision_recall(
    model_type: str = Query(..., description="Model type to get metrics for"),
    positive_class: Optional[str] = Query(None, description="Positive class for binary classification")
) -> Dict[str, Any]:
    """
    Get precision, recall, and F1 score for a model.
    """
    tracker = get_ml_metrics_tracker()
    metrics = tracker.calculate_precision_recall(model_type, positive_class)
    
    return {
        "model_type": model_type,
        "metrics": metrics
    }


@router.get("/calibration")
async def get_calibration_metrics(
    model_type: str = Query(..., description="Model type to get calibration for")
) -> Dict[str, Any]:
    """
    Get confidence calibration metrics for a model.
    
    Shows how well the model's confidence scores align with actual accuracy.
    """
    tracker = get_ml_metrics_tracker()
    calibration = tracker.calculate_confidence_calibration(model_type)
    
    return {
        "model_type": model_type,
        "calibration": calibration
    }


@router.get("/approval-rates")
async def get_approval_rates() -> Dict[str, Any]:
    """
    Get approval rates for all reviewed item types.
    """
    tracker = get_ml_metrics_tracker()
    return tracker.get_approval_metrics()


@router.get("/coverage-gaps")
async def get_coverage_gap_metrics() -> Dict[str, Any]:
    """
    Get coverage gap metrics and statistics.
    """
    tracker = get_ml_metrics_tracker()
    return tracker.get_coverage_gap_metrics()


@router.get("/all")
async def get_all_metrics() -> Dict[str, Any]:
    """
    Get all ML metrics in a comprehensive report.
    """
    return get_ml_metrics()


@router.get("/dashboard")
async def get_dashboard_metrics() -> Dict[str, Any]:
    """
    Get metrics formatted for dashboard visualization.
    
    Returns Grafana-compatible format.
    """
    return export_dashboard_metrics()