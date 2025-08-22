"""Machine learning metrics tracking for model performance."""

import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import json
import numpy as np

logger = logging.getLogger(__name__)


class MLMetricsTracker:
    """Track ML model performance metrics."""
    
    def __init__(self):
        """Initialize metrics tracker."""
        # Performance metrics
        self.predictions = defaultdict(list)  # true/predicted pairs
        self.confidence_scores = defaultdict(list)
        
        # Review metrics
        self.review_decisions = defaultdict(lambda: {"accept": 0, "edit": 0, "reject": 0})
        self.approval_rates = defaultdict(float)
        
        # Coverage metrics
        self.coverage_gaps = defaultdict(list)
        self.coverage_improvements = defaultdict(float)
        
        # Time series data for trends
        self.metrics_history = defaultdict(list)
        
    def record_prediction(
        self,
        model_type: str,
        true_label: str,
        predicted_label: str,
        confidence: float,
        metadata: Optional[Dict] = None
    ):
        """
        Record a model prediction for metrics calculation.
        
        Args:
            model_type: Type of model (e.g., "technique_mapping", "flow_edge")
            true_label: Ground truth label
            predicted_label: Model's prediction
            confidence: Confidence score
            metadata: Additional metadata
        """
        self.predictions[model_type].append({
            "true": true_label,
            "predicted": predicted_label,
            "confidence": confidence,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata or {}
        })
        
        self.confidence_scores[model_type].append(confidence)
    
    def record_review_decision(
        self,
        item_type: str,
        decision: str,
        original_confidence: float,
        reviewer_id: Optional[str] = None
    ):
        """
        Record a review decision.
        
        Args:
            item_type: Type of item reviewed
            decision: Review decision (accept/edit/reject)
            original_confidence: Original model confidence
            reviewer_id: ID of reviewer
        """
        self.review_decisions[item_type][decision] += 1
        
        # Update approval rate
        total = sum(self.review_decisions[item_type].values())
        if total > 0:
            self.approval_rates[item_type] = (
                self.review_decisions[item_type]["accept"] / total
            )
    
    def record_coverage_gap(
        self,
        gap_type: str,
        technique_id: str,
        severity: str = "medium"
    ):
        """
        Record a coverage gap.
        
        Args:
            gap_type: Type of gap (detection/mitigation/d3fend)
            technique_id: Technique with gap
            severity: Gap severity
        """
        self.coverage_gaps[gap_type].append({
            "technique_id": technique_id,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    def calculate_precision_recall(
        self,
        model_type: str,
        positive_class: Optional[str] = None
    ) -> Dict[str, float]:
        """
        Calculate precision and recall for a model.
        
        Args:
            model_type: Type of model
            positive_class: Positive class label (for binary)
            
        Returns:
            Dictionary with precision, recall, f1
        """
        predictions = self.predictions.get(model_type, [])
        
        if not predictions:
            return {
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "support": 0
            }
        
        # For binary classification
        if positive_class:
            tp = sum(1 for p in predictions 
                    if p["true"] == positive_class and p["predicted"] == positive_class)
            fp = sum(1 for p in predictions 
                    if p["true"] != positive_class and p["predicted"] == positive_class)
            fn = sum(1 for p in predictions 
                    if p["true"] == positive_class and p["predicted"] != positive_class)
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            return {
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1_score": round(f1, 3),
                "support": len(predictions)
            }
        
        # For multi-class, calculate macro average
        classes = set([p["true"] for p in predictions] + [p["predicted"] for p in predictions])
        
        precisions = []
        recalls = []
        
        for cls in classes:
            tp = sum(1 for p in predictions if p["true"] == cls and p["predicted"] == cls)
            fp = sum(1 for p in predictions if p["true"] != cls and p["predicted"] == cls)
            fn = sum(1 for p in predictions if p["true"] == cls and p["predicted"] != cls)
            
            if (tp + fp) > 0:
                precisions.append(tp / (tp + fp))
            if (tp + fn) > 0:
                recalls.append(tp / (tp + fn))
        
        avg_precision = np.mean(precisions) if precisions else 0
        avg_recall = np.mean(recalls) if recalls else 0
        avg_f1 = 2 * (avg_precision * avg_recall) / (avg_precision + avg_recall) if (avg_precision + avg_recall) > 0 else 0
        
        return {
            "precision": round(avg_precision, 3),
            "recall": round(avg_recall, 3),
            "f1_score": round(avg_f1, 3),
            "support": len(predictions),
            "num_classes": len(classes)
        }
    
    def calculate_confidence_calibration(self, model_type: str) -> Dict[str, Any]:
        """
        Calculate confidence calibration metrics.
        
        Args:
            model_type: Type of model
            
        Returns:
            Calibration metrics
        """
        predictions = self.predictions.get(model_type, [])
        
        if not predictions:
            return {
                "mean_confidence": 0.0,
                "accuracy": 0.0,
                "calibration_error": 0.0
            }
        
        # Calculate accuracy at different confidence bins
        bins = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
        calibration_data = []
        
        for i in range(len(bins) - 1):
            bin_predictions = [
                p for p in predictions 
                if bins[i] <= p["confidence"] < bins[i+1]
            ]
            
            if bin_predictions:
                accuracy = sum(1 for p in bin_predictions if p["true"] == p["predicted"]) / len(bin_predictions)
                avg_confidence = np.mean([p["confidence"] for p in bin_predictions])
                calibration_data.append({
                    "bin": f"{bins[i]:.1f}-{bins[i+1]:.1f}",
                    "accuracy": accuracy,
                    "confidence": avg_confidence,
                    "count": len(bin_predictions)
                })
        
        # Calculate expected calibration error
        total_samples = len(predictions)
        ece = sum(
            abs(d["accuracy"] - d["confidence"]) * d["count"] / total_samples
            for d in calibration_data
        ) if calibration_data else 0
        
        overall_accuracy = sum(1 for p in predictions if p["true"] == p["predicted"]) / len(predictions)
        mean_confidence = np.mean([p["confidence"] for p in predictions])
        
        return {
            "mean_confidence": round(mean_confidence, 3),
            "accuracy": round(overall_accuracy, 3),
            "calibration_error": round(ece, 3),
            "calibration_bins": calibration_data
        }
    
    def get_approval_metrics(self) -> Dict[str, Any]:
        """
        Get approval rate metrics.
        
        Returns:
            Approval metrics by item type
        """
        metrics = {}
        
        for item_type, decisions in self.review_decisions.items():
            total = sum(decisions.values())
            if total > 0:
                metrics[item_type] = {
                    "total_reviews": total,
                    "accept": decisions["accept"],
                    "edit": decisions["edit"],
                    "reject": decisions["reject"],
                    "approval_rate": round(decisions["accept"] / total, 3),
                    "edit_rate": round(decisions["edit"] / total, 3),
                    "reject_rate": round(decisions["reject"] / total, 3)
                }
        
        return metrics
    
    def get_coverage_gap_metrics(self) -> Dict[str, Any]:
        """
        Get coverage gap metrics.
        
        Returns:
            Coverage gap statistics
        """
        metrics = {}
        
        for gap_type, gaps in self.coverage_gaps.items():
            if gaps:
                severity_counts = defaultdict(int)
                for gap in gaps:
                    severity_counts[gap["severity"]] += 1
                
                metrics[gap_type] = {
                    "total_gaps": len(gaps),
                    "by_severity": dict(severity_counts),
                    "gap_rate": round(len(gaps) / 100, 3)  # Normalized per 100 techniques
                }
        
        return metrics
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """
        Get all metrics in a dashboard-ready format.
        
        Returns:
            Complete metrics dictionary
        """
        all_metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "ml_performance": {},
            "approval_metrics": self.get_approval_metrics(),
            "coverage_gaps": self.get_coverage_gap_metrics()
        }
        
        # Add ML performance for each model type
        for model_type in self.predictions.keys():
            all_metrics["ml_performance"][model_type] = {
                "precision_recall": self.calculate_precision_recall(model_type),
                "calibration": self.calculate_confidence_calibration(model_type)
            }
        
        return all_metrics
    
    def export_for_dashboard(self) -> Dict[str, Any]:
        """
        Export metrics in Grafana-compatible format.
        
        Returns:
            Dashboard-ready metrics
        """
        metrics = self.get_all_metrics()
        
        # Format for Grafana
        dashboard_data = {
            "version": "1.0",
            "timestamp": metrics["timestamp"],
            "panels": [
                {
                    "id": "ml_performance",
                    "title": "ML Model Performance",
                    "type": "graph",
                    "data": metrics["ml_performance"]
                },
                {
                    "id": "approval_rates",
                    "title": "Review Approval Rates",
                    "type": "stat",
                    "data": metrics["approval_metrics"]
                },
                {
                    "id": "coverage_gaps",
                    "title": "Coverage Gap Analysis",
                    "type": "heatmap",
                    "data": metrics["coverage_gaps"]
                }
            ]
        }
        
        return dashboard_data


# Global metrics tracker
_ml_metrics_tracker: Optional[MLMetricsTracker] = None


def get_ml_metrics_tracker() -> MLMetricsTracker:
    """Get or create ML metrics tracker singleton."""
    global _ml_metrics_tracker
    if _ml_metrics_tracker is None:
        _ml_metrics_tracker = MLMetricsTracker()
    return _ml_metrics_tracker


def record_model_prediction(
    model_type: str,
    true_label: str,
    predicted_label: str,
    confidence: float
):
    """Convenience function to record prediction."""
    tracker = get_ml_metrics_tracker()
    tracker.record_prediction(model_type, true_label, predicted_label, confidence)


def record_review(item_type: str, decision: str, confidence: float):
    """Convenience function to record review decision."""
    tracker = get_ml_metrics_tracker()
    tracker.record_review_decision(item_type, decision, confidence)


def get_ml_metrics() -> Dict[str, Any]:
    """Get current ML metrics."""
    tracker = get_ml_metrics_tracker()
    return tracker.get_all_metrics()


def export_dashboard_metrics() -> Dict[str, Any]:
    """Export metrics for dashboard."""
    tracker = get_ml_metrics_tracker()
    return tracker.export_for_dashboard()