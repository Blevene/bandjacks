"""Compliance and detection metrics for monitoring ADM compliance and system health."""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from threading import Lock
import json

logger = logging.getLogger(__name__)


class ComplianceMetrics:
    """Singleton metrics collector for ADM compliance and detection coverage."""
    
    _instance = None
    _lock = Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        # ADM Compliance Counters
        self.bundles_ingested_total = 0
        self.bundles_rejected_total = 0
        self.validation_errors_total = 0
        self.spec_version_violations = 0
        self.relationship_violations = 0
        self.missing_required_fields = 0
        
        # Detection Coverage Metrics
        self.detection_strategies_total = 0
        self.analytics_total = 0
        self.log_sources_total = 0
        self.techniques_with_detection = 0
        self.techniques_without_detection = 0
        self.avg_detections_per_technique = 0.0
        
        # Revoked/Deprecated Filtering
        self.revoked_filtered_count = 0
        self.deprecated_filtered_count = 0
        self.include_revoked_requests = 0
        self.include_deprecated_requests = 0
        
        # Review and Feedback Metrics
        self.review_decisions_total = 0
        self.review_accepts = 0
        self.review_edits = 0
        self.review_rejects = 0
        self.uncertainty_queue_size = 0
        self.avg_confidence_score = 0.0
        
        # Retrain Metrics
        self.retrain_jobs_total = 0
        self.items_retrained_total = 0
        self.embeddings_refreshed_total = 0
        self.last_retrain_timestamp = None
        
        # Error tracking
        self.validation_error_details = []
        self.compliance_violations = []
        
        self._initialized = True
    
    def record_bundle_ingestion(
        self,
        bundle_id: str,
        success: bool,
        validation_errors: List[str] = None,
        objects_count: int = 0
    ):
        """Record metrics for bundle ingestion."""
        if success:
            self.bundles_ingested_total += 1
        else:
            self.bundles_rejected_total += 1
        
        if validation_errors:
            self.validation_errors_total += len(validation_errors)
            
            # Categorize errors
            for error in validation_errors:
                error_lower = error.lower()
                if "spec_version" in error_lower:
                    self.spec_version_violations += 1
                elif "relationship" in error_lower:
                    self.relationship_violations += 1
                elif "missing" in error_lower:
                    self.missing_required_fields += 1
                
                # Store detailed error for analysis
                self.validation_error_details.append({
                    "bundle_id": bundle_id,
                    "error": error,
                    "timestamp": datetime.utcnow().isoformat()
                })
                
                # Keep only last 100 errors
                if len(self.validation_error_details) > 100:
                    self.validation_error_details = self.validation_error_details[-100:]
        
        logger.info(f"Bundle ingestion {'succeeded' if success else 'failed'}: {bundle_id}")
    
    def record_detection_coverage(
        self,
        technique_id: str,
        has_detection: bool,
        detection_count: int = 0,
        analytic_count: int = 0,
        log_source_count: int = 0
    ):
        """Record detection coverage metrics for a technique."""
        if has_detection:
            self.techniques_with_detection += 1
        else:
            self.techniques_without_detection += 1
        
        # Update running average
        total_techniques = self.techniques_with_detection + self.techniques_without_detection
        if total_techniques > 0:
            current_sum = self.avg_detections_per_technique * (total_techniques - 1)
            self.avg_detections_per_technique = (current_sum + detection_count) / total_techniques
    
    def record_filtering(
        self,
        filtered_type: str,
        include_requested: bool = False
    ):
        """Record revoked/deprecated filtering metrics."""
        if filtered_type == "revoked":
            if include_requested:
                self.include_revoked_requests += 1
            else:
                self.revoked_filtered_count += 1
        elif filtered_type == "deprecated":
            if include_requested:
                self.include_deprecated_requests += 1
            else:
                self.deprecated_filtered_count += 1
    
    def record_review_decision(
        self,
        decision: str,
        item_type: str,
        confidence: Optional[float] = None
    ):
        """Record review decision metrics."""
        self.review_decisions_total += 1
        
        if decision == "accept":
            self.review_accepts += 1
        elif decision == "edit":
            self.review_edits += 1
        elif decision == "reject":
            self.review_rejects += 1
        
        # Update average confidence if provided
        if confidence is not None:
            if self.avg_confidence_score == 0:
                self.avg_confidence_score = confidence
            else:
                # Running average
                self.avg_confidence_score = (
                    self.avg_confidence_score * 0.9 + confidence * 0.1
                )
    
    def record_retrain(
        self,
        job_id: str,
        items_count: int,
        embeddings_refreshed: int = 0
    ):
        """Record retrain job metrics."""
        self.retrain_jobs_total += 1
        self.items_retrained_total += items_count
        self.embeddings_refreshed_total += embeddings_refreshed
        self.last_retrain_timestamp = datetime.utcnow()
        
        logger.info(f"Retrain job {job_id} completed: {items_count} items, {embeddings_refreshed} embeddings")
    
    def record_compliance_violation(
        self,
        violation_type: str,
        details: Dict[str, Any]
    ):
        """Record a compliance violation."""
        violation = {
            "type": violation_type,
            "details": details,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        self.compliance_violations.append(violation)
        
        # Keep only last 50 violations
        if len(self.compliance_violations) > 50:
            self.compliance_violations = self.compliance_violations[-50:]
        
        logger.warning(f"Compliance violation: {violation_type} - {details}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics snapshot."""
        metrics = {
            # ADM Compliance
            "adm_compliance": {
                "bundles_ingested_total": self.bundles_ingested_total,
                "bundles_rejected_total": self.bundles_rejected_total,
                "validation_errors_total": self.validation_errors_total,
                "spec_version_violations": self.spec_version_violations,
                "relationship_violations": self.relationship_violations,
                "missing_required_fields": self.missing_required_fields,
                "compliance_rate": (
                    self.bundles_ingested_total / 
                    (self.bundles_ingested_total + self.bundles_rejected_total)
                    if (self.bundles_ingested_total + self.bundles_rejected_total) > 0 else 0
                )
            },
            
            # Detection Coverage
            "detection_coverage": {
                "strategies_total": self.detection_strategies_total,
                "analytics_total": self.analytics_total,
                "log_sources_total": self.log_sources_total,
                "techniques_with_detection": self.techniques_with_detection,
                "techniques_without_detection": self.techniques_without_detection,
                "avg_detections_per_technique": round(self.avg_detections_per_technique, 2),
                "coverage_percentage": (
                    self.techniques_with_detection /
                    (self.techniques_with_detection + self.techniques_without_detection) * 100
                    if (self.techniques_with_detection + self.techniques_without_detection) > 0 else 0
                )
            },
            
            # Filtering
            "filtering": {
                "revoked_filtered": self.revoked_filtered_count,
                "deprecated_filtered": self.deprecated_filtered_count,
                "include_revoked_requests": self.include_revoked_requests,
                "include_deprecated_requests": self.include_deprecated_requests,
                "default_filtering_rate": (
                    (self.revoked_filtered_count + self.deprecated_filtered_count) /
                    (self.revoked_filtered_count + self.deprecated_filtered_count + 
                     self.include_revoked_requests + self.include_deprecated_requests)
                    if (self.revoked_filtered_count + self.deprecated_filtered_count +
                        self.include_revoked_requests + self.include_deprecated_requests) > 0 else 0
                )
            },
            
            # Review and Feedback
            "review_feedback": {
                "decisions_total": self.review_decisions_total,
                "accepts": self.review_accepts,
                "edits": self.review_edits,
                "rejects": self.review_rejects,
                "uncertainty_queue_size": self.uncertainty_queue_size,
                "avg_confidence_score": round(self.avg_confidence_score, 3),
                "edit_reject_rate": (
                    (self.review_edits + self.review_rejects) / self.review_decisions_total
                    if self.review_decisions_total > 0 else 0
                )
            },
            
            # Retrain
            "retrain": {
                "jobs_total": self.retrain_jobs_total,
                "items_retrained": self.items_retrained_total,
                "embeddings_refreshed": self.embeddings_refreshed_total,
                "last_retrain": self.last_retrain_timestamp.isoformat() if self.last_retrain_timestamp else None,
                "days_since_retrain": (
                    (datetime.utcnow() - self.last_retrain_timestamp).days
                    if self.last_retrain_timestamp else None
                )
            },
            
            # Recent Issues
            "recent_issues": {
                "recent_validation_errors": self.validation_error_details[-5:],
                "recent_compliance_violations": self.compliance_violations[-5:]
            }
        }
        
        return metrics
    
    def get_compliance_report(self) -> Dict[str, Any]:
        """Generate a compliance report."""
        metrics = self.get_metrics()
        
        # Determine overall compliance status
        compliance_score = 0
        max_score = 5
        
        # Check ADM compliance rate
        if metrics["adm_compliance"]["compliance_rate"] >= 0.95:
            compliance_score += 1
        
        # Check spec version violations
        if self.spec_version_violations == 0:
            compliance_score += 1
        
        # Check relationship violations
        if self.relationship_violations == 0:
            compliance_score += 1
        
        # Check detection coverage
        if metrics["detection_coverage"]["coverage_percentage"] >= 70:
            compliance_score += 1
        
        # Check review feedback rate
        if metrics["review_feedback"]["edit_reject_rate"] <= 0.2:
            compliance_score += 1
        
        status = "COMPLIANT" if compliance_score >= 4 else "NEEDS_ATTENTION" if compliance_score >= 2 else "NON_COMPLIANT"
        
        return {
            "status": status,
            "compliance_score": f"{compliance_score}/{max_score}",
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": metrics,
            "recommendations": self._generate_recommendations(metrics, compliance_score)
        }
    
    def _generate_recommendations(self, metrics: Dict[str, Any], score: int) -> List[str]:
        """Generate recommendations based on metrics."""
        recommendations = []
        
        if metrics["adm_compliance"]["spec_version_violations"] > 0:
            recommendations.append("Review and fix STIX objects with incorrect spec_version")
        
        if metrics["adm_compliance"]["relationship_violations"] > 0:
            recommendations.append("Ensure all relationships use ADM-compliant types")
        
        if metrics["detection_coverage"]["coverage_percentage"] < 70:
            recommendations.append("Increase detection coverage by adding more detection strategies")
        
        if metrics["review_feedback"]["edit_reject_rate"] > 0.2:
            recommendations.append("High edit/reject rate indicates quality issues - review extraction process")
        
        if metrics["retrain"]["days_since_retrain"] and metrics["retrain"]["days_since_retrain"] > 7:
            recommendations.append("Schedule a retrain job - last retrain was over a week ago")
        
        return recommendations
    
    def reset_metrics(self):
        """Reset all metrics (use with caution)."""
        self.__init__()
        self._initialized = True
        logger.info("All compliance metrics have been reset")


# Global instance
_metrics = ComplianceMetrics()


def get_compliance_metrics() -> ComplianceMetrics:
    """Get the global compliance metrics instance."""
    return _metrics


def record_bundle_ingestion(bundle_id: str, success: bool, validation_errors: List[str] = None, objects_count: int = 0):
    """Convenience function to record bundle ingestion."""
    _metrics.record_bundle_ingestion(bundle_id, success, validation_errors, objects_count)


def record_detection_coverage(technique_id: str, has_detection: bool, detection_count: int = 0):
    """Convenience function to record detection coverage."""
    _metrics.record_detection_coverage(technique_id, has_detection, detection_count)


def record_filtering(filtered_type: str, include_requested: bool = False):
    """Convenience function to record filtering."""
    _metrics.record_filtering(filtered_type, include_requested)


def record_review_decision(decision: str, item_type: str, confidence: Optional[float] = None):
    """Convenience function to record review decision."""
    _metrics.record_review_decision(decision, item_type, confidence)


def get_compliance_report() -> Dict[str, Any]:
    """Convenience function to get compliance report."""
    return _metrics.get_compliance_report()