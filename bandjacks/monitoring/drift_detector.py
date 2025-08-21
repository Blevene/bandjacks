"""Drift detection for model performance and data quality."""

import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import statistics
from neo4j import GraphDatabase
from bandjacks.services.api.schemas import DriftMetric, DriftAlert, DriftStatus

logger = logging.getLogger(__name__)


@dataclass
class DriftThresholds:
    """Configurable thresholds for drift detection."""
    version_mismatch: float = 0.0  # Any version difference is significant
    schema_change: float = 0.1  # 10% change in schema fields
    confidence_drop: float = 0.15  # 15% drop in confidence scores
    quality_drop: float = 0.2  # 20% drop in quality scores
    performance_degradation: float = 0.3  # 30% increase in response times
    embedding_drift: float = 0.25  # 25% drift in embedding similarity


class DriftDetector:
    """Detect drift in various system metrics."""
    
    def __init__(
        self,
        neo4j_uri: str,
        neo4j_user: str,
        neo4j_password: str,
        thresholds: Optional[DriftThresholds] = None
    ):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.thresholds = thresholds or DriftThresholds()
        self.alerts: List[DriftAlert] = []
    
    def analyze_version_drift(self) -> DriftMetric:
        """Detect version mismatches in ATT&CK data."""
        with self.driver.session() as session:
            # Get all unique versions in the graph
            result = session.run("""
                MATCH (n)
                WHERE n.source_version IS NOT NULL
                RETURN DISTINCT n.source_version as version, 
                       n.source_collection as collection,
                       count(n) as node_count
                ORDER BY node_count DESC
            """)
            
            versions = list(result)
            
            if len(versions) > 1:
                # Multiple versions detected
                primary_version = versions[0]["version"]
                total_nodes = sum(v["node_count"] for v in versions)
                mixed_nodes = sum(v["node_count"] for v in versions[1:])
                drift_pct = mixed_nodes / total_nodes if total_nodes > 0 else 0
                
                metric = DriftMetric(
                    metric_name="version_consistency",
                    current_value=len(versions),
                    baseline_value=1.0,
                    drift_percentage=drift_pct * 100,
                    is_significant=drift_pct > self.thresholds.version_mismatch,
                    threshold=self.thresholds.version_mismatch,
                    timestamp=datetime.utcnow().isoformat()
                )
                
                if metric.is_significant:
                    self.alerts.append(DriftAlert(
                        alert_id=f"drift-version-{datetime.utcnow().timestamp()}",
                        alert_type="version",
                        severity="high" if len(versions) > 2 else "medium",
                        description=f"Multiple ATT&CK versions detected: {', '.join(v['version'] for v in versions[:3])}",
                        metrics=[metric],
                        recommended_action="Consolidate to a single ATT&CK version or implement version isolation",
                        created_at=datetime.utcnow().isoformat(),
                        acknowledged=False
                    ))
                
                return metric
            
            return DriftMetric(
                metric_name="version_consistency",
                current_value=1.0,
                baseline_value=1.0,
                drift_percentage=0.0,
                is_significant=False,
                threshold=self.thresholds.version_mismatch,
                timestamp=datetime.utcnow().isoformat()
            )
    
    def analyze_confidence_drift(self, days_back: int = 30) -> DriftMetric:
        """Analyze drift in confidence scores over time."""
        with self.driver.session() as session:
            # Get confidence scores from recent vs older periods
            cutoff_date = datetime.utcnow() - timedelta(days=days_back)
            
            # Recent confidence scores
            recent_result = session.run("""
                MATCH (n)
                WHERE n.x_bj_confidence IS NOT NULL 
                AND n.created_ts > $cutoff
                RETURN avg(n.x_bj_confidence) as avg_confidence,
                       stdev(n.x_bj_confidence) as stdev_confidence,
                       count(n) as count
            """, cutoff=cutoff_date.timestamp() * 1000)
            
            recent = recent_result.single()
            
            # Historical baseline
            baseline_result = session.run("""
                MATCH (n)
                WHERE n.x_bj_confidence IS NOT NULL 
                AND n.created_ts <= $cutoff
                RETURN avg(n.x_bj_confidence) as avg_confidence,
                       stdev(n.x_bj_confidence) as stdev_confidence,
                       count(n) as count
            """, cutoff=cutoff_date.timestamp() * 1000)
            
            baseline = baseline_result.single()
            
            if recent and baseline and recent["count"] > 0 and baseline["count"] > 0:
                current_avg = recent["avg_confidence"] or 50
                baseline_avg = baseline["avg_confidence"] or 50
                drift_pct = abs(current_avg - baseline_avg) / baseline_avg if baseline_avg > 0 else 0
                
                metric = DriftMetric(
                    metric_name="confidence_scores",
                    current_value=current_avg,
                    baseline_value=baseline_avg,
                    drift_percentage=drift_pct * 100,
                    is_significant=drift_pct > self.thresholds.confidence_drop and current_avg < baseline_avg,
                    threshold=self.thresholds.confidence_drop,
                    timestamp=datetime.utcnow().isoformat()
                )
                
                if metric.is_significant:
                    self.alerts.append(DriftAlert(
                        alert_id=f"drift-confidence-{datetime.utcnow().timestamp()}",
                        alert_type="quality",
                        severity="medium",
                        description=f"Confidence scores dropped {drift_pct*100:.1f}% from baseline",
                        metrics=[metric],
                        recommended_action="Review recent extractions and mappings for quality issues",
                        created_at=datetime.utcnow().isoformat(),
                        acknowledged=False
                    ))
                
                return metric
            
            return DriftMetric(
                metric_name="confidence_scores",
                current_value=50.0,
                baseline_value=50.0,
                drift_percentage=0.0,
                is_significant=False,
                threshold=self.thresholds.confidence_drop,
                timestamp=datetime.utcnow().isoformat()
            )
    
    def analyze_quality_drift(self, days_back: int = 30) -> DriftMetric:
        """Analyze drift in quality feedback scores."""
        with self.driver.session() as session:
            cutoff_date = datetime.utcnow() - timedelta(days=days_back)
            
            # Recent quality scores
            recent_result = session.run("""
                MATCH (f:Feedback {type: 'quality'})
                WHERE f.timestamp > datetime() - duration('P%dD')
                RETURN avg(f.overall) as avg_quality,
                       avg(f.accuracy) as avg_accuracy,
                       avg(f.relevance) as avg_relevance,
                       count(f) as count
            """ % days_back)
            
            recent = recent_result.single()
            
            # Historical baseline
            baseline_result = session.run("""
                MATCH (f:Feedback {type: 'quality'})
                WHERE f.timestamp <= datetime() - duration('P%dD')
                AND f.timestamp > datetime() - duration('P%dD')
                RETURN avg(f.overall) as avg_quality,
                       avg(f.accuracy) as avg_accuracy,
                       avg(f.relevance) as avg_relevance,
                       count(f) as count
            """ % (days_back, days_back * 2))
            
            baseline = baseline_result.single()
            
            if recent and baseline and recent["count"] > 0 and baseline["count"] > 0:
                current_avg = recent["avg_quality"] or 3.0
                baseline_avg = baseline["avg_quality"] or 3.0
                drift_pct = abs(current_avg - baseline_avg) / baseline_avg if baseline_avg > 0 else 0
                
                metric = DriftMetric(
                    metric_name="quality_scores",
                    current_value=current_avg,
                    baseline_value=baseline_avg,
                    drift_percentage=drift_pct * 100,
                    is_significant=drift_pct > self.thresholds.quality_drop and current_avg < baseline_avg,
                    threshold=self.thresholds.quality_drop,
                    timestamp=datetime.utcnow().isoformat()
                )
                
                if metric.is_significant:
                    severity = "critical" if drift_pct > 0.4 else "high" if drift_pct > 0.3 else "medium"
                    self.alerts.append(DriftAlert(
                        alert_id=f"drift-quality-{datetime.utcnow().timestamp()}",
                        alert_type="quality",
                        severity=severity,
                        description=f"Quality scores dropped {drift_pct*100:.1f}% from baseline (now {current_avg:.1f}/5)",
                        metrics=[metric],
                        recommended_action="Investigate quality issues; consider retraining or model updates",
                        created_at=datetime.utcnow().isoformat(),
                        acknowledged=False
                    ))
                
                return metric
            
            return DriftMetric(
                metric_name="quality_scores",
                current_value=3.0,
                baseline_value=3.0,
                drift_percentage=0.0,
                is_significant=False,
                threshold=self.thresholds.quality_drop,
                timestamp=datetime.utcnow().isoformat()
            )
    
    def analyze_schema_drift(self) -> DriftMetric:
        """Detect schema changes in graph nodes."""
        with self.driver.session() as session:
            # Get all unique property combinations
            result = session.run("""
                MATCH (n)
                WHERE n.type IN ['attack-pattern', 'intrusion-set', 'malware', 'tool']
                WITH n.type as node_type, keys(n) as props
                RETURN node_type, 
                       collect(DISTINCT props) as property_sets,
                       count(*) as count
            """)
            
            schema_variations = {}
            for record in result:
                node_type = record["node_type"]
                prop_sets = record["property_sets"]
                
                # Find the most common property set (baseline)
                if prop_sets:
                    # Convert lists to tuples for hashing
                    prop_tuples = [tuple(sorted(ps)) for ps in prop_sets]
                    baseline_props = max(set(prop_tuples), key=prop_tuples.count)
                    
                    # Count deviations
                    deviations = sum(1 for pt in prop_tuples if pt != baseline_props)
                    total = len(prop_tuples)
                    
                    schema_variations[node_type] = deviations / total if total > 0 else 0
            
            if schema_variations:
                avg_variation = statistics.mean(schema_variations.values())
                
                metric = DriftMetric(
                    metric_name="schema_consistency",
                    current_value=1 - avg_variation,  # Convert to consistency score
                    baseline_value=1.0,
                    drift_percentage=avg_variation * 100,
                    is_significant=avg_variation > self.thresholds.schema_change,
                    threshold=self.thresholds.schema_change,
                    timestamp=datetime.utcnow().isoformat()
                )
                
                if metric.is_significant:
                    self.alerts.append(DriftAlert(
                        alert_id=f"drift-schema-{datetime.utcnow().timestamp()}",
                        alert_type="schema",
                        severity="low",
                        description=f"Schema inconsistency detected: {avg_variation*100:.1f}% of nodes have non-standard properties",
                        metrics=[metric],
                        recommended_action="Review data ingestion pipeline for schema violations",
                        created_at=datetime.utcnow().isoformat(),
                        acknowledged=False
                    ))
                
                return metric
            
            return DriftMetric(
                metric_name="schema_consistency",
                current_value=1.0,
                baseline_value=1.0,
                drift_percentage=0.0,
                is_significant=False,
                threshold=self.thresholds.schema_change,
                timestamp=datetime.utcnow().isoformat()
            )
    
    def get_drift_status(self) -> DriftStatus:
        """Get overall drift status."""
        # Clear previous alerts
        self.alerts = []
        
        # Analyze all drift metrics
        metrics = {
            "version": self.analyze_version_drift(),
            "confidence": self.analyze_confidence_drift(),
            "quality": self.analyze_quality_drift(),
            "schema": self.analyze_schema_drift()
        }
        
        # Determine overall status
        critical_alerts = [a for a in self.alerts if a.severity == "critical"]
        high_alerts = [a for a in self.alerts if a.severity == "high"]
        
        if critical_alerts:
            status = "critical"
        elif high_alerts:
            status = "major_drift"
        elif self.alerts:
            status = "minor_drift"
        else:
            status = "stable"
        
        return DriftStatus(
            status=status,
            active_alerts=len(self.alerts),
            last_analysis=datetime.utcnow().isoformat(),
            metrics=metrics
        )
    
    def close(self):
        """Close database connection."""
        if self.driver:
            self.driver.close()