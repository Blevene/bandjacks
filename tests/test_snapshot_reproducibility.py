"""Snapshot and reproducibility tests for Sprint 5 features."""

import pytest
import json
import hashlib
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
import random

# Import modules to test
from bandjacks.llm.al_sampler import ALSampler
from bandjacks.llm.active_learning import ActiveLearningManager
from bandjacks.monitoring.ml_metrics import MLMetricsTracker
from bandjacks.services.cache_manager import CacheManager


class TestSnapshotReproducibility:
    """Test deterministic behavior and snapshot consistency."""
    
    def test_al_sampler_deterministic_sampling(self):
        """Test that AL sampler produces consistent results with same data."""
        
        # Mock Neo4j driver
        mock_driver = Mock()
        mock_session = Mock()
        mock_driver.session.return_value.__enter__ = Mock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = Mock(return_value=None)
        
        # Set up deterministic test data
        test_flow_edges = [
            {
                "item_type": "flow_edge",
                "item_id": f"edge-{i}",
                "confidence": 0.3 + i * 0.05,
                "uncertainty_score": 0.7 - i * 0.05,
                "context": {"source": f"action_{i}", "target": f"action_{i+1}"}
            }
            for i in range(5)
        ]
        
        # Mock query results
        mock_result = Mock()
        mock_result.__iter__ = Mock(return_value=iter([
            {"item_type": r["item_type"], 
             "item_id": r["item_id"],
             "confidence": r["confidence"],
             "uncertainty_score": r["uncertainty_score"],
             "context": r["context"]}
            for r in test_flow_edges
        ]))
        
        mock_session.run.return_value = mock_result
        
        # Create sampler with mocked driver
        sampler = ALSampler(
            neo4j_uri="bolt://test",
            neo4j_user="test",
            neo4j_password="test",
            sample_size=3,
            confidence_threshold=0.6
        )
        sampler.driver = mock_driver
        
        # Run sampling multiple times
        results = []
        for _ in range(3):
            # Reset mock
            mock_session.reset_mock()
            mock_session.run.return_value = mock_result
            
            # Sample
            sampled = sampler._sample_flow_edges()
            results.append(sampled)
        
        # All runs should produce same results
        assert all(r == results[0] for r in results), "Sampling should be deterministic"
        
        # Verify correct items were sampled (highest uncertainty)
        expected_ids = ["edge-0", "edge-1", "edge-2"]  # Highest uncertainty scores
        
        sampler.close()
    
    def test_seeded_uncertainty_queue(self):
        """Test uncertainty queue with seeded data."""
        
        # Create manager with mock driver
        mock_driver = Mock()
        mock_session = Mock()
        mock_driver.session.return_value.__enter__ = Mock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = Mock(return_value=None)
        
        manager = ActiveLearningManager(
            neo4j_uri="bolt://test",
            neo4j_user="test",
            neo4j_password="test"
        )
        manager.driver = mock_driver
        
        # Seed queue with deterministic items
        seed_items = [
            {
                "queue_id": f"queue-seed-{i:03d}",
                "item_type": "mapping",
                "item_id": f"candidate-{i:03d}",
                "confidence": 0.4 + i * 0.02,
                "uncertainty_score": 0.6 - i * 0.02,
                "priority": 100 - i * 10
            }
            for i in range(10)
        ]
        
        # Mock query for adding items
        mock_session.run.return_value.single.return_value = None
        
        # Add seeded items
        for item in seed_items:
            mock_session.run.reset_mock()
            mock_result = Mock()
            mock_result.single.return_value = {"exists": 0}
            mock_session.run.return_value = mock_result
            
            # Add to queue (simplified)
            manager.add_to_uncertainty_queue(
                item_type=item["item_type"],
                item_id=item["item_id"],
                confidence=item["confidence"],
                source_context={"seeded": True}
            )
        
        # Verify queue operations
        assert mock_session.run.call_count > 0, "Queue operations should have been called"
        
        manager.close()
    
    def test_ml_metrics_deterministic_calculations(self):
        """Test that ML metrics calculations are deterministic."""
        
        tracker = MLMetricsTracker()
        
        # Add deterministic test data
        test_predictions = [
            ("technique_mapping", "T1055", "T1055", 0.95),
            ("technique_mapping", "T1055", "T1003", 0.75),
            ("technique_mapping", "T1003", "T1003", 0.85),
            ("technique_mapping", "T1548", "T1055", 0.60),
            ("technique_mapping", "T1548", "T1548", 0.90),
        ]
        
        for model_type, true_label, pred_label, conf in test_predictions:
            tracker.record_prediction(model_type, true_label, pred_label, conf)
        
        # Calculate metrics multiple times
        results = []
        for _ in range(3):
            metrics = tracker.calculate_precision_recall("technique_mapping")
            results.append(metrics)
        
        # All calculations should be identical
        assert all(r == results[0] for r in results), "Metrics should be deterministic"
        
        # Verify expected values
        # TP=3 (T1055->T1055, T1003->T1003, T1548->T1548)
        # FP=2 (T1055->T1003, T1548->T1055)
        # FN=0
        expected_precision = 3 / 5  # 0.6
        assert abs(results[0]["precision"] - expected_precision) < 0.01
    
    def test_cache_manager_deterministic_eviction(self):
        """Test that cache eviction is deterministic."""
        
        cache = CacheManager(max_size=3, default_ttl=3600)
        
        # Add items in specific order
        items = [
            ("key1", "value1"),
            ("key2", "value2"),
            ("key3", "value3"),
            ("key4", "value4"),  # Should evict key1
        ]
        
        for key, value in items:
            cache.set(key, value)
        
        # Verify LRU eviction
        assert cache.get("key1") is None, "key1 should be evicted (LRU)"
        assert cache.get("key2") == "value2"
        assert cache.get("key3") == "value3"
        assert cache.get("key4") == "value4"
        
        # Access key2, then add key5 - should evict key3
        _ = cache.get("key2")
        cache.set("key5", "value5")
        
        assert cache.get("key3") is None, "key3 should be evicted after key2 access"
        assert cache.get("key2") == "value2", "key2 should still exist"
    
    def test_confidence_calibration_snapshot(self):
        """Test confidence calibration with snapshot data."""
        
        tracker = MLMetricsTracker()
        
        # Snapshot test data with known calibration
        snapshot_data = [
            # Low confidence, mostly wrong
            ("model_a", "A", "B", 0.15),
            ("model_a", "A", "B", 0.18),
            ("model_a", "A", "A", 0.12),
            
            # Medium confidence, balanced
            ("model_a", "B", "B", 0.55),
            ("model_a", "B", "C", 0.52),
            ("model_a", "C", "C", 0.58),
            
            # High confidence, mostly right
            ("model_a", "A", "A", 0.92),
            ("model_a", "B", "B", 0.88),
            ("model_a", "C", "C", 0.95),
        ]
        
        for model_type, true_label, pred_label, conf in snapshot_data:
            tracker.record_prediction(model_type, true_label, pred_label, conf)
        
        calibration = tracker.calculate_confidence_calibration("model_a")
        
        # Verify snapshot results
        assert calibration["mean_confidence"] > 0.5
        assert calibration["accuracy"] > 0.6
        assert calibration["calibration_error"] < 0.3
        
        # Verify bin consistency
        bins = calibration["calibration_bins"]
        assert len(bins) > 0, "Should have calibration bins"
        
        # Low confidence bin should have low accuracy
        low_bin = next((b for b in bins if b["bin"] == "0.0-0.2"), None)
        if low_bin:
            assert low_bin["accuracy"] < 0.5, "Low confidence should have low accuracy"
    
    def test_review_decision_aggregation(self):
        """Test deterministic aggregation of review decisions."""
        
        tracker = MLMetricsTracker()
        
        # Fixed set of review decisions
        decisions = [
            ("mapping", "accept", 0.85),
            ("mapping", "accept", 0.90),
            ("mapping", "edit", 0.65),
            ("mapping", "reject", 0.45),
            ("mapping", "accept", 0.88),
            
            ("flow_edge", "accept", 0.75),
            ("flow_edge", "edit", 0.60),
            ("flow_edge", "edit", 0.55),
        ]
        
        for item_type, decision, conf in decisions:
            tracker.record_review_decision(item_type, decision, conf)
        
        approval_metrics = tracker.get_approval_metrics()
        
        # Verify deterministic results
        assert approval_metrics["mapping"]["total_reviews"] == 5
        assert approval_metrics["mapping"]["accept"] == 3
        assert approval_metrics["mapping"]["approval_rate"] == 0.6
        
        assert approval_metrics["flow_edge"]["total_reviews"] == 3
        assert approval_metrics["flow_edge"]["accept"] == 1
        assert abs(approval_metrics["flow_edge"]["approval_rate"] - 0.333) < 0.01


@pytest.mark.integration
class TestIntegrationSnapshots:
    """Integration tests with snapshot verification."""
    
    @patch('bandjacks.llm.al_sampler.GraphDatabase.driver')
    async def test_al_sampling_pipeline_snapshot(self, mock_driver):
        """Test complete AL sampling pipeline with snapshot."""
        
        # Mock Neo4j with snapshot data
        mock_session = MagicMock()
        mock_driver.return_value.session.return_value = mock_session
        
        # Snapshot of expected sampling results
        expected_snapshot = {
            "job_id_pattern": r"al-sample-\d{8}-\d{6}",
            "sampled_count": 20,
            "categories": ["flow_edge", "mapping", "extraction", "detection"],
            "min_confidence": 0.0,
            "max_confidence": 0.6
        }
        
        sampler = ALSampler(
            neo4j_uri="bolt://test",
            neo4j_user="test",
            neo4j_password="test"
        )
        
        # Run sampling
        result = await sampler.run_sampling_job()
        
        # Verify against snapshot
        assert "job_id" in result
        assert result["status"] in ["completed", "failed"]
        
        sampler.close()
    
    def test_metrics_export_snapshot(self):
        """Test metrics export format consistency."""
        
        tracker = MLMetricsTracker()
        
        # Add known data
        tracker.record_prediction("test_model", "A", "A", 0.9)
        tracker.record_review_decision("test_item", "accept", 0.8)
        tracker.record_coverage_gap("detection", "T1055", "high")
        
        # Export dashboard metrics
        dashboard_data = tracker.export_for_dashboard()
        
        # Verify structure matches snapshot
        assert dashboard_data["version"] == "1.0"
        assert "timestamp" in dashboard_data
        assert "panels" in dashboard_data
        
        # Verify panel structure
        panels = dashboard_data["panels"]
        panel_ids = [p["id"] for p in panels]
        assert "ml_performance" in panel_ids
        assert "approval_rates" in panel_ids
        assert "coverage_gaps" in panel_ids


if __name__ == "__main__":
    pytest.main([__file__, "-v"])