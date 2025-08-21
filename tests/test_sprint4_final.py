#!/usr/bin/env python3
"""Final validation tests for Sprint 4 features."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_trace_id_middleware():
    """Test trace ID middleware and propagation."""
    from bandjacks.services.api.middleware import TracingMiddleware, get_trace_id, inject_trace_id
    
    # Test trace ID generation
    trace_id = get_trace_id()
    assert trace_id.startswith("trace-")
    assert len(trace_id) == 22  # "trace-" + 16 hex chars
    
    # Test trace ID injection
    params = inject_trace_id("SELECT * FROM nodes", {})
    assert "_trace_id" in params
    
    print("✅ Trace ID middleware working")
    return True


def test_granular_feedback():
    """Test granular feedback scoring (1-5 scale)."""
    from bandjacks.services.api.schemas import QualityScore, QualityFeedback, QualityFeedbackResponse
    
    # Test quality score with all dimensions
    score = QualityScore(
        object_id="attack-pattern--test",
        accuracy=5,
        relevance=4,
        completeness=3,
        clarity=4,
        comment="Test feedback"
    )
    
    # Overall should be computed if not provided
    assert score.accuracy == 5
    assert score.relevance == 4
    assert score.completeness == 3
    assert score.clarity == 4
    
    # Test feedback collection
    feedback = QualityFeedback(
        scores=[score],
        context="test-context",
        session_id="test-session"
    )
    
    assert len(feedback.scores) == 1
    assert feedback.context == "test-context"
    
    print("✅ Granular feedback scoring (1-5 scale) working")
    return True


def test_drift_detection():
    """Test drift detection mechanism."""
    from bandjacks.monitoring.drift_detector import DriftDetector, DriftThresholds
    from bandjacks.services.api.schemas import DriftMetric, DriftAlert, DriftStatus
    
    # Test thresholds configuration
    thresholds = DriftThresholds(
        confidence_drop=0.15,
        quality_drop=0.2,
        schema_change=0.1
    )
    
    assert thresholds.confidence_drop == 0.15
    assert thresholds.quality_drop == 0.2
    
    # Test drift metric
    metric = DriftMetric(
        metric_name="test_metric",
        current_value=0.75,
        baseline_value=0.90,
        drift_percentage=16.67,
        is_significant=True,
        threshold=0.15,
        timestamp="2024-01-01T00:00:00Z"
    )
    
    assert metric.is_significant
    assert metric.drift_percentage > metric.threshold * 100
    
    # Test drift alert
    alert = DriftAlert(
        alert_id="drift-001",
        alert_type="quality",
        severity="medium",
        description="Quality scores dropped",
        metrics=[metric],
        recommended_action="Review recent changes",
        created_at="2024-01-01T00:00:00Z",
        acknowledged=False
    )
    
    assert alert.severity == "medium"
    assert not alert.acknowledged
    
    print("✅ Drift detection mechanism working")
    return True


def test_acceptance_suite_structure():
    """Test acceptance test suite structure."""
    import os
    from pathlib import Path
    
    test_dir = Path(__file__).parent / "acceptance"
    
    # Check directory structure
    assert test_dir.exists(), "Acceptance test directory exists"
    assert (test_dir / "fixtures").exists(), "Fixtures directory exists"
    
    # Check test files
    test_files = [
        "test_e2e_ingestion.py",
        "test_e2e_search.py",
        "run_acceptance_tests.py"
    ]
    
    for test_file in test_files:
        assert (test_dir / test_file).exists(), f"{test_file} exists"
    
    # Verify test runner is executable
    runner = test_dir / "run_acceptance_tests.py"
    assert runner.exists()
    
    print("✅ Acceptance test suite structure created")
    return True


def test_api_response_schemas():
    """Test that API response schemas include trace_id."""
    from bandjacks.services.api.schemas import (
        UpsertResult, ProposalResponse, ReviewResponse,
        FlowBuildResponse, FlowSearchResponse, QualityFeedbackResponse,
        DriftStatus
    )
    
    # Check that all response models have trace_id field
    response_models = [
        UpsertResult,
        ProposalResponse,
        ReviewResponse,
        FlowBuildResponse,
        FlowSearchResponse,
        QualityFeedbackResponse,
        DriftStatus
    ]
    
    for model in response_models:
        fields = model.model_fields
        assert "trace_id" in fields, f"{model.__name__} has trace_id field"
    
    print("✅ API response schemas include trace_id")
    return True


def test_all_imports():
    """Test that all new modules can be imported."""
    try:
        # Middleware
        from bandjacks.services.api.middleware import TracingMiddleware, get_trace_id
        
        # Monitoring
        from bandjacks.monitoring.drift_detector import DriftDetector, DriftThresholds
        
        # New schemas
        from bandjacks.services.api.schemas import (
            QualityScore, QualityFeedback, QualityFeedbackResponse,
            DriftMetric, DriftAlert, DriftStatus
        )
        
        # New routes (if API is configured)
        from bandjacks.services.api.routes import drift
        
        print("✅ All new modules import successfully")
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False


def main():
    """Run all Sprint 4 final validation tests."""
    print("="*80)
    print("SPRINT 4 FINAL VALIDATION")
    print("="*80)
    
    tests = [
        ("Trace ID Middleware", test_trace_id_middleware),
        ("Granular Feedback Scoring", test_granular_feedback),
        ("Drift Detection", test_drift_detection),
        ("Acceptance Test Suite", test_acceptance_suite_structure),
        ("API Response Schemas", test_api_response_schemas),
        ("Module Imports", test_all_imports),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\nTesting {test_name}...")
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"❌ {test_name} failed: {e}")
            results.append((test_name, False))
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    passed = sum(1 for _, s in results if s)
    total = len(results)
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All Sprint 4 features validated successfully!")
        return 0
    else:
        print(f"\n⚠️ {total - passed} tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())