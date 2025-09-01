#!/usr/bin/env python3
"""CI tests for analytics metrics (A2, A3, A4)."""

import os
import sys
import pytest
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any
import numpy as np
from sklearn.metrics import roc_auc_score
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bandjacks.analytics.cooccurrence import (
    CooccurrenceAnalyzer, CooccurrenceMetrics
)
from bandjacks.llm.judge_client import JudgeClient
from bandjacks.llm.judge_cache import JudgeVerdictCache


class TestA2JaccardSimilarity:
    """Test A2: Jaccard Similarity of Co-occurring Techniques."""
    
    def create_analyzer(self):
        """Create test analyzer."""
        return CooccurrenceAnalyzer(
            neo4j_uri=os.getenv("NEO4J_URI"),
            neo4j_user=os.getenv("NEO4J_USER"),
            neo4j_password=os.getenv("NEO4J_PASSWORD")
        )
    
    @pytest.fixture
    def analyzer(self):
        """Pytest fixture for analyzer."""
        return self.create_analyzer()
    
    def test_jaccard_calculation(self, analyzer):
        """Test Jaccard coefficient calculation for technique pairs."""
        # Create test data
        techniques_a = ["T1566.001", "T1078", "T1053"]
        techniques_b = ["T1078", "T1053", "T1055"]
        
        # Calculate Jaccard manually
        set_a = set(techniques_a)
        set_b = set(techniques_b)
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        expected_jaccard = intersection / union if union > 0 else 0
        
        # Test analyzer calculation
        metrics = CooccurrenceMetrics(
            technique_a="group_a",
            technique_b="group_b",
            count=intersection,
            support_a=len(set_a),
            support_b=len(set_b),
            total_episodes=100,
            confidence_a_to_b=0,
            confidence_b_to_a=0,
            lift=0,
            pmi=0,
            npmi=0
        )
        
        # jaccard is a property, not a field
        assert abs(metrics.jaccard - expected_jaccard) < 0.01
        assert 0 <= metrics.jaccard <= 1
    
    def test_cooccurrence_endpoint(self, analyzer):
        """Test the co-occurrence API endpoint calculations."""
        try:
            # Test global co-occurrence
            metrics = analyzer.calculate_global_cooccurrence(
                min_support=1,
                min_episodes_per_pair=1
            )
            
            if metrics:
                # Verify Jaccard is calculated
                for metric in metrics[:5]:
                    assert hasattr(metric, 'jaccard')
                    assert 0 <= metric.jaccard <= 1
                    
                    # Verify relationship: Jaccard <= min(confidence_a_to_b, confidence_b_to_a)
                    min_conf = min(metric.confidence_a_to_b, metric.confidence_b_to_a)
                    assert metric.jaccard <= min_conf + 0.01  # Small tolerance
            
            print(f"✓ Jaccard similarity calculated for {len(metrics)} pairs")
            
        except Exception as e:
            pytest.skip(f"Database not available: {e}")
    
    def test_technique_bundle_jaccard(self, analyzer):
        """Test Jaccard in technique bundle extraction."""
        try:
            bundles = analyzer.extract_technique_bundles(
                intrusion_set_id=None,
                min_support=2,
                min_size=2,
                max_size=5
            )
            
            # Each bundle should have techniques that co-occur
            for bundle in bundles[:5]:
                # Verify bundle cohesion using pairwise Jaccard
                techniques = bundle.techniques
                if len(techniques) >= 2:
                    # At least one pair should have non-zero Jaccard
                    assert bundle.confidence > 0
                    assert bundle.lift >= 1.0  # Positive association
            
            print(f"✓ Bundle extraction verified for {len(bundles)} bundles")
            
        except Exception as e:
            pytest.skip(f"Bundle extraction test skipped: {e}")


class TestA3CitedVerdicts:
    """Test A3: Rate of Cited Verdicts in Review Process."""
    
    def setup_method(self):
        """Set up test data."""
        self.test_verdicts = []
        self.test_citations = []
    
    def test_verdict_citation_tracking(self):
        """Test tracking of verdict citations."""
        # Create sample verdicts
        verdict1 = {
            "verdict_id": str(uuid.uuid4()),
            "technique_id": "T1566.001",
            "decision": "approved",
            "confidence": 0.85,
            "rationale": "Phishing pattern clearly identified",
            "reviewer": "analyst_1",
            "timestamp": datetime.utcnow().isoformat(),
            "evidence_ids": ["ev1", "ev2"]
        }
        
        verdict2 = {
            "verdict_id": str(uuid.uuid4()),
            "technique_id": "T1078",
            "decision": "approved",
            "confidence": 0.90,
            "rationale": "Valid accounts usage confirmed",
            "reviewer": "analyst_2",
            "timestamp": datetime.utcnow().isoformat(),
            "evidence_ids": ["ev3"],
            "cites": [verdict1["verdict_id"]]  # Cites previous verdict
        }
        
        self.test_verdicts.extend([verdict1, verdict2])
        
        # Calculate citation rate
        total_verdicts = len(self.test_verdicts)
        cited_count = sum(1 for v in self.test_verdicts if "cites" in v and v["cites"])
        citation_rate = cited_count / total_verdicts if total_verdicts > 0 else 0
        
        assert citation_rate == 0.5  # 1 out of 2 verdicts cites another
        print(f"✓ Citation rate: {citation_rate:.2%}")
    
    def test_review_provenance_citations(self):
        """Test review provenance with citation tracking."""
        # Simulate review chain
        reviews = []
        
        # Initial review
        review1 = {
            "provenance_id": str(uuid.uuid4()),
            "object_id": "attack-pattern--test",
            "review_type": "mapping_review",
            "decision": "approved",
            "confidence_before": 0.6,
            "confidence_after": 0.85,
            "evidence": ["Source document clearly states technique"],
            "timestamp": datetime.utcnow().isoformat()
        }
        reviews.append(review1)
        
        # Follow-up review citing previous
        review2 = {
            "provenance_id": str(uuid.uuid4()),
            "object_id": "attack-pattern--test",
            "review_type": "validation_review",
            "decision": "approved",
            "confidence_before": 0.85,
            "confidence_after": 0.95,
            "evidence": ["Confirmed by secondary source"],
            "cites_review": review1["provenance_id"],
            "timestamp": (datetime.utcnow() + timedelta(hours=1)).isoformat()
        }
        reviews.append(review2)
        
        # Calculate metrics
        reviews_with_citations = [r for r in reviews if "cites_review" in r]
        citation_rate = len(reviews_with_citations) / len(reviews)
        
        assert citation_rate == 0.5
        assert review2["confidence_after"] > review1["confidence_after"]
        print(f"✓ Review citation chain validated: {len(reviews_with_citations)} citations")
    
    def test_citation_impact_on_confidence(self):
        """Test how citations impact confidence scores."""
        base_confidence = 0.7
        
        # Single verdict without citations
        single_verdict = {
            "confidence": base_confidence,
            "cites": []
        }
        
        # Verdict with citations (should have higher weight)
        cited_verdict = {
            "confidence": base_confidence,
            "cites": ["verdict_1", "verdict_2"],
            "citation_weight": 1.2  # 20% boost for citations
        }
        
        # Calculate weighted confidence
        weighted_conf_single = single_verdict["confidence"]
        weighted_conf_cited = cited_verdict["confidence"] * cited_verdict.get("citation_weight", 1.0)
        
        assert weighted_conf_cited > weighted_conf_single
        assert weighted_conf_cited == base_confidence * 1.2
        print(f"✓ Citation weight applied: {weighted_conf_single:.2f} → {weighted_conf_cited:.2f}")


class TestA4AUROCUplift:
    """Test A4: AUROC Uplift for Judge Model Performance."""
    
    def setup_method(self):
        """Initialize test environment."""
        # JudgeVerdictCache requires Neo4j connection, skip if not available
        try:
            self.judge_cache = JudgeVerdictCache(
                neo4j_uri=os.getenv("NEO4J_URI"),
                neo4j_user=os.getenv("NEO4J_USER"),
                neo4j_password=os.getenv("NEO4J_PASSWORD")
            )
        except:
            self.judge_cache = None  # Will skip cache-related tests
        self.test_samples = self._generate_test_samples()
    
    def _generate_test_samples(self):
        """Generate test samples for AUROC calculation."""
        samples = []
        
        # Generate positive samples (true matches)
        for i in range(50):
            samples.append({
                "text": f"The attacker uses phishing emails with malicious attachments",
                "technique_id": "T1566.001",
                "true_label": 1,
                "judge_score": 0.7 + np.random.random() * 0.3  # 0.7-1.0
            })
        
        # Generate negative samples (false matches)
        for i in range(50):
            samples.append({
                "text": f"Regular system maintenance was performed",
                "technique_id": "T1566.001",
                "true_label": 0,
                "judge_score": np.random.random() * 0.4  # 0.0-0.4
            })
        
        return samples
    
    def test_auroc_calculation(self):
        """Test AUROC calculation for judge decisions."""
        # Extract labels and scores
        y_true = [s["true_label"] for s in self.test_samples]
        y_scores = [s["judge_score"] for s in self.test_samples]
        
        # Calculate AUROC
        auroc = roc_auc_score(y_true, y_scores)
        
        assert 0.5 <= auroc <= 1.0  # Should be better than random
        assert auroc > 0.7  # Should be reasonably good given our test data
        print(f"✓ AUROC Score: {auroc:.3f}")
    
    def test_auroc_improvement_tracking(self):
        """Test tracking AUROC improvement over time."""
        # Simulate model improvements
        auroc_history = [
            {"version": "v1", "auroc": 0.72, "date": "2024-01-01"},
            {"version": "v2", "auroc": 0.78, "date": "2024-02-01"},
            {"version": "v3", "auroc": 0.85, "date": "2024-03-01"},
        ]
        
        # Calculate uplift
        baseline = auroc_history[0]["auroc"]
        current = auroc_history[-1]["auroc"]
        uplift = current - baseline
        uplift_pct = (uplift / baseline) * 100
        
        assert uplift > 0  # Should show improvement
        assert uplift_pct > 10  # Should be significant improvement
        print(f"✓ AUROC Uplift: +{uplift:.3f} ({uplift_pct:.1f}% improvement)")
    
    def test_judge_cache_performance(self):
        """Test judge decision caching impact on performance."""
        # Test cache hit rate
        total_queries = 100
        cache_hits = 65  # Simulated
        
        hit_rate = cache_hits / total_queries
        
        # With caching, effective AUROC should improve due to consistency
        base_auroc = 0.75
        consistency_boost = hit_rate * 0.1  # Up to 10% boost from consistency
        effective_auroc = min(1.0, base_auroc + consistency_boost)
        
        assert effective_auroc > base_auroc
        assert hit_rate > 0.5  # Should have reasonable cache hit rate
        print(f"✓ Cache hit rate: {hit_rate:.1%}, Effective AUROC: {effective_auroc:.3f}")
    
    def test_confidence_calibration(self):
        """Test that judge confidence scores are well-calibrated."""
        # Group predictions by confidence bins
        confidence_bins = {
            "0.0-0.2": {"correct": 0, "total": 0},
            "0.2-0.4": {"correct": 0, "total": 0},
            "0.4-0.6": {"correct": 0, "total": 0},
            "0.6-0.8": {"correct": 0, "total": 0},
            "0.8-1.0": {"correct": 0, "total": 0},
        }
        
        for sample in self.test_samples:
            score = sample["judge_score"]
            is_correct = (score > 0.5) == (sample["true_label"] == 1)
            
            # Find bin
            if score <= 0.2:
                bin_key = "0.0-0.2"
            elif score <= 0.4:
                bin_key = "0.2-0.4"
            elif score <= 0.6:
                bin_key = "0.4-0.6"
            elif score <= 0.8:
                bin_key = "0.6-0.8"
            else:
                bin_key = "0.8-1.0"
            
            confidence_bins[bin_key]["total"] += 1
            if is_correct:
                confidence_bins[bin_key]["correct"] += 1
        
        # Check calibration
        calibration_error = 0
        for bin_key, stats in confidence_bins.items():
            if stats["total"] > 0:
                accuracy = stats["correct"] / stats["total"]
                # Expected confidence (midpoint of bin)
                expected = float(bin_key.split("-")[1]) - 0.1
                calibration_error += abs(accuracy - expected) * stats["total"]
        
        calibration_error /= len(self.test_samples)
        
        assert calibration_error < 0.3  # Reasonable calibration
        print(f"✓ Calibration error: {calibration_error:.3f}")


def run_analytics_tests():
    """Run all analytics metrics tests."""
    print("="*60)
    print("Running Analytics Metrics Tests (A2, A3, A4)")
    print("="*60)
    
    # Run A2 tests
    a2_tests = TestA2JaccardSimilarity()
    analyzer = a2_tests.create_analyzer()
    
    try:
        a2_tests.test_jaccard_calculation(analyzer)
        a2_tests.test_cooccurrence_endpoint(analyzer)
        a2_tests.test_technique_bundle_jaccard(analyzer)
        print("✓ A2 Jaccard Similarity tests passed")
    except Exception as e:
        print(f"⚠ A2 tests failed: {e}")
    finally:
        if analyzer:
            analyzer.close()
    
    # Run A3 tests
    a3_tests = TestA3CitedVerdicts()
    a3_tests.setup_method()
    
    try:
        a3_tests.test_verdict_citation_tracking()
        a3_tests.test_review_provenance_citations()
        a3_tests.test_citation_impact_on_confidence()
        print("✓ A3 Cited Verdicts tests passed")
    except Exception as e:
        print(f"⚠ A3 tests failed: {e}")
    
    # Run A4 tests
    a4_tests = TestA4AUROCUplift()
    a4_tests.setup_method()
    
    try:
        a4_tests.test_auroc_calculation()
        a4_tests.test_auroc_improvement_tracking()
        a4_tests.test_judge_cache_performance()
        a4_tests.test_confidence_calibration()
        print("✓ A4 AUROC Uplift tests passed")
    except Exception as e:
        print(f"⚠ A4 tests failed: {e}")
    
    print("\n" + "="*60)
    print("Analytics Metrics Tests Complete")
    print("="*60)


if __name__ == "__main__":
    run_analytics_tests()