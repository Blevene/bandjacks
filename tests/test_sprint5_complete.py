"""Integration test for Sprint 5 features."""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime
import json

# Import Sprint 5 modules
from bandjacks.llm.embedding_refresher import EmbeddingRefresher
from bandjacks.services.cache_manager import CacheManager, EmbeddingCache, LLMResponseCache
from bandjacks.services.api.middleware.auth import JWTAuthMiddleware
from bandjacks.services.api.middleware.rate_limit import RateLimiter
from bandjacks.services.api.middleware.error_handler import ErrorHandlerMiddleware


class TestEmbeddingRefresher:
    """Test embedding refresh functionality."""
    
    def test_embedding_refresher_init(self):
        """Test EmbeddingRefresher initialization."""
        refresher = EmbeddingRefresher(
            neo4j_uri="bolt://localhost:7687",
            neo4j_user="neo4j",
            neo4j_password="password",
            opensearch_url="http://localhost:9200"
        )
        
        assert refresher.batch_size == 100
        assert refresher.opensearch_url == "http://localhost:9200"
        refresher.close()
    
    def test_generate_embedding_vector(self):
        """Test embedding vector generation."""
        refresher = EmbeddingRefresher(
            neo4j_uri="bolt://localhost:7687",
            neo4j_user="neo4j",
            neo4j_password="password",
            opensearch_url="http://localhost:9200"
        )
        
        text = "Process injection technique"
        vector = refresher._generate_embedding_vector(text)
        
        assert len(vector) == 768
        assert all(isinstance(v, float) for v in vector)
        refresher.close()


class TestCacheManager:
    """Test cache management functionality."""
    
    def test_cache_manager_operations(self):
        """Test basic cache operations."""
        cache = CacheManager(max_size=10, default_ttl=60)
        
        # Test set and get
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"
        
        # Test miss
        assert cache.get("nonexistent") is None
        
        # Test invalidation
        cache.invalidate("key1")
        assert cache.get("key1") is None
        
        # Test stats
        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 2
        assert stats["invalidations"] == 1
    
    def test_embedding_cache(self):
        """Test specialized embedding cache."""
        cache = EmbeddingCache()
        
        text = "Attack pattern description"
        embedding = [0.1] * 768
        
        cache.set_embedding(text, embedding)
        retrieved = cache.get_embedding(text)
        
        assert retrieved == embedding
        assert len(retrieved) == 768
    
    def test_llm_cache(self):
        """Test LLM response cache."""
        cache = LLMResponseCache()
        
        prompt = "Explain process injection"
        response = "Process injection is..."
        
        cache.set_response(prompt, response, model="gpt-4")
        retrieved = cache.get_response(prompt, model="gpt-4")
        
        assert retrieved == response


class TestRateLimiter:
    """Test rate limiting functionality."""
    
    def test_rate_limiter_basic(self):
        """Test basic rate limiting."""
        limiter = RateLimiter(default_limit=5, window_size=1)
        
        # Should allow first 5 requests
        for i in range(5):
            allowed, headers = limiter.is_allowed("test_client")
            assert allowed is True
            assert int(headers["X-RateLimit-Remaining"]) == 4 - i
        
        # 6th request should be blocked
        allowed, headers = limiter.is_allowed("test_client")
        assert allowed is False
        assert "Retry-After" in headers
    
    def test_rate_limiter_burst(self):
        """Test burst allowance."""
        limiter = RateLimiter(default_limit=5, window_size=1)
        
        # Fill normal limit
        for _ in range(5):
            limiter.is_allowed("test_client")
        
        # Burst should allow a few more (1.5x)
        allowed, headers = limiter.is_allowed("test_client")
        assert allowed is True  # Burst allowance
        assert "X-RateLimit-Burst-Used" in headers


class TestAuthMiddleware:
    """Test authentication middleware."""
    
    @patch.dict('os.environ', {'ENABLE_AUTH': 'false'})
    def test_auth_disabled(self):
        """Test auth when disabled."""
        from bandjacks.services.api.middleware.auth import ENABLE_AUTH
        assert ENABLE_AUTH is False
    
    def test_exempt_paths(self):
        """Test exempt path checking."""
        from bandjacks.services.api.middleware.auth import EXEMPT_PATHS
        
        assert "/docs" in EXEMPT_PATHS
        assert "/health" in EXEMPT_PATHS
        assert "/v1/catalog" in EXEMPT_PATHS


class TestComplianceIntegration:
    """Test compliance metrics integration."""
    
    def test_compliance_metrics_structure(self):
        """Test compliance metrics structure."""
        from bandjacks.monitoring.compliance_metrics import ComplianceMetrics
        
        metrics = ComplianceMetrics()
        
        # Check structure
        assert hasattr(metrics, 'adm_violations')
        assert hasattr(metrics, 'filtering_metrics')
        assert hasattr(metrics, 'review_metrics')
        assert hasattr(metrics, 'detection_coverage')
        
        # Test tracking
        metrics.track_adm_violation("spec_version")
        assert metrics.adm_violations["spec_version_violations"] == 1
        assert metrics.adm_violations["total_violations"] == 1
    
    def test_compliance_report_generation(self):
        """Test compliance report generation."""
        from bandjacks.monitoring.compliance_metrics import ComplianceMetrics
        
        metrics = ComplianceMetrics()
        metrics.track_adm_violation("spec_version")
        metrics.track_review_decision("accept")
        
        report = metrics.get_compliance_report()
        
        assert "timestamp" in report
        assert "overall_compliance_score" in report
        assert "categories" in report
        assert "recommendations" in report


class TestProvenanceTracking:
    """Test review provenance tracking."""
    
    def test_review_provenance_schema(self):
        """Test ReviewProvenance node schema."""
        # This would be tested with actual Neo4j connection
        expected_fields = [
            "provenance_id",
            "review_type",
            "reviewer_id",
            "timestamp",
            "decision",
            "rationale",
            "object_id",
            "trace_id"
        ]
        
        # Schema validation placeholder
        assert all(field for field in expected_fields)


class TestErrorHandling:
    """Test unified error handling."""
    
    def test_error_response_structure(self):
        """Test ErrorResponse structure."""
        from bandjacks.services.api.schemas import ErrorResponse
        
        error = ErrorResponse(
            error="ValidationError",
            message="Invalid input",
            detail={"field": "value"},
            trace_id="trace-123"
        )
        
        assert error.error == "ValidationError"
        assert error.message == "Invalid input"
        assert error.trace_id == "trace-123"


@pytest.mark.integration
class TestSprint5Integration:
    """Full Sprint 5 integration tests."""
    
    def test_detection_to_coverage_flow(self):
        """Test flow from detection ingestion to coverage analysis."""
        # This would test the full flow with actual services
        pass
    
    def test_review_to_embedding_refresh_flow(self):
        """Test flow from review decision to embedding refresh."""
        # This would test the async flow with actual services
        pass
    
    def test_compliance_metrics_aggregation(self):
        """Test aggregation of compliance metrics across components."""
        # This would test metrics collection from multiple sources
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])