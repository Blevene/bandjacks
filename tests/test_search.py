"""Tests for search endpoints."""

from bandjacks.services.api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_ttx_search():
    """Test text-to-technique search endpoint."""
    # Test with a query about process injection
    response = client.post(
        "/v1/search/ttx",
        json={
            "text": "injecting code into running processes to evade detection",
            "top_k": 5
        }
    )
    
    # Allow 200 (success) or 502 (OpenSearch not available)
    assert response.status_code in (200, 502)
    
    if response.status_code == 200:
        data = response.json()
        assert "results" in data
        results = data["results"]
        
        # Check result structure if we got results
        if results:
            first = results[0]
            assert "stix_id" in first
            assert "kb_type" in first
            assert "score" in first
            assert "name_or_snippet" in first

def test_ttx_search_empty():
    """Test TTX search with empty query."""
    response = client.post(
        "/v1/search/ttx",
        json={
            "text": "",
            "top_k": 5
        }
    )
    
    # Should handle empty text gracefully
    assert response.status_code in (200, 502)
    
    if response.status_code == 200:
        data = response.json()
        assert "results" in data
        # Empty text should return empty results
        assert data["results"] == []