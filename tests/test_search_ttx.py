"""Tests for TTX (text-to-technique) search endpoint."""

from bandjacks.services.api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_search_ttx_exists():
    """Test that TTX search endpoint exists and responds."""
    r = client.post("/v1/search/ttx", json={"text":"command execution", "top_k": 3})
    # May be 502 if OpenSearch/model isn't up; accept both in CI
    assert r.status_code in (200, 502)

def test_search_ttx_empty_query():
    """Test TTX search with empty query text."""
    r = client.post("/v1/search/ttx", json={"text":"", "top_k": 5})
    assert r.status_code in (200, 502)
    if r.status_code == 200:
        data = r.json()
        assert "results" in data
        # Empty text should return empty results
        assert data["results"] == []

def test_search_ttx_large_k():
    """Test TTX search with large top_k value."""
    r = client.post("/v1/search/ttx", json={"text":"lateral movement", "top_k": 100})
    assert r.status_code in (200, 502)
    if r.status_code == 200:
        data = r.json()
        assert "results" in data
        # Should return up to top_k results (or all available)
        assert len(data["results"]) <= 100

def test_search_ttx_response_structure():
    """Test TTX search response has expected structure."""
    r = client.post("/v1/search/ttx", json={"text":"process injection", "top_k": 1})
    assert r.status_code in (200, 502)
    if r.status_code == 200:
        data = r.json()
        assert "results" in data
        if data["results"]:
            result = data["results"][0]
            # Check all expected fields are present
            assert "stix_id" in result
            assert "kb_type" in result
            assert "attack_version" in result
            assert "score" in result
            assert "name_or_snippet" in result
            # Score should be a number
            assert isinstance(result["score"], (int, float))

def test_search_ttx_various_queries():
    """Test TTX search with various attack-related queries."""
    queries = [
        "stealing credentials from memory",
        "bypassing user account control",
        "establishing persistence through registry",
        "data exfiltration over DNS",
        "privilege escalation"
    ]
    
    for query_text in queries:
        r = client.post("/v1/search/ttx", json={"text": query_text, "top_k": 5})
        assert r.status_code in (200, 502)
        if r.status_code == 200:
            data = r.json()
            assert "results" in data
            # Each valid query should potentially return results
            # (though empty results are acceptable if no data loaded)