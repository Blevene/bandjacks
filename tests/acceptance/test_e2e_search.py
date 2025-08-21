"""End-to-end acceptance tests for search functionality."""

import pytest
import httpx
import time
from typing import List, Dict, Any

BASE_URL = "http://localhost:8000/v1"


class TestE2ESearch:
    """Test complete search workflow."""
    
    @pytest.fixture(scope="class")
    def api_client(self):
        """Create HTTP client for API calls."""
        with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
            yield client
    
    @pytest.fixture(scope="class")
    def ensure_test_data(self, api_client):
        """Ensure test data is loaded."""
        # Create test techniques for searching
        bundle = {
            "type": "bundle",
            "id": "bundle--search-test-data",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--search-001",
                    "created": "2024-01-01T00:00:00.000Z",
                    "modified": "2024-01-01T00:00:00.000Z",
                    "name": "Credential Dumping via Registry",
                    "description": "Adversaries may attempt to extract credential material from the Registry",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
                    "x_mitre_platforms": ["Windows"]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--search-002",
                    "created": "2024-01-01T00:00:00.000Z",
                    "modified": "2024-01-01T00:00:00.000Z",
                    "name": "PowerShell Script Execution",
                    "description": "Adversaries may use PowerShell to perform malicious actions",
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                    "x_mitre_platforms": ["Windows"]
                },
                {
                    "type": "intrusion-set",
                    "id": "intrusion-set--search-001",
                    "created": "2024-01-01T00:00:00.000Z",
                    "modified": "2024-01-01T00:00:00.000Z",
                    "name": "Test APT Group",
                    "description": "A sophisticated threat actor group for testing",
                    "aliases": ["TestAPT", "GhostTest"]
                },
                {
                    "type": "malware",
                    "id": "malware--search-001",
                    "created": "2024-01-01T00:00:00.000Z",
                    "modified": "2024-01-01T00:00:00.000Z",
                    "name": "TestRAT",
                    "description": "Remote access trojan used for testing",
                    "malware_types": ["remote-access-trojan"]
                }
            ]
        }
        
        response = api_client.post("/stix/bundles", json=bundle, params={"strict": False})
        assert response.status_code == 200
        
        # Wait for indexing
        time.sleep(2)
        
        return bundle["objects"]
    
    def test_01_text_to_technique_search(self, api_client, ensure_test_data):
        """Test text-to-technique (TTX) search."""
        queries = [
            ("credential dumping registry", "Credential Dumping via Registry"),
            ("powershell execution", "PowerShell Script Execution"),
            ("extract passwords from windows", "Credential Dumping via Registry"),
        ]
        
        for query_text, expected_name in queries:
            response = api_client.post(
                "/search/ttx",
                json={"text": query_text, "top_k": 10}
            )
            
            assert response.status_code == 200
            data = response.json()
            
            assert "results" in data
            assert len(data["results"]) > 0
            
            # Check if expected result is in top results
            found = any(
                expected_name in r.get("kb_name", "")
                for r in data["results"][:3]
            )
            assert found, f"Expected '{expected_name}' not found for query '{query_text}'"
            
            # Verify result structure
            result = data["results"][0]
            assert "score" in result
            assert "kb_id" in result
            assert "kb_name" in result
            assert "kb_type" in result
            assert result["score"] > 0
    
    def test_02_filtered_search(self, api_client, ensure_test_data):
        """Test search with type filtering."""
        # Search only for groups
        response = api_client.post(
            "/search/ttx",
            json={
                "text": "sophisticated threat actor",
                "top_k": 10,
                "kb_types": ["IntrusionSet"]
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should only return IntrusionSet types
        for result in data["results"]:
            assert result["kb_type"] == "IntrusionSet"
        
        # Should find our test group
        found = any(
            "Test APT Group" in r.get("kb_name", "")
            for r in data["results"]
        )
        assert found
    
    def test_03_multi_type_search(self, api_client, ensure_test_data):
        """Test searching across multiple entity types."""
        response = api_client.post(
            "/search/ttx",
            json={
                "text": "remote access",
                "top_k": 20,
                "kb_types": ["AttackPattern", "Software"]
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should return multiple types
        types_found = set(r["kb_type"] for r in data["results"])
        assert len(types_found) >= 1  # At least one type
        
        # All results should be of requested types
        for result in data["results"]:
            assert result["kb_type"] in ["AttackPattern", "Software"]
    
    def test_04_search_performance(self, api_client):
        """Test search performance benchmarks."""
        queries = [
            "lateral movement techniques",
            "data exfiltration over DNS",
            "privilege escalation windows",
            "ransomware encryption",
            "phishing email attachment"
        ]
        
        response_times = []
        
        for query in queries:
            start_time = time.time()
            
            response = api_client.post(
                "/search/ttx",
                json={"text": query, "top_k": 10}
            )
            
            elapsed = time.time() - start_time
            response_times.append(elapsed)
            
            assert response.status_code == 200
            assert elapsed < 1.0  # Should respond within 1 second
        
        avg_time = sum(response_times) / len(response_times)
        p95_time = sorted(response_times)[int(len(response_times) * 0.95)]
        
        print(f"\nSearch Performance:")
        print(f"  Average: {avg_time*1000:.2f}ms")
        print(f"  P95: {p95_time*1000:.2f}ms")
        
        # Performance requirements
        assert avg_time < 0.5  # Average under 500ms
        assert p95_time < 1.0  # P95 under 1 second
    
    def test_05_search_relevance_feedback(self, api_client):
        """Test search with relevance feedback loop."""
        # Initial search
        response = api_client.post(
            "/search/ttx",
            json={"text": "credential theft", "top_k": 5}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Submit relevance feedback for top result
        if data["results"]:
            top_result = data["results"][0]
            
            feedback_response = api_client.post(
                "/feedback/relevance",
                json={
                    "object_id": top_result["kb_id"],
                    "relevance": "relevant",
                    "comment": "Highly relevant to credential theft",
                    "analyst_id": "test-analyst"
                }
            )
            
            assert feedback_response.status_code == 200
            
            # Search again - relevance feedback should be recorded
            response2 = api_client.post(
                "/search/ttx",
                json={"text": "credential theft", "top_k": 5}
            )
            
            assert response2.status_code == 200
    
    def test_06_empty_search_handling(self, api_client):
        """Test handling of edge cases in search."""
        # Empty query
        response = api_client.post(
            "/search/ttx",
            json={"text": "", "top_k": 10}
        )
        
        # Should handle gracefully (either error or empty results)
        assert response.status_code in [200, 400, 422]
        
        # Very long query
        long_query = " ".join(["test"] * 500)
        response = api_client.post(
            "/search/ttx",
            json={"text": long_query, "top_k": 10}
        )
        
        assert response.status_code in [200, 400]
        
        # Special characters
        response = api_client.post(
            "/search/ttx",
            json={"text": "!@#$%^&*()", "top_k": 10}
        )
        
        assert response.status_code in [200, 400]
    
    def test_07_search_quality_scoring(self, api_client):
        """Test quality scoring for search results."""
        # Perform search
        response = api_client.post(
            "/search/ttx",
            json={"text": "powershell", "top_k": 5}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        if data["results"]:
            # Submit quality scores for search results
            scores = []
            for result in data["results"][:3]:
                scores.append({
                    "object_id": result["kb_id"],
                    "accuracy": 4,
                    "relevance": 5,
                    "completeness": 3,
                    "clarity": 4,
                    "analyst_id": "test-analyst"
                })
            
            feedback_response = api_client.post(
                "/feedback/quality",
                json={
                    "scores": scores,
                    "context": "search-quality-test"
                }
            )
            
            assert feedback_response.status_code == 200
            feedback_data = feedback_response.json()
            
            assert feedback_data["scores_recorded"] == len(scores)
            assert feedback_data["average_overall"] > 0
            assert "trace_id" in feedback_data
    
    def test_08_search_drift_detection(self, api_client):
        """Test drift detection after search operations."""
        # Check drift metrics
        response = api_client.get("/drift/metrics/confidence")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["metric_name"] == "confidence_scores"
        assert "current_value" in data
        assert "baseline_value" in data
        assert "drift_percentage" in data
        assert "is_significant" in data


@pytest.mark.benchmark
class TestSearchBenchmarks:
    """Performance benchmarks for search functionality."""
    
    def test_concurrent_search_load(self, api_client):
        """Test search under concurrent load."""
        import concurrent.futures
        
        def search_query(query):
            """Execute a single search query."""
            try:
                response = api_client.post(
                    "/search/ttx",
                    json={"text": query, "top_k": 10}
                )
                return response.status_code == 200, response.elapsed.total_seconds()
            except:
                return False, None
        
        queries = [
            "lateral movement",
            "data exfiltration",
            "privilege escalation",
            "persistence mechanisms",
            "defense evasion"
        ] * 10  # 50 total queries
        
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(search_query, queries))
        
        total_time = time.time() - start_time
        
        successful = sum(1 for success, _ in results if success)
        response_times = [t for success, t in results if success and t is not None]
        
        print(f"\nConcurrent Search Load Test:")
        print(f"  Total queries: {len(queries)}")
        print(f"  Successful: {successful}")
        print(f"  Total time: {total_time:.2f}s")
        print(f"  Throughput: {len(queries)/total_time:.2f} queries/sec")
        
        if response_times:
            print(f"  Avg response: {sum(response_times)/len(response_times)*1000:.2f}ms")
        
        # All queries should succeed
        assert successful == len(queries)
        # Should handle at least 10 queries per second
        assert len(queries) / total_time > 10