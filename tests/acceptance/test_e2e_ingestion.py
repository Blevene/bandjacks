"""End-to-end acceptance tests for data ingestion."""

import pytest
import httpx
import time
from typing import Dict, Any
from datetime import datetime

# Base URL for API testing
BASE_URL = "http://localhost:8000/v1"


class TestE2EIngestion:
    """Test complete ingestion workflow."""
    
    @pytest.fixture(scope="class")
    def api_client(self):
        """Create HTTP client for API calls."""
        with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
            yield client
    
    def test_01_catalog_retrieval(self, api_client):
        """Test retrieving ATT&CK catalog."""
        response = api_client.get("/catalog/attack/releases")
        assert response.status_code == 200
        
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        
        # Check structure
        catalog_item = data[0]
        assert "name" in catalog_item
        assert "key" in catalog_item
        assert "versions" in catalog_item
        assert len(catalog_item["versions"]) > 0
        
        # Verify trace ID is present
        assert "x-trace-id" in response.headers
    
    def test_02_load_attack_collection(self, api_client):
        """Test loading ATT&CK collection."""
        # Load a specific version (or latest)
        response = api_client.post(
            "/stix/load/attack",
            params={
                "collection": "enterprise-attack",
                "version": "latest",
                "adm_strict": True
            }
        )
        
        # Allow for longer processing time
        if response.status_code == 502:
            # Retry once if gateway timeout
            time.sleep(5)
            response = api_client.post(
                "/stix/load/attack",
                params={
                    "collection": "enterprise-attack",
                    "version": "latest",
                    "adm_strict": True
                }
            )
        
        assert response.status_code == 200
        
        data = response.json()
        assert "inserted" in data
        assert "updated" in data
        assert "provenance" in data
        assert "trace_id" in data
        
        # Should have loaded some data
        assert data["inserted"] + data["updated"] > 0
        
        # Check provenance
        prov = data["provenance"]
        assert prov["collection"] == "enterprise-attack"
        assert "version" in prov
        assert "url" in prov
    
    def test_03_ingest_custom_bundle(self, api_client):
        """Test ingesting a custom STIX bundle."""
        # Create a minimal valid STIX bundle
        bundle = {
            "type": "bundle",
            "id": "bundle--test-" + datetime.utcnow().isoformat(),
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--test-123",
                    "created": "2024-01-01T00:00:00.000Z",
                    "modified": "2024-01-01T00:00:00.000Z",
                    "name": "Test Technique",
                    "description": "A test technique for acceptance testing",
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": "execution"
                        }
                    ],
                    "x_mitre_is_subtechnique": False,
                    "x_mitre_platforms": ["Windows", "Linux"],
                    "x_mitre_detection": "Monitor for unusual process execution",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T9999",
                            "url": "https://attack.mitre.org/techniques/T9999"
                        }
                    ]
                }
            ]
        }
        
        response = api_client.post(
            "/stix/bundles",
            json=bundle,
            params={"strict": False}  # Disable strict validation for test data
        )
        
        assert response.status_code == 200
        
        data = response.json()
        assert data["inserted"] == 1
        assert data["trace_id"] is not None
        
        # Verify provenance
        assert data["provenance"]["collection"] == "user-supplied"
    
    def test_04_verify_data_loaded(self, api_client):
        """Verify data was successfully loaded into the graph."""
        # Search for techniques
        response = api_client.post(
            "/search/ttx",
            json={
                "text": "process execution monitoring",
                "top_k": 5
            }
        )
        
        assert response.status_code == 200
        
        data = response.json()
        assert "results" in data
        assert len(data["results"]) > 0
        
        # At least one result should be found
        result = data["results"][0]
        assert "score" in result
        assert "kb_id" in result
        assert "kb_name" in result
    
    def test_05_check_drift_after_ingestion(self, api_client):
        """Check drift status after data ingestion."""
        response = api_client.get("/drift/status")
        
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "metrics" in data
        assert "trace_id" in data
        
        # Check metrics are present
        metrics = data["metrics"]
        assert "version" in metrics
        assert "confidence" in metrics
        assert "quality" in metrics
        assert "schema" in metrics
        
        # Version metric should show consistency if only one version loaded
        version_metric = metrics["version"]
        assert version_metric["metric_name"] == "version_consistency"
        assert version_metric["drift_percentage"] >= 0
    
    def test_06_submit_quality_feedback(self, api_client):
        """Test submitting quality feedback for ingested data."""
        response = api_client.post(
            "/feedback/quality",
            json={
                "scores": [
                    {
                        "object_id": "attack-pattern--test-123",
                        "accuracy": 4,
                        "relevance": 5,
                        "completeness": 3,
                        "clarity": 4,
                        "comment": "Good test data for acceptance testing",
                        "analyst_id": "test-analyst"
                    }
                ],
                "context": "acceptance-test",
                "session_id": "test-session-001"
            }
        )
        
        assert response.status_code == 200
        
        data = response.json()
        assert data["scores_recorded"] == 1
        assert data["average_overall"] > 0
        assert "trace_id" in data
    
    def test_07_performance_benchmark(self, api_client):
        """Benchmark ingestion performance."""
        start_time = time.time()
        
        # Create a larger bundle for performance testing
        objects = []
        for i in range(10):
            objects.append({
                "type": "attack-pattern",
                "id": f"attack-pattern--perf-test-{i}",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "name": f"Performance Test Technique {i}",
                "description": f"Technique {i} for performance testing",
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "execution"
                    }
                ]
            })
        
        bundle = {
            "type": "bundle",
            "id": "bundle--perf-test",
            "objects": objects
        }
        
        response = api_client.post(
            "/stix/bundles",
            json=bundle,
            params={"strict": False}
        )
        
        elapsed = time.time() - start_time
        
        assert response.status_code == 200
        assert elapsed < 10.0  # Should complete within 10 seconds
        
        data = response.json()
        assert data["inserted"] == 10
        
        # Log performance metric
        print(f"Ingested {len(objects)} objects in {elapsed:.2f} seconds")
        print(f"Rate: {len(objects)/elapsed:.2f} objects/second")
    
    def test_08_validate_trace_propagation(self, api_client):
        """Validate trace ID propagation across multiple calls."""
        # Make first call and get trace ID
        response1 = api_client.get("/catalog/attack/releases")
        trace_id1 = response1.headers.get("x-trace-id")
        assert trace_id1 is not None
        
        # Make second call with explicit trace ID
        response2 = api_client.get(
            "/drift/status",
            headers={"X-Trace-ID": trace_id1}
        )
        trace_id2 = response2.headers.get("x-trace-id")
        
        # Should preserve the provided trace ID
        assert trace_id2 == trace_id1
        
        # Verify trace ID in response body
        data = response2.json()
        assert data.get("trace_id") == trace_id1


@pytest.mark.integration
class TestIngestionIntegration:
    """Integration tests for ingestion with other components."""
    
    def test_ingestion_to_search_integration(self, api_client):
        """Test that ingested data is searchable."""
        # Ingest a specific technique
        bundle = {
            "type": "bundle",
            "id": "bundle--integration-test",
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--integration-001",
                    "created": "2024-01-01T00:00:00.000Z",
                    "modified": "2024-01-01T00:00:00.000Z",
                    "name": "PowerShell Remote Execution",
                    "description": "Adversaries may use PowerShell to perform remote execution",
                    "kill_chain_phases": [
                        {
                            "kill_chain_name": "mitre-attack",
                            "phase_name": "execution"
                        }
                    ]
                }
            ]
        }
        
        # Ingest
        response = api_client.post("/stix/bundles", json=bundle, params={"strict": False})
        assert response.status_code == 200
        
        # Wait for indexing
        time.sleep(2)
        
        # Search for it
        response = api_client.post(
            "/search/ttx",
            json={"text": "PowerShell remote execution", "top_k": 10}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should find our technique
        found = any(
            "PowerShell Remote Execution" in r.get("kb_name", "")
            for r in data["results"]
        )
        assert found, "Ingested technique not found in search"