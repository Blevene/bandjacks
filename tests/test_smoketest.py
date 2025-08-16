"""Smoketest for Sprint 1 functionality."""

from bandjacks.services.api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_ingest_enterprise_latest():
    """Test ingesting enterprise-attack latest version."""
    r = client.post("/v1/stix/load/attack?collection=enterprise-attack&version=latest&adm_strict=true")
    # In CI/offline environments this may be 502; allow both
    assert r.status_code in (200, 502)
    if r.status_code == 200:
        body = r.json()
        assert "provenance" in body
        assert body["provenance"]["collection"] == "enterprise-attack"