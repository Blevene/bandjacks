"""Tests for STIX loading functionality."""

from bandjacks.services.api.settings import settings
from bandjacks.services.api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_load_route_exists():
    url = f"{settings.api_prefix}/stix/load/attack?collection=enterprise-attack&version=latest"
    r = client.post(url)
    assert r.status_code in (200, 502)