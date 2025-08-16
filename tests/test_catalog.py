"""Tests for ATT&CK catalog functionality."""

from bandjacks.services.api.settings import settings
from bandjacks.services.api.main import app
from fastapi.testclient import TestClient

client = TestClient(app)

def test_catalog_exists():
    r = client.get(f"{settings.api_prefix}/catalog/attack/releases")
    assert r.status_code in (200, 502)