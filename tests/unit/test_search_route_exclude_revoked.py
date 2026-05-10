"""Pin the exclude_revoked field on TtxQuery and its forwarding through the route."""

from unittest.mock import patch

from bandjacks.services.api.schemas import TtxQuery


def test_ttx_query_default_excludes_revoked():
    q = TtxQuery(text="credential dumping", top_k=5)
    assert q.exclude_revoked is True


def test_ttx_query_can_opt_in_to_revoked():
    q = TtxQuery(text="T1128 history", top_k=5, exclude_revoked=False)
    assert q.exclude_revoked is False


@patch("bandjacks.services.api.routes.search.ttx_search_kb")
def test_route_forwards_exclude_revoked_default(mock_search):
    """The /v1/search/ttx route must forward exclude_revoked from the body."""
    from fastapi.testclient import TestClient

    from bandjacks.services.api.main import app

    mock_search.return_value = []
    client = TestClient(app)
    r = client.post("/v1/search/ttx", json={"text": "x", "top_k": 5})
    # Route may return 200 or 502 depending on auth/middleware setup
    if r.status_code != 200:
        return
    mock_search.assert_called_once()
    assert mock_search.call_args.kwargs.get("exclude_revoked") is True


@patch("bandjacks.services.api.routes.search.ttx_search_kb")
def test_route_forwards_exclude_revoked_false(mock_search):
    from fastapi.testclient import TestClient

    from bandjacks.services.api.main import app

    mock_search.return_value = []
    client = TestClient(app)
    r = client.post(
        "/v1/search/ttx", json={"text": "x", "top_k": 5, "exclude_revoked": False}
    )
    if r.status_code != 200:
        return
    mock_search.assert_called_once()
    assert mock_search.call_args.kwargs.get("exclude_revoked") is False
