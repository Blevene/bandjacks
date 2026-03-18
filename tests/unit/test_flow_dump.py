"""Tests for flow dump functionality."""

from unittest.mock import MagicMock, AsyncMock, patch
import asyncio


def _make_report_hit(report_id, name, ingested_at, flows):
    """Helper to build an OpenSearch hit dict."""
    return {
        "_source": {
            "report_id": report_id,
            "name": name,
            "ingested_at": ingested_at,
            "extraction": {"flows": flows},
        }
    }


def _make_flow(flow_id, flow_type="deterministic", steps=None, edges=None):
    """Helper to build a flow dict."""
    return {
        "flow_id": flow_id,
        "flow_name": f"Flow {flow_id}",
        "flow_type": flow_type,
        "confidence": 0.5,
        "stats": {"steps_count": len(steps or []), "edges_count": len(edges or [])},
        "steps": steps or [],
        "edges": edges or [],
    }


# --- dump_flows() store method tests ---


def test_dump_flows_unnests_from_reports():
    """Flows from multiple reports are unnested into flat list with report metadata."""
    from bandjacks.store.opensearch_report_store import OpenSearchReportStore

    mock_client = MagicMock()
    mock_client.search.return_value = {
        "hits": {
            "total": {"value": 2},
            "hits": [
                _make_report_hit("report--1", "Report One", "2026-03-18T00:00:00Z", [
                    _make_flow("flow-a"),
                    _make_flow("flow-b", flow_type="llm_synthesized"),
                ]),
                _make_report_hit("report--2", "Report Two", "2026-03-17T00:00:00Z", [
                    _make_flow("flow-c"),
                ]),
            ],
        }
    }

    store = OpenSearchReportStore(mock_client)
    flows, truncated = store.dump_flows()

    assert len(flows) == 3
    assert not truncated
    assert flows[0]["report_name"] == "Report One"
    assert flows[0]["source_id"] == "report--1"
    assert flows[0]["ingested_at"] == "2026-03-18T00:00:00Z"
    assert flows[2]["report_name"] == "Report Two"


def test_dump_flows_does_not_mutate_source():
    """dump_flows must not mutate the OpenSearch response dicts."""
    from bandjacks.store.opensearch_report_store import OpenSearchReportStore

    original_flow = _make_flow("flow-a")
    mock_client = MagicMock()
    mock_client.search.return_value = {
        "hits": {
            "total": {"value": 1},
            "hits": [
                _make_report_hit("report--1", "Report One", "2026-03-18T00:00:00Z", [original_flow]),
            ],
        }
    }

    store = OpenSearchReportStore(mock_client)
    flows, _ = store.dump_flows()

    # The returned flow should have metadata, but the original should not
    assert "source_id" in flows[0]
    assert "source_id" not in original_flow


def test_dump_flows_empty_index():
    """Empty index returns empty list."""
    from bandjacks.store.opensearch_report_store import OpenSearchReportStore

    mock_client = MagicMock()
    mock_client.search.side_effect = Exception("index_not_found_exception")

    store = OpenSearchReportStore(mock_client)
    flows, truncated = store.dump_flows()

    assert flows == []
    assert not truncated


def test_dump_flows_report_with_no_flows():
    """Reports without flows are skipped."""
    from bandjacks.store.opensearch_report_store import OpenSearchReportStore

    mock_client = MagicMock()
    mock_client.search.return_value = {
        "hits": {
            "total": {"value": 1},
            "hits": [
                _make_report_hit("report--1", "Empty Report", "2026-03-18T00:00:00Z", []),
            ],
        }
    }

    store = OpenSearchReportStore(mock_client)
    flows, truncated = store.dump_flows()

    assert flows == []


def test_dump_flows_report_id_filter():
    """report_ids parameter filters the OpenSearch query."""
    from bandjacks.store.opensearch_report_store import OpenSearchReportStore

    mock_client = MagicMock()
    mock_client.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}

    store = OpenSearchReportStore(mock_client)
    store.dump_flows(report_ids=["report--1", "report--2"])

    call_body = mock_client.search.call_args[1]["body"]
    must = call_body["query"]["bool"]["must"]
    assert any(
        "terms" in clause and "report_id" in clause["terms"]
        for clause in must
    )


def test_dump_flows_date_range_filter():
    """Date range parameters add range filter to OpenSearch query."""
    from bandjacks.store.opensearch_report_store import OpenSearchReportStore

    mock_client = MagicMock()
    mock_client.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}

    store = OpenSearchReportStore(mock_client)
    store.dump_flows(ingested_after="2026-01-01T00:00:00Z", ingested_before="2026-03-18T00:00:00Z")

    call_body = mock_client.search.call_args[1]["body"]
    must = call_body["query"]["bool"]["must"]
    range_clauses = [c for c in must if "range" in c]
    assert len(range_clauses) == 1
    assert "gte" in range_clauses[0]["range"]["ingested_at"]
    assert "lte" in range_clauses[0]["range"]["ingested_at"]


def test_dump_flows_uses_track_total_hits():
    """dump_flows sends track_total_hits=True for accurate counts."""
    from bandjacks.store.opensearch_report_store import OpenSearchReportStore

    mock_client = MagicMock()
    mock_client.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}

    store = OpenSearchReportStore(mock_client)
    store.dump_flows()

    call_body = mock_client.search.call_args[1]["body"]
    assert call_body.get("track_total_hits") is True


def test_dump_flows_defaults_confidence():
    """Flows missing confidence get default 0.5."""
    from bandjacks.store.opensearch_report_store import OpenSearchReportStore

    flow_no_confidence = {"flow_id": "f1", "flow_type": "deterministic", "steps": [], "edges": []}
    mock_client = MagicMock()
    mock_client.search.return_value = {
        "hits": {
            "total": {"value": 1},
            "hits": [_make_report_hit("r1", "R1", "2026-03-18T00:00:00Z", [flow_no_confidence])],
        }
    }

    store = OpenSearchReportStore(mock_client)
    flows, _ = store.dump_flows()

    assert flows[0]["confidence"] == 0.5


# --- Post-query filter tests ---


def test_flow_type_filter_deterministic():
    """flow_type=deterministic matches 'deterministic' and 'deterministic_full'."""
    flows = [
        {"flow_type": "deterministic", "steps": []},
        {"flow_type": "deterministic_full", "steps": []},
        {"flow_type": "llm_synthesized", "steps": []},
        {"flow_type": "co-occurrence", "steps": []},
    ]
    from bandjacks.services.api.routes.flows import _filter_by_flow_type
    result = _filter_by_flow_type(flows, "deterministic")
    assert len(result) == 2
    assert all(f["flow_type"] in ("deterministic", "deterministic_full") for f in result)


def test_flow_type_filter_llm():
    """flow_type=llm_synthesized matches only llm_synthesized."""
    flows = [
        {"flow_type": "deterministic", "steps": []},
        {"flow_type": "llm_synthesized", "steps": []},
    ]
    from bandjacks.services.api.routes.flows import _filter_by_flow_type
    result = _filter_by_flow_type(flows, "llm_synthesized")
    assert len(result) == 1


def test_flow_type_filter_co_occurrence():
    """flow_type=co-occurrence matches co-occurrence."""
    flows = [
        {"flow_type": "co-occurrence", "steps": []},
        {"flow_type": "deterministic", "steps": []},
    ]
    from bandjacks.services.api.routes.flows import _filter_by_flow_type
    result = _filter_by_flow_type(flows, "co-occurrence")
    assert len(result) == 1


def test_technique_filter_suffix_match():
    """technique filter matches ATT&CK ID with boundary delimiter."""
    flows = [
        {"steps": [{"attack_pattern_ref": "attack-pattern--T1566.001"}, {"attack_pattern_ref": "attack-pattern--T1059"}]},
        {"steps": [{"attack_pattern_ref": "attack-pattern--T1003.001"}]},
        {"steps": []},
    ]
    from bandjacks.services.api.routes.flows import _filter_by_technique
    result = _filter_by_technique(flows, "T1566.001")
    assert len(result) == 1
    assert result[0]["steps"][0]["attack_pattern_ref"] == "attack-pattern--T1566.001"


def test_technique_filter_no_partial_match():
    """technique filter must not allow partial ID matches (T156 should not match T1566)."""
    flows = [
        {"steps": [{"attack_pattern_ref": "attack-pattern--T1566.001"}]},
    ]
    from bandjacks.services.api.routes.flows import _filter_by_technique
    result = _filter_by_technique(flows, "T156")
    assert len(result) == 0


def test_technique_filter_no_match():
    """technique filter with no matching flows returns empty list."""
    flows = [
        {"steps": [{"attack_pattern_ref": "attack-pattern--T1059"}]},
    ]
    from bandjacks.services.api.routes.flows import _filter_by_technique
    result = _filter_by_technique(flows, "T9999")
    assert len(result) == 0


# --- Route handler tests ---


def _call_dump_route(**kwargs):
    """Call dump_flows_route with all Query defaults resolved to plain values."""
    from bandjacks.services.api.routes.flows import dump_flows_route

    defaults = {
        "os_client": MagicMock(),
        "neo4j_session": MagicMock(),
        "report_id": None,
        "actor": None,
        "actor_id": None,
        "campaign": None,
        "campaign_id": None,
        "flow_type": None,
        "technique": None,
        "ingested_after": None,
        "ingested_before": None,
        "fmt": "json",
        "limit": 50,
        "offset": 0,
    }
    defaults.update(kwargs)
    return asyncio.run(dump_flows_route(**defaults))


def test_dump_route_basic_json():
    """GET /flows/dump returns paginated flows in JSON format."""
    mock_os_client = MagicMock()
    mock_os_client.search.return_value = {
        "hits": {
            "total": {"value": 1},
            "hits": [
                _make_report_hit("report--1", "Test Report", "2026-03-18T00:00:00Z", [
                    _make_flow("flow-a", steps=[
                        {"action_id": "a1", "order": 1, "attack_pattern_ref": "attack-pattern--T1566.001",
                         "name": "Phishing", "confidence": 90.0, "tactic": "initial-access"}
                    ]),
                ]),
            ],
        }
    }

    result = _call_dump_route(os_client=mock_os_client, limit=50, offset=0)

    assert "flows" in result
    assert len(result["flows"]) == 1
    assert result["total"] == 1
    assert result["limit"] == 50
    assert result["offset"] == 0
    assert result["flows"][0]["flow_id"] == "flow-a"
    assert result["flows"][0]["report_name"] == "Test Report"


def test_dump_route_pagination():
    """Offset/limit correctly slices the flow list."""
    mock_os_client = MagicMock()
    mock_os_client.search.return_value = {
        "hits": {
            "total": {"value": 1},
            "hits": [
                _make_report_hit("report--1", "Report", "2026-03-18T00:00:00Z", [
                    _make_flow("flow-a"),
                    _make_flow("flow-b"),
                ]),
            ],
        }
    }

    result = _call_dump_route(os_client=mock_os_client, limit=1, offset=1)

    assert result["total"] == 2
    assert len(result["flows"]) == 1
    assert result["flows"][0]["flow_id"] == "flow-b"


def test_dump_route_invalid_flow_type():
    """Invalid flow_type returns 400."""
    from fastapi import HTTPException

    try:
        _call_dump_route(flow_type="invalid_type")
        assert False, "Should have raised HTTPException"
    except HTTPException as e:
        assert e.status_code == 400
        assert "deterministic" in e.detail


# --- STIX response tests ---


def test_build_stix_response_skips_non_neo4j_flows():
    """STIX response omits flows not backed by Neo4j."""
    from bandjacks.services.api.routes.flows import _build_stix_response

    mock_session = MagicMock()
    # Simulate: flow-a exists in Neo4j, flow-b does not
    mock_session.run.return_value = [{"flow_id": "flow-a"}]

    flows = [
        {"flow_id": "flow-a", "source_id": "report--1"},
        {"flow_id": "flow-b", "source_id": "report--2"},
    ]

    with patch("bandjacks.services.api.deps.get_neo4j_driver") as mock_driver, \
         patch("bandjacks.services.api.routes.flows.AttackFlowExporter") as mock_exporter_cls:
        mock_exporter = MagicMock()
        mock_exporter.export_to_attack_flow.return_value = {"type": "bundle", "objects": []}
        mock_exporter_cls.from_driver.return_value = mock_exporter

        result = _build_stix_response(flows, total=2, limit=50, offset=0, neo4j_session=mock_session)

    assert result["total"] == 2
    assert result["exported_count"] == 1
    assert len(result["flows"]) == 1
    assert result["flows"][0]["flow_id"] == "flow-a"


def test_build_stix_response_empty():
    """STIX response with no flows returns correctly."""
    from bandjacks.services.api.routes.flows import _build_stix_response

    result = _build_stix_response([], total=0, limit=50, offset=0, neo4j_session=MagicMock())

    assert result["flows"] == []
    assert result["exported_count"] == 0


# --- E2E test (requires running API) ---


def test_e2e_dump_endpoint():
    """E2E: Hit the live API and verify response structure."""
    import requests

    try:
        resp = requests.get("http://localhost:8000/v1/flows/dump", params={"limit": 5}, timeout=10)
    except requests.ConnectionError:
        print("SKIP: API server not running")
        return

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "flows" in data
    assert "total" in data
    assert "limit" in data
    assert "offset" in data
    assert data["limit"] == 5

    if data["flows"]:
        flow = data["flows"][0]
        assert "flow_id" in flow
        assert "flow_type" in flow
        assert "steps" in flow
        assert "edges" in flow
        assert "report_name" in flow
        assert "source_id" in flow
        print(f"E2E: Got {len(data['flows'])} flows, total={data['total']}")
    else:
        print("E2E: No flows in database (empty result OK)")
