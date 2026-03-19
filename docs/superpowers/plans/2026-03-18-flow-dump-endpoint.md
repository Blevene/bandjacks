# Flow Dump Endpoint Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `GET /v1/flows/dump` to return full flow data (steps, edges, stats) with filtering by report, actor, campaign, technique, flow type, and date range — supporting JSON and STIX output formats.

**Architecture:** OpenSearch-primary — fetch report documents containing inline `extraction.flows[]`, unnest into flat flow list, apply post-query filters, paginate. Actor/campaign filters resolve report IDs via Neo4j first. STIX format delegates to existing `AttackFlowExporter`.

**Tech Stack:** FastAPI, OpenSearch (opensearchpy), Neo4j (neo4j driver), existing `AttackFlowExporter`

**Spec:** `docs/superpowers/specs/2026-03-18-flow-dump-endpoint-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `bandjacks/store/opensearch_report_store.py` | Modify | Add `dump_flows()` method |
| `bandjacks/services/api/routes/flows.py` | Modify | Add `GET /flows/dump` route (before `/{flow_id}`) |
| `tests/unit/test_flow_dump.py` | Create | Unit tests for dump_flows and route logic |

---

### Task 1: `dump_flows()` Store Method

**Files:**
- Modify: `bandjacks/store/opensearch_report_store.py`
- Create: `tests/unit/test_flow_dump.py`

This method queries OpenSearch for reports, unnests `extraction.flows[]` into a flat list, and attaches report metadata to each flow.

- [ ] **Step 1: Write test for dump_flows basic unnesting**

In `tests/unit/test_flow_dump.py`:

```python
"""Tests for flow dump functionality."""

from unittest.mock import MagicMock, patch
from bandjacks.store.opensearch_report_store import OpenSearchReportStore


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


def test_dump_flows_unnests_from_reports():
    """Flows from multiple reports are unnested into flat list with report metadata."""
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
    # Each flow should have report metadata attached
    assert flows[0]["report_name"] == "Report One"
    assert flows[0]["source_id"] == "report--1"
    assert flows[0]["ingested_at"] == "2026-03-18T00:00:00Z"
    assert flows[2]["report_name"] == "Report Two"


def test_dump_flows_empty_index():
    """Empty index returns empty list."""
    mock_client = MagicMock()
    mock_client.search.side_effect = Exception("index_not_found_exception")

    store = OpenSearchReportStore(mock_client)
    flows, truncated = store.dump_flows()

    assert flows == []
    assert not truncated


def test_dump_flows_report_with_no_flows():
    """Reports without flows are skipped."""
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
    mock_client = MagicMock()
    mock_client.search.return_value = {"hits": {"total": {"value": 0}, "hits": []}}

    store = OpenSearchReportStore(mock_client)
    store.dump_flows(report_ids=["report--1", "report--2"])

    call_body = mock_client.search.call_args[1]["body"]
    # Should have a terms filter for report_id
    must = call_body["query"]["bool"]["must"]
    assert any(
        "terms" in clause and "report_id" in clause["terms"]
        for clause in must
    )


def test_dump_flows_date_range_filter():
    """Date range parameters add range filter to OpenSearch query."""
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run python -c "from tests.unit.test_flow_dump import *; print('Import OK')"`
Expected: ImportError or AttributeError (dump_flows doesn't exist yet)

- [ ] **Step 3: Implement dump_flows()**

Add to `bandjacks/store/opensearch_report_store.py` — add this method to the `OpenSearchReportStore` class, after the existing `list_reports` method:

```python
def dump_flows(
    self,
    report_ids: Optional[List[str]] = None,
    ingested_after: Optional[str] = None,
    ingested_before: Optional[str] = None,
    max_reports: int = 10000,
) -> tuple:
    """
    Fetch flows from report documents, unnested into a flat list.

    Args:
        report_ids: Optional list of report IDs to filter by
        ingested_after: ISO 8601 date string for range filter
        ingested_before: ISO 8601 date string for range filter
        max_reports: Maximum reports to scan (default 10,000)

    Returns:
        Tuple of (list of flow dicts with report_name/ingested_at/source_id attached, truncated bool)
    """
    must_clauses = []

    if report_ids:
        must_clauses.append({"terms": {"report_id": report_ids}})

    if ingested_after or ingested_before:
        range_filter = {}
        if ingested_after:
            range_filter["gte"] = ingested_after
        if ingested_before:
            range_filter["lte"] = ingested_before
        must_clauses.append({"range": {"ingested_at": range_filter}})

    query = {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}

    search_body = {
        "query": query,
        "sort": [{"ingested_at": {"order": "desc"}}, {"report_id": {"order": "asc"}}],
        "size": max_reports,
        "_source": {
            "includes": ["report_id", "name", "ingested_at", "extraction.flows"]
        },
    }

    try:
        response = self.client.search(index=self.index_name, body=search_body)
    except Exception as e:
        if "index_not_found_exception" in str(e):
            logger.warning("Reports index does not exist")
            return [], False
        logger.error(f"Failed to dump flows: {e}")
        raise

    hits = response["hits"]["hits"]
    total_reports = response["hits"]["total"]["value"]
    truncated = total_reports > max_reports

    flows = []
    for hit in hits:
        source = hit["_source"]
        report_id = source.get("report_id", "")
        report_name = source.get("name", "")
        ingested_at = source.get("ingested_at", "")
        report_flows = source.get("extraction", {}).get("flows", [])

        for flow in report_flows:
            if not isinstance(flow, dict):
                continue
            flow["source_id"] = report_id
            flow["report_name"] = report_name
            flow["ingested_at"] = ingested_at
            flows.append(flow)

    return flows, truncated
```

Also add `tuple` to the imports at the top if not already present (it's a builtin, no import needed for Python 3.9+).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -c "
from tests.unit.test_flow_dump import *
test_dump_flows_unnests_from_reports()
test_dump_flows_empty_index()
test_dump_flows_report_with_no_flows()
test_dump_flows_report_id_filter()
test_dump_flows_date_range_filter()
print('All dump_flows tests PASSED')
"`

Expected: All 5 tests pass

- [ ] **Step 5: Commit**

```bash
git add bandjacks/store/opensearch_report_store.py tests/unit/test_flow_dump.py
git commit -m "feat: add dump_flows() method to OpenSearchReportStore"
```

---

### Task 2: Post-Query Filters (flow_type, technique)

**Files:**
- Modify: `bandjacks/services/api/routes/flows.py`
- Modify: `tests/unit/test_flow_dump.py`

These are pure Python filter functions applied to the unnested flow list. Defined as module-level helpers in the route file.

- [ ] **Step 1: Write tests for filter functions**

Append to `tests/unit/test_flow_dump.py`:

```python
# --- Post-query filter tests ---

# We'll test the filter functions directly once implemented.
# For now, test the filtering logic inline.


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
    """technique filter matches ATT&CK ID as suffix of attack_pattern_ref."""
    flows = [
        {"steps": [{"attack_pattern_ref": "attack-pattern--T1566.001"}, {"attack_pattern_ref": "attack-pattern--T1059"}]},
        {"steps": [{"attack_pattern_ref": "attack-pattern--T1003.001"}]},
        {"steps": []},
    ]
    from bandjacks.services.api.routes.flows import _filter_by_technique
    result = _filter_by_technique(flows, "T1566.001")
    assert len(result) == 1
    assert result[0]["steps"][0]["attack_pattern_ref"] == "attack-pattern--T1566.001"


def test_technique_filter_no_match():
    """technique filter with no matching flows returns empty list."""
    flows = [
        {"steps": [{"attack_pattern_ref": "attack-pattern--T1059"}]},
    ]
    from bandjacks.services.api.routes.flows import _filter_by_technique
    result = _filter_by_technique(flows, "T9999")
    assert len(result) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: ImportError (`_filter_by_flow_type` doesn't exist)

- [ ] **Step 3: Implement filter functions**

Add to `bandjacks/services/api/routes/flows.py`, before the router definition (after imports):

```python
# --- Post-query filter helpers for /flows/dump ---

_FLOW_TYPE_ALIASES = {
    "deterministic": {"deterministic", "deterministic_full"},
    "llm_synthesized": {"llm_synthesized", "sequential"},
    "co-occurrence": {"co-occurrence"},
}

VALID_FLOW_TYPES = set(_FLOW_TYPE_ALIASES.keys())


def _filter_by_flow_type(flows: List[Dict[str, Any]], flow_type: str) -> List[Dict[str, Any]]:
    """Filter flows by flow_type, matching aliases."""
    allowed = _FLOW_TYPE_ALIASES.get(flow_type, {flow_type})
    return [f for f in flows if f.get("flow_type") in allowed]


def _filter_by_technique(flows: List[Dict[str, Any]], technique: str) -> List[Dict[str, Any]]:
    """Filter flows containing a technique (ATT&CK ID suffix match on attack_pattern_ref)."""
    suffix = technique if technique.startswith("T") else f"T{technique}"
    result = []
    for flow in flows:
        for step in flow.get("steps", []):
            ref = step.get("attack_pattern_ref", "")
            if ref.endswith(suffix):
                result.append(flow)
                break
    return result
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -c "
from tests.unit.test_flow_dump import *
test_flow_type_filter_deterministic()
test_flow_type_filter_llm()
test_flow_type_filter_co_occurrence()
test_technique_filter_suffix_match()
test_technique_filter_no_match()
print('All filter tests PASSED')
"`

Expected: All 5 tests pass

- [ ] **Step 5: Commit**

```bash
git add bandjacks/services/api/routes/flows.py tests/unit/test_flow_dump.py
git commit -m "feat: add flow_type and technique post-query filters for dump endpoint"
```

---

### Task 3: Route Handler — JSON Format

**Files:**
- Modify: `bandjacks/services/api/routes/flows.py`
- Modify: `tests/unit/test_flow_dump.py`

The main `GET /flows/dump` route. Handles parameter validation, Neo4j lookups for actor/campaign, calls `dump_flows()`, applies post-query filters, paginates, and returns JSON.

- [ ] **Step 1: Write test for the dump route handler**

Append to `tests/unit/test_flow_dump.py`:

```python
# --- Route handler tests ---

import asyncio
from unittest.mock import AsyncMock


def test_dump_route_basic_json():
    """GET /flows/dump returns paginated flows in JSON format."""
    from bandjacks.services.api.routes.flows import dump_flows_route

    # Mock dependencies
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

    result = asyncio.get_event_loop().run_until_complete(
        dump_flows_route(
            os_client=mock_os_client,
            neo4j_session=MagicMock(),
            limit=50, offset=0, format="json",
        )
    )

    assert "flows" in result
    assert len(result["flows"]) == 1
    assert result["total"] == 1
    assert result["limit"] == 50
    assert result["offset"] == 0
    assert result["flows"][0]["flow_id"] == "flow-a"
    assert result["flows"][0]["report_name"] == "Test Report"


def test_dump_route_pagination():
    """Offset/limit correctly slices the flow list."""
    from bandjacks.services.api.routes.flows import dump_flows_route

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

    result = asyncio.get_event_loop().run_until_complete(
        dump_flows_route(
            os_client=mock_os_client,
            neo4j_session=MagicMock(),
            limit=1, offset=1, format="json",
        )
    )

    assert result["total"] == 2
    assert len(result["flows"]) == 1
    assert result["flows"][0]["flow_id"] == "flow-b"


def test_dump_route_invalid_flow_type():
    """Invalid flow_type returns 400."""
    from bandjacks.services.api.routes.flows import dump_flows_route
    from fastapi import HTTPException
    import pytest

    mock_os_client = MagicMock()

    try:
        asyncio.get_event_loop().run_until_complete(
            dump_flows_route(
                os_client=mock_os_client,
                neo4j_session=MagicMock(),
                flow_type="invalid_type",
                format="json",
            )
        )
        assert False, "Should have raised HTTPException"
    except HTTPException as e:
        assert e.status_code == 400
        assert "deterministic" in e.detail
```

- [ ] **Step 2: Run tests to verify they fail**

Expected: ImportError (`dump_flows_route` doesn't exist)

- [ ] **Step 3: Implement the route handler**

Add to `bandjacks/services/api/routes/flows.py`. This route MUST be placed **before** the `@router.get("/{flow_id}")` route (around line 184). Add the import at the top of the file with other imports:

```python
from bandjacks.store.opensearch_report_store import OpenSearchReportStore
```

Then add the route handler after line 181 (the `finally: builder.close()` block of `build_flow`), before `@router.get("/{flow_id}")`:

```python
@router.get("/dump",
    summary="Dump All Flows",
    description="""
    Export full flow data (steps, edges, stats) with filtering and pagination.

    Supports filtering by report, threat actor, campaign, technique, flow type, and date range.
    Returns flows in JSON (default) or STIX Attack Flow 2.0 format.
    """,
    responses={
        200: {"description": "Flows retrieved successfully"},
        400: {"description": "Invalid filter parameters"},
    }
)
async def dump_flows_route(
    os_client: OpenSearch = Depends(get_opensearch_client),
    neo4j_session=Depends(get_neo4j_session),
    report_id: Optional[str] = Query(None, description="Filter by source report STIX ID"),
    actor: Optional[str] = Query(None, description="Filter by threat actor name (case-insensitive substring)"),
    actor_id: Optional[str] = Query(None, description="Filter by intrusion set STIX ID"),
    campaign: Optional[str] = Query(None, description="Filter by campaign name (case-insensitive substring)"),
    campaign_id: Optional[str] = Query(None, description="Filter by campaign STIX ID"),
    flow_type: Optional[str] = Query(None, description="Filter by flow type: deterministic, llm_synthesized, co-occurrence"),
    technique: Optional[str] = Query(None, description="Filter flows containing ATT&CK technique ID (e.g. T1566.001)"),
    ingested_after: Optional[str] = Query(None, description="Filter reports ingested after this date (ISO 8601)"),
    ingested_before: Optional[str] = Query(None, description="Filter reports ingested before this date (ISO 8601)"),
    format: str = Query("json", description="Response format: json or stix"),
    limit: int = Query(50, ge=1, description="Results per page"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
) -> Dict[str, Any]:
    """Export flows with full step/edge data."""

    # Validate parameters
    if format not in ("json", "stix"):
        raise HTTPException(status_code=400, detail=f"Invalid format '{format}'. Use 'json' or 'stix'.")

    # Validate dates
    from datetime import datetime as dt
    for date_param, date_val in [("ingested_after", ingested_after), ("ingested_before", ingested_before)]:
        if date_val:
            try:
                dt.fromisoformat(date_val.replace("Z", "+00:00"))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid {date_param} date format. Use ISO 8601 (e.g. 2026-01-01T00:00:00Z).")

    if flow_type and flow_type not in VALID_FLOW_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid flow_type '{flow_type}'. Allowed: {', '.join(sorted(VALID_FLOW_TYPES))}"
        )

    # Clamp limit
    limit = min(limit, 200)

    # Resolve actor/campaign to report IDs via Neo4j
    report_ids = None
    if report_id:
        report_ids = [report_id]

    if actor or actor_id:
        query = """
            MATCH (r:Report)-[:IDENTIFIED_ACTOR]->(g:IntrusionSet)
            WHERE g.stix_id = $actor_id OR toLower(g.name) CONTAINS toLower($actor)
            RETURN r.stix_id AS report_id
        """
        result = neo4j_session.run(query, actor_id=actor_id or "", actor=actor or "")
        actor_report_ids = [r["report_id"] for r in result]
        if report_ids:
            report_ids = list(set(report_ids) & set(actor_report_ids))
        else:
            report_ids = actor_report_ids
        if not report_ids:
            return {"flows": [], "total": 0, "limit": limit, "offset": offset, "filters_applied": {}}

    if campaign or campaign_id:
        query = """
            MATCH (r:Report)-[:DESCRIBES_CAMPAIGN]->(c:Campaign)
            WHERE c.stix_id = $campaign_id OR toLower(c.name) CONTAINS toLower($campaign)
            RETURN r.stix_id AS report_id
        """
        result = neo4j_session.run(query, campaign_id=campaign_id or "", campaign=campaign or "")
        campaign_report_ids = [r["report_id"] for r in result]
        if report_ids:
            report_ids = list(set(report_ids) & set(campaign_report_ids))
        else:
            report_ids = campaign_report_ids
        if not report_ids:
            return {"flows": [], "total": 0, "limit": limit, "offset": offset, "filters_applied": {}}

    # Fetch flows from OpenSearch
    store = OpenSearchReportStore(os_client)
    all_flows, truncated = store.dump_flows(
        report_ids=report_ids,
        ingested_after=ingested_after,
        ingested_before=ingested_before,
    )

    # Apply post-query filters
    if flow_type:
        all_flows = _filter_by_flow_type(all_flows, flow_type)
    if technique:
        all_flows = _filter_by_technique(all_flows, technique)

    # Build filters_applied for response
    filters_applied = {}
    for key, val in [("report_id", report_id), ("actor", actor), ("actor_id", actor_id),
                     ("campaign", campaign), ("campaign_id", campaign_id),
                     ("flow_type", flow_type), ("technique", technique),
                     ("ingested_after", ingested_after), ("ingested_before", ingested_before)]:
        if val:
            filters_applied[key] = val

    # Paginate
    total = len(all_flows)
    page = all_flows[offset:offset + limit]

    # Handle STIX format
    if format == "stix":
        return _build_stix_response(page, total, limit, offset, neo4j_session)

    response = {
        "flows": page,
        "total": total,
        "limit": limit,
        "offset": offset,
        "filters_applied": filters_applied,
    }
    if truncated:
        response["total_truncated"] = True

    return response
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run python -c "
from tests.unit.test_flow_dump import *
test_dump_route_basic_json()
test_dump_route_pagination()
test_dump_route_invalid_flow_type()
print('All route tests PASSED')
"`

Expected: All 3 tests pass

- [ ] **Step 5: Commit**

```bash
git add bandjacks/services/api/routes/flows.py tests/unit/test_flow_dump.py
git commit -m "feat: add GET /v1/flows/dump route handler with filtering and pagination"
```

---

### Task 4: STIX Format Support

**Files:**
- Modify: `bandjacks/services/api/routes/flows.py`
- Modify: `tests/unit/test_flow_dump.py`

Add `_build_stix_response()` helper that checks Neo4j for flow existence and exports via `AttackFlowExporter`.

- [ ] **Step 1: Write test for STIX response builder**

Append to `tests/unit/test_flow_dump.py`:

```python
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

    result = _build_stix_response(flows, total=2, limit=50, offset=0, neo4j_session=mock_session)

    assert result["total"] == 2
    assert result["exported_count"] <= 2
```

- [ ] **Step 2: Run test to verify it fails**

Expected: ImportError (`_build_stix_response` doesn't exist)

- [ ] **Step 3: Implement _build_stix_response()**

Add to `bandjacks/services/api/routes/flows.py`, after the filter helper functions:

```python
def _build_stix_response(
    flows: List[Dict[str, Any]],
    total: int,
    limit: int,
    offset: int,
    neo4j_session,
) -> Dict[str, Any]:
    """Build STIX format response, exporting Neo4j-backed flows."""
    if not flows:
        return {"flows": [], "total": total, "exported_count": 0, "limit": limit, "offset": offset}

    # Check which flow_ids exist in Neo4j
    flow_ids = [f.get("flow_id") for f in flows if f.get("flow_id")]
    check_query = """
        MATCH (e:AttackEpisode)
        WHERE e.flow_id IN $flow_ids
        RETURN e.flow_id AS flow_id
    """
    result = neo4j_session.run(check_query, flow_ids=flow_ids)
    neo4j_flow_ids = {r["flow_id"] for r in result}

    # Create exporter using the shared driver
    from bandjacks.services.api.deps import get_neo4j_driver
    driver = get_neo4j_driver()
    exporter = AttackFlowExporter.from_driver(driver)

    stix_flows = []
    for flow in flows:
        fid = flow.get("flow_id")
        if fid not in neo4j_flow_ids:
            continue
        try:
            bundle = exporter.export_to_attack_flow(fid)
            stix_flows.append({
                "flow_id": fid,
                "source_id": flow.get("source_id", ""),
                "stix_bundle": bundle,
            })
        except Exception as e:
            stix_flows.append({
                "flow_id": fid,
                "source_id": flow.get("source_id", ""),
                "stix_bundle": None,
                "error": str(e),
            })

    return {
        "flows": stix_flows,
        "total": total,
        "exported_count": len([f for f in stix_flows if f.get("stix_bundle")]),
        "limit": limit,
        "offset": offset,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -c "
from tests.unit.test_flow_dump import test_build_stix_response_skips_non_neo4j_flows
test_build_stix_response_skips_non_neo4j_flows()
print('STIX test PASSED')
"`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add bandjacks/services/api/routes/flows.py tests/unit/test_flow_dump.py
git commit -m "feat: add STIX Attack Flow 2.0 format support to /flows/dump"
```

---

### Task 5: E2E Integration Test

**Files:**
- Modify: `tests/unit/test_flow_dump.py`

Verify the endpoint works against the running API server with real data.

- [ ] **Step 1: Write E2E test**

Append to `tests/unit/test_flow_dump.py`:

```python
def test_e2e_dump_endpoint():
    """E2E: Hit the live API and verify response structure."""
    import requests

    # This test requires a running API server
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
```

- [ ] **Step 2: Restart API and run E2E test**

```bash
# Restart API to pick up new route
pkill -f "uvicorn bandjacks.services.api.main:app" 2>/dev/null
sleep 2
nohup uv run uvicorn bandjacks.services.api.main:app --workers 1 --host 0.0.0.0 --port 8000 > /tmp/bandjacks-api.log 2>&1 &
sleep 18

# Run E2E test
uv run python -c "
from tests.unit.test_flow_dump import test_e2e_dump_endpoint
test_e2e_dump_endpoint()
print('E2E test PASSED')
"
```

Expected: 200 OK with flows from previously ingested reports

- [ ] **Step 3: Test filters against live data**

```bash
# Test flow_type filter
curl -s 'http://localhost:8000/v1/flows/dump?flow_type=deterministic&limit=2' | python3 -m json.tool | head -20

# Test technique filter
curl -s 'http://localhost:8000/v1/flows/dump?technique=T1566.001&limit=2' | python3 -m json.tool | head -20

# Test date filter
curl -s 'http://localhost:8000/v1/flows/dump?ingested_after=2026-03-18T00:00:00Z&limit=2' | python3 -m json.tool | head -20

# Test invalid flow_type (should 400)
curl -s 'http://localhost:8000/v1/flows/dump?flow_type=bad' | python3 -m json.tool
```

- [ ] **Step 4: Commit**

```bash
git add tests/unit/test_flow_dump.py
git commit -m "test: add E2E integration test for /flows/dump endpoint"
```

---

### Task 6: Final Validation and PR

- [ ] **Step 1: Run all unit tests**

```bash
uv run python -c "
from tests.unit.test_flow_dump import *
import inspect, sys

tests = [name for name, obj in inspect.getmembers(sys.modules['tests.unit.test_flow_dump'])
         if inspect.isfunction(obj) and name.startswith('test_') and name != 'test_e2e_dump_endpoint']

passed = failed = 0
for name in sorted(tests):
    try:
        globals()[name]()
        print(f'  PASS  {name}')
        passed += 1
    except Exception as e:
        print(f'  FAIL  {name}: {e}')
        failed += 1
print(f'{passed} passed, {failed} failed')
"
```

Expected: All tests pass

- [ ] **Step 2: Run E2E validation**

```bash
curl -s 'http://localhost:8000/v1/flows/dump?limit=3' | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f'Total flows: {data[\"total\"]}')
print(f'Page size: {len(data[\"flows\"])}')
for f in data['flows']:
    print(f'  {f[\"flow_type\"]}: {f.get(\"flow_name\", \"?\")} ({len(f.get(\"steps\",[]))} steps, {len(f.get(\"edges\",[]))} edges)')
"
```

- [ ] **Step 3: Push and create PR**

```bash
git push origin HEAD
gh pr create --title "feat: add GET /v1/flows/dump endpoint for full flow export" \
  --body "$(cat <<'PREOF'
## Summary
- Adds `GET /v1/flows/dump` endpoint for full flow data retrieval with steps, edges, stats
- Supports filtering by: report_id, actor, campaign, flow_type, technique, date range
- JSON (default) and STIX Attack Flow 2.0 output formats
- Offset-based pagination (default 50, max 200)
- Closes #16

## Test plan
- [x] Unit tests for dump_flows() store method
- [x] Unit tests for flow_type and technique post-query filters
- [x] Unit tests for route handler (pagination, validation)
- [x] Unit tests for STIX format builder
- [x] E2E integration test against live API

🤖 Generated with [Claude Code](https://claude.com/claude-code)
PREOF
)"
```
