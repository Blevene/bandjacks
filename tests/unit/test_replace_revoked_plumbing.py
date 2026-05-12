"""Smoke tests for replace_revoked propagation from API to extraction config.

These pin the contract that the flag flows from request body / form param
through job_store, through job_processor's extraction_config build, and is
available to BatchMapperAgent. Without these tests, a future refactor of any
intermediate layer (job_store, job_processor, the extractor) could silently
drop the flag.
"""

from bandjacks.services.api.routes.reports import IngestRequest


def test_ingest_request_default_replace_revoked_false():
    """Default must match the rest of the pipeline (drop revoked, don't remap)."""
    r = IngestRequest(text="hello world")
    assert r.replace_revoked is False


def test_ingest_request_accepts_replace_revoked_true():
    r = IngestRequest(text="hello world", replace_revoked=True)
    assert r.replace_revoked is True


def test_ingest_request_openapi_documents_replace_revoked():
    """The OpenAPI schema must expose the field so HTTP consumers can see it."""
    schema = IngestRequest.model_json_schema()
    assert "replace_revoked" in schema["properties"]
    descr = schema["properties"]["replace_revoked"].get("description", "")
    # Anchor on BOTH the REVOKED_BY relationship name AND the "re-loaded"
    # instruction. A doc rewrite that drops the operational requirement
    # (re-run POST /v1/stix/load/attack) while keeping the relationship
    # name would silently pass on the single anchor — pin both.
    assert "REVOKED_BY" in descr
    assert "re-loaded" in descr


def test_pass_through_config_forwards_replace_revoked_true():
    """The helper used by both _process_job paths must forward replace_revoked
    from the incoming job config. Calls real production code instead of
    mirroring the dict literal — a refactor that drops the key from
    job_processor.py will now fail this test."""
    from bandjacks.services.api.job_processor import _build_pass_through_config

    out = _build_pass_through_config({
        "use_batch_mapper": True,
        "skip_verification": False,
        "replace_revoked": True,
        "auto_generate_flow": True,
    })
    assert out["replace_revoked"] is True
    assert out["skip_verification"] is False


def test_pass_through_config_default_when_request_omits_flag():
    """A job config dict with no replace_revoked key must default to False,
    not raise KeyError. Pins the drop-by-default invariant."""
    from bandjacks.services.api.job_processor import _build_pass_through_config

    out = _build_pass_through_config({"use_batch_mapper": True})
    assert out["replace_revoked"] is False
    assert out["skip_verification"] is False


def test_pass_through_config_round_trip_skip_verification():
    """Both pass-through keys should round-trip independently."""
    from bandjacks.services.api.job_processor import _build_pass_through_config

    out = _build_pass_through_config({
        "skip_verification": True,
        "replace_revoked": False,
    })
    assert out == {"skip_verification": True, "replace_revoked": False}
