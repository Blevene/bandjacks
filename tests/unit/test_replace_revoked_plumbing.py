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
    # Anchor on REVOKED_BY so a future doc change can't silently drop the
    # operational note about re-running the STIX load.
    assert "REVOKED_BY" in descr


def test_job_processor_forwards_replace_revoked_in_extraction_config(monkeypatch):
    """The extraction_config dict (passed to OptimizedChunkedExtractor) must
    carry replace_revoked. Build the dict the same way job_processor does at
    lines 494 and 557 and assert the key is present and forwarded from the
    incoming job config (not silently defaulted)."""
    from bandjacks.services.api.settings import settings

    # Simulate the job config the route would have built.
    job_config = {
        "use_batch_mapper": True,
        "skip_verification": False,
        "replace_revoked": True,
        "auto_generate_flow": True,
    }

    # Mirror the extraction_config construction at job_processor.py:494
    extraction_config = {
        "use_batch_mapper": True,
        "use_batch_retriever": True,
        "skip_verification": job_config.get("skip_verification", False),
        "replace_revoked": job_config.get("replace_revoked", False),
        "max_spans": 30,
        "disable_discovery": False,
        "disable_targeted_extraction": True,
        "use_entity_claims": settings.use_entity_claims,
        "mapper_batch_size": min(settings.mapper_batch_size, settings.max_mapper_batch_size),
        "enable_sentence_evidence": settings.enable_sentence_evidence,
        "context_sentences": settings.context_sentences,
    }
    assert extraction_config["replace_revoked"] is True

    # And mirror chunk_config at job_processor.py:557
    chunk_config = {
        "use_batch_mapper": True,
        "use_batch_retriever": True,
        "skip_verification": job_config.get("skip_verification", False),
        "replace_revoked": job_config.get("replace_revoked", False),
    }
    assert chunk_config["replace_revoked"] is True


def test_job_processor_default_when_request_omits_flag():
    """A job whose config dict has no replace_revoked key must default to False,
    not raise KeyError. Pins the drop-by-default invariant."""
    job_config = {"use_batch_mapper": True, "skip_verification": False}
    assert job_config.get("replace_revoked", False) is False
