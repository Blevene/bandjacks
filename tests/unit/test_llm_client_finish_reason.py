"""Pin the finish_reason field on LLMClient._extract_response().

Without this field, the BatchMapper truncation telemetry at
mapper_optimized.py:209-225 is dead code (the if-branch never fires).
Test asserts the field is propagated from LiteLLM's choice object.
"""

from types import SimpleNamespace

from bandjacks.llm.client import LLMClient


def _stub_response(content: str, finish_reason: str | None):
    """Build the minimal LiteLLM-shape response that _extract_response reads."""
    message = SimpleNamespace(content=content, tool_calls=None)
    choice = SimpleNamespace(message=message, finish_reason=finish_reason)
    return SimpleNamespace(choices=[choice])


def test_finish_reason_stop_propagated():
    client = LLMClient.__new__(LLMClient)  # bypass __init__ (no env needed)
    out = client._extract_response(_stub_response("hello", "stop"))
    assert out["finish_reason"] == "stop"


def test_finish_reason_length_propagated():
    client = LLMClient.__new__(LLMClient)
    out = client._extract_response(_stub_response("partial", "length"))
    assert out["finish_reason"] == "length"


def test_finish_reason_missing_returns_empty_string():
    """Old / non-conformant providers may omit the field entirely.
    Consumers should be able to do `response.get('finish_reason', '')` without surprise."""
    client = LLMClient.__new__(LLMClient)
    out = client._extract_response(_stub_response("hi", None))
    assert out["finish_reason"] == ""
