"""Pin LLMClient._should_retry to walk tenacity's RetryError wrapping.

When the inner @retry decorator in LLMClient.call() exhausts its attempts on a
transient cloud failure (503, 429, timeout, etc.), tenacity re-raises the
failure wrapped as tenacity.RetryError. The wrapper's str() looks like:

    RetryError[<Future at 0x... state=finished raised ServiceUnavailableError>]

It contains no literal "503"/"429"/"timeout" token. Without unwrapping the
inner exception via tenacity's last_attempt.exception() API, _should_retry
returns False and the outer fallback-model chain at client.py:410 never fires.
The call then dies with `RuntimeError: LLM call failed after 1 attempts: ...`
instead of falling back to the next provider.

These tests pin the cause-walking behavior so a regression flips back to the
old failure mode immediately.
"""

import tenacity

from bandjacks.llm.client import LLMClient


def test_should_retry_unwraps_tenacity_retry_error():
    """RetryError wrapping a 503 should still trigger fallback."""

    class FakeServiceUnavailable(Exception):
        def __init__(self):
            super().__init__("Error code: 503 - shim only translates BatchMapperAgent...")

    inner = FakeServiceUnavailable()

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(1),
        retry=tenacity.retry_if_exception_type(Exception),
        reraise=False,
    )
    def _raise():
        raise inner

    try:
        _raise()
    except tenacity.RetryError as wrapped:
        client = LLMClient.__new__(LLMClient)  # bypass __init__ side effects
        assert client._should_retry(wrapped) is True
    else:
        raise AssertionError("expected RetryError")


def test_should_retry_handles_plain_503():
    """Backward-compat: a plain 503 message still triggers retry."""
    client = LLMClient.__new__(LLMClient)
    assert client._should_retry(RuntimeError("Error code: 503")) is True


def test_should_retry_rejects_non_retryable():
    """Non-transient errors (bad JSON, validation) must not trigger fallback."""
    client = LLMClient.__new__(LLMClient)
    assert client._should_retry(ValueError("bad json")) is False


def test_should_retry_unwraps_cause_chain():
    """When a non-retry-keyword wrapper has a retryable __cause__,
    the walk should still recognize it. Covers the case where a different
    library re-raises a transient failure as its own exception type."""

    class WrapperError(Exception):
        pass

    inner = RuntimeError("Error code: 429 rate_limit")
    try:
        try:
            raise inner
        except RuntimeError:
            raise WrapperError("upstream failed") from inner
    except WrapperError as wrapped:
        client = LLMClient.__new__(LLMClient)
        assert client._should_retry(wrapped) is True


def test_should_retry_handles_cycles():
    """Cause-chain cycles must not hang the walker."""

    a = RuntimeError("not retryable")
    b = RuntimeError("also not retryable")
    a.__cause__ = b
    b.__cause__ = a  # cycle
    client = LLMClient.__new__(LLMClient)
    assert client._should_retry(a) is False
