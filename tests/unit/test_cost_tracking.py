"""Tests for LLM usage and cost extraction in client.call()."""

import sys
from unittest.mock import MagicMock, patch

# Pre-mock the bandjacks.llm.tools module to prevent transitive import chains
# (tools -> search_nodes -> opensearchpy, technique_cache -> neo4j, etc.)
# We only need to test client.py which does NOT import tools.
_tools_mock = MagicMock()
sys.modules["bandjacks.llm.tools"] = _tools_mock


def _mock_litellm_response(prompt_tokens=100, completion_tokens=50, model="gemini/gemini-2.5-flash"):
    """Create a mock LiteLLM response with usage data."""
    response = MagicMock()
    response.choices = [MagicMock()]
    response.choices[0].message.content = '{"result": "ok"}'
    response.choices[0].message.tool_calls = None
    response.usage = MagicMock()
    response.usage.prompt_tokens = prompt_tokens
    response.usage.completion_tokens = completion_tokens
    response.model = model
    return response


class TestClientUsageExtraction:
    """Tests for usage/cost extraction from LiteLLM responses."""

    @patch("bandjacks.llm.client.get_budget_tracker")
    @patch("bandjacks.llm.client.get_cache")
    @patch("bandjacks.llm.client.get_circuit_breaker")
    @patch("bandjacks.llm.client.get_rate_limiter")
    @patch("bandjacks.llm.client.completion_cost", return_value=0.00042)
    @patch("bandjacks.llm.client.completion")
    def test_call_returns_usage_dict(self, mock_completion, mock_cost, mock_rl, mock_cb, mock_cache, mock_bt):
        """Verify result has usage dict with correct token counts, cost, and model."""
        mock_cache.return_value.get.return_value = None
        mock_cb.return_value.is_open.return_value = False
        mock_rl.return_value.wait_if_needed.return_value = None
        mock_completion.return_value = _mock_litellm_response()

        from bandjacks.llm.client import LLMClient
        client = LLMClient()
        result = client.call([{"role": "user", "content": "hello"}], use_cache=True)

        assert "usage" in result
        usage = result["usage"]
        assert usage["tokens_in"] == 100
        assert usage["tokens_out"] == 50
        assert usage["cost_usd"] == 0.00042
        assert usage["model"] == client.model

    @patch("bandjacks.llm.client.get_budget_tracker")
    @patch("bandjacks.llm.client.get_cache")
    @patch("bandjacks.llm.client.get_circuit_breaker")
    @patch("bandjacks.llm.client.get_rate_limiter")
    @patch("bandjacks.llm.client.completion_cost", side_effect=Exception("cost error"))
    @patch("bandjacks.llm.client.completion")
    def test_cost_fallback_on_error(self, mock_completion, mock_cost, mock_rl, mock_cb, mock_cache, mock_bt):
        """When completion_cost raises, cost_usd should fall back to 0.0 but tokens should be correct."""
        mock_cache.return_value.get.return_value = None
        mock_cb.return_value.is_open.return_value = False
        mock_rl.return_value.wait_if_needed.return_value = None
        mock_completion.return_value = _mock_litellm_response(prompt_tokens=200, completion_tokens=80)

        from bandjacks.llm.client import LLMClient
        client = LLMClient()
        result = client.call([{"role": "user", "content": "hello"}], use_cache=True)

        usage = result["usage"]
        assert usage["tokens_in"] == 200
        assert usage["tokens_out"] == 80
        assert usage["cost_usd"] == 0.0

    @patch("bandjacks.llm.client.get_budget_tracker")
    @patch("bandjacks.llm.client.get_cache")
    @patch("bandjacks.llm.client.get_circuit_breaker")
    @patch("bandjacks.llm.client.get_rate_limiter")
    @patch("bandjacks.llm.client.completion_cost", return_value=0.00042)
    @patch("bandjacks.llm.client.completion")
    def test_cache_hit_returns_none_usage(self, mock_completion, mock_cost, mock_rl, mock_cb, mock_cache, mock_bt):
        """Cache hits should return usage=None to prevent double-counting."""
        mock_cache.return_value.get.return_value = {"content": "cached", "tool_calls": []}
        mock_cb.return_value.is_open.return_value = False

        from bandjacks.llm.client import LLMClient
        client = LLMClient()
        result = client.call([{"role": "user", "content": "hello"}], use_cache=True)

        assert result["usage"] is None
        # completion should not have been called
        mock_completion.assert_not_called()

    @patch("bandjacks.llm.client.get_budget_tracker")
    @patch("bandjacks.llm.client.get_cache")
    @patch("bandjacks.llm.client.get_circuit_breaker")
    @patch("bandjacks.llm.client.get_rate_limiter")
    @patch("bandjacks.llm.client.completion_cost", return_value=0.0)
    @patch("bandjacks.llm.client.completion")
    def test_missing_response_usage_defaults_to_zero(self, mock_completion, mock_cost, mock_rl, mock_cb, mock_cache, mock_bt):
        """If response.usage is None, tokens should default to 0."""
        mock_cache.return_value.get.return_value = None
        mock_cb.return_value.is_open.return_value = False
        mock_rl.return_value.wait_if_needed.return_value = None
        response = _mock_litellm_response()
        response.usage = None
        mock_completion.return_value = response

        from bandjacks.llm.client import LLMClient
        client = LLMClient()
        result = client.call([{"role": "user", "content": "hello"}], use_cache=True)

        usage = result["usage"]
        assert usage["tokens_in"] == 0
        assert usage["tokens_out"] == 0

    @patch("bandjacks.llm.client.get_budget_tracker")
    @patch("bandjacks.llm.client.get_cache")
    @patch("bandjacks.llm.client.get_circuit_breaker")
    @patch("bandjacks.llm.client.get_rate_limiter")
    @patch("bandjacks.llm.client.completion_cost", return_value=0.00042)
    @patch("bandjacks.llm.client.completion")
    def test_cache_set_excludes_usage_key(self, mock_completion, mock_cost, mock_rl, mock_cb, mock_cache, mock_bt):
        """Verify cache.set() is called with a dict that does NOT contain usage."""
        mock_cache.return_value.get.return_value = None
        mock_cb.return_value.is_open.return_value = False
        mock_rl.return_value.wait_if_needed.return_value = None
        mock_completion.return_value = _mock_litellm_response()

        from bandjacks.llm.client import LLMClient
        client = LLMClient()
        client.call([{"role": "user", "content": "hello"}], use_cache=True)

        # cache.set should have been called
        cache_instance = mock_cache.return_value
        cache_instance.set.assert_called_once()
        # The second positional arg is the result dict stored in cache
        cached_value = cache_instance.set.call_args[0][1]
        assert "usage" not in cached_value

    @patch("bandjacks.llm.client.get_budget_tracker")
    @patch("bandjacks.llm.client.get_cache")
    @patch("bandjacks.llm.client.get_circuit_breaker")
    @patch("bandjacks.llm.client.get_rate_limiter")
    @patch("bandjacks.llm.client.completion_cost", return_value=0.001)
    @patch("bandjacks.llm.client.completion")
    def test_fallback_model_returns_usage(self, mock_completion, mock_cost, mock_rl, mock_cb, mock_cache, mock_bt):
        """When primary fails and fallback succeeds, usage should reflect fallback model."""
        mock_cache.return_value.get.return_value = None
        mock_cb.return_value.is_open.return_value = False
        mock_rl.return_value.wait_if_needed.return_value = None

        # Primary call raises a retryable error
        fallback_response = _mock_litellm_response(prompt_tokens=150, completion_tokens=60, model="gpt-4o-mini")
        mock_completion.side_effect = [Exception("503 Service Unavailable"), fallback_response]

        from bandjacks.llm.client import LLMClient
        client = LLMClient()
        client.fallback_models = ["gpt-4o-mini"]

        result = client.call([{"role": "user", "content": "hello"}], use_cache=True)

        usage = result["usage"]
        assert usage["tokens_in"] == 150
        assert usage["tokens_out"] == 60
        assert usage["model"] == "gpt-4o-mini"
        assert usage["cost_usd"] == 0.001


from bandjacks.llm.token_utils import BudgetTracker, BudgetConfig


class TestBudgetTrackerStats:
    """Test BudgetTracker returns separate token counts."""

    def test_get_usage_stats_split_tokens(self):
        tracker = BudgetTracker(BudgetConfig(enforce_limits=False))
        tracker.record_usage("gemini/gemini-2.5-flash", tokens_in=500, tokens_out=200, actual_cost=0.001)
        tracker.record_usage("gemini/gemini-2.5-flash", tokens_in=300, tokens_out=100, actual_cost=0.0005)

        stats = tracker.get_usage_stats()
        assert stats["total_tokens_in"] == 800
        assert stats["total_tokens_out"] == 300
        assert "total_tokens" not in stats  # replaced by split fields


from bandjacks.llm.tracker import ExtractionTracker
from bandjacks.llm.client import record_usage_to_tracker


class TestExtractionTrackerCost:
    """Test ExtractionTracker accumulates cost from usage dicts."""

    def test_add_llm_call_from_usage(self):
        tracker = ExtractionTracker()
        usage = {"tokens_in": 500, "tokens_out": 200, "cost_usd": 0.001, "model": "gemini/gemini-2.5-flash"}
        tracker.add_llm_call(
            model=usage["model"], ms=150, tokens_in=usage["tokens_in"],
            tokens_out=usage["tokens_out"], tool_calls=0, cost_usd=usage["cost_usd"],
        )
        assert tracker.cost_usd == 0.001
        assert tracker.counters["llm_calls"] == 1
        assert len(tracker.llm_stats) == 1
        assert tracker.llm_stats[0].tokens_in == 500

    def test_snapshot_includes_cost(self):
        tracker = ExtractionTracker()
        tracker.add_llm_call("gemini/gemini-2.5-flash", 100, 500, 200, 0, 0.001)
        tracker.add_llm_call("gemini/gemini-2.5-flash", 120, 300, 100, 0, 0.0005)
        snap = tracker.snapshot()
        assert snap["cost_usd"] == 0.0015


class TestRecordUsageToTracker:
    """Test the record_usage_to_tracker helper function."""

    def test_records_usage_to_tracker(self):
        tracker = ExtractionTracker()
        response = {
            "content": "test", "tool_calls": [{"id": "1"}],
            "usage": {"tokens_in": 500, "tokens_out": 200, "cost_usd": 0.001, "model": "gemini/gemini-2.5-flash"},
        }
        record_usage_to_tracker(response, tracker, elapsed_ms=150)
        assert tracker.cost_usd == 0.001
        assert tracker.llm_stats[0].tool_calls == 1

    def test_noop_when_tracker_is_none(self):
        response = {"content": "test", "usage": {"tokens_in": 1, "tokens_out": 1, "cost_usd": 0.1, "model": "x"}}
        record_usage_to_tracker(response, None, 0)  # should not raise

    def test_noop_when_usage_is_none(self):
        tracker = ExtractionTracker()
        response = {"content": "test", "usage": None}
        record_usage_to_tracker(response, tracker, 0)
        assert tracker.cost_usd == 0.0
        assert tracker.counters["llm_calls"] == 0


from fastapi.testclient import TestClient


class TestCostEndpoint:
    """Test GET /v1/costs/stats endpoint."""

    def test_cost_stats_returns_daily(self):
        from bandjacks.services.api.routes.costs import router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router, prefix="/v1")

        client = TestClient(app)
        response = client.get("/v1/costs/stats")

        assert response.status_code == 200
        data = response.json()
        assert "daily" in data
        daily = data["daily"]
        assert "total_cost_usd" in daily
        assert "total_calls" in daily
        assert "total_tokens_in" in daily
        assert "total_tokens_out" in daily
        assert "calls_by_model" in daily
        assert "cost_by_model" in daily
        assert "last_reset" in daily
