"""
Tests for bandjacks.llm.constants module.
"""

import pytest
from bandjacks.llm.constants import (
    DEFAULT_TACTIC_ORDER,
    TACTIC_ORDER,
    get_tactic_order,
    make_failed_chunk_result,
)


class TestTacticOrder:
    """Tests for tactic ordering constants and functions."""

    def test_tactic_order_has_14_tactics(self):
        """Test that TACTIC_ORDER contains exactly 14 tactics."""
        assert len(TACTIC_ORDER) == 14

    def test_tactic_order_values(self):
        """Test tactic order values for first, last, and unknown."""
        # First tactic should be 1
        assert TACTIC_ORDER["reconnaissance"] == 1

        # Last tactic should be 14
        assert TACTIC_ORDER["impact"] == 14

        # Unknown tactic should use default
        assert get_tactic_order("nonexistent-tactic") == DEFAULT_TACTIC_ORDER

    def test_get_tactic_order_with_valid_tactics(self):
        """Test get_tactic_order with valid tactics."""
        assert get_tactic_order("reconnaissance") == 1
        assert get_tactic_order("resource-development") == 2
        assert get_tactic_order("initial-access") == 3
        assert get_tactic_order("execution") == 4
        assert get_tactic_order("persistence") == 5
        assert get_tactic_order("privilege-escalation") == 6
        assert get_tactic_order("defense-evasion") == 7
        assert get_tactic_order("credential-access") == 8
        assert get_tactic_order("discovery") == 9
        assert get_tactic_order("lateral-movement") == 10
        assert get_tactic_order("collection") == 11
        assert get_tactic_order("command-and-control") == 12
        assert get_tactic_order("exfiltration") == 13
        assert get_tactic_order("impact") == 14

    def test_get_tactic_order_with_unknown_tactic(self):
        """Test get_tactic_order returns default for unknown tactics."""
        assert get_tactic_order("unknown") == DEFAULT_TACTIC_ORDER
        assert get_tactic_order("") == DEFAULT_TACTIC_ORDER
        assert get_tactic_order("invalid-tactic") == DEFAULT_TACTIC_ORDER


class TestMakeFailedChunkResult:
    """Tests for failed chunk result factory."""

    def test_failed_chunk_result_default_args(self):
        """Test make_failed_chunk_result with default arguments."""
        result = make_failed_chunk_result("chunk-1")

        assert result["chunk_id"] == "chunk-1"
        assert result["chunk_boundaries"] == (0, 0)
        assert result["claims"] == []
        assert result["techniques"] == {}
        assert result["entities"] == {}
        assert result["error"] == ""
        assert result["failed"] is True

    def test_failed_chunk_result_with_boundaries(self):
        """Test make_failed_chunk_result with boundaries."""
        result = make_failed_chunk_result("chunk-2", boundaries=(100, 500))

        assert result["chunk_id"] == "chunk-2"
        assert result["chunk_boundaries"] == (100, 500)
        assert result["failed"] is True

    def test_failed_chunk_result_with_error(self):
        """Test make_failed_chunk_result with error message."""
        error_msg = "Processing timeout exceeded"
        result = make_failed_chunk_result("chunk-3", error=error_msg)

        assert result["chunk_id"] == "chunk-3"
        assert result["error"] == error_msg
        assert result["failed"] is True

    def test_failed_chunk_result_with_all_args(self):
        """Test make_failed_chunk_result with all arguments."""
        result = make_failed_chunk_result(
            "chunk-4", boundaries=(250, 750), error="LLM API failed"
        )

        assert result["chunk_id"] == "chunk-4"
        assert result["chunk_boundaries"] == (250, 750)
        assert result["error"] == "LLM API failed"
        assert result["claims"] == []
        assert result["techniques"] == {}
        assert result["entities"] == {}
        assert result["failed"] is True

    def test_failed_chunk_result_structure(self):
        """Test that failed chunk result has expected structure."""
        result = make_failed_chunk_result("test-chunk")

        # Verify all required keys are present
        expected_keys = {
            "chunk_id",
            "chunk_boundaries",
            "claims",
            "techniques",
            "entities",
            "error",
            "failed",
        }
        assert set(result.keys()) == expected_keys

        # Verify types
        assert isinstance(result["chunk_id"], str)
        assert isinstance(result["chunk_boundaries"], tuple)
        assert isinstance(result["claims"], list)
        assert isinstance(result["techniques"], dict)
        assert isinstance(result["entities"], dict)
        assert isinstance(result["error"], str)
        assert isinstance(result["failed"], bool)
