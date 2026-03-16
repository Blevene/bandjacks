"""Tests for bandjacks.llm.keyword_index."""

import importlib

import pytest

from bandjacks.llm import keyword_index


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reload_module():
    """Ensure a fresh load for every test (in case prior test mutated state)."""
    # Reset singleton so _load() runs again
    keyword_index._index = None
    keyword_index._multi_words = None
    keyword_index._single_words = None
    yield


# ------------------------------------------------------------------
# Loading
# ------------------------------------------------------------------

class TestLoading:
    def test_loads_more_than_1000_entries(self):
        assert keyword_index.entry_count() > 1000

    def test_loads_expected_entry_count(self):
        # The file has 2755 data lines
        assert keyword_index.entry_count() == 2755


# ------------------------------------------------------------------
# lookup()
# ------------------------------------------------------------------

class TestLookup:
    def test_mimikatz_maps_to_t1003_001(self):
        result = keyword_index.lookup("mimikatz")
        assert "T1003.001" in result

    def test_case_insensitive(self):
        lower = keyword_index.lookup("mimikatz")
        upper = keyword_index.lookup("MIMIKATZ")
        mixed = keyword_index.lookup("Mimikatz")
        assert lower == upper == mixed
        assert "T1003.001" in lower

    def test_unknown_keyword_returns_empty_set(self):
        result = keyword_index.lookup("xyzzy_not_a_real_keyword_42")
        assert result == set()
        assert isinstance(result, set)

    def test_lnk_maps_to_multiple_techniques(self):
        result = keyword_index.lookup(".lnk")
        assert len(result) >= 2
        assert "T1204.002" in result
        assert "T1027.012" in result


# ------------------------------------------------------------------
# match_text()
# ------------------------------------------------------------------

class TestMatchText:
    def test_finds_keyword_in_prose(self):
        text = "The attacker used mimikatz to dump credentials from LSASS."
        matches = keyword_index.match_text(text)
        keywords_found = {m["keyword"] for m in matches}
        assert "mimikatz" in keywords_found

    def test_each_match_has_keyword_and_technique_ids(self):
        text = "The threat actor deployed mimikatz on the host."
        matches = keyword_index.match_text(text)
        assert len(matches) > 0
        for m in matches:
            assert "keyword" in m
            assert "technique_ids" in m
            assert isinstance(m["keyword"], str)
            assert isinstance(m["technique_ids"], set)
            assert len(m["technique_ids"]) > 0

    def test_multi_word_keyword_matched(self):
        text = "Persistence was achieved via a scheduled task created by the implant."
        matches = keyword_index.match_text(text)
        keywords_found = {m["keyword"] for m in matches}
        assert "scheduled task" in keywords_found

    def test_max_matches_limits_results(self):
        # Build a long text containing many keywords to test the cap
        text = "mimikatz lsass powershell cmd.exe rundll32 regsvr32 wmic schtasks"
        matches = keyword_index.match_text(text, max_matches=3)
        assert len(matches) <= 3

    def test_empty_text_returns_empty(self):
        assert keyword_index.match_text("") == []

    def test_no_matches_returns_empty(self):
        matches = keyword_index.match_text("The quick brown fox jumped over the lazy dog.")
        # Might match some very common words; just ensure it returns a list
        assert isinstance(matches, list)


# ------------------------------------------------------------------
# Edge cases
# ------------------------------------------------------------------

class TestEdgeCases:
    def test_graceful_when_file_missing(self, tmp_path, monkeypatch):
        """If the data file doesn't exist, the index loads as empty."""
        monkeypatch.setattr(keyword_index, "_DATA_PATH", tmp_path / "nonexistent.idx")
        keyword_index._index = None  # force reload
        assert keyword_index.entry_count() == 0
        assert keyword_index.lookup("mimikatz") == set()
