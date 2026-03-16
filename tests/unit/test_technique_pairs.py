"""Tests for bandjacks.llm.technique_pairs module."""

from __future__ import annotations

from bandjacks.llm.technique_pairs import (
    _load,
    match_commonly_missed,
    match_red_flags,
    suggest_missing,
)


class TestDataLoading:
    """Verify that the JSON data loads correctly."""

    def test_loads_pairs(self):
        data = _load()
        assert "technique_pairs" in data
        assert len(data["technique_pairs"]) > 0

    def test_loads_red_flags(self):
        data = _load()
        assert "red_flag_phrases" in data
        assert len(data["red_flag_phrases"]) > 0

    def test_loads_commonly_missed(self):
        data = _load()
        assert "commonly_missed" in data
        assert len(data["commonly_missed"]) > 0


class TestSuggestMissing:
    """Co-occurrence suggestion tests."""

    def test_t1566_suggests_t1204(self):
        suggestions = suggest_missing({"T1566"})
        ids = [s["technique_id"] for s in suggestions]
        assert "T1204" in ids

    def test_both_present_no_suggestion(self):
        suggestions = suggest_missing({"T1566", "T1204"})
        ids = [s["technique_id"] for s in suggestions]
        assert "T1204" not in ids

    def test_subtechnique_triggers_parent_rule(self):
        # T1566.001 should expand to also trigger the T1566 rule
        suggestions = suggest_missing({"T1566.001"})
        ids = [s["technique_id"] for s in suggestions]
        # Should suggest T1204 (from T1566 rule) and T1204.002 (from T1566.001 rule)
        assert "T1204" in ids
        assert "T1204.002" in ids

    def test_no_suggestions_when_nothing_matches(self):
        suggestions = suggest_missing({"T9999"})
        assert suggestions == []


class TestMatchRedFlags:
    """Red flag phrase matching tests."""

    def test_downloads_and_executes(self):
        matches = match_red_flags("The malware downloads and executes a payload.")
        assert len(matches) >= 1
        m = next(m for m in matches if m["phrase"] == "downloads and executes")
        assert "T1105" in m["techniques"]
        assert "T1059" in m["techniques"]

    def test_case_insensitive(self):
        matches = match_red_flags("C2 OVER HTTPS channel established")
        phrases = [m["phrase"] for m in matches]
        assert "c2 over https" in phrases

    def test_no_match_on_unrelated_text(self):
        matches = match_red_flags("The quick brown fox jumps over the lazy dog.")
        assert matches == []


class TestMatchCommonlyMissed:
    """Commonly missed indicator tests."""

    def test_windowstyle_hidden_and_encodedcommand(self):
        text = "powershell.exe -windowstyle hidden -encodedcommand SQBFAFG..."
        matches = match_commonly_missed(text)
        indicators = [m["indicator"] for m in matches]
        assert "-windowstyle hidden" in indicators
        assert "-encodedcommand" in indicators
        # Check mapped techniques
        techs = set()
        for m in matches:
            techs.update(m["techniques"])
        assert "T1564.003" in techs
        assert "T1027.010" in techs

    def test_no_match_on_clean_text(self):
        matches = match_commonly_missed("Normal application startup sequence.")
        assert matches == []
