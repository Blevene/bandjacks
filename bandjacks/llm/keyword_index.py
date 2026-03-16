"""Keyword-to-ATT&CK technique index.

Loads ``data/attack_keywords.idx`` once as a module-level singleton and
exposes fast lookup helpers used by the extraction pipeline.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Set

# ---------------------------------------------------------------------------
# Singleton index  (same pattern as loaders/embedder.py)
# ---------------------------------------------------------------------------

_index: Dict[str, Set[str]] | None = None

# Multi-word keywords sorted longest-first so more specific phrases match
# before shorter substrings.
_multi_words: List[str] | None = None
_single_words: Set[str] | None = None

_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "attack_keywords.idx"

_WORD_RE = re.compile(r"[a-z0-9_.%$#@+\-]+")


def _load() -> Dict[str, Set[str]]:
    """Parse the ``.idx`` file and populate module-level caches."""
    global _index, _multi_words, _single_words

    index: Dict[str, Set[str]] = {}

    try:
        with open(_DATA_PATH, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Format: keyword:T1234,T5678
                colon_pos = line.find(":")
                if colon_pos == -1:
                    continue
                keyword = line[:colon_pos].lower()
                technique_ids = {
                    tid.strip()
                    for tid in line[colon_pos + 1 :].split(",")
                    if tid.strip()
                }
                if keyword and technique_ids:
                    index[keyword] = technique_ids
    except FileNotFoundError:
        pass

    _index = index

    # Partition into multi-word and single-word sets.
    multi = []
    single = set()
    for kw in index:
        if " " in kw:
            multi.append(kw)
        else:
            single.add(kw)
    # Longest first so we match "scheduled task/job" before "scheduled task".
    multi.sort(key=len, reverse=True)
    _multi_words = multi
    _single_words = single

    return index


def _ensure_loaded() -> Dict[str, Set[str]]:
    if _index is None:
        _load()
    assert _index is not None
    return _index


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def lookup(keyword: str) -> Set[str]:
    """Return technique IDs for an exact keyword, case-insensitive.

    Returns an empty set when the keyword is not in the index.
    """
    idx = _ensure_loaded()
    return set(idx.get(keyword.lower(), set()))


def match_text(text: str, *, max_matches: int = 50) -> List[Dict]:
    """Find all keyword matches present in *text*.

    Multi-word keywords are checked via substring presence.
    Single-word keywords are checked against the set of tokens in the text.

    Returns a list of ``{"keyword": str, "technique_ids": set}`` dicts,
    capped at *max_matches* (sorted longest keyword first).
    """
    idx = _ensure_loaded()
    assert _multi_words is not None
    assert _single_words is not None

    text_lower = text.lower()
    tokens = set(_WORD_RE.findall(text_lower))

    hits: List[Dict] = []

    # Multi-word (substring match, longest first)
    for kw in _multi_words:
        if kw in text_lower:
            hits.append({"keyword": kw, "technique_ids": set(idx[kw])})
            if len(hits) >= max_matches:
                return hits

    # Single-word (token membership)
    for kw in _single_words:
        if kw in tokens:
            hits.append({"keyword": kw, "technique_ids": set(idx[kw])})
            if len(hits) >= max_matches:
                return hits

    return hits


def entry_count() -> int:
    """Return the number of entries in the loaded index."""
    return len(_ensure_loaded())


class KeywordIndex:
    """Thin OO wrapper so callers can hold an instance reference."""

    def __init__(self) -> None:
        _ensure_loaded()
        if not _DATA_PATH.exists():
            raise FileNotFoundError(f"Keyword index not found: {_DATA_PATH}")

    @staticmethod
    def match_text(text: str, *, max_matches: int = 50) -> List[Dict]:
        return match_text(text, max_matches=max_matches)

    @staticmethod
    def lookup(keyword: str) -> Set[str]:
        return lookup(keyword)

    @staticmethod
    def entry_count() -> int:
        return entry_count()
