"""TechniquePairValidator — co-occurrence rules, red-flag phrases, and
commonly-missed indicator detection.

Data is loaded once from ``data/technique_pairs.json`` using a module-level
singleton so that repeated calls inside the extraction pipeline pay no
repeated I/O cost.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Set

_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "technique_pairs.json"

_data: Dict[str, Any] | None = None


def _load() -> Dict[str, Any]:
    global _data
    if _data is None:
        with open(_DATA_PATH) as fh:
            _data = json.load(fh)
    return _data


def _parent_id(tid: str) -> str | None:
    """Return the parent technique ID for a sub-technique, or None."""
    if "." in tid:
        return tid.split(".")[0]
    return None


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------


def suggest_missing(found_techniques: Set[str]) -> List[Dict[str, str]]:
    """Given a set of found technique IDs, return suggestions for
    co-occurring techniques that are absent.

    Each returned dict has keys ``technique_id``, ``reason``, and
    ``triggered_by``.
    """
    data = _load()
    suggestions: List[Dict[str, str]] = []
    seen: Set[str] = set()

    # Build an expanded set that includes parent IDs so that
    # T1566.001 also triggers rules keyed on T1566.
    expanded: Set[str] = set(found_techniques)
    for tid in found_techniques:
        parent = _parent_id(tid)
        if parent is not None:
            expanded.add(parent)

    for pair in data["technique_pairs"]:
        if_found: str = pair["if_found"]
        if if_found not in expanded:
            continue
        for target in pair["check_for"]:
            if target in found_techniques:
                continue
            # Also skip if a sub-technique of the target is already present
            if any(t.startswith(target + ".") for t in found_techniques):
                continue
            if target in seen:
                continue
            seen.add(target)
            suggestions.append(
                {
                    "technique_id": target,
                    "reason": pair["reason"],
                    "triggered_by": if_found,
                }
            )

    return suggestions


def match_red_flags(text: str) -> List[Dict[str, Any]]:
    """Scan *text* (case-insensitive) for red-flag phrases and return
    matching entries with ``phrase``, ``techniques``, and ``reason``.
    """
    data = _load()
    lower = text.lower()
    matches: List[Dict[str, Any]] = []
    for entry in data["red_flag_phrases"]:
        if entry["phrase"] in lower:
            matches.append(
                {
                    "phrase": entry["phrase"],
                    "techniques": list(entry["techniques"]),
                    "reason": entry["reason"],
                }
            )
    return matches


def match_commonly_missed(text: str) -> List[Dict[str, Any]]:
    """Scan *text* (case-insensitive) for commonly-missed CLI indicators
    and return matching entries with ``indicator`` and ``techniques``.
    """
    data = _load()
    lower = text.lower()
    matches: List[Dict[str, Any]] = []
    for indicator, techniques in data["commonly_missed"].items():
        if indicator.lower() in lower:
            matches.append(
                {
                    "indicator": indicator,
                    "techniques": list(techniques),
                }
            )
    return matches
