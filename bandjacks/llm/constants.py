"""
Shared constants for the LLM pipeline.

This module provides standardized constants used across the extraction and
processing pipeline, including MITRE ATT&CK tactic ordering and error result
factories.
"""

# MITRE ATT&CK tactic ordering (kill chain)
# Maps tactic shortnames to numeric order (1-14)
TACTIC_ORDER = {
    "reconnaissance": 1,
    "resource-development": 2,
    "initial-access": 3,
    "execution": 4,
    "persistence": 5,
    "privilege-escalation": 6,
    "defense-evasion": 7,
    "credential-access": 8,
    "discovery": 9,
    "lateral-movement": 10,
    "collection": 11,
    "command-and-control": 12,
    "exfiltration": 13,
    "impact": 14,
}

# Fallback tactic order for unknown tactics
DEFAULT_TACTIC_ORDER = 7


def get_tactic_order(tactic: str) -> int:
    """
    Get the numeric order for a tactic.

    Args:
        tactic: Tactic shortname (e.g., "reconnaissance")

    Returns:
        Numeric order (1-14), or DEFAULT_TACTIC_ORDER if unknown
    """
    return TACTIC_ORDER.get(tactic, DEFAULT_TACTIC_ORDER)


def make_failed_chunk_result(
    chunk_id: str, boundaries: tuple = (0, 0), error: str = ""
) -> dict:
    """
    Create a standardized error result for a failed chunk.

    Args:
        chunk_id: Identifier for the chunk
        boundaries: Tuple of (start, end) character positions
        error: Error message

    Returns:
        Dictionary with failed chunk result structure
    """
    return {
        "chunk_id": chunk_id,
        "chunk_boundaries": boundaries,
        "claims": [],
        "techniques": {},
        "entities": {},
        "error": error,
        "failed": True,
    }
