"""
Tests for DeterministicFlowBuilder.

Comprehensive coverage of deduplication, tactic ordering, narrative position,
edge confidence tiers, and stats computation.
"""

from bandjacks.llm.flow_deterministic import DeterministicFlowBuilder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CACHE_DATA = {
    "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "initial-access", "tactics": ["initial-access"]},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "execution", "tactics": ["execution"]},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution", "tactics": ["execution"]},
    "T1055": {"name": "Process Injection", "tactic": "defense-evasion", "tactics": ["defense-evasion", "privilege-escalation"]},
    "T1003.001": {"name": "OS Credential Dumping: LSASS Memory", "tactic": "credential-access", "tactics": ["credential-access"]},
    "T1021.001": {"name": "Remote Services: Remote Desktop Protocol", "tactic": "lateral-movement", "tactics": ["lateral-movement"]},
    "T1547.001": {"name": "Boot or Logon Autostart Execution: Registry Run Keys", "tactic": "persistence", "tactics": ["persistence"]},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration", "tactics": ["exfiltration"]},
}


class _FakeCache:
    """Mimics TechniqueCache.get() for testing."""

    def __init__(self, data=None):
        self._data = data or _CACHE_DATA

    def get(self, external_id):
        return self._data.get(external_id)


def _make_claim(tid, line_refs=None, confidence=0.8, name=""):
    return {
        "external_id": tid,
        "line_refs": line_refs if line_refs is not None else [],
        "confidence": confidence,
        "name": name,
    }


def _builder(cache=None):
    return DeterministicFlowBuilder(cache or _FakeCache())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_empty_claims_returns_none():
    result = _builder().build([], source_id="src-1")
    assert result is None


def test_single_technique_returns_none():
    claims = [_make_claim("T1566.001", [10], 0.9)]
    result = _builder().build(claims)
    assert result is None


def test_two_techniques_kill_chain_high_confidence():
    """Two techniques in kill-chain order with forward positions → high tier."""
    claims = [
        _make_claim("T1566.001", [5], 0.9),   # initial-access (rank 3)
        _make_claim("T1059.001", [20], 0.85),  # execution (rank 4)
    ]
    result = _builder().build(claims)
    assert result is not None
    assert len(result["actions"]) == 2
    assert result["actions"][0]["tactic"] == "initial-access"
    assert result["actions"][1]["tactic"] == "execution"
    assert len(result["edges"]) == 1
    assert result["edges"][0]["tier"] == "high"
    assert result["edges"][0]["probability"] == 0.8


def test_same_tactic_medium_confidence():
    """T1059 and T1059.001 share execution tactic → medium tier."""
    claims = [
        _make_claim("T1059", [3], 0.7),
        _make_claim("T1059.001", [10], 0.8),
    ]
    result = _builder().build(claims)
    assert result is not None
    assert len(result["edges"]) == 1
    assert result["edges"][0]["tier"] == "medium"
    assert result["edges"][0]["probability"] == 0.5


def test_forward_tactic_backward_position_low():
    """Forward tactic but backward position → low tier."""
    claims = [
        _make_claim("T1566.001", [100], 0.9),  # initial-access, pos 100
        _make_claim("T1059.001", [5], 0.85),    # execution, pos 5
    ]
    result = _builder().build(claims)
    assert result is not None
    # Sorted by tactic_rank first: initial-access(3) before execution(4)
    assert result["actions"][0]["tactic"] == "initial-access"
    assert result["actions"][1]["tactic"] == "execution"
    # tactic_forward=True but position_forward=False → low
    assert result["edges"][0]["tier"] == "low"
    assert result["edges"][0]["probability"] == 0.25


def test_deduplication():
    """Same TID twice → keep max confidence."""
    claims = [
        _make_claim("T1566.001", [10], 0.6),
        _make_claim("T1566.001", [5], 0.9),
        _make_claim("T1059.001", [20], 0.8),
    ]
    result = _builder().build(claims)
    assert result is not None
    # Only 2 unique techniques
    assert len(result["actions"]) == 2
    # T1566.001 should have max confidence 0.9 and min position 5
    phishing = result["actions"][0]
    assert phishing["confidence"] == 0.9
    assert phishing["narrative_position"] == 5


def test_no_line_refs_sorts_last():
    """Empty line_refs → narrative_position=_NO_POSITION, sorts after positioned techniques in same tactic."""
    claims = [
        _make_claim("T1059", [], 0.7),         # execution, no position → _NO_POSITION
        _make_claim("T1059.001", [10], 0.8),   # execution, position 10
        _make_claim("T1566.001", [1], 0.9),    # initial-access, position 1
    ]
    result = _builder().build(claims)
    assert result is not None
    # Order: T1566.001 (rank 3), T1059.001 (rank 4, pos 10), T1059 (rank 4, pos _NO_POSITION)
    assert result["actions"][0]["attack_pattern_ref"] == "attack-pattern--T1566.001"
    assert result["actions"][1]["attack_pattern_ref"] == "attack-pattern--T1059.001"
    assert result["actions"][2]["attack_pattern_ref"] == "attack-pattern--T1059"
    assert result["actions"][2]["narrative_position"] == 999_999


def test_self_loop_guard():
    """No edge between actions with same attack_pattern_ref."""
    # This shouldn't normally happen after dedup, but test the guard.
    # We test indirectly: dedup prevents duplicates, so we just verify
    # that dedup works and no self-loops appear.
    claims = [
        _make_claim("T1566.001", [5], 0.9),
        _make_claim("T1566.001", [10], 0.8),  # duplicate, will be deduped
        _make_claim("T1059.001", [20], 0.85),
    ]
    result = _builder().build(claims)
    assert result is not None
    for edge in result["edges"]:
        assert edge["source_ref"] != edge["target_ref"]


def test_tier_distribution_stats():
    """Stats include correct tier distribution."""
    claims = [
        _make_claim("T1566.001", [5], 0.9),   # initial-access
        _make_claim("T1059.001", [20], 0.85),  # execution
        _make_claim("T1055", [25], 0.7),       # defense-evasion
    ]
    result = _builder().build(claims)
    stats = result["stats"]
    assert stats["steps_count"] == 3
    assert stats["edges_count"] == 2
    # All forward tactic + forward position → all high
    assert stats["tier_distribution"]["high"] == 2
    assert stats["tier_distribution"]["medium"] == 0
    assert stats["tier_distribution"]["low"] == 0


def test_techniques_without_position_stat():
    """Stats track techniques with no line_refs (inf position)."""
    claims = [
        _make_claim("T1566.001", [], 0.9),    # no position
        _make_claim("T1059.001", [20], 0.85),  # has position
    ]
    result = _builder().build(claims)
    assert result["stats"]["techniques_without_position"] == 1


def test_unknown_tactic_gets_rank_7():
    """Technique with unknown tactic gets rank 7."""
    cache = _FakeCache({
        "T9999": {"name": "Unknown Technique", "tactic": "made-up-tactic", "tactics": ["made-up-tactic"]},
        "T1059.001": _CACHE_DATA["T1059.001"],
    })
    claims = [
        _make_claim("T9999", [1], 0.9),
        _make_claim("T1059.001", [10], 0.8),
    ]
    result = DeterministicFlowBuilder(cache).build(claims)
    assert result is not None
    # execution=rank 4 < unknown=rank 7
    assert result["actions"][0]["tactic"] == "execution"
    assert result["actions"][1]["tactic"] == "made-up-tactic"
    assert result["actions"][1]["tactic_rank"] == 7


def test_subtechnique_after_parent():
    """T1059 before T1059.001 due to lexicographic sort (same tactic+position)."""
    claims = [
        _make_claim("T1059.001", [10], 0.8),
        _make_claim("T1059", [10], 0.7),
    ]
    result = _builder().build(claims)
    assert result is not None
    # Same tactic (execution, rank 4), same position (10), sorted by external_id
    assert result["actions"][0]["attack_pattern_ref"] == "attack-pattern--T1059"
    assert result["actions"][1]["attack_pattern_ref"] == "attack-pattern--T1059.001"


def test_source_id_in_result():
    """source_id is passed through to the result."""
    claims = [
        _make_claim("T1566.001", [5], 0.9),
        _make_claim("T1059.001", [20], 0.85),
    ]
    result = _builder().build(claims, source_id="report-abc-123")
    assert result["source_id"] == "report-abc-123"


def test_flow_type_is_deterministic_full():
    """flow_type must be 'deterministic_full'."""
    claims = [
        _make_claim("T1566.001", [5], 0.9),
        _make_claim("T1059.001", [20], 0.85),
    ]
    result = _builder().build(claims)
    assert result["flow_type"] == "deterministic_full"
    assert result["llm_synthesized"] is False


def test_full_kill_chain_ordering():
    """7 techniques across kill chain, verify exact order."""
    claims = [
        _make_claim("T1041", [70], 0.7),       # exfiltration (13)
        _make_claim("T1021.001", [50], 0.75),   # lateral-movement (10)
        _make_claim("T1547.001", [30], 0.8),    # persistence (5)
        _make_claim("T1003.001", [40], 0.85),   # credential-access (8)
        _make_claim("T1059.001", [20], 0.85),   # execution (4)
        _make_claim("T1566.001", [5], 0.9),     # initial-access (3)
        _make_claim("T1055", [25], 0.7),        # defense-evasion (7)
    ]
    result = _builder().build(claims)
    assert result is not None
    assert len(result["actions"]) == 7

    expected_order = [
        "attack-pattern--T1566.001",  # initial-access (3)
        "attack-pattern--T1059.001",  # execution (4)
        "attack-pattern--T1547.001",  # persistence (5)
        "attack-pattern--T1055",      # defense-evasion (7)
        "attack-pattern--T1003.001",  # credential-access (8)
        "attack-pattern--T1021.001",  # lateral-movement (10)
        "attack-pattern--T1041",      # exfiltration (13)
    ]

    actual_order = [a["attack_pattern_ref"] for a in result["actions"]]
    assert actual_order == expected_order

    # 6 edges between 7 actions
    assert len(result["edges"]) == 6
    # Most edges are high (forward tactic + forward position)
    # Exception: persistence(rank=5,pos=30) → defense-evasion(rank=7,pos=25)
    #   tactic_forward=True but position_forward=False → low
    tiers = [e["tier"] for e in result["edges"]]
    assert tiers.count("high") == 5
    assert tiers.count("low") == 1
    # The low edge is the 3rd one (persistence → defense-evasion)
    assert result["edges"][2]["tier"] == "low"

    # Stats
    assert result["stats"]["steps_count"] == 7
    assert result["stats"]["edges_count"] == 6
    assert result["stats"]["tier_distribution"]["high"] == 5
    assert result["stats"]["tier_distribution"]["low"] == 1
    assert result["stats"]["techniques_without_position"] == 0
