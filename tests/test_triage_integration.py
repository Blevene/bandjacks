"""Integration tests for the triage system."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime
from collections import Counter

from bandjacks.llm.triage import PairTriage, TriageConfig, TriagedPair
from bandjacks.llm.sequence_extractor import PairwiseStatistics


@pytest.fixture
def mock_sequence_extractor():
    """Mock sequence extractor with test data."""
    extractor = Mock()
    
    # Mock the find_ambiguous_pairs method
    extractor.find_ambiguous_pairs.return_value = [
        ("attack-pattern--123", "attack-pattern--456"),
        ("attack-pattern--789", "attack-pattern--abc"),
        ("attack-pattern--def", "attack-pattern--ghi")
    ]
    
    # Mock the driver and session for tactic lookups
    session_mock = Mock()
    session_mock.__enter__ = Mock(return_value=session_mock)
    session_mock.__exit__ = Mock(return_value=None)
    
    # Mock tactic lookup responses
    def mock_get_primary_tactic(session, technique_id):
        tactic_map = {
            "attack-pattern--123": "initial-access",
            "attack-pattern--456": "execution", 
            "attack-pattern--789": "persistence",
            "attack-pattern--abc": "privilege-escalation",
            "attack-pattern--def": "discovery",
            "attack-pattern--ghi": "lateral-movement"
        }
        return tactic_map.get(technique_id)
    
    extractor._get_primary_tactic = mock_get_primary_tactic
    
    driver_mock = Mock()
    driver_mock.session.return_value = session_mock
    extractor.driver = driver_mock
    
    return extractor


@pytest.fixture
def mock_evidence_builder():
    """Mock evidence builder."""
    builder = Mock()
    
    # Mock evidence pack creation
    from bandjacks.llm.evidence_pack import EvidencePack, EvidenceSnippet, TechniqueContext
    
    def mock_build_evidence_pack(from_tech, to_tech, scope=None):
        return EvidencePack(
            pair={"from_technique": from_tech, "to_technique": to_tech},
            statistics={"asymmetry": 0.1, "forward_prob": 0.3, "reverse_prob": 0.2},
            tactic_context={"from_tactic": "initial-access", "to_tactic": "execution"},
            technique_details={
                from_tech: TechniqueContext(
                    technique_id=from_tech,
                    name="Test Technique 1",
                    description="Test description",
                    tactic="initial-access",
                    subtechniques=[],
                    platforms=["Windows"],
                    data_sources=["Process monitoring"]
                )
            },
            graph_hints=["Test hint"],
            evidence_snippets=[
                EvidenceSnippet(
                    doc_id="test-1",
                    text="Test evidence",
                    source="test-source",
                    score=0.8,
                    metadata={"kb_type": "attack-pattern"}
                )
            ],
            historical_flows=[],
            retrieval_hash="test-hash-123"
        )
    
    builder.build_evidence_pack = mock_build_evidence_pack
    return builder


@pytest.fixture
def test_stats():
    """Create test pairwise statistics."""
    return PairwiseStatistics(
        scope="global",
        scope_type="global",
        technique_counts={
            "attack-pattern--123": 10,
            "attack-pattern--456": 8,
            "attack-pattern--789": 12,
            "attack-pattern--abc": 6,
            "attack-pattern--def": 15,
            "attack-pattern--ghi": 9
        },
        pair_counts={
            ("attack-pattern--123", "attack-pattern--456"): 5,
            ("attack-pattern--456", "attack-pattern--123"): 3,
            ("attack-pattern--789", "attack-pattern--abc"): 4,
            ("attack-pattern--abc", "attack-pattern--789"): 4,
            ("attack-pattern--def", "attack-pattern--ghi"): 6,
            ("attack-pattern--ghi", "attack-pattern--def"): 2
        },
        conditional_probs={
            ("attack-pattern--123", "attack-pattern--456"): 0.5,
            ("attack-pattern--456", "attack-pattern--123"): 0.375,
            ("attack-pattern--789", "attack-pattern--abc"): 0.33,
            ("attack-pattern--abc", "attack-pattern--789"): 0.67,
            ("attack-pattern--def", "attack-pattern--ghi"): 0.4,
            ("attack-pattern--ghi", "attack-pattern--def"): 0.22
        },
        asymmetry_scores={
            ("attack-pattern--123", "attack-pattern--456"): 0.125,  # |0.5 - 0.375|
            ("attack-pattern--789", "attack-pattern--abc"): 0.14,   # Within threshold
            ("attack-pattern--def", "attack-pattern--ghi"): 0.12    # Within threshold
        },
        total_flows=20,
        total_techniques=6,
        total_pairs=6
    )


def test_triage_config_defaults():
    """Test triage configuration defaults."""
    config = TriageConfig()
    
    assert config.ambiguity_threshold == 0.15
    assert config.min_count == 3
    assert config.max_pairs_per_scope == 50
    assert config.exclude_subtechniques == False
    assert config.exclude_same_tactic == True
    assert config.min_confidence == 0.1


def test_triaged_pair_priority_calculation():
    """Test priority score calculation for triaged pairs."""
    pair = TriagedPair(
        from_technique="attack-pattern--123",
        to_technique="attack-pattern--456", 
        scope="global",
        scope_type="global",
        asymmetry_score=0.1,
        forward_prob=0.4,
        reverse_prob=0.3,
        co_occurrence_count=5,
        from_tactic="initial-access",
        to_tactic="execution",
        tactic_distance=1
    )
    
    # Priority should be calculated in __post_init__
    assert pair.priority_score > 0
    
    # Lower asymmetry should give higher priority
    assert pair.priority_score > 0.8  # 1.0 - 0.1 + bonuses


def test_triage_scope(mock_sequence_extractor, mock_evidence_builder, test_stats):
    """Test triage for a single scope."""
    config = TriageConfig(ambiguity_threshold=0.15, min_count=3)
    triage = PairTriage(mock_sequence_extractor, mock_evidence_builder, config)
    
    triaged_pairs = triage.triage_scope(test_stats)
    
    # Should have filtered pairs based on config
    assert len(triaged_pairs) > 0
    
    # Should be sorted by priority (descending)
    priorities = [p.priority_score for p in triaged_pairs]
    assert priorities == sorted(priorities, reverse=True)
    
    # Check that pairs have required fields
    for pair in triaged_pairs:
        assert pair.from_technique
        assert pair.to_technique
        assert pair.scope == "global"
        assert pair.asymmetry_score <= config.ambiguity_threshold
        assert pair.co_occurrence_count >= config.min_count
        assert pair.priority_score > 0
        assert pair.triaged_at


def test_should_skip_pair(mock_sequence_extractor, mock_evidence_builder, test_stats):
    """Test pair filtering logic."""
    config = TriageConfig(
        exclude_subtechniques=True,
        exclude_same_tactic=True,
        min_confidence=0.2
    )
    triage = PairTriage(mock_sequence_extractor, mock_evidence_builder, config)
    
    # Should skip subtechniques
    assert triage._should_skip_pair("attack-pattern--123.001", "attack-pattern--456", test_stats)
    
    # Should skip low confidence pairs
    test_stats.conditional_probs[("attack-pattern--123", "attack-pattern--456")] = 0.1
    test_stats.conditional_probs[("attack-pattern--456", "attack-pattern--123")] = 0.05
    assert triage._should_skip_pair("attack-pattern--123", "attack-pattern--456", test_stats)


def test_tactic_distance_calculation(mock_sequence_extractor, mock_evidence_builder):
    """Test tactic distance calculation."""
    triage = PairTriage(mock_sequence_extractor, mock_evidence_builder)
    
    # Adjacent tactics should have distance 1
    assert triage._calculate_tactic_distance("initial-access", "execution") == 1
    
    # Same tactic should have distance 0
    assert triage._calculate_tactic_distance("execution", "execution") == 0
    
    # Far apart tactics should have larger distance
    assert triage._calculate_tactic_distance("initial-access", "impact") == 11
    
    # Unknown tactics should return None
    assert triage._calculate_tactic_distance("unknown-tactic", "execution") is None


def test_build_evidence_packs_for_batch(mock_sequence_extractor, mock_evidence_builder, test_stats):
    """Test evidence pack building for batches."""
    triage = PairTriage(mock_sequence_extractor, mock_evidence_builder)
    
    # Create some triaged pairs
    pairs = [
        TriagedPair(
            from_technique="attack-pattern--123",
            to_technique="attack-pattern--456",
            scope="global", 
            scope_type="global",
            asymmetry_score=0.1,
            forward_prob=0.4,
            reverse_prob=0.3,
            co_occurrence_count=5
        ),
        TriagedPair(
            from_technique="attack-pattern--789",
            to_technique="attack-pattern--abc",
            scope="global",
            scope_type="global", 
            asymmetry_score=0.12,
            forward_prob=0.35,
            reverse_prob=0.28,
            co_occurrence_count=4
        )
    ]
    
    results = triage.build_evidence_packs_for_batch(pairs, batch_size=1)
    
    assert len(results) == 2
    
    for pair, evidence_pack in results:
        assert isinstance(pair, TriagedPair)
        assert evidence_pack is not None
        assert pair.evidence_pack_hash == "test-hash-123"


def test_budget_filtering(mock_sequence_extractor, mock_evidence_builder):
    """Test budget constraint application."""
    triage = PairTriage(mock_sequence_extractor, mock_evidence_builder)
    
    # Create test data with multiple scopes
    all_triaged = {
        "global": [
            TriagedPair(
                from_technique="attack-pattern--1",
                to_technique="attack-pattern--2",
                scope="global",
                scope_type="global",
                asymmetry_score=0.1,
                forward_prob=0.4,
                reverse_prob=0.3,
                co_occurrence_count=5,
                priority_score=0.9
            )
        ],
        "intrusion-set--123": [
            TriagedPair(
                from_technique="attack-pattern--3",
                to_technique="attack-pattern--4",
                scope="intrusion-set--123",
                scope_type="intrusion-set",
                asymmetry_score=0.12,
                forward_prob=0.35,
                reverse_prob=0.28,
                co_occurrence_count=4,
                priority_score=0.7
            )
        ]
    }
    
    # Apply budget with limit of 1 pair
    filtered = triage.filter_by_budget(all_triaged, max_total_pairs=1, prioritize_global=True)
    
    # Should keep only the highest priority pair
    total_pairs = sum(len(pairs) for pairs in filtered.values())
    assert total_pairs == 1
    
    # Global scope should be prioritized
    assert "global" in filtered
    assert len(filtered["global"]) == 1


def test_triage_summary(mock_sequence_extractor, mock_evidence_builder):
    """Test summary statistics generation."""
    triage = PairTriage(mock_sequence_extractor, mock_evidence_builder)
    
    # Create test triaged pairs
    all_triaged = {
        "global": [
            TriagedPair(
                from_technique="attack-pattern--1",
                to_technique="attack-pattern--2",
                scope="global",
                scope_type="global",
                asymmetry_score=0.1,
                forward_prob=0.4,
                reverse_prob=0.3,
                co_occurrence_count=5,
                from_tactic="initial-access",
                to_tactic="execution"
            ),
            TriagedPair(
                from_technique="attack-pattern--3", 
                to_technique="attack-pattern--4",
                scope="global",
                scope_type="global",
                asymmetry_score=0.12,
                forward_prob=0.35,
                reverse_prob=0.28,
                co_occurrence_count=4,
                from_tactic="execution",
                to_tactic="persistence"
            )
        ]
    }
    
    summary = triage.get_triage_summary(all_triaged)
    
    assert summary["total_pairs"] == 2
    assert "global" in summary["scopes"]
    assert summary["scope_counts"]["global"] == 2
    assert "avg_asymmetry" in summary
    assert "avg_priority" in summary
    assert "cross_tactic_pairs" in summary
    assert "config" in summary
    
    # Should identify cross-tactic transitions
    assert summary["cross_tactic_pairs"] == 2  # Both pairs cross tactics
    assert summary["same_tactic_pairs"] == 0


def test_triage_empty_stats(mock_sequence_extractor, mock_evidence_builder):
    """Test triage with empty statistics."""
    empty_stats = PairwiseStatistics(
        scope="test",
        scope_type="global",
        technique_counts={},
        pair_counts={},
        conditional_probs={},
        asymmetry_scores={},
        total_flows=0,
        total_techniques=0,
        total_pairs=0
    )
    
    # Mock extractor to return no ambiguous pairs
    mock_sequence_extractor.find_ambiguous_pairs.return_value = []
    
    triage = PairTriage(mock_sequence_extractor, mock_evidence_builder)
    
    triaged_pairs = triage.triage_scope(empty_stats)
    assert len(triaged_pairs) == 0
    
    summary = triage.get_triage_summary({"test": triaged_pairs})
    assert summary["total_pairs"] == 0