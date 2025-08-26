"""Tests for judge integration with PTG."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

from bandjacks.llm.judge_integration import (
    JudgeScoreConverter, JudgeScore, PTGJudgeIntegrator
)
from bandjacks.llm.judge_client import JudgeVerdict, VerdictType
from bandjacks.llm.triage import TriagedPair
from bandjacks.llm.sequence_extractor import PairwiseStatistics
from bandjacks.llm.ptg_builder import PTGParameters


@pytest.fixture
def sample_verdicts():
    """Create sample judge verdicts for testing."""
    return [
        JudgeVerdict(
            from_technique="attack-pattern--123",
            to_technique="attack-pattern--456", 
            verdict=VerdictType.FORWARD,
            confidence=0.85,
            evidence_ids=["evidence-1", "evidence-2"],
            rationale_summary="Clear temporal sequence observed in evidence.",
            model_name="gemini/gemini-2.5-flash"
        ),
        JudgeVerdict(
            from_technique="attack-pattern--789",
            to_technique="attack-pattern--abc",
            verdict=VerdictType.REVERSE,
            confidence=0.70,
            evidence_ids=["evidence-3"],
            rationale_summary="Evidence suggests reverse temporal ordering.",
            model_name="gemini/gemini-2.5-flash"
        ),
        JudgeVerdict(
            from_technique="attack-pattern--def",
            to_technique="attack-pattern--ghi",
            verdict=VerdictType.BIDIRECTIONAL,
            confidence=0.60,
            evidence_ids=["evidence-4", "evidence-5"],
            rationale_summary="Both directions are valid based on context.",
            model_name="gemini/gemini-2.5-flash"
        ),
        JudgeVerdict(
            from_technique="attack-pattern--jkl",
            to_technique="attack-pattern--mno",
            verdict=VerdictType.UNKNOWN,
            confidence=0.0,
            evidence_ids=[],
            rationale_summary="Insufficient evidence to determine relationship.",
            model_name="gemini/gemini-2.5-flash"
        )
    ]


@pytest.fixture 
def sample_pairwise_stats():
    """Create sample pairwise statistics for testing."""
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
            ("attack-pattern--789", "attack-pattern--abc"): 4,
            ("attack-pattern--def", "attack-pattern--ghi"): 6
        },
        conditional_probs={
            ("attack-pattern--123", "attack-pattern--456"): 0.5,
            ("attack-pattern--789", "attack-pattern--abc"): 0.33,
            ("attack-pattern--def", "attack-pattern--ghi"): 0.4
        },
        asymmetry_scores={
            ("attack-pattern--123", "attack-pattern--456"): 0.125,
            ("attack-pattern--789", "attack-pattern--abc"): 0.14,
            ("attack-pattern--def", "attack-pattern--ghi"): 0.12
        },
        total_flows=20,
        total_techniques=6,
        total_pairs=3
    )


def test_judge_score_converter_initialization():
    """Test JudgeScoreConverter initialization."""
    converter = JudgeScoreConverter()
    assert converter.confidence_weight == 0.8
    assert converter.evidence_weight == 0.2
    
    converter = JudgeScoreConverter(confidence_weight=0.7, evidence_weight=0.3)
    assert converter.confidence_weight == 0.7
    assert converter.evidence_weight == 0.3


def test_verdict_to_base_score():
    """Test verdict type to base score conversion."""
    converter = JudgeScoreConverter()
    
    # Forward verdict should give positive score
    assert converter._verdict_to_base_score(VerdictType.FORWARD, 0.8) == 0.8
    
    # Reverse verdict should give negative score 
    assert converter._verdict_to_base_score(VerdictType.REVERSE, 0.7) == -0.7
    
    # Bidirectional should give reduced positive score
    assert converter._verdict_to_base_score(VerdictType.BIDIRECTIONAL, 0.6) == 0.3
    
    # Unknown should give zero score
    assert converter._verdict_to_base_score(VerdictType.UNKNOWN, 0.0) == 0.0


def test_calculate_evidence_strength():
    """Test evidence strength calculation."""
    converter = JudgeScoreConverter()
    
    # Full citation coverage
    assert converter._calculate_evidence_strength(["e1", "e2"], 2) == 1.0
    
    # Partial citation coverage  
    assert converter._calculate_evidence_strength(["e1"], 3) == pytest.approx(0.667, rel=1e-2)
    
    # No evidence available
    assert converter._calculate_evidence_strength([], 0) == 0.0
    
    # Over-citation (more than available) should cap at 1.0
    assert converter._calculate_evidence_strength(["e1", "e2", "e3"], 2) == 1.0


def test_convert_verdict_to_score(sample_verdicts):
    """Test single verdict to score conversion."""
    converter = JudgeScoreConverter()
    verdict = sample_verdicts[0]  # Forward verdict with high confidence
    
    score = converter.convert_verdict_to_score(verdict, evidence_pack_size=3)
    
    assert isinstance(score, JudgeScore)
    assert score.from_technique == "attack-pattern--123"
    assert score.to_technique == "attack-pattern--456"
    assert score.verdict_type == VerdictType.FORWARD
    assert score.confidence == 0.85
    assert score.score > 0  # Should be positive for forward verdict
    assert -1.0 <= score.score <= 1.0  # Should be within valid range


def test_batch_convert_verdicts(sample_verdicts):
    """Test batch verdict conversion."""
    converter = JudgeScoreConverter()
    
    # Convert all verdicts
    score_dict = converter.batch_convert_verdicts(sample_verdicts)
    
    assert len(score_dict) == 4
    
    # Check forward verdict
    forward_key = ("attack-pattern--123", "attack-pattern--456")
    assert forward_key in score_dict
    assert score_dict[forward_key].score > 0
    
    # Check reverse verdict  
    reverse_key = ("attack-pattern--789", "attack-pattern--abc")
    assert reverse_key in score_dict
    assert score_dict[reverse_key].score < 0
    
    # Check bidirectional verdict
    bidirectional_key = ("attack-pattern--def", "attack-pattern--ghi")
    assert bidirectional_key in score_dict
    assert score_dict[bidirectional_key].score > 0  # Should be positive but smaller
    
    # Check unknown verdict
    unknown_key = ("attack-pattern--jkl", "attack-pattern--mno")
    assert unknown_key in score_dict
    assert score_dict[unknown_key].score == 0.0


def test_batch_convert_with_evidence_sizes(sample_verdicts):
    """Test batch conversion with evidence pack sizes."""
    converter = JudgeScoreConverter()
    
    evidence_sizes = {
        ("attack-pattern--123", "attack-pattern--456"): 5,
        ("attack-pattern--789", "attack-pattern--abc"): 3,
        ("attack-pattern--def", "attack-pattern--ghi"): 2
    }
    
    score_dict = converter.batch_convert_verdicts(sample_verdicts, evidence_sizes)
    
    # Scores should be influenced by evidence strength
    for pair, score in score_dict.items():
        if pair in evidence_sizes:
            assert score.evidence_strength > 0


@patch('bandjacks.llm.judge_integration.PTGBuilder')
@patch('bandjacks.llm.judge_integration.EvidencePackBuilder')
def test_ptg_judge_integrator_initialization(mock_evidence_builder, mock_ptg_builder):
    """Test PTGJudgeIntegrator initialization."""
    integrator = PTGJudgeIntegrator(
        "neo4j://localhost:7687",
        "neo4j", "password",
        "http://localhost:9200",
        "attack-patterns"
    )
    
    assert integrator.ptg_builder is not None
    assert integrator.evidence_builder is not None
    assert integrator.score_converter is not None


@patch('bandjacks.llm.judge_integration.PTGBuilder')
@patch('bandjacks.llm.judge_integration.EvidencePackBuilder')
def test_build_ptg_with_judge(mock_evidence_builder, mock_ptg_builder, sample_pairwise_stats, sample_verdicts):
    """Test PTG building with judge integration."""
    # Mock PTG builder response
    mock_ptg_model = Mock()
    mock_ptg_model.model_id = "ptg-test-123"
    mock_ptg_model.parameters = {}
    mock_ptg_builder.return_value.build_ptg.return_value = mock_ptg_model
    
    integrator = PTGJudgeIntegrator(
        "neo4j://localhost:7687", "neo4j", "password",
        "http://localhost:9200", "attack-patterns"
    )
    
    # Create mock triaged pairs
    triaged_pairs = [
        Mock(from_technique=v.from_technique, to_technique=v.to_technique)
        for v in sample_verdicts
    ]
    
    result = integrator.build_ptg_with_judge(
        sample_pairwise_stats, triaged_pairs, sample_verdicts
    )
    
    # Verify PTG builder was called with judge scores
    assert mock_ptg_builder.return_value.build_ptg.called
    call_args = mock_ptg_builder.return_value.build_ptg.call_args
    
    assert call_args[1]['stats'] == sample_pairwise_stats
    assert call_args[1]['judge_scores'] is not None
    assert len(call_args[1]['judge_scores']) > 0
    
    # Verify judge metadata was added
    assert "judge_integration" in result.parameters
    assert result.parameters["judge_integration"]["judge_enabled"] == True
    assert result.parameters["judge_integration"]["total_verdicts"] == 4


@patch('bandjacks.llm.judge_integration.PTGBuilder')
@patch('bandjacks.llm.judge_integration.EvidencePackBuilder')
def test_build_ptg_without_judge(mock_evidence_builder, mock_ptg_builder, sample_pairwise_stats):
    """Test baseline PTG building without judge."""
    # Mock PTG builder response
    mock_ptg_model = Mock()
    mock_ptg_model.model_id = "ptg-baseline-123"
    mock_ptg_model.parameters = {}
    mock_ptg_builder.return_value.build_ptg.return_value = mock_ptg_model
    
    integrator = PTGJudgeIntegrator(
        "neo4j://localhost:7687", "neo4j", "password",
        "http://localhost:9200", "attack-patterns"
    )
    
    result = integrator.build_ptg_without_judge(sample_pairwise_stats)
    
    # Verify PTG builder was called without judge scores
    call_args = mock_ptg_builder.return_value.build_ptg.call_args
    assert call_args[1]['judge_scores'] is None
    
    # Verify baseline metadata
    assert result.parameters["judge_integration"]["judge_enabled"] == False
    assert result.parameters["judge_integration"]["baseline_model"] == True


@patch('bandjacks.llm.judge_integration.PTGBuilder')
@patch('bandjacks.llm.judge_integration.EvidencePackBuilder')
def test_analyze_judge_impact(mock_evidence_builder, mock_ptg_builder):
    """Test judge impact analysis."""
    integrator = PTGJudgeIntegrator(
        "neo4j://localhost:7687", "neo4j", "password",
        "http://localhost:9200", "attack-patterns"
    )
    
    # Create mock models with edges
    baseline_model = Mock()
    baseline_model.edges = [
        Mock(from_technique="T1", to_technique="T2", probability=0.3),
        Mock(from_technique="T2", to_technique="T3", probability=0.5)
    ]
    
    judge_model = Mock()
    judge_model.edges = [
        Mock(from_technique="T1", to_technique="T2", probability=0.6),  # Increased
        Mock(from_technique="T2", to_technique="T4", probability=0.4),  # New edge
        # T2->T3 removed
    ]
    
    analysis = integrator.analyze_judge_impact(baseline_model, judge_model)
    
    assert "edge_changes" in analysis
    assert analysis["edge_changes"]["total_baseline_edges"] == 2
    assert analysis["edge_changes"]["total_judge_edges"] == 2
    assert analysis["edge_changes"]["new_edges"] == 1
    assert analysis["edge_changes"]["removed_edges"] == 1
    assert analysis["edge_changes"]["modified_edges"] == 1
    
    assert "top_probability_increases" in analysis
    assert "top_probability_decreases" in analysis
    assert "summary" in analysis


def test_score_ranges_validation(sample_verdicts):
    """Test that all converted scores are within valid ranges."""
    converter = JudgeScoreConverter()
    
    for verdict in sample_verdicts:
        score = converter.convert_verdict_to_score(verdict, evidence_pack_size=5)
        
        # All scores should be within [-1, 1]
        assert -1.0 <= score.score <= 1.0
        
        # Confidence should be preserved
        assert score.confidence == verdict.confidence
        
        # Evidence strength should be in [0, 1]
        assert 0.0 <= score.evidence_strength <= 1.0


def test_verdict_type_score_directions(sample_verdicts):
    """Test that verdict types map to correct score directions."""
    converter = JudgeScoreConverter()
    
    score_dict = converter.batch_convert_verdicts(sample_verdicts)
    
    # Find scores by verdict type
    forward_score = next(s for s in score_dict.values() if s.verdict_type == VerdictType.FORWARD)
    reverse_score = next(s for s in score_dict.values() if s.verdict_type == VerdictType.REVERSE)
    bidirectional_score = next(s for s in score_dict.values() if s.verdict_type == VerdictType.BIDIRECTIONAL)
    unknown_score = next(s for s in score_dict.values() if s.verdict_type == VerdictType.UNKNOWN)
    
    # Verify score directions
    assert forward_score.score > 0  # Positive for forward
    assert reverse_score.score < 0  # Negative for reverse
    assert bidirectional_score.score > 0  # Positive but smaller for bidirectional
    assert unknown_score.score == 0.0  # Zero for unknown
    
    # Verify bidirectional is smaller than forward (when confidence is similar)
    if forward_score.confidence >= bidirectional_score.confidence:
        assert forward_score.score > bidirectional_score.score


def test_empty_verdict_list():
    """Test handling of empty verdict list."""
    converter = JudgeScoreConverter()
    
    result = converter.batch_convert_verdicts([])
    assert result == {}


def test_edge_case_confidences():
    """Test edge cases for confidence values."""
    converter = JudgeScoreConverter()
    
    # Zero confidence
    verdict_zero = JudgeVerdict(
        from_technique="T1", to_technique="T2",
        verdict=VerdictType.FORWARD, confidence=0.0,
        evidence_ids=[], rationale_summary="Test"
    )
    
    # Maximum confidence
    verdict_max = JudgeVerdict(
        from_technique="T1", to_technique="T2",
        verdict=VerdictType.FORWARD, confidence=1.0,
        evidence_ids=["e1"], rationale_summary="Test"
    )
    
    score_zero = converter.convert_verdict_to_score(verdict_zero)
    score_max = converter.convert_verdict_to_score(verdict_max, evidence_pack_size=1)
    
    # Zero confidence should result in very low score
    assert abs(score_zero.score) < 0.1
    
    # Maximum confidence should result in higher score
    assert score_max.score > score_zero.score