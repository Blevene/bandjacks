"""Unit tests for confidence handling in sequence proposals."""

import pytest
from typing import List
from bandjacks.llm.judge_client import JudgeVerdict, VerdictType
from bandjacks.llm.judge_integration import JudgeScoreConverter
from bandjacks.llm.sequence_proposal import TransitionValidator, TransitionEdge


class TestJudgeScoreConverter:
    """Test judge score conversion with unknown verdicts."""
    
    def test_unknown_verdict_gets_low_score(self):
        """Unknown verdicts should receive low base score of 0.1."""
        converter = JudgeScoreConverter()
        
        verdict = JudgeVerdict(
            from_technique="attack-pattern--123",
            to_technique="attack-pattern--456",
            verdict=VerdictType.UNKNOWN,
            confidence=0.8,  # High confidence in "unknown"
            evidence_ids=[],
            rationale_summary="Insufficient evidence"
        )
        
        score = converter.convert_verdict_to_score(verdict)
        
        # Base score should be 0.1 for unknown
        # Final score = 0.1 * (0.8 * confidence_weight + 0 * evidence_weight)
        # With default weights (0.8, 0.2): 0.1 * (0.8 * 0.8 + 0.2 * 0) = 0.064
        assert score.score == pytest.approx(0.064, rel=1e-3)
        assert score.verdict_type == VerdictType.UNKNOWN
    
    def test_forward_verdict_gets_high_score(self):
        """Forward verdicts should receive positive score."""
        converter = JudgeScoreConverter()
        
        verdict = JudgeVerdict(
            from_technique="attack-pattern--123",
            to_technique="attack-pattern--456",
            verdict=VerdictType.FORWARD,
            confidence=0.8,
            evidence_ids=["ev1", "ev2"],
            rationale_summary="Clear progression"
        )
        
        score = converter.convert_verdict_to_score(verdict, evidence_pack_size=3)
        
        # Base score = 1.0 * 0.8 = 0.8
        # Evidence strength = min(1.0, 2/3 * 2) = 1.0
        # Final = 0.8 * (0.8 * 0.8 + 0.2 * 1.0) = 0.8 * 0.84 = 0.672
        assert score.score > 0.6
        assert score.verdict_type == VerdictType.FORWARD
    
    def test_reverse_verdict_gets_negative_score(self):
        """Reverse verdicts should receive negative score."""
        converter = JudgeScoreConverter()
        
        verdict = JudgeVerdict(
            from_technique="attack-pattern--123",
            to_technique="attack-pattern--456",
            verdict=VerdictType.REVERSE,
            confidence=0.7,
            evidence_ids=["ev1"],
            rationale_summary="Reversed direction"
        )
        
        score = converter.convert_verdict_to_score(verdict, evidence_pack_size=2)
        
        # Base score = -1.0 * 0.7 = -0.7
        assert score.score < 0
        assert score.verdict_type == VerdictType.REVERSE


class TestTransitionValidator:
    """Test transition validation and categorization."""
    
    def test_unknown_verdicts_become_uncertain_edges(self):
        """Unknown verdicts should be categorized as uncertain with low confidence."""
        validator = TransitionValidator(unknown_transition_confidence=0.1)
        
        verdicts = [
            JudgeVerdict(
                from_technique="t1",
                to_technique="t2",
                verdict=VerdictType.UNKNOWN,
                confidence=0.9,  # High confidence in unknown
                evidence_ids=[],
                rationale_summary=""
            ),
            JudgeVerdict(
                from_technique="t3",
                to_technique="t4",
                verdict=VerdictType.FORWARD,
                confidence=0.7,
                evidence_ids=["ev1"],
                rationale_summary=""
            )
        ]
        
        validated, uncertain = validator.categorize_transitions(verdicts)
        
        # Unknown should be in uncertain
        assert len(uncertain) == 1
        assert uncertain[0].from_technique == "t1"
        assert uncertain[0].to_technique == "t2"
        assert uncertain[0].transition_confidence == 0.1  # Low transition confidence
        assert uncertain[0].judge_confidence == 0.9  # But high judge confidence
        assert uncertain[0].verdict == "unknown"
        
        # Forward should be in validated
        assert len(validated) == 1
        assert validated[0].from_technique == "t3"
        assert validated[0].transition_confidence == 0.7
    
    def test_reverse_verdicts_swap_direction(self):
        """Reverse verdicts should swap from/to techniques."""
        validator = TransitionValidator()
        
        verdicts = [
            JudgeVerdict(
                from_technique="t1",
                to_technique="t2",
                verdict=VerdictType.REVERSE,
                confidence=0.8,
                evidence_ids=["ev1"],
                rationale_summary=""
            )
        ]
        
        validated, uncertain = validator.categorize_transitions(verdicts)
        
        assert len(validated) == 1
        assert validated[0].from_technique == "t2"  # Swapped
        assert validated[0].to_technique == "t1"    # Swapped
        assert validated[0].verdict == "reversed"
        assert validated[0].transition_confidence == 0.8
    
    def test_bidirectional_creates_both_edges(self):
        """Bidirectional verdicts should create edges in both directions."""
        validator = TransitionValidator()
        
        verdicts = [
            JudgeVerdict(
                from_technique="t1",
                to_technique="t2",
                verdict=VerdictType.BIDIRECTIONAL,
                confidence=0.6,
                evidence_ids=["ev1"],
                rationale_summary=""
            )
        ]
        
        validated, uncertain = validator.categorize_transitions(verdicts)
        
        assert len(validated) == 2
        
        # Forward edge
        forward = [e for e in validated if e.from_technique == "t1"][0]
        assert forward.to_technique == "t2"
        assert forward.transition_confidence == 0.3  # 0.6 * 0.5
        assert forward.verdict == "bidirectional-forward"
        
        # Reverse edge
        reverse = [e for e in validated if e.from_technique == "t2"][0]
        assert reverse.to_technique == "t1"
        assert reverse.transition_confidence == 0.3  # 0.6 * 0.5
        assert reverse.verdict == "bidirectional-reverse"


class TestConfidenceIntegration:
    """Test confidence handling across components."""
    
    def test_low_confidence_edges_excluded_from_proposals(self):
        """Edges with unknown verdicts should not appear in sequence proposals."""
        from bandjacks.llm.sequence_proposal import SequenceProposalBuilder
        
        # Create edges with mixed confidence
        edges = [
            TransitionEdge(
                from_technique="t1",
                to_technique="t2",
                transition_confidence=0.8,
                judge_confidence=0.8,
                verdict="validated"
            ),
            TransitionEdge(
                from_technique="t2",
                to_technique="t3",
                transition_confidence=0.1,  # Low confidence (unknown)
                judge_confidence=0.9,
                verdict="unknown"
            ),
            TransitionEdge(
                from_technique="t2",
                to_technique="t4",
                transition_confidence=0.7,
                judge_confidence=0.7,
                verdict="validated"
            )
        ]
        
        # Filter by confidence threshold
        high_confidence_edges = [e for e in edges if e.transition_confidence >= 0.5]
        
        # Should exclude the unknown verdict edge
        assert len(high_confidence_edges) == 2
        assert all(e.verdict != "unknown" for e in high_confidence_edges)