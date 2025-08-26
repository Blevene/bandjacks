"""Tests for LLM judge client."""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from bandjacks.llm.judge_client import (
    JudgeClient, JudgeConfig, JudgeVerdict, VerdictType,
    judge_technique_pairs
)
from bandjacks.llm.evidence_pack import (
    EvidencePack, EvidenceSnippet, TechniqueContext
)


@pytest.fixture
def sample_evidence_pack():
    """Create a sample evidence pack for testing."""
    return EvidencePack(
        pair={"from_technique": "attack-pattern--123", "to_technique": "attack-pattern--456"},
        statistics={"asymmetry": 0.12, "forward_prob": 0.4, "reverse_prob": 0.28, "co_occurrence_count": 5},
        tactic_context={"from_tactic": "initial-access", "to_tactic": "execution", "tactic_distance": 1},
        technique_details={
            "attack-pattern--123": TechniqueContext(
                technique_id="attack-pattern--123",
                name="Spearphishing Attachment",
                description="Adversaries may send spearphishing emails with a malicious attachment",
                tactic="initial-access",
                platforms=["Windows", "macOS"]
            ),
            "attack-pattern--456": TechniqueContext(
                technique_id="attack-pattern--456", 
                name="Command and Scripting Interpreter",
                description="Adversaries may abuse command and script interpreters",
                tactic="execution",
                platforms=["Windows", "macOS", "Linux"]
            )
        },
        graph_hints=["Spearphishing typically precedes command execution", "Common attack pattern observed"],
        evidence_snippets=[
            EvidenceSnippet(
                doc_id="evidence-1",
                text="The attacker first sent a spearphishing email with malicious attachment, then executed PowerShell commands",
                source="threat-report-1",
                score=0.9,
                metadata={"type": "sequence_description"}
            ),
            EvidenceSnippet(
                doc_id="evidence-2",
                text="Initial access gained through email attachment, followed by script-based execution",
                source="threat-report-2",
                score=0.8,
                metadata={"type": "sequence_description"}
            )
        ],
        historical_flows=[
            {"flow_id": "flow-123", "techniques": ["attack-pattern--123", "attack-pattern--456"]}
        ],
        retrieval_hash="test-hash-abc123"
    )


@pytest.fixture
def mock_llm_client():
    """Mock LLM client for testing."""
    with patch('bandjacks.llm.judge_client.LLMClient') as mock_class:
        mock_instance = Mock()
        mock_class.return_value = mock_instance
        
        # Mock successful response
        mock_instance.call.return_value = {
            "content": json.dumps({
                "verdict": "i->j",
                "confidence": 0.85,
                "evidence_ids": ["evidence-1", "evidence-2"],
                "rationale_summary": "Evidence shows spearphishing typically precedes command execution in attack sequences."
            })
        }
        mock_instance.model = "gemini/gemini-2.5-flash"
        
        yield mock_instance


def test_judge_config_defaults():
    """Test default configuration values."""
    config = JudgeConfig()
    
    assert config.model_name == "gemini/gemini-2.5-flash"
    assert config.fallback_model == "gpt-4o-mini"
    assert config.temperature == 0.1
    assert config.require_evidence_citations == True
    assert config.max_retries == 2
    assert config.enable_caching == True


def test_verdict_type_enum():
    """Test verdict type enumeration."""
    assert VerdictType.FORWARD.value == "i->j"
    assert VerdictType.REVERSE.value == "j->i"
    assert VerdictType.BIDIRECTIONAL.value == "bidirectional"
    assert VerdictType.UNKNOWN.value == "unknown"


def test_judge_verdict_creation():
    """Test judge verdict dataclass creation."""
    verdict = JudgeVerdict(
        from_technique="T1566.001",
        to_technique="T1059.001",
        verdict=VerdictType.FORWARD,
        confidence=0.85,
        evidence_ids=["evidence-1"],
        rationale_summary="Clear temporal sequence in evidence.",
        model_name="gemini/gemini-2.5-flash"
    )
    
    assert verdict.verdict == VerdictType.FORWARD
    assert verdict.confidence == 0.85
    assert len(verdict.evidence_ids) == 1
    assert verdict.judged_at is not None


def test_judge_client_initialization():
    """Test judge client initialization."""
    config = JudgeConfig(model_name="custom-model")
    
    with patch('bandjacks.llm.judge_client.LLMClient') as mock_client:
        client = JudgeClient(config)
        
        assert client.config.model_name == "custom-model"
        assert client.judgments_made == 0
        assert client.total_cost_tokens == 0


def test_build_judgment_prompt(sample_evidence_pack):
    """Test judgment prompt building."""
    client = JudgeClient()
    
    messages = client._build_judgment_prompt(sample_evidence_pack)
    
    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    
    # Check that evidence is included
    user_content = messages[1]["content"]
    assert "attack-pattern--123" in user_content
    assert "attack-pattern--456" in user_content
    assert "EVIDENCE SNIPPETS" in user_content
    assert "evidence-1" in user_content


def test_build_judgment_prompt_with_scope(sample_evidence_pack):
    """Test judgment prompt with scope context."""
    client = JudgeClient()
    
    messages = client._build_judgment_prompt(sample_evidence_pack, "APT29 intrusion set")
    
    user_content = messages[1]["content"]
    assert "APT29 intrusion set" in user_content
    assert "SCOPE:" in user_content


def test_successful_judgment(mock_llm_client, sample_evidence_pack):
    """Test successful judgment flow."""
    client = JudgeClient()
    
    verdict = client.judge_pair(sample_evidence_pack)
    
    assert isinstance(verdict, JudgeVerdict)
    assert verdict.verdict == VerdictType.FORWARD
    assert verdict.confidence == 0.85
    assert "evidence-1" in verdict.evidence_ids
    assert "evidence-2" in verdict.evidence_ids
    assert len(verdict.rationale_summary) > 10
    assert verdict.retrieval_hash == "test-hash-abc123"


def test_judgment_with_invalid_json(mock_llm_client, sample_evidence_pack):
    """Test handling of invalid JSON response."""
    mock_llm_client.call.return_value = {"content": "invalid json response"}
    
    client = JudgeClient()
    
    # Should retry and then return unknown verdict
    verdict = client.judge_pair(sample_evidence_pack)
    assert verdict.verdict == VerdictType.UNKNOWN
    assert verdict.confidence == 0.0


def test_judgment_with_missing_evidence_citations(mock_llm_client, sample_evidence_pack):
    """Test quality check for missing evidence citations."""
    # Return verdict without evidence IDs
    mock_llm_client.call.return_value = {
        "content": json.dumps({
            "verdict": "i->j",
            "confidence": 0.85,
            "evidence_ids": [],  # Missing citations
            "rationale_summary": "Evidence shows clear temporal sequence between techniques."
        })
    }
    
    config = JudgeConfig(require_evidence_citations=True)
    client = JudgeClient(config)
    
    # Should fail quality check and return unknown
    verdict = client.judge_pair(sample_evidence_pack)
    assert verdict.verdict == VerdictType.UNKNOWN


def test_judgment_with_invalid_evidence_id(mock_llm_client, sample_evidence_pack):
    """Test quality check for invalid evidence ID."""
    # Return verdict with invalid evidence ID
    mock_llm_client.call.return_value = {
        "content": json.dumps({
            "verdict": "i->j",
            "confidence": 0.85,
            "evidence_ids": ["invalid-evidence-id"],  # Not in evidence pack
            "rationale_summary": "Evidence shows clear temporal sequence between techniques."
        })
    }
    
    client = JudgeClient()
    
    # Should fail quality check
    verdict = client.judge_pair(sample_evidence_pack)
    assert verdict.verdict == VerdictType.UNKNOWN


def test_judgment_with_short_rationale(mock_llm_client, sample_evidence_pack):
    """Test quality check for insufficient rationale."""
    # Return verdict with short rationale
    mock_llm_client.call.return_value = {
        "content": json.dumps({
            "verdict": "i->j",
            "confidence": 0.85,
            "evidence_ids": ["evidence-1"],
            "rationale_summary": "Clear."  # Too short
        })
    }
    
    client = JudgeClient()
    
    # Should fail quality check
    verdict = client.judge_pair(sample_evidence_pack)
    assert verdict.verdict == VerdictType.UNKNOWN


def test_judgment_with_confidence_out_of_bounds(mock_llm_client, sample_evidence_pack):
    """Test quality check for invalid confidence."""
    # Return verdict with invalid confidence
    mock_llm_client.call.return_value = {
        "content": json.dumps({
            "verdict": "i->j",
            "confidence": 1.5,  # Out of bounds
            "evidence_ids": ["evidence-1"],
            "rationale_summary": "Evidence shows clear temporal sequence between techniques."
        })
    }
    
    client = JudgeClient()
    
    # Should fail quality check
    verdict = client.judge_pair(sample_evidence_pack)
    assert verdict.verdict == VerdictType.UNKNOWN


def test_judgment_with_fallback_model(sample_evidence_pack):
    """Test fallback to secondary model."""
    with patch('bandjacks.llm.judge_client.LLMClient') as mock_client_class:
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.model = "gemini/gemini-2.5-flash"
        
        # First call fails, second succeeds
        mock_client.call.side_effect = [
            RuntimeError("Primary model failed"),
            {
                "content": json.dumps({
                    "verdict": "i->j",
                    "confidence": 0.75,
                    "evidence_ids": ["evidence-1"],
                    "rationale_summary": "Evidence from fallback model shows clear sequence."
                })
            }
        ]
        
        config = JudgeConfig(fallback_model="gpt-4o-mini")
        client = JudgeClient(config)
        
        verdict = client.judge_pair(sample_evidence_pack)
        
        assert verdict.verdict == VerdictType.FORWARD
        assert verdict.confidence == 0.75
        # Should have called LLM twice (primary + fallback)
        assert mock_client.call.call_count == 2


def test_batch_judgment(mock_llm_client):
    """Test batch judgment of multiple pairs.""" 
    client = JudgeClient(JudgeConfig(min_rationale_words=5))  # Lower threshold for tests
    
    # Create multiple evidence packs with consistent evidence IDs
    evidence_packs = [
        EvidencePack(
            pair={"from_technique": f"attack-pattern--{i}", "to_technique": f"attack-pattern--{i+1}"},
            statistics={},
            tactic_context={},
            technique_details={},
            graph_hints=[],
            evidence_snippets=[
                EvidenceSnippet(
                    doc_id=f"evidence-{i}",
                    text=f"Test evidence {i} showing clear temporal sequence between techniques",
                    source="test",
                    score=0.8
                )
            ],
            historical_flows=[],
            retrieval_hash=f"hash-{i}"
        )
        for i in range(3)
    ]
    
    # Mock consistent responses that cite the correct evidence IDs
    mock_llm_client.call.return_value = {
        "content": json.dumps({
            "verdict": "i->j",
            "confidence": 0.8,
            "evidence_ids": ["evidence-1", "evidence-2"],
            "rationale_summary": "Clear evidence shows temporal sequence based on provided data analysis."
        })
    }
    
    verdicts = client.batch_judge_pairs(evidence_packs)
    
    assert len(verdicts) == 3
    assert all(isinstance(v, JudgeVerdict) for v in verdicts)


def test_batch_judgment_with_failures(sample_evidence_pack):
    """Test batch judgment with some failures."""
    with patch('bandjacks.llm.judge_client.LLMClient') as mock_client_class:
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.model = "test-model"
        
        # First call succeeds, second fails
        mock_client.call.side_effect = [
            {
                "content": json.dumps({
                    "verdict": "i->j",
                    "confidence": 0.8,
                    "evidence_ids": ["evidence-1"],
                    "rationale_summary": "Clear evidence for temporal sequence."
                })
            },
            RuntimeError("Model failure")
        ]
        
        client = JudgeClient()
        
        verdicts = client.batch_judge_pairs([sample_evidence_pack, sample_evidence_pack])
        
        assert len(verdicts) == 2
        assert verdicts[0].verdict == VerdictType.FORWARD
        assert verdicts[1].verdict == VerdictType.UNKNOWN  # Failed judgment


def test_judgment_statistics():
    """Test judgment statistics tracking."""
    with patch('bandjacks.llm.judge_client.LLMClient') as mock_client_class:
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.call.return_value = {
            "content": json.dumps({
                "verdict": "i->j",
                "confidence": 0.8,
                "evidence_ids": ["e1"],  # Match the evidence snippet ID
                "rationale_summary": "Clear evidence for temporal sequence based on provided data."
            })
        }
        
        client = JudgeClient()
        
        stats = client.get_statistics()
        assert stats["judgments_made"] == 0
        assert stats["total_cost_tokens"] == 0
        
        # Make a judgment
        evidence_pack = EvidencePack(
            pair={"from_technique": "T1", "to_technique": "T2"},
            statistics={},
            tactic_context={},
            technique_details={},
            graph_hints=[],
            evidence_snippets=[
                EvidenceSnippet(doc_id="e1", text="test evidence", source="test", score=0.8)
            ],
            historical_flows=[],
            retrieval_hash="hash"
        )
        
        client.judge_pair(evidence_pack)
        
        stats = client.get_statistics()
        assert stats["judgments_made"] == 1
        assert stats["total_cost_tokens"] > 0


def test_format_evidence_for_prompt(sample_evidence_pack):
    """Test evidence formatting for prompt."""
    client = JudgeClient()
    
    formatted = client._format_evidence_for_prompt(sample_evidence_pack)
    
    assert "STATISTICAL EVIDENCE" in formatted
    assert "TACTIC CONTEXT" in formatted
    assert "TECHNIQUE DETAILS" in formatted
    assert "EVIDENCE SNIPPETS" in formatted
    assert "evidence-1" in formatted
    assert "evidence-2" in formatted


def test_convenience_function():
    """Test convenience function for judging pairs."""
    with patch('bandjacks.llm.judge_client.JudgeClient') as mock_client_class:
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        
        mock_verdict = JudgeVerdict(
            from_technique="T1",
            to_technique="T2", 
            verdict=VerdictType.FORWARD,
            confidence=0.8,
            evidence_ids=["e1"],
            rationale_summary="Test rationale"
        )
        
        mock_client.batch_judge_pairs.return_value = [mock_verdict]
        mock_client.get_statistics.return_value = {"judgments_made": 1}
        
        evidence_pack = EvidencePack(
            pair={"from_technique": "T1", "to_technique": "T2"},
            statistics={},
            tactic_context={},
            technique_details={},
            graph_hints=[],
            evidence_snippets=[],
            historical_flows=[],
            retrieval_hash="hash"
        )
        
        verdicts = judge_technique_pairs([evidence_pack])
        
        assert len(verdicts) == 1
        assert verdicts[0].verdict == VerdictType.FORWARD


def test_verdict_type_conversion():
    """Test conversion of string verdict to enum."""
    assert VerdictType("i->j") == VerdictType.FORWARD
    assert VerdictType("j->i") == VerdictType.REVERSE
    assert VerdictType("bidirectional") == VerdictType.BIDIRECTIONAL
    assert VerdictType("unknown") == VerdictType.UNKNOWN
    
    with pytest.raises(ValueError):
        VerdictType("invalid-verdict")


def test_evidence_formatting_edge_cases():
    """Test evidence formatting with missing data."""
    # Create minimal evidence pack
    minimal_pack = EvidencePack(
        pair={"from_technique": "T1", "to_technique": "T2"},
        statistics={},
        tactic_context={},
        technique_details={},
        graph_hints=[],
        evidence_snippets=[],
        historical_flows=[],
        retrieval_hash="hash"
    )
    
    client = JudgeClient()
    formatted = client._format_evidence_for_prompt(minimal_pack)
    
    # Should handle empty sections gracefully
    assert "Available evidence_ids: []" in formatted


def test_quality_checks_allow_unknown_without_citations():
    """Test that unknown verdicts don't require evidence citations."""
    client = JudgeClient(JudgeConfig(require_evidence_citations=True, min_rationale_words=5))
    
    verdict = JudgeVerdict(
        from_technique="T1",
        to_technique="T2",
        verdict=VerdictType.UNKNOWN,
        confidence=0.0,
        evidence_ids=[],  # No citations for unknown verdict
        rationale_summary="Insufficient evidence available to determine temporal relationship between techniques.",  # Long enough
        model_name="test"
    )
    
    evidence_pack = EvidencePack(
        pair={"from_technique": "T1", "to_technique": "T2"},
        statistics={}, tactic_context={}, technique_details={},
        graph_hints=[], evidence_snippets=[], historical_flows=[],
        retrieval_hash="hash"
    )
    
    # Unknown verdicts should pass quality checks without citations
    assert client._passes_quality_checks(verdict, evidence_pack) == True