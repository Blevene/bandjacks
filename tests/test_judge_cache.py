"""Tests for judge verdict caching system."""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from bandjacks.llm.judge_cache import JudgeVerdictCache
from bandjacks.llm.judge_client import JudgeVerdict, VerdictType


@pytest.fixture
def sample_verdict():
    """Create a sample judge verdict for testing."""
    return JudgeVerdict(
        from_technique="attack-pattern--123",
        to_technique="attack-pattern--456",
        verdict=VerdictType.FORWARD,
        confidence=0.85,
        evidence_ids=["evidence-1", "evidence-2"],
        rationale_summary="Clear temporal sequence observed in evidence.",
        model_name="gemini/gemini-2.5-flash",
        retrieval_hash="abc123def456",
        cost_tokens=150
    )


@pytest.fixture 
def mock_neo4j_session():
    """Mock Neo4j session for testing."""
    with patch('neo4j.GraphDatabase.driver') as mock_driver:
        mock_session = Mock()
        mock_driver.return_value.session.return_value.__enter__ = Mock(return_value=mock_session)
        mock_driver.return_value.session.return_value.__exit__ = Mock(return_value=None)
        yield mock_session


def test_judge_cache_initialization():
    """Test judge cache initialization."""
    with patch('neo4j.GraphDatabase.driver') as mock_driver:
        cache = JudgeVerdictCache("neo4j://localhost", "neo4j", "password")
        
        # Should have created driver
        mock_driver.assert_called_once()
        assert cache.driver is not None


def test_verdict_to_neo4j_conversion(sample_verdict):
    """Test conversion of verdict to Neo4j properties."""
    with patch('neo4j.GraphDatabase.driver'):
        cache = JudgeVerdictCache("neo4j://localhost", "neo4j", "password")
        
        props = cache._verdict_to_neo4j(sample_verdict)
        
        assert props["from_technique"] == "attack-pattern--123"
        assert props["to_technique"] == "attack-pattern--456"
        assert props["verdict_type"] == "i->j"
        assert props["confidence"] == 0.85
        assert props["evidence_ids"] == ["evidence-1", "evidence-2"]
        assert props["model_name"] == "gemini/gemini-2.5-flash"
        assert props["retrieval_hash"] == "abc123def456"
        assert props["cost_tokens"] == 150


def test_neo4j_to_verdict_conversion(sample_verdict):
    """Test conversion from Neo4j properties to verdict."""
    with patch('neo4j.GraphDatabase.driver'):
        cache = JudgeVerdictCache("neo4j://localhost", "neo4j", "password")
        
        # Convert to Neo4j format and back
        props = cache._verdict_to_neo4j(sample_verdict)
        converted_verdict = cache._neo4j_to_verdict(props)
        
        assert converted_verdict.from_technique == sample_verdict.from_technique
        assert converted_verdict.to_technique == sample_verdict.to_technique
        assert converted_verdict.verdict == sample_verdict.verdict
        assert converted_verdict.confidence == sample_verdict.confidence
        assert converted_verdict.evidence_ids == sample_verdict.evidence_ids
        assert converted_verdict.model_name == sample_verdict.model_name
        assert converted_verdict.retrieval_hash == sample_verdict.retrieval_hash


def test_cache_verdict(mock_neo4j_session, sample_verdict):
    """Test caching a single verdict."""
    # Mock successful cache operation (new verdict)
    mock_result = Mock()
    mock_result.single.return_value = {"was_created": True}
    mock_neo4j_session.run.return_value = mock_result
    
    cache = JudgeVerdictCache("neo4j://localhost", "neo4j", "password")
    
    result = cache.cache_verdict(sample_verdict)
    
    # Should return True for new verdict
    assert result == True
    
    # Should have called Neo4j with correct parameters (5 calls: 4 constraints + 1 merge)
    assert mock_neo4j_session.run.call_count == 5
    # Last call should be the MERGE query
    last_call_args = mock_neo4j_session.run.call_args
    assert "MERGE" in last_call_args[0][0]  # Should use MERGE query


def test_cache_verdict_already_exists(mock_neo4j_session, sample_verdict):
    """Test caching a verdict that already exists."""
    # Mock existing verdict (access count updated)
    mock_result = Mock()
    mock_result.single.return_value = {"was_created": False}
    mock_neo4j_session.run.return_value = mock_result
    
    cache = JudgeVerdictCache("neo4j://localhost", "neo4j", "password")
    
    result = cache.cache_verdict(sample_verdict)
    
    # Should return False for existing verdict
    assert result == False


def test_get_cached_verdict_hit(mock_neo4j_session, sample_verdict):
    """Test successful cache hit."""
    # Mock cached verdict found
    cached_data = {
        "from_technique": "attack-pattern--123",
        "to_technique": "attack-pattern--456",
        "verdict_type": "i->j",
        "confidence": 0.85,
        "evidence_ids": ["evidence-1"],
        "rationale_summary": "Test rationale",
        "model_name": "gemini/gemini-2.5-flash",
        "retrieval_hash": "abc123",
        "judge_version": "1.0",
        "judged_at": datetime.utcnow().isoformat(),
        "cost_tokens": 100
    }
    
    mock_record = Mock()
    mock_record.__getitem__ = lambda self, key: cached_data
    mock_result = Mock()
    mock_result.single.return_value = mock_record
    mock_neo4j_session.run.return_value = mock_result
    
    cache = JudgeVerdictCache("neo4j://localhost", "neo4j", "password")
    
    verdict = cache.get_cached_verdict(
        "attack-pattern--123", "attack-pattern--456", "abc123"
    )
    
    assert verdict is not None
    assert verdict.from_technique == "attack-pattern--123"
    assert verdict.verdict == VerdictType.FORWARD


def test_get_cached_verdict_miss(mock_neo4j_session):
    """Test cache miss (no cached verdict)."""
    # Mock no cached verdict found
    mock_result = Mock()
    mock_result.single.return_value = None
    mock_neo4j_session.run.return_value = mock_result
    
    cache = JudgeVerdictCache("neo4j://localhost", "neo4j", "password")
    
    verdict = cache.get_cached_verdict(
        "attack-pattern--123", "attack-pattern--456", "abc123"
    )
    
    assert verdict is None


def test_batch_cache_verdicts(mock_neo4j_session):
    """Test batch caching of multiple verdicts."""
    verdicts = [
        JudgeVerdict(
            from_technique=f"attack-pattern--{i}",
            to_technique=f"attack-pattern--{i+1}",
            verdict=VerdictType.FORWARD,
            confidence=0.8,
            evidence_ids=[f"evidence-{i}"],
            rationale_summary=f"Rationale {i}",
            model_name="test-model",
            retrieval_hash=f"hash-{i}"
        )
        for i in range(3)
    ]
    
    # Mock transaction and results
    mock_tx = Mock()
    mock_result = Mock()
    mock_result.single.return_value = {"was_created": True}
    mock_tx.run.return_value = mock_result
    
    mock_neo4j_session.execute_write.side_effect = lambda func: func(mock_tx)
    
    cache = JudgeVerdictCache("neo4j://localhost", "neo4j", "password")
    
    stats = cache.batch_cache_verdicts(verdicts)
    
    assert stats["cached"] == 3
    assert stats["updated"] == 0
    assert stats["total"] == 3


def test_get_cached_verdicts_for_pairs(mock_neo4j_session):
    """Test getting cached verdicts for multiple pairs."""
    pairs = [
        ("attack-pattern--123", "attack-pattern--456"),
        ("attack-pattern--789", "attack-pattern--abc")
    ]
    
    retrieval_hashes = {
        pairs[0]: "hash-1",
        pairs[1]: "hash-2"
    }
    
    # Mock one cache hit, one miss
    def mock_get_cached_verdict(from_tech, to_tech, retrieval_hash):
        if (from_tech, to_tech) == pairs[0]:
            return JudgeVerdict(
                from_technique=from_tech,
                to_technique=to_tech,
                verdict=VerdictType.FORWARD,
                confidence=0.8,
                evidence_ids=["evidence-1"],
                rationale_summary="Test rationale",
                model_name="test-model",
                retrieval_hash=retrieval_hash
            )
        return None
    
    cache = JudgeVerdictCache("neo4j://localhost", "neo4j", "password")
    cache.get_cached_verdict = mock_get_cached_verdict
    
    cached_verdicts = cache.get_cached_verdicts_for_pairs(pairs, retrieval_hashes)
    
    assert len(cached_verdicts) == 1
    assert pairs[0] in cached_verdicts
    assert pairs[1] not in cached_verdicts


def test_get_cache_statistics(mock_neo4j_session):
    """Test cache statistics retrieval."""
    # Mock statistics query results
    mock_main_result = Mock()
    mock_main_result.single.return_value = {
        "total_cached_verdicts": 100,
        "avg_access_count": 2.5,
        "max_access_count": 10,
        "unique_models": 3,
        "unique_evidence_packs": 50,
        "verdict_types": ["i->j", "j->i", "unknown"]
    }
    
    mock_verdict_dist = [
        {"verdict_type": "i->j", "count": 60},
        {"verdict_type": "j->i", "count": 30},
        {"verdict_type": "unknown", "count": 10}
    ]
    
    mock_model_usage = [
        {"model": "gemini/gemini-2.5-flash", "count": 70},
        {"model": "gpt-4o-mini", "count": 30}
    ]
    
    # Mock multiple query responses (4 constraints + 3 statistics queries)
    mock_neo4j_session.run.side_effect = [
        None,  # Constraint 1
        None,  # Constraint 2
        None,  # Constraint 3 
        None,  # Constraint 4
        mock_main_result,  # Main stats query
        mock_verdict_dist,  # Verdict distribution
        mock_model_usage  # Model usage
    ]
    
    cache = JudgeVerdictCache("neo4j://localhost", "neo4j", "password")
    
    stats = cache.get_cache_statistics()
    
    assert stats["total_cached_verdicts"] == 100
    assert stats["unique_models"] == 3
    assert "verdict_distribution" in stats
    assert "model_usage" in stats
    assert stats["verdict_distribution"]["i->j"] == 60


def test_cleanup_old_verdicts(mock_neo4j_session):
    """Test cleanup of old verdicts."""
    # Mock cleanup result
    mock_result = Mock()
    mock_result.single.return_value = {"deleted_count": 25}
    mock_neo4j_session.run.return_value = mock_result
    
    cache = JudgeVerdictCache("neo4j://localhost", "neo4j", "password")
    
    deleted_count = cache.cleanup_old_verdicts(max_age_days=30, keep_min_access_count=2)
    
    assert deleted_count == 25
    
    # Should have called DELETE query
    call_args = mock_neo4j_session.run.call_args[0][0]
    assert "DELETE" in call_args
    assert "created_at" in call_args
    assert "access_count" in call_args


def test_invalidate_verdicts_by_model(mock_neo4j_session):
    """Test invalidating verdicts from specific model."""
    # Mock constraint creation results and invalidation result
    mock_result = Mock()
    mock_result.single.return_value = {"deleted_count": 15}
    mock_neo4j_session.run.side_effect = [
        None,  # Constraint 1
        None,  # Constraint 2
        None,  # Constraint 3
        None,  # Constraint 4
        mock_result  # DELETE query
    ]
    
    cache = JudgeVerdictCache("neo4j://localhost", "neo4j", "password")
    
    deleted_count = cache.invalidate_verdicts_by_model("old-model")
    
    assert deleted_count == 15
    
    # Should have called DELETE with model filter (last call after constraints)
    call_args = mock_neo4j_session.run.call_args
    assert "DELETE" in call_args[0][0]
    # Parameters are passed correctly (model_name should be in the query)


def test_judge_client_with_cache_integration():
    """Test JudgeClient integration with cache."""
    from bandjacks.llm.judge_client import JudgeClient, JudgeConfig
    from bandjacks.llm.evidence_pack import EvidencePack, EvidenceSnippet, TechniqueContext
    
    # Mock cache
    mock_cache = Mock(spec=JudgeVerdictCache)
    mock_cache.get_cached_verdict.return_value = None  # Cache miss
    
    # Mock LLM client
    with patch('bandjacks.llm.judge_client.LLMClient') as mock_llm_class:
        mock_llm = Mock()
        mock_llm_class.return_value = mock_llm
        mock_llm.call.return_value = {
            "content": '{"verdict": "i->j", "confidence": 0.8, "evidence_ids": ["e1"], "rationale_summary": "Clear evidence shows temporal sequence based on provided analysis data."}'
        }
        
        config = JudgeConfig(enable_caching=True)
        client = JudgeClient(config=config, cache=mock_cache)
        
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
            retrieval_hash="test-hash"
        )
        
        verdict = client.judge_pair(evidence_pack)
        
        # Should have checked cache
        mock_cache.get_cached_verdict.assert_called_once_with("T1", "T2", "test-hash")
        
        # Should have cached the result
        mock_cache.cache_verdict.assert_called_once()


def test_judge_client_cache_hit():
    """Test JudgeClient with cache hit."""
    from bandjacks.llm.judge_client import JudgeClient, JudgeConfig
    from bandjacks.llm.evidence_pack import EvidencePack
    
    # Mock cached verdict
    cached_verdict = JudgeVerdict(
        from_technique="T1",
        to_technique="T2", 
        verdict=VerdictType.FORWARD,
        confidence=0.9,
        evidence_ids=["e1"],
        rationale_summary="Cached rationale",
        model_name="cached-model",
        retrieval_hash="test-hash"
    )
    
    mock_cache = Mock(spec=JudgeVerdictCache)
    mock_cache.get_cached_verdict.return_value = cached_verdict
    
    config = JudgeConfig(enable_caching=True)
    client = JudgeClient(config=config, cache=mock_cache)
    
    evidence_pack = EvidencePack(
        pair={"from_technique": "T1", "to_technique": "T2"},
        statistics={}, tactic_context={}, technique_details={},
        graph_hints=[], evidence_snippets=[], historical_flows=[],
        retrieval_hash="test-hash"
    )
    
    verdict = client.judge_pair(evidence_pack)
    
    # Should return cached verdict
    assert verdict == cached_verdict
    assert client.cache_hits == 1
    
    # Should not have called cache_verdict (no new judgment made)
    mock_cache.cache_verdict.assert_not_called()


def test_empty_cache_statistics(mock_neo4j_session):
    """Test cache statistics with empty cache."""
    # Mock empty cache
    mock_result = Mock()
    mock_result.single.return_value = None
    mock_neo4j_session.run.return_value = mock_result
    
    cache = JudgeVerdictCache("neo4j://localhost", "neo4j", "password")
    
    stats = cache.get_cache_statistics()
    
    assert stats["total_cached_verdicts"] == 0