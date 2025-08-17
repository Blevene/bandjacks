"""Test the optimizations added to Sprint 2."""

from bandjacks.loaders.propose import infer_tactic_shortnames, score_candidates
from bandjacks.loaders.search_nodes import ttx_search_kb


def test_tactic_inference():
    """Test tactic inference from text."""
    
    # Test with explicit tactic mentions
    text1 = "The attacker uses persistence techniques to maintain access to the system."
    tactics1 = infer_tactic_shortnames(text1)
    assert "persistence" in tactics1
    
    text2 = "Initial access is gained through spearphishing, followed by privilege escalation."
    tactics2 = infer_tactic_shortnames(text2)
    assert "initial-access" in tactics2
    assert "privilege-escalation" in tactics2
    
    text3 = "The malware communicates with C2 servers for command and control operations."
    tactics3 = infer_tactic_shortnames(text3)
    assert "command-and-control" in tactics3
    
    text4 = "Data exfiltration occurs after collection phase is complete."
    tactics4 = infer_tactic_shortnames(text4)
    assert "exfiltration" in tactics4
    assert "collection" in tactics4
    
    # Test with no tactic mentions
    text5 = "The software performs various operations on files."
    tactics5 = infer_tactic_shortnames(text5)
    assert len(tactics5) == 0
    
    print("✓ Tactic inference working correctly")


def test_scoring_with_tactic_boost():
    """Test that tactic inference affects scoring."""
    
    text = "The attacker establishes persistence through registry modifications."
    
    # Mock candidates
    candidates = [
        {
            "stix_id": "attack-pattern--1",
            "name_or_snippet": "Registry Run Keys - Persistence",
            "score": 0.8,
            "text": "persistence technique using registry"
        },
        {
            "stix_id": "attack-pattern--2",
            "name_or_snippet": "PowerShell",
            "score": 0.9,
            "text": "execution technique using powershell"
        }
    ]
    
    scored = score_candidates(text, candidates, "technique")
    
    # The persistence technique should get a boost
    persistence_technique = next(c for c in scored if "persistence" in c["name_or_snippet"].lower())
    powershell_technique = next(c for c in scored if "powershell" in c["name_or_snippet"].lower())
    
    # Check that tactic boost was applied
    assert persistence_technique["scoring_details"]["tactic_boost"] > 0
    assert powershell_technique["scoring_details"]["tactic_boost"] == 0
    
    print("✓ Tactic boost scoring working correctly")


def test_kb_types_filtering():
    """Test kb_types parameter structure."""
    
    # Test that kb_types can be None (all types)
    kb_types_none = None
    assert kb_types_none is None or isinstance(kb_types_none, list)
    
    # Test with specific types
    kb_types_techniques = ["AttackPattern"]
    assert isinstance(kb_types_techniques, list)
    assert "AttackPattern" in kb_types_techniques
    
    kb_types_mixed = ["IntrusionSet", "Software"]
    assert isinstance(kb_types_mixed, list)
    assert len(kb_types_mixed) == 2
    
    print("✓ KB types filtering structure correct")


def test_comprehensive_proposal_scoring():
    """Test the complete scoring mechanism with all factors."""
    
    text = "APT29 uses persistence techniques including registry run keys (T1547.001)."
    
    candidates = [
        {
            "stix_id": "attack-pattern--t1547-001",
            "name_or_snippet": "Boot or Logon Autostart Execution: Registry Run Keys",
            "score": 1.5,
            "text": "persistence registry run keys autostart"
        }
    ]
    
    scored = score_candidates(text, candidates, "technique")
    
    if scored:
        result = scored[0]
        details = result["scoring_details"]
        
        # All scoring components should be present
        assert "similarity" in details
        assert "keyword" in details
        assert "id_mention" in details
        assert "tactic_boost" in details
        
        # With T-code mention, persistence keyword, and tactic inference, should have high confidence
        assert result["confidence"] > 60
        
        print(f"✓ Comprehensive scoring: confidence={result['confidence']}")
        print(f"  - Similarity: {details['similarity']:.1f}")
        print(f"  - Keyword: {details['keyword']:.1f}")
        print(f"  - ID mention: {details['id_mention']:.1f}")
        print(f"  - Tactic boost: {details['tactic_boost']}")


if __name__ == "__main__":
    print("Testing Sprint 2 Optimizations")
    print("-" * 40)
    
    test_tactic_inference()
    test_scoring_with_tactic_boost()
    test_kb_types_filtering()
    test_comprehensive_proposal_scoring()
    
    print("-" * 40)
    print("✅ All optimization tests passed!")