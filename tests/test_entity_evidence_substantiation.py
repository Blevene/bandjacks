#!/usr/bin/env python3
"""Test entity evidence substantiation with claim-based validation."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bandjacks.llm.entity_consolidator import EntityConsolidatorAgent, EntityClaim
from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.accumulator import ThreadSafeAccumulator


def test_entity_claims_creation():
    """Test that entity claims are properly created with evidence."""
    print("Testing entity claims creation...")
    
    # Create entity claims similar to technique claims
    entity_claims = [
        {
            "entity_id": "group_apt29",
            "name": "APT29",
            "entity_type": "group",
            "quotes": ["APT29, also known as Cozy Bear, is a Russian threat group"],
            "line_refs": [10, 11],
            "confidence": 85,
            "evidence_score": 90,
            "chunk_id": 1,
            "context": "primary_mention"
        },
        {
            "entity_id": "malware_solarwinds",
            "name": "SUNBURST",
            "entity_type": "malware",
            "quotes": ["The SUNBURST backdoor was deployed through SolarWinds"],
            "line_refs": [25],
            "confidence": 95,
            "evidence_score": 95,
            "chunk_id": 1,
            "context": "primary_mention"
        }
    ]
    
    # Verify claims have proper structure
    for claim in entity_claims:
        assert "entity_id" in claim, "Claim missing entity_id"
        assert "quotes" in claim, "Claim missing quotes (evidence)"
        assert "line_refs" in claim, "Claim missing line references"
        assert "confidence" in claim, "Claim missing confidence score"
        assert isinstance(claim["quotes"], list), "Quotes should be a list"
        assert isinstance(claim["line_refs"], list), "Line refs should be a list"
    
    print("✓ Entity claims have proper evidence structure")


def test_entity_consolidation():
    """Test that EntityConsolidatorAgent consolidates claims properly."""
    print("\nTesting entity consolidation...")
    
    mem = WorkingMemory()
    
    # Add entity claims from multiple chunks
    mem.entity_claims = [
        {
            "entity_id": "group_apt29",
            "name": "APT29",
            "entity_type": "group",
            "quotes": ["APT29 is a sophisticated threat actor"],
            "line_refs": [10],
            "confidence": 80,
            "evidence_score": 85,
            "chunk_id": 1
        },
        {
            "entity_id": "group_apt29",
            "name": "APT29",
            "entity_type": "group",
            "quotes": ["The group APT29 uses advanced techniques"],
            "line_refs": [50],
            "confidence": 85,
            "evidence_score": 90,
            "chunk_id": 2  # Different chunk
        },
        {
            "entity_id": "group_cozy_bear",
            "name": "Cozy Bear",
            "entity_type": "group",
            "quotes": ["Cozy Bear (APT29) targets government organizations"],
            "line_refs": [75],
            "confidence": 75,
            "evidence_score": 80,
            "chunk_id": 3,
            "context": "alias"
        }
    ]
    
    # Run consolidation
    consolidator = EntityConsolidatorAgent()
    consolidator.run(mem, {})
    
    # Check consolidated entities
    assert hasattr(mem, 'consolidated_entities'), "Missing consolidated_entities"
    assert len(mem.consolidated_entities) > 0, "No entities consolidated"
    
    # Check APT29 consolidation
    apt29 = mem.consolidated_entities.get("group_apt29")
    assert apt29 is not None, "APT29 not found in consolidated entities"
    
    print(f"  APT29 confidence: {apt29['confidence']}")
    print(f"  APT29 evidence pieces: {len(apt29['evidence'])}")
    print(f"  APT29 chunks: {apt29['chunks_found']}")
    
    # Confidence should be boosted for multi-chunk discovery
    assert apt29['confidence'] > 85, f"Confidence not boosted: {apt29['confidence']}"
    assert len(apt29['chunks_found']) == 2, f"Should be found in 2 chunks, got {apt29['chunks_found']}"
    assert len(apt29['evidence']) == 2, f"Should have 2 evidence pieces, got {len(apt29['evidence'])}"
    
    print("✓ Entity consolidation working with evidence merging")


def test_entity_accumulator_support():
    """Test that accumulator properly handles entities."""
    print("\nTesting accumulator entity support...")
    
    accumulator = ThreadSafeAccumulator()
    
    # Add entities from different chunks
    accumulator.add_entity(
        entity_id="group_apt28",
        name="APT28",
        entity_type="group",
        confidence=75,
        evidence=["APT28 is linked to Russian military intelligence"],
        chunk_id=1
    )
    
    accumulator.add_entity(
        entity_id="group_apt28",
        name="APT28",
        entity_type="group", 
        confidence=80,
        evidence=["APT28, also known as Fancy Bear"],
        chunk_id=2
    )
    
    # Get accumulated entities
    entities = accumulator.get_accumulated_entities()
    
    assert "group_apt28" in entities, "APT28 not in accumulated entities"
    
    apt28 = entities["group_apt28"]
    print(f"  APT28 confidence: {apt28['confidence']}")
    print(f"  APT28 evidence count: {len(apt28['evidence'])}")
    print(f"  APT28 chunks: {apt28['chunk_ids']}")
    
    # Check confidence boost
    assert apt28['confidence'] > 80, f"Confidence not boosted: {apt28['confidence']}"
    assert len(apt28['chunk_ids']) == 2, "Should be found in 2 chunks"
    assert len(apt28['evidence']) == 2, "Should have 2 evidence pieces"
    
    # Check statistics
    stats = accumulator.get_statistics()
    assert stats['total_entities'] == 1, f"Expected 1 entity, got {stats['total_entities']}"
    assert stats['multi_chunk_entities'] == 1, "Expected 1 multi-chunk entity"
    
    print("✓ Accumulator supports entities with evidence")


def test_entity_evidence_deduplication():
    """Test that duplicate evidence is properly deduplicated."""
    print("\nTesting entity evidence deduplication...")
    
    consolidator = EntityConsolidatorAgent()
    
    # Test with duplicate evidence
    evidence_list = [
        "APT29 uses spearphishing emails",
        "apt29 uses spearphishing emails",  # Lowercase duplicate
        "APT29  uses  spearphishing  emails",  # Extra spaces
        "APT29 deploys custom malware",  # Different evidence
    ]
    
    merged = consolidator._merge_evidence_intelligently(evidence_list)
    
    print(f"  Original evidence: {len(evidence_list)} pieces")
    print(f"  Merged evidence: {len(merged)} pieces")
    
    assert len(merged) == 2, f"Expected 2 unique pieces, got {len(merged)}"
    
    print("✓ Evidence deduplication working")


def test_entity_line_references():
    """Test that entity claims maintain line references."""
    print("\nTesting entity line reference tracking...")
    
    mem = WorkingMemory()
    
    mem.entity_claims = [
        {
            "entity_id": "malware_emotet",
            "name": "Emotet",
            "entity_type": "malware",
            "quotes": ["Emotet is a banking trojan"],
            "line_refs": [100, 101, 102],
            "confidence": 90,
            "chunk_id": 1
        },
        {
            "entity_id": "malware_emotet",
            "name": "Emotet",
            "entity_type": "malware",
            "quotes": ["The Emotet malware spreads via email"],
            "line_refs": [200, 201],
            "confidence": 85,
            "chunk_id": 2
        }
    ]
    
    consolidator = EntityConsolidatorAgent()
    consolidator.run(mem, {})
    
    emotet = mem.consolidated_entities.get("malware_emotet")
    assert emotet is not None, "Emotet not found"
    
    line_refs = emotet.get('line_refs', [])
    print(f"  Line references: {line_refs}")
    
    # Should have all line refs
    assert len(line_refs) == 5, f"Should have 5 line refs, got {len(line_refs)}"
    assert 100 in line_refs and 200 in line_refs, "Missing line references"
    
    print("✓ Line references preserved in consolidation")


def test_entity_confidence_boosting():
    """Test that entities found in multiple chunks get confidence boost."""
    print("\nTesting multi-chunk entity confidence boost...")
    
    mem = WorkingMemory()
    
    # Single chunk entity
    mem.entity_claims = [
        {
            "entity_id": "tool_mimikatz",
            "name": "Mimikatz",
            "entity_type": "tool",
            "quotes": ["Mimikatz is used for credential dumping"],
            "line_refs": [50],
            "confidence": 70,
            "chunk_id": 1
        }
    ]
    
    consolidator = EntityConsolidatorAgent()
    consolidator.run(mem, {})
    
    single_chunk_confidence = mem.consolidated_entities["tool_mimikatz"]["confidence"]
    print(f"  Single chunk confidence: {single_chunk_confidence}")
    
    # Multi-chunk entity
    mem.entity_claims.append({
        "entity_id": "tool_mimikatz",
        "name": "Mimikatz", 
        "entity_type": "tool",
        "quotes": ["The tool Mimikatz extracts passwords"],
        "line_refs": [150],
        "confidence": 75,
        "chunk_id": 2
    })
    
    consolidator.run(mem, {})
    
    multi_chunk_confidence = mem.consolidated_entities["tool_mimikatz"]["confidence"]
    print(f"  Multi-chunk confidence: {multi_chunk_confidence}")
    
    # Confidence should be boosted
    assert multi_chunk_confidence > single_chunk_confidence, "Confidence not boosted for multi-chunk"
    assert multi_chunk_confidence > 75, "Confidence should exceed max individual confidence"
    
    print("✓ Multi-chunk confidence boosting working")


if __name__ == "__main__":
    print("="*60)
    print("ENTITY EVIDENCE SUBSTANTIATION TEST")
    print("="*60)
    
    try:
        test_entity_claims_creation()
        test_entity_consolidation()
        test_entity_accumulator_support()
        test_entity_evidence_deduplication()
        test_entity_line_references()
        test_entity_confidence_boosting()
        
        print("\n" + "="*60)
        print("✅ All entity evidence substantiation tests passed!")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)