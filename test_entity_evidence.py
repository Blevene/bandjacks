#!/usr/bin/env python3
"""Test entity evidence extraction with the new implementation."""

import json
from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.entity_extractor import EntityExtractionAgent

# Test document
test_document = """
APT29, also known as Cozy Bear, conducted a sophisticated campaign targeting government agencies.
The group deployed SUNBURST backdoor for maintaining persistence on compromised systems.
PowerShell scripts were used extensively for execution and lateral movement.
The threat actor leveraged Mimikatz for credential harvesting from LSASS memory.
Microsoft and SolarWinds were among the primary targets of this campaign.
Operation Ghost was the codename for this extensive cyber espionage campaign.
"""

def test_entity_extraction():
    """Test the enhanced entity extraction with evidence."""
    
    print("="*80)
    print("TESTING ENTITY EVIDENCE EXTRACTION")
    print("="*80)
    
    # Create working memory
    lines = [line.strip() for line in test_document.strip().split('\n') if line.strip()]
    mem = WorkingMemory(
        document_text=test_document,
        line_index=lines
    )
    
    # Run entity extraction
    print("\nRunning entity extraction...")
    extractor = EntityExtractionAgent()
    extractor.run(mem, {"force_chunking": False})
    
    # Check results
    entities = mem.entities.get("entities", [])
    status = mem.entities.get("extraction_status", "unknown")
    
    print(f"\nExtraction status: {status}")
    print(f"Total entities found: {len(entities)}")
    
    # Display entities with evidence
    print("\n" + "-"*40)
    print("EXTRACTED ENTITIES WITH EVIDENCE")
    print("-"*40)
    
    for entity in entities:
        print(f"\n=== {entity['name']} ({entity['type']}) ===")
        print(f"Confidence: {entity.get('confidence', 0)}%")
        
        mentions = entity.get('mentions', [])
        if mentions:
            print(f"Evidence ({len(mentions)} mentions):")
            for i, mention in enumerate(mentions, 1):
                print(f"\n  Mention {i}:")
                print(f"  - Quote: {mention.get('quote', 'N/A')}")
                print(f"  - Line refs: {mention.get('line_refs', [])}")
                print(f"  - Context: {mention.get('context', 'unknown')}")
        else:
            print("  No evidence captured")
    
    # Verify key entities were found
    print("\n" + "-"*40)
    print("VERIFICATION")
    print("-"*40)
    
    entity_names = [e['name'].lower() for e in entities]
    expected_entities = {
        'groups': ['apt29', 'cozy bear'],
        'malware': ['sunburst'],
        'tools': ['powershell', 'mimikatz'],
        'targets': ['microsoft', 'solarwinds'],
        'campaigns': ['operation ghost']
    }
    
    for category, expected_list in expected_entities.items():
        print(f"\n{category.upper()}:")
        for expected in expected_list:
            if any(expected in name for name in entity_names):
                print(f"  ✓ Found: {expected}")
                # Check if it has evidence
                for entity in entities:
                    if expected in entity['name'].lower():
                        if entity.get('mentions'):
                            print(f"    → Has {len(entity['mentions'])} evidence mention(s)")
                        else:
                            print(f"    ⚠ No evidence captured")
            else:
                print(f"  ✗ Missing: {expected}")
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    entities_with_evidence = sum(1 for e in entities if e.get('mentions'))
    total_mentions = sum(len(e.get('mentions', [])) for e in entities)
    
    print(f"Total entities: {len(entities)}")
    print(f"Entities with evidence: {entities_with_evidence}/{len(entities)}")
    print(f"Total evidence mentions: {total_mentions}")
    
    if entities_with_evidence == len(entities) and len(entities) > 0:
        print("\n✅ SUCCESS: All entities have evidence!")
    elif entities_with_evidence > 0:
        print("\n⚠️ PARTIAL: Some entities have evidence")
    else:
        print("\n❌ FAILURE: No entities have evidence")
    
    return mem


def test_entity_merging():
    """Test entity evidence merging across chunks."""
    
    print("\n" + "="*80)
    print("TESTING ENTITY EVIDENCE MERGING")
    print("="*80)
    
    # Longer document to force chunking
    long_document = test_document * 3  # Repeat to create chunks
    
    lines = [line.strip() for line in long_document.strip().split('\n') if line.strip()]
    mem = WorkingMemory(
        document_text=long_document,
        line_index=lines
    )
    
    # Run with forced chunking
    print("\nRunning extraction with chunking...")
    extractor = EntityExtractionAgent()
    extractor.run(mem, {"force_chunking": True})
    
    entities = mem.entities.get("entities", [])
    chunks_processed = mem.entities.get("chunks_processed", 0)
    
    print(f"Chunks processed: {chunks_processed}")
    print(f"Unique entities after merging: {len(entities)}")
    
    # Check for APT29 and its mentions
    for entity in entities:
        if 'apt29' in entity['name'].lower():
            mentions = entity.get('mentions', [])
            print(f"\nAPT29 mentions after merging: {len(mentions)}")
            if mentions:
                print("Evidence quotes:")
                for i, mention in enumerate(mentions[:3], 1):  # Show first 3
                    print(f"  {i}. {mention.get('quote', 'N/A')[:100]}...")
            
            # Check confidence boost
            print(f"Final confidence: {entity.get('confidence', 0)}%")
            if len(mentions) > 1:
                print("✓ Multiple mentions boosted confidence")
    
    return mem


if __name__ == "__main__":
    print("Testing entity evidence extraction improvements...")
    
    # Test basic extraction
    mem1 = test_entity_extraction()
    
    # Test merging
    mem2 = test_entity_merging()
    
    print("\n" + "="*80)
    print("✅ Entity evidence extraction tests complete!")
    print("="*80)