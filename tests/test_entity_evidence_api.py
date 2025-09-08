#!/usr/bin/env python3
"""Test that entity evidence appears in API response."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bandjacks.llm.optimized_chunked_extractor import OptimizedChunkedExtractor
import json

# Test document with multiple entities
test_document = """
APT29, also known as Cozy Bear, is a sophisticated Russian threat actor group that has been 
active since at least 2008. The group is attributed to the Russian Foreign Intelligence Service (SVR).

In 2020, APT29 was responsible for the SolarWinds supply chain attack, deploying the SUNBURST 
backdoor to compromise thousands of organizations worldwide. The SUNBURST malware was designed 
to be stealthy and evade detection by mimicking legitimate SolarWinds traffic.

The campaign targeted major organizations including Microsoft, FireEye, and numerous U.S. 
government agencies. APT29 used a variety of tools and techniques in this operation:

1. PowerShell scripts for initial access and execution
2. Mimikatz for credential dumping
3. Cobalt Strike beacons for command and control
4. Custom malware families like TEARDROP and RAINDROP

The group employed sophisticated techniques including:
- T1195.002: Supply Chain Compromise
- T1055: Process Injection
- T1003.001: OS Credential Dumping using LSASS Memory
- T1071.001: Application Layer Protocol for C2 communications

This attack demonstrated APT29's advanced capabilities and their focus on long-term, 
stealthy operations within target networks. The group continues to be a significant threat
to organizations worldwide, particularly those in government and technology sectors.

FireEye's analysis revealed that APT29 had been present in some networks for over a year
before detection, highlighting the group's patience and operational security.
"""

def test_entity_evidence_in_pipeline():
    """Test that entities have evidence in the full extraction pipeline."""
    print("=" * 60)
    print("TESTING ENTITY EVIDENCE IN EXTRACTION PIPELINE")
    print("=" * 60)
    
    # Configure extraction with entity claims
    config = {
        "use_entity_claims": True,
        "use_batch_entity_extraction": False,  # Use standard extraction for testing
        "progressive_mode": "async",
        "disable_entity_extraction": False
    }
    
    # Run extraction
    extractor = OptimizedChunkedExtractor()
    result = extractor.extract(test_document, config)
    
    # Check entities
    entities = result.get("entities", {})
    entity_list = entities.get("entities", [])
    
    print(f"\nExtracted {len(entity_list)} entities")
    print("-" * 40)
    
    entities_with_evidence = 0
    entities_with_line_refs = 0
    
    for entity in entity_list:
        name = entity.get("name", "Unknown")
        entity_type = entity.get("type", "unknown")
        confidence = entity.get("confidence", 0)
        mentions = entity.get("mentions", [])
        
        has_evidence = False
        has_line_refs = False
        
        if mentions:
            for mention in mentions:
                if mention.get("quote"):
                    has_evidence = True
                if mention.get("line_refs"):
                    has_line_refs = True
        
        if has_evidence:
            entities_with_evidence += 1
        if has_line_refs:
            entities_with_line_refs += 1
            
        print(f"\n{name} ({entity_type}):")
        print(f"  Confidence: {confidence}%")
        print(f"  Mentions: {len(mentions)}")
        if mentions and mentions[0].get("quote"):
            quote = mentions[0]["quote"]
            if len(quote) > 100:
                quote = quote[:100] + "..."
            print(f"  Evidence: \"{quote}\"")
        print(f"  Has evidence: {'✓' if has_evidence else '✗'}")
        print(f"  Has line refs: {'✓' if has_line_refs else '✗'}")
    
    # Check techniques for comparison
    techniques = result.get("techniques", {})
    print(f"\n\nAlso extracted {len(techniques)} techniques for comparison")
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total entities: {len(entity_list)}")
    print(f"Entities with evidence: {entities_with_evidence}")
    print(f"Entities with line refs: {entities_with_line_refs}")
    
    # Validation
    if entities_with_evidence > 0:
        print("\n✅ Entity evidence is being captured!")
    else:
        print("\n❌ No entity evidence found - this needs investigation")
    
    if entities_with_line_refs > 0:
        print("✅ Entity line references are being tracked!")
    else:
        print("⚠️  Line references not fully implemented yet")
    
    # Save result for inspection
    output_file = "/tmp/entity_evidence_test_result.json"
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nFull result saved to: {output_file}")
    
    return entities_with_evidence > 0

if __name__ == "__main__":
    success = test_entity_evidence_in_pipeline()
    sys.exit(0 if success else 1)