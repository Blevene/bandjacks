#!/usr/bin/env python3
"""Test entity evidence consolidation in chunked extractor."""

import json
from bandjacks.llm.chunked_extractor import ChunkedExtractor

# Create test document that will be split into chunks
test_document = """
The threat actor APT29, also known as Cozy Bear, has been active since 2008.
APT29 uses sophisticated spear-phishing campaigns to gain initial access.
The group has targeted government organizations across Europe and North America.

[Section break to force new chunk]
""" + "." * 3500 + """

In recent campaigns, APT29 has deployed the SUNBURST backdoor for persistence.
Cozy Bear continues to evolve their tactics, using PowerShell extensively.
The SUNBURST malware was distributed through supply chain attacks.

[Another section to force third chunk]
""" + "." * 3500 + """

APT29's operations demonstrate advanced operational security practices.
PowerShell Empire and Mimikatz are frequently used tools in their arsenal.
The group's SUNBURST implant communicates via DNS tunneling.
"""

def test_entity_consolidation():
    """Test that entity evidence is properly consolidated across chunks."""
    
    print("="*80)
    print("TESTING ENTITY EVIDENCE CONSOLIDATION")
    print("="*80)
    
    # Create chunked extractor with small chunk size to force multiple chunks
    extractor = ChunkedExtractor(
        chunk_size=4000,  # Small chunks to force splitting
        overlap=200,
        max_chunks=5,
        parallel_workers=1  # Sequential for easier debugging
    )
    
    # Create chunks
    chunks = extractor.create_chunks(test_document)
    print(f"\nDocument split into {len(chunks)} chunks")
    
    # Simulate extraction results from each chunk
    chunk_results = []
    
    # Chunk 1 results
    chunk_results.append({
        "chunk_id": 0,
        "entities": {
            "entities": [
                {
                    "name": "APT29",
                    "type": "group",
                    "confidence": 90,
                    "mentions": [{
                        "quote": "The threat actor APT29, also known as Cozy Bear, has been active since 2008.",
                        "line_refs": [1],
                        "context": "primary_mention"
                    }]
                },
                {
                    "name": "Cozy Bear",
                    "type": "group", 
                    "confidence": 85,
                    "mentions": [{
                        "quote": "The threat actor APT29, also known as Cozy Bear, has been active since 2008.",
                        "line_refs": [1],
                        "context": "alias"
                    }]
                }
            ],
            "extraction_status": "completed"
        },
        "claims": [],
        "techniques": {}
    })
    
    # Chunk 2 results
    chunk_results.append({
        "chunk_id": 1,
        "entities": {
            "entities": [
                {
                    "name": "APT29",
                    "type": "group",
                    "confidence": 95,
                    "mentions": [{
                        "quote": "In recent campaigns, APT29 has deployed the SUNBURST backdoor for persistence.",
                        "line_refs": [8],
                        "context": "primary_mention"
                    }]
                },
                {
                    "name": "SUNBURST",
                    "type": "malware",
                    "confidence": 100,
                    "mentions": [
                        {
                            "quote": "In recent campaigns, APT29 has deployed the SUNBURST backdoor for persistence.",
                            "line_refs": [8],
                            "context": "primary_mention"
                        },
                        {
                            "quote": "The SUNBURST malware was distributed through supply chain attacks.",
                            "line_refs": [10],
                            "context": "primary_mention"
                        }
                    ]
                },
                {
                    "name": "PowerShell",
                    "type": "tool",
                    "confidence": 80,
                    "mentions": [{
                        "quote": "Cozy Bear continues to evolve their tactics, using PowerShell extensively.",
                        "line_refs": [9],
                        "context": "primary_mention"
                    }]
                }
            ],
            "extraction_status": "completed"
        },
        "claims": [],
        "techniques": {}
    })
    
    # Chunk 3 results
    chunk_results.append({
        "chunk_id": 2,
        "entities": {
            "entities": [
                {
                    "name": "APT29",
                    "type": "group",
                    "confidence": 85,
                    "mentions": [{
                        "quote": "APT29's operations demonstrate advanced operational security practices.",
                        "line_refs": [15],
                        "context": "primary_mention"
                    }]
                },
                {
                    "name": "PowerShell Empire",
                    "type": "tool",
                    "confidence": 75,
                    "mentions": [{
                        "quote": "PowerShell Empire and Mimikatz are frequently used tools in their arsenal.",
                        "line_refs": [16],
                        "context": "primary_mention"
                    }]
                },
                {
                    "name": "Mimikatz",
                    "type": "tool",
                    "confidence": 90,
                    "mentions": [{
                        "quote": "PowerShell Empire and Mimikatz are frequently used tools in their arsenal.",
                        "line_refs": [16],
                        "context": "primary_mention"
                    }]
                },
                {
                    "name": "SUNBURST",
                    "type": "malware",
                    "confidence": 95,
                    "mentions": [{
                        "quote": "The group's SUNBURST implant communicates via DNS tunneling.",
                        "line_refs": [17],
                        "context": "coreference"
                    }]
                }
            ],
            "extraction_status": "completed"
        },
        "claims": [],
        "techniques": {}
    })
    
    # Test merging
    print("\nMerging results from chunks...")
    merged = extractor.merge_results(chunk_results)
    
    # Analyze results
    entities = merged["entities"]["entities"]
    print(f"\n{len(entities)} unique entities after consolidation:")
    
    for entity in entities:
        name = entity["name"]
        entity_type = entity["type"]
        confidence = entity.get("confidence", 0)
        mentions = entity.get("mentions", [])
        
        print(f"\n  {name} ({entity_type}):")
        print(f"    - Confidence: {confidence}%")
        print(f"    - Total mentions: {len(mentions)}")
        
        # Show evidence
        for i, mention in enumerate(mentions[:2], 1):  # Show first 2
            quote = mention.get("quote", "")[:80]
            context = mention.get("context", "unknown")
            print(f"    - Evidence {i} ({context}): {quote}...")
    
    # Verify consolidation worked
    print("\n" + "="*80)
    print("VERIFICATION")
    print("="*80)
    
    # Check APT29/Cozy Bear consolidation
    apt29_entities = [e for e in entities if "apt29" in e["name"].lower() or "cozy" in e["name"].lower()]
    print(f"\n✓ APT29/Cozy Bear consolidation: {len(apt29_entities)} entity (expected 1)")
    if apt29_entities:
        apt29 = apt29_entities[0]
        print(f"  - Name: {apt29['name']}")
        print(f"  - Mentions: {len(apt29.get('mentions', []))}")
        print(f"  - Confidence: {apt29.get('confidence', 0)}% (should be boosted)")
    
    # Check SUNBURST consolidation
    sunburst_entities = [e for e in entities if "sunburst" in e["name"].lower()]
    print(f"\n✓ SUNBURST consolidation: {len(sunburst_entities)} entity (expected 1)")
    if sunburst_entities:
        sunburst = sunburst_entities[0]
        print(f"  - Name: {sunburst['name']}")
        print(f"  - Mentions: {len(sunburst.get('mentions', []))} (expected 3)")
        print(f"  - Confidence: {sunburst.get('confidence', 0)}% (should be boosted)")
    
    # Check no duplicates
    entity_names = [e["name"].lower() for e in entities]
    unique_names = set(entity_names)
    print(f"\n✓ No duplicates: {len(entity_names)} names, {len(unique_names)} unique")
    
    # Check confidence boosting
    high_confidence = [e for e in entities if e.get("confidence", 0) > 90]
    print(f"\n✓ Confidence boosting: {len(high_confidence)} entities with >90% confidence")
    
    print("\n" + "="*80)
    if len(apt29_entities) == 1 and len(sunburst_entities) == 1 and len(entity_names) == len(unique_names):
        print("✅ Entity evidence consolidation working correctly!")
    else:
        print("⚠️ Issues detected in entity consolidation")
    print("="*80)
    
    return merged


if __name__ == "__main__":
    test_entity_consolidation()