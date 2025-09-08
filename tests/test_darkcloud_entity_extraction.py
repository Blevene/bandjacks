#!/usr/bin/env python3
"""Test entity extraction with evidence on DarkCloud Stealer PDF."""

import sys
import time
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bandjacks.services.api.extraction_pipeline import run_extraction_pipeline
from bandjacks.llm.optimized_chunked_extractor import OptimizedChunkedExtractor

def test_darkcloud_entity_extraction():
    """Test entity extraction with claims on the DarkCloud Stealer PDF."""
    
    pdf_path = "/Volumes/tank/bandjacks/samples/reports/new-darkcloud-stealer-infection-chain.pdf"
    
    print("=" * 80)
    print("TESTING ENTITY EXTRACTION ON DARKCLOUD STEALER PDF")
    print("=" * 80)
    print(f"PDF: {pdf_path}")
    print("-" * 80)
    
    # Read PDF content
    from bandjacks.services.api.pdf_utils import extract_pdf_text
    
    print("\n📄 Extracting text from PDF...")
    text_content = extract_pdf_text(pdf_path)
    print(f"   Document size: {len(text_content)} characters")
    
    # Configure extraction with entity claims
    config = {
        "use_entity_claims": True,
        "use_batch_entity_extraction": False,  # Use standard extraction for better evidence
        "progressive_mode": "async",
        "disable_entity_extraction": False,
        "use_optimized_extractor": True,
        "chunk_size": 4000,
        "max_chunks": 30
    }
    
    print("\n🔍 Running extraction pipeline with entity claims...")
    start_time = time.time()
    
    # Use optimized extractor
    extractor = OptimizedChunkedExtractor()
    result = extractor.extract(text_content, config)
    
    elapsed = time.time() - start_time
    print(f"   Extraction completed in {elapsed:.1f} seconds")
    
    # Analyze entities
    print("\n📊 Entity Extraction Results:")
    print("-" * 40)
    
    entities = result.get("entities", {})
    entity_list = entities.get("entities", [])
    
    print(f"Total entities extracted: {len(entity_list)}")
    
    # Group by type
    entities_by_type = {}
    for entity in entity_list:
        entity_type = entity.get("type", "unknown")
        if entity_type not in entities_by_type:
            entities_by_type[entity_type] = []
        entities_by_type[entity_type].append(entity)
    
    print("\nEntities by type:")
    for entity_type, type_entities in sorted(entities_by_type.items()):
        print(f"  {entity_type}: {len(type_entities)}")
    
    # Analyze evidence quality
    print("\n🔬 Evidence Quality Analysis:")
    print("-" * 40)
    
    entities_with_evidence = 0
    entities_with_line_refs = 0
    total_evidence_pieces = 0
    evidence_lengths = []
    
    for entity in entity_list:
        mentions = entity.get("mentions", [])
        has_evidence = False
        has_line_refs = False
        
        for mention in mentions:
            if mention.get("quote"):
                has_evidence = True
                total_evidence_pieces += 1
                evidence_lengths.append(len(mention["quote"]))
            if mention.get("line_refs"):
                has_line_refs = True
        
        if has_evidence:
            entities_with_evidence += 1
        if has_line_refs:
            entities_with_line_refs += 1
    
    print(f"Entities with evidence: {entities_with_evidence}/{len(entity_list)} ({100*entities_with_evidence/len(entity_list):.1f}%)")
    print(f"Entities with line refs: {entities_with_line_refs}/{len(entity_list)} ({100*entities_with_line_refs/len(entity_list):.1f}%)")
    print(f"Total evidence pieces: {total_evidence_pieces}")
    if evidence_lengths:
        print(f"Average evidence length: {sum(evidence_lengths)/len(evidence_lengths):.0f} characters")
    
    # Show some examples
    print("\n📝 Sample Entities with Evidence:")
    print("-" * 40)
    
    # Show interesting entities
    interesting_types = ["malware", "group", "tool", "campaign"]
    shown = 0
    
    for entity_type in interesting_types:
        if entity_type in entities_by_type:
            for entity in entities_by_type[entity_type][:2]:  # Show max 2 per type
                name = entity.get("name", "Unknown")
                confidence = entity.get("confidence", 0)
                mentions = entity.get("mentions", [])
                
                print(f"\n{name} ({entity_type}):")
                print(f"  Confidence: {confidence}%")
                
                if mentions and mentions[0].get("quote"):
                    quote = mentions[0]["quote"]
                    if len(quote) > 150:
                        quote = quote[:150] + "..."
                    print(f"  Evidence: \"{quote}\"")
                    
                    if mentions[0].get("line_refs"):
                        line_refs = mentions[0]["line_refs"][:5]  # Show first 5
                        print(f"  Line refs: {line_refs}")
                
                shown += 1
                if shown >= 6:  # Limit total examples
                    break
            if shown >= 6:
                break
    
    # Check techniques for comparison
    techniques = result.get("techniques", {})
    print(f"\n\n📈 Comparison with Techniques:")
    print("-" * 40)
    print(f"Techniques extracted: {len(techniques)}")
    
    # Check accumulator stats if available
    if "accumulator_stats" in result:
        stats = result["accumulator_stats"]
        print(f"\n🔄 Progressive Accumulation Stats:")
        print(f"  Chunks processed: {stats.get('chunks_processed', 0)}")
        print(f"  Multi-chunk entities: {stats.get('multi_chunk_entities', 0)}")
        print(f"  Average entity confidence: {stats.get('avg_entity_confidence', 0):.1f}%")
    
    # Performance summary
    print("\n" + "=" * 80)
    print("PERFORMANCE SUMMARY")
    print("=" * 80)
    print(f"Document size: {len(text_content)} characters")
    print(f"Processing time: {elapsed:.1f} seconds")
    print(f"Entities extracted: {len(entity_list)}")
    print(f"Techniques extracted: {len(techniques)}")
    print(f"Evidence coverage: {100*entities_with_evidence/len(entity_list):.1f}%")
    
    # Save detailed results
    output_file = "/tmp/darkcloud_entity_extraction_result.json"
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nDetailed results saved to: {output_file}")
    
    # Final verdict
    print("\n" + "=" * 80)
    if entities_with_evidence == len(entity_list):
        print("✅ SUCCESS: All entities have evidence!")
    elif entities_with_evidence >= len(entity_list) * 0.8:
        print("✅ GOOD: Most entities have evidence (>80%)")
    else:
        print(f"⚠️  WARNING: Only {100*entities_with_evidence/len(entity_list):.1f}% of entities have evidence")
    
    return entities_with_evidence > 0

if __name__ == "__main__":
    success = test_darkcloud_entity_extraction()
    sys.exit(0 if success else 1)