#!/usr/bin/env python3
"""Test entity extraction via API with DarkCloud Stealer PDF."""

import requests
import json
import time
import sys
from pathlib import Path

API_BASE_URL = "http://localhost:8000"

def test_entity_extraction_via_api():
    """Test entity extraction through the API with the DarkCloud PDF."""
    
    pdf_path = "/Volumes/tank/bandjacks/samples/reports/new-darkcloud-stealer-infection-chain.pdf"
    
    print("=" * 80)
    print("TESTING ENTITY EXTRACTION VIA API")
    print("=" * 80)
    print(f"PDF: {pdf_path}")
    print(f"API: {API_BASE_URL}")
    print("-" * 80)
    
    # Check API health
    print("\n🔍 Checking API health...")
    try:
        response = requests.get(f"{API_BASE_URL}/docs")
        if response.status_code == 200:
            print("   ✅ API is running")
        else:
            print(f"   ⚠️  API returned status {response.status_code}")
    except Exception as e:
        print(f"   ❌ Could not connect to API: {e}")
        return False
    
    # Upload the PDF file
    print("\n📤 Uploading PDF to API...")
    
    with open(pdf_path, "rb") as f:
        files = {"file": ("darkcloud.pdf", f, "application/pdf")}
        
        # Use async endpoint for large PDF
        response = requests.post(
            f"{API_BASE_URL}/v1/reports/ingest_file_async",
            files=files
        )
    
    if response.status_code != 200:
        print(f"   ❌ Upload failed: {response.status_code}")
        print(f"   Response: {response.text}")
        return False
    
    job_data = response.json()
    job_id = job_data.get("job_id")
    print(f"   ✅ Job created: {job_id}")
    
    # Poll for job completion
    print("\n⏳ Waiting for extraction to complete...")
    start_time = time.time()
    last_progress = -1
    
    while True:
        response = requests.get(f"{API_BASE_URL}/v1/reports/jobs/{job_id}/status")
        if response.status_code != 200:
            print(f"   ❌ Status check failed: {response.status_code}")
            return False
        
        status_data = response.json()
        status = status_data.get("status")
        progress = status_data.get("progress", 0)
        message = status_data.get("message", "")
        
        if progress != last_progress:
            elapsed = time.time() - start_time
            print(f"   [{elapsed:.1f}s] {progress}% - {message}")
            last_progress = progress
        
        if status == "completed":
            print(f"   ✅ Extraction completed in {time.time() - start_time:.1f} seconds")
            break
        elif status == "failed":
            print(f"   ❌ Extraction failed: {status_data.get('error')}")
            return False
        
        time.sleep(2)
    
    # Get the extraction results
    result = status_data.get("result", {})
    
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
        # Show first few entities of this type
        for entity in type_entities[:3]:
            print(f"    - {entity.get('name', 'Unknown')}")
    
    # Analyze evidence quality
    print("\n🔬 Evidence Quality Analysis:")
    print("-" * 40)
    
    entities_with_evidence = 0
    entities_with_line_refs = 0
    entities_with_confidence = 0
    
    for entity in entity_list:
        mentions = entity.get("mentions", [])
        has_evidence = False
        has_line_refs = False
        
        for mention in mentions:
            if mention.get("quote"):
                has_evidence = True
            if mention.get("line_refs"):
                has_line_refs = True
        
        if has_evidence:
            entities_with_evidence += 1
        if has_line_refs:
            entities_with_line_refs += 1
        if entity.get("confidence", 0) > 0:
            entities_with_confidence += 1
    
    print(f"Entities with evidence: {entities_with_evidence}/{len(entity_list)} ({100*entities_with_evidence/len(entity_list):.1f}%)")
    print(f"Entities with line refs: {entities_with_line_refs}/{len(entity_list)} ({100*entities_with_line_refs/len(entity_list):.1f}%)")
    print(f"Entities with confidence scores: {entities_with_confidence}/{len(entity_list)} ({100*entities_with_confidence/len(entity_list):.1f}%)")
    
    # Show detailed examples
    print("\n📝 Sample Entities with Evidence:")
    print("-" * 40)
    
    # Show one example from each major type
    shown_types = set()
    for entity in entity_list:
        entity_type = entity.get("type", "unknown")
        if entity_type in shown_types:
            continue
        if entity_type not in ["malware", "group", "tool", "campaign"]:
            continue
            
        name = entity.get("name", "Unknown")
        confidence = entity.get("confidence", 0)
        mentions = entity.get("mentions", [])
        
        print(f"\n{name} ({entity_type}):")
        print(f"  Confidence: {confidence}%")
        
        if mentions:
            for i, mention in enumerate(mentions[:2]):  # Show first 2 mentions
                if mention.get("quote"):
                    quote = mention["quote"]
                    if len(quote) > 150:
                        quote = quote[:150] + "..."
                    print(f"  Evidence {i+1}: \"{quote}\"")
                    
                    if mention.get("line_refs"):
                        line_refs = mention["line_refs"][:5]
                        print(f"    Line refs: {line_refs}")
        
        shown_types.add(entity_type)
        if len(shown_types) >= 4:
            break
    
    # Check techniques for comparison
    techniques = result.get("techniques", {})
    print(f"\n\n📈 Comparison with Techniques:")
    print("-" * 40)
    print(f"Techniques extracted: {len(techniques)}")
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"✅ API extraction completed successfully")
    print(f"✅ Extracted {len(entity_list)} entities")
    print(f"✅ Evidence coverage: {100*entities_with_evidence/len(entity_list):.1f}%")
    print(f"✅ Confidence scores: {100*entities_with_confidence/len(entity_list):.1f}%")
    
    # Save full results
    output_file = "/tmp/api_entity_extraction_result.json"
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nFull results saved to: {output_file}")
    
    # Final check
    if entities_with_evidence == len(entity_list):
        print("\n🎉 PERFECT: All entities have evidence!")
        return True
    elif entities_with_evidence >= len(entity_list) * 0.8:
        print(f"\n✅ SUCCESS: {100*entities_with_evidence/len(entity_list):.1f}% of entities have evidence")
        return True
    else:
        print(f"\n⚠️  WARNING: Only {100*entities_with_evidence/len(entity_list):.1f}% of entities have evidence")
        return False

if __name__ == "__main__":
    success = test_entity_extraction_via_api()
    sys.exit(0 if success else 1)