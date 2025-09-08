#!/usr/bin/env python3
"""Test extraction with detailed logging to track technique preservation."""

import logging
import json
from pathlib import Path
from bandjacks.llm.optimized_chunked_extractor import OptimizedChunkedExtractor
import pdfplumber

def extract_text_from_pdf(pdf_path):
    """Extract text from PDF."""
    text = ""
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"
    return text

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Focus on relevant loggers
logging.getLogger("bandjacks.llm.optimized_chunked_extractor").setLevel(logging.DEBUG)
logging.getLogger("bandjacks.llm.chunked_extractor").setLevel(logging.DEBUG)
logging.getLogger("bandjacks.llm.agents_v2").setLevel(logging.INFO)
logging.getLogger("bandjacks.llm.mapper_optimized").setLevel(logging.INFO)

def test_extraction(pdf_path: str):
    """Test extraction and log technique counts at each stage."""
    print(f"\n{'='*60}")
    print(f"Testing extraction on: {pdf_path}")
    print(f"{'='*60}\n")
    
    # Extract text from PDF
    text = extract_text_from_pdf(pdf_path)
    print(f"PDF text extracted: {len(text)} characters\n")
    
    # Configure extraction
    config = {
        "chunk_size": 4000,
        "max_chunks": 30,
        "parallel_workers": 1,  # Single worker for clearer logging
        "use_optimized": True,
        "progressive_mode": "async",
        "early_termination_threshold": 100.0,  # Don't terminate early
        "min_techniques_for_termination": 100,  # High threshold
    }
    
    # Run extraction
    extractor = OptimizedChunkedExtractor()
    
    print("Starting extraction...\n")
    result = extractor.extract(text, config, parallel=False)
    
    # Analyze results
    print(f"\n{'='*60}")
    print("EXTRACTION RESULTS")
    print(f"{'='*60}\n")
    
    techniques = result.get("techniques", {})
    claims = result.get("claims", [])
    
    print(f"Total claims: {len(claims)}")
    print(f"Total techniques: {len(techniques)}")
    
    # Analyze parent/subtechnique distribution
    technique_ids = sorted(techniques.keys())
    parent_ids = [tid for tid in technique_ids if "." not in tid]
    sub_ids = [tid for tid in technique_ids if "." in tid]
    
    print(f"\nParent techniques ({len(parent_ids)}): {', '.join(parent_ids)}")
    print(f"Subtechniques ({len(sub_ids)}): {', '.join(sub_ids)}")
    
    # Check for parent/subtechnique relationships
    print(f"\n{'='*60}")
    print("PARENT/SUBTECHNIQUE RELATIONSHIPS")
    print(f"{'='*60}\n")
    
    parents_with_subs = {}
    orphan_subs = []
    
    for sub_id in sub_ids:
        parent = sub_id.split(".")[0]
        if parent in parent_ids:
            if parent not in parents_with_subs:
                parents_with_subs[parent] = []
            parents_with_subs[parent].append(sub_id)
        else:
            orphan_subs.append(sub_id)
    
    for parent, subs in sorted(parents_with_subs.items()):
        print(f"{parent} (parent)")
        for sub in subs:
            print(f"  └─ {sub}: {techniques[sub]['name']}")
    
    if orphan_subs:
        print(f"\nSubtechniques without parent in results:")
        for sub in orphan_subs:
            parent = sub.split(".")[0]
            print(f"  {sub} (parent {parent} not found)")
    
    # Check if any subtechniques might have been dropped
    print(f"\n{'='*60}")
    print("POTENTIAL ISSUES")
    print(f"{'='*60}\n")
    
    # Check claims vs techniques
    claim_ids = set()
    for claim in claims:
        tech_id = claim.get("technique_id") or claim.get("external_id", "")
        if tech_id:
            claim_ids.add(tech_id)
    
    techniques_set = set(techniques.keys())
    
    if claim_ids != techniques_set:
        missing_in_techniques = claim_ids - techniques_set
        missing_in_claims = techniques_set - claim_ids
        
        if missing_in_techniques:
            print(f"⚠️  Techniques in claims but not in final techniques dict:")
            for tid in sorted(missing_in_techniques):
                print(f"    - {tid}")
        
        if missing_in_claims:
            print(f"⚠️  Techniques in final dict but not in claims:")
            for tid in sorted(missing_in_claims):
                print(f"    - {tid}")
    else:
        print("✅ All claimed techniques appear in final results")
    
    return result


if __name__ == "__main__":
    pdf_path = "/Volumes/tank/bandjacks/samples/reports/new-darkcloud-stealer-infection-chain.pdf"
    
    if not Path(pdf_path).exists():
        print(f"Error: PDF not found at {pdf_path}")
    else:
        result = test_extraction(pdf_path)
        
        # Save results for inspection
        output_path = "/Volumes/tank/bandjacks/test_extraction_results.json"
        with open(output_path, "w") as f:
            # Convert sets to lists for JSON serialization
            serializable_result = {
                "techniques": result.get("techniques", {}),
                "claims_count": len(result.get("claims", [])),
                "technique_ids": sorted(result.get("techniques", {}).keys())
            }
            json.dump(serializable_result, f, indent=2)
        print(f"\nResults saved to: {output_path}")