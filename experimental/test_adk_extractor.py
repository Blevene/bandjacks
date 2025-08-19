#!/usr/bin/env python3
"""Test the ADK-based multi-agent TTP extractor."""

import sys
import json
import time
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).parent))

from bandjacks.llm.adk_extractor import ADKTTPExtractor, extract_pdf_text


def test_adk_extraction():
    """Test ADK-based extraction on DarkCloud Stealer report."""
    
    # Expected techniques for DarkCloud Stealer
    expected_techniques = [
        "T1566", "T1566.001",  # Phishing
        "T1059", "T1059.001", "T1059.007",  # PowerShell, JavaScript
        "T1027", "T1140",  # Obfuscation
        "T1055",  # Process Injection
        "T1071",  # C2
        "T1547",  # Persistence
        "T1555", "T1555.003",  # Credentials
        "T1005", "T1041",  # Collection/Exfiltration
        "T1105", "T1204"  # Tool Transfer, User Execution
    ]
    
    # Load test document
    pdf_path = Path("samples/reports/new-darkcloud-stealer-infection-chain.pdf")
    if not pdf_path.exists():
        print(f"✗ Test file not found: {pdf_path}")
        return
    
    print("="*80)
    print("ADK-BASED MULTI-AGENT TTP EXTRACTION TEST")
    print("="*80)
    
    # Extract text
    print("\n[1] Extracting text from PDF...")
    text = extract_pdf_text(pdf_path)
    print(f"  Extracted {len(text)} characters")
    
    # Initialize extractor
    print("\n[2] Initializing ADK multi-agent system...")
    try:
        extractor = ADKTTPExtractor(model="gemini-2.0-flash")
        print("  ✓ ADK agents created successfully")
    except Exception as e:
        print(f"  ✗ Failed to initialize: {e}")
        print("\nMake sure to set GEMINI_API_KEY or GOOGLE_API_KEY environment variable")
        return
    
    # Run extraction
    print("\n[3] Running multi-agent extraction...")
    print("  Workflow: SpanFinder → Retriever → Mapper → Verifier → Consolidator")
    
    start_time = time.time()
    try:
        results = extractor.extract_ttps(text, "darkcloud_stealer")
        elapsed = time.time() - start_time
        
        print(f"\n  Completed in {elapsed:.1f} seconds")
        
        # Analyze results
        techniques = results.get("techniques", {})
        print(f"\n[4] Results:")
        print(f"  Total techniques found: {len(techniques)}")
        
        if results.get("context"):
            ctx = results["context"]
            print(f"  Spans analyzed: {ctx.get('spans_analyzed', 0)}")
            print(f"  Candidates retrieved: {ctx.get('candidates_retrieved', 0)}")
            print(f"  Techniques verified: {ctx.get('techniques_verified', 0)}")
        
        # Calculate recall
        found_ids = set(techniques.keys())
        # Add parent techniques
        for tech_id in list(found_ids):
            if '.' in tech_id:
                found_ids.add(tech_id.split('.')[0])
        
        recall = len(found_ids & set(expected_techniques)) / len(expected_techniques)
        
        print(f"\n[5] Performance Metrics:")
        print(f"  Recall: {recall:.1%} (target: 75%)")
        print(f"  Techniques found: {sorted(found_ids)[:10]}")
        
        # Show top techniques with evidence
        print(f"\n[6] Top Techniques with Evidence:")
        sorted_techs = sorted(
            techniques.items(),
            key=lambda x: x[1].get('confidence', 0),
            reverse=True
        )
        
        for tech_id, info in sorted_techs[:5]:
            print(f"\n  {tech_id}: {info.get('name', 'Unknown')}")
            print(f"    Confidence: {info.get('confidence', 0)}")
            evidence = info.get('evidence', [])
            if evidence:
                print(f"    Evidence: {evidence[0][:100]}...")
            line_refs = info.get('line_refs', [])
            if line_refs:
                print(f"    Lines: {line_refs}")
        
        # Check what we missed
        missed = set(expected_techniques) - found_ids
        if missed:
            print(f"\n[7] Missed Techniques: {sorted(missed)}")
        
        # Save results
        output_file = "/tmp/adk_extraction_results.json"
        with open(output_file, "w") as f:
            json.dump({
                "source": "darkcloud_stealer",
                "elapsed": elapsed,
                "recall": recall,
                "techniques": techniques,
                "found_ids": sorted(found_ids),
                "missed_ids": sorted(missed)
            }, f, indent=2)
        
        print(f"\n✓ Results saved to {output_file}")
        
        if recall >= 0.75:
            print(f"\n🎉 SUCCESS: Achieved {recall:.1%} recall (≥75% target)!")
        else:
            print(f"\n⚠️  Need improvement: {recall:.1%} recall (target: 75%)")
        
    except Exception as e:
        print(f"\n  ✗ Extraction failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_adk_extraction()