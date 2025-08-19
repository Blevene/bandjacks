#!/usr/bin/env python3
"""Test the simplified ADK-based TTP extractor."""

import sys
import json
import time
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bandjacks.llm.adk_simple_extractor import SimpleADKExtractor, extract_pdf_text


def test_simple_adk():
    """Test simplified ADK extraction."""
    
    # Load environment variables from .env
    from dotenv import load_dotenv
    load_dotenv()
    
    # Check API key
    if not os.environ.get("GEMINI_API_KEY") and not os.environ.get("GOOGLE_API_KEY"):
        print("Please set GEMINI_API_KEY or GOOGLE_API_KEY environment variable")
        return
    
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
    print("SIMPLIFIED ADK TTP EXTRACTION TEST")
    print("="*80)
    
    # Extract text
    print("\n[1] Extracting text from PDF...")
    text = extract_pdf_text(pdf_path)
    print(f"  Extracted {len(text)} characters")
    
    # Initialize extractor
    print("\n[2] Initializing simplified ADK extractor...")
    try:
        extractor = SimpleADKExtractor(model="gemini-2.5-flash")
        print("  ✓ ADK agent created")
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return
    
    # Run extraction
    print("\n[3] Running extraction with retrieval grounding...")
    print("  Workflow: Extract behaviors → Search techniques → Select & verify")
    
    start_time = time.time()
    try:
        results = extractor.extract_ttps(text, "darkcloud_test")
        elapsed = time.time() - start_time
        
        print(f"\n  Completed in {elapsed:.1f} seconds")
        
        # Analyze results
        techniques = results.get("techniques", {})
        print(f"\n[4] Results:")
        print(f"  Total techniques found: {len(techniques)}")
        
        # Calculate recall
        found_ids = set(techniques.keys())
        # Add parent techniques
        for tech_id in list(found_ids):
            if '.' in tech_id:
                found_ids.add(tech_id.split('.')[0])
        
        recall = len(found_ids & set(expected_techniques)) / len(expected_techniques) if expected_techniques else 0
        
        print(f"\n[5] Performance:")
        print(f"  Recall: {recall:.1%} (target: 75%)")
        print(f"  Found: {sorted(found_ids)[:10]}")
        
        # Show techniques with evidence
        print(f"\n[6] Techniques with Evidence:")
        for tech_id, info in sorted(techniques.items())[:5]:
            print(f"\n  {tech_id}: {info.get('name', 'Unknown')}")
            print(f"    Confidence: {info.get('confidence', 0)}")
            evidence = info.get('evidence', [])
            if evidence:
                print(f"    Evidence: \"{evidence[0][:80]}...\"")
        
        # Check what we missed
        missed = set(expected_techniques) - found_ids
        if missed:
            print(f"\n[7] Missed: {sorted(missed)}")
        
        # Save results
        output = {
            "source": "darkcloud_stealer",
            "elapsed": elapsed,
            "recall": recall,
            "found_count": len(techniques),
            "found_ids": sorted(found_ids),
            "missed_ids": sorted(missed),
            "techniques": techniques
        }
        
        output_file = "/tmp/adk_simple_results.json"
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        
        print(f"\n✓ Results saved to {output_file}")
        
        if recall >= 0.75:
            print(f"\n🎉 SUCCESS: {recall:.1%} recall achieved!")
        else:
            print(f"\n⚠️  {recall:.1%} recall (need 75%)")
        
    except Exception as e:
        print(f"\n✗ Extraction failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_simple_adk()