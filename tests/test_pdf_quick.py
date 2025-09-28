#!/usr/bin/env python3
"""Quick test of agentic_v2 extraction with limited scope."""

import sys
import json
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import PyPDF2
from bandjacks.llm.extraction_pipeline import run_extraction_pipeline


def test_darkcloud_quick():
    """Quick test on DarkCloud PDF with limited text."""
    
    print("="*80)
    print("QUICK AGENTIC V2 TEST - DarkCloud Stealer")
    print("="*80)
    
    pdf_path = Path(__file__).parent.parent / "samples" / "reports" / "new-darkcloud-stealer-infection-chain.pdf"
    
    if not pdf_path.exists():
        print(f"❌ PDF not found")
        return False
    
    # Extract first 2 pages only for quick test
    print("1. Extracting first 2 pages of PDF...")
    try:
        text_content = []
        with open(pdf_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)
            for i in range(min(2, len(pdf_reader.pages))):
                text_content.append(pdf_reader.pages[i].extract_text())
        
        text = '\n'.join(text_content)[:5000]  # Limit to 5000 chars
        print(f"   ✅ Extracted {len(text)} characters")
        
    except Exception as e:
        print(f"   ❌ Extraction failed: {e}")
        return False
    
    # Simple config with limits
    import os
    config = {
        "neo4j_uri": os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        "neo4j_user": os.getenv("NEO4J_USER", "neo4j"),
        "neo4j_password": os.getenv("NEO4J_PASSWORD", ""),
        "model": "gemini/gemini-2.5-flash",
        "discovery_model": "gemini/gemini-2.5-flash",
        "mapper_model": "gemini/gemini-2.5-flash",
        "title": "DarkCloud Quick Test",
        "url": "test",
        "ts": time.time(),
        "min_quotes": 1,
        "max_discovery_per_span": 3,  # Limit discoveries
        "top_k": 5  # Fewer candidates
    }
    
    print("\n2. Running limited extraction...")
    try:
        # Temporarily limit spans for quick test
        from bandjacks.llm.memory import WorkingMemory
        from bandjacks.llm.agents_v2 import (
            SpanFinderAgent, RetrieverAgent, DiscoveryAgent,
            MapperAgent, EvidenceVerifierAgent, ConsolidatorAgent,
            AssemblerAgent
        )
        
        mem = WorkingMemory(document_text=text, line_index=text.splitlines())
        
        # Run limited pipeline
        SpanFinderAgent().run(mem, config)
        
        # Limit to first 10 spans
        mem.spans = mem.spans[:10]
        print(f"   📍 Processing {len(mem.spans)} spans")
        
        RetrieverAgent().run(mem, config)
        DiscoveryAgent().run(mem, config)
        MapperAgent().run(mem, config)
        EvidenceVerifierAgent().run(mem, config)
        ConsolidatorAgent().run(mem, config)
        
        result = AssemblerAgent().run(mem, config)
        
        techniques = result.get("techniques", {})
        print(f"   ✅ Found {len(techniques)} techniques")
        
        # Expected techniques in first pages
        expected = {
            "T1566": "Phishing",
            "T1059.001": "PowerShell",
            "T1059.007": "JavaScript",
            "T1204": "User Execution"
        }
        
        print("\n3. Quick Validation:")
        found = 0
        for tech_id, name in expected.items():
            if any(tech_id in t for t in techniques.keys()):
                print(f"   ✅ {tech_id}: {name}")
                found += 1
            else:
                print(f"   ❌ {tech_id}: {name}")
        
        recall = (found / len(expected)) * 100
        print(f"\n   Quick Recall: {recall:.0f}% ({found}/{len(expected)})")
        
        print("\n4. Top Techniques Found:")
        for i, (tech_id, info) in enumerate(list(techniques.items())[:5]):
            print(f"   {i+1}. {tech_id}: {info['name']} (confidence: {info['confidence']}%)")
        
        return recall >= 50  # Lower bar for quick test
        
    except Exception as e:
        print(f"   ❌ Extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    success = test_darkcloud_quick()
    
    print("\n" + "="*80)
    if success:
        print("✅ Quick test passed - pipeline is working")
    else:
        print("❌ Quick test failed - needs investigation")
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())