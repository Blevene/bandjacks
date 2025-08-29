#!/usr/bin/env python3
"""Debug script to test extraction pipeline step by step."""

import json
import sys
from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.agents_v2 import (
    SpanFinderAgent,
    RetrieverAgent,
    MapperAgent,
    ConsolidatorAgent,
)
from bandjacks.llm.tracker import ExtractionTracker

def test_extraction():
    # Test text with explicit technique IDs
    test_text = """
    APT28 uses T1566.001 Spearphishing Attachment to deliver malware. 
    They also employ T1055 Process Injection for persistence.
    The group leverages T1070.004 File Deletion to cover their tracks.
    """
    
    print("=== Testing Extraction Pipeline ===")
    print(f"Input text: {test_text[:100]}...")
    print()
    
    # Initialize WorkingMemory with both text and line index
    mem = WorkingMemory(
        document_text=test_text,
        line_index=test_text.splitlines()
    )
    config = {
        "max_spans": 10,
        "skip_verification": True,
        "disable_discovery": True,
        "disable_targeted_extraction": True
    }
    tracker = ExtractionTracker()
    
    # Step 1: SpanFinder
    print("1. Running SpanFinderAgent...")
    SpanFinderAgent().run(mem, config)
    print(f"   Found {len(mem.spans)} spans")
    for i, span in enumerate(mem.spans[:3]):
        print(f"   Span {i}: {span.get('text', '')[:80]}...")
    print()
    
    # Step 2: Retriever
    print("2. Running RetrieverAgent...")
    try:
        RetrieverAgent().run(mem, config)
        total_candidates = sum(len(c) for c in mem.candidates.values())
        print(f"   Found {total_candidates} total candidates")
        for span_idx, candidates in list(mem.candidates.items())[:2]:
            print(f"   Span {span_idx}: {len(candidates)} candidates")
            for cand in candidates[:2]:
                print(f"     - {cand.get('external_id')}: {cand.get('name')}")
    except Exception as e:
        print(f"   ERROR in RetrieverAgent: {e}")
    print()
    
    # Step 3: Mapper
    print("3. Running MapperAgent...")
    try:
        MapperAgent().run(mem, config)
        print(f"   Created {len(mem.claims)} claims")
        for claim in mem.claims[:3]:
            print(f"   Claim: {claim.get('technique_id')} - {claim.get('technique_name')}")
    except Exception as e:
        print(f"   ERROR in MapperAgent: {e}")
    print()
    
    # Step 4: Consolidator
    print("4. Running ConsolidatorAgent...")
    try:
        ConsolidatorAgent().run(mem, config)
        print(f"   Final techniques: {len(mem.techniques)}")
        for tech_id, tech_data in list(mem.techniques.items())[:5]:
            print(f"   - {tech_id}: {tech_data.get('name')}")
    except Exception as e:
        print(f"   ERROR in ConsolidatorAgent: {e}")
    print()
    
    # Results
    print("=== Final Results ===")
    print(f"Techniques extracted: {len(mem.techniques)}")
    print(f"Claims: {len(mem.claims)}")
    
    # Check what went wrong if no techniques
    if len(mem.techniques) == 0:
        print("\n=== Debugging: Why no techniques? ===")
        print(f"1. Spans found: {len(mem.spans)}")
        print(f"2. Candidates found: {sum(len(c) for c in mem.candidates.values())}")
        print(f"3. Claims created: {len(mem.claims)}")
        
        if len(mem.spans) == 0:
            print("   -> PROBLEM: SpanFinderAgent found no spans")
        elif sum(len(c) for c in mem.candidates.values()) == 0:
            print("   -> PROBLEM: RetrieverAgent found no candidates")
        elif len(mem.claims) == 0:
            print("   -> PROBLEM: MapperAgent created no claims")
        else:
            print("   -> PROBLEM: ConsolidatorAgent didn't consolidate claims")
    
    return mem

if __name__ == "__main__":
    try:
        mem = test_extraction()
    except Exception as e:
        print(f"FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)