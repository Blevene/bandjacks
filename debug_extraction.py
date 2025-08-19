#!/usr/bin/env python3
"""Debug script to see what LLM extraction returns."""

import sys
import json
from pathlib import Path
from bandjacks.llm.extractor import LLMExtractor

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def debug_extraction():
    """Test LLM extraction with a small sample."""
    
    # Sample text from DarkCloud report
    sample_text = """
    New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer
    
    Advanced WildFire researchers recently observed a shift in the delivery method 
    in the distribution of DarkCloud Stealer and the obfuscation techniques used to 
    complicate analysis. This chain involves obfuscation by ConfuserEx and a final 
    payload written in Visual Basic 6 (VB6).
    
    Each attack chain starts with a phishing email that contains either a tarball (TAR), 
    Roshal (RAR) or a 7-Zip (7Z) archive. Both the TAR or RAR versions contain a 
    JavaScript (JS) file, while the 7Z version contains a Windows Script File (WSF).
    """
    
    print("Debug LLM Extraction")
    print("=" * 50)
    
    extractor = LLMExtractor()
    
    result = extractor.extract_document(
        source_id="debug-test",
        source_type="md",
        inline_text=sample_text,
        chunking_params={"target_chars": 800, "overlap": 100}
    )
    
    print("Raw extraction result:")
    print(json.dumps(result, indent=2))
    
    # Check chunks
    if "chunks" in result:
        print(f"\nFound {len(result['chunks'])} chunks:")
        for i, chunk in enumerate(result["chunks"]):
            print(f"\nChunk {i}:")
            print(f"  - Chunk ID: {chunk.get('chunk_id', 'N/A')}")
            print(f"  - Claims: {len(chunk.get('claims', []))}")
            if chunk.get('claims'):
                for j, claim in enumerate(chunk['claims']):
                    print(f"    Claim {j}: {claim.get('technique', 'N/A')} - {claim.get('type', 'N/A')}")
                    if claim.get('mappings'):
                        for mapping in claim['mappings']:
                            print(f"      -> {mapping.get('external_id', 'N/A')}: {mapping.get('name', 'N/A')} (conf: {mapping.get('confidence', 0)}%)")
    else:
        print("No chunks found in result!")
    
    return result

if __name__ == "__main__":
    debug_extraction()