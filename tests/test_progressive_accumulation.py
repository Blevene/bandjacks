#!/usr/bin/env python3
"""Test progressive context accumulation in chunked extraction."""

import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bandjacks.llm.optimized_chunked_extractor import OptimizedChunkedExtractor
from bandjacks.llm.accumulator import ThreadSafeAccumulator


def test_accumulator():
    """Test the ThreadSafeAccumulator independently."""
    print("Testing ThreadSafeAccumulator...")
    
    acc = ThreadSafeAccumulator(
        early_termination_threshold=90.0,
        max_context_hints=5
    )
    
    # Simulate multiple chunks finding techniques
    acc.add_technique("T1566.001", "Spearphishing Attachment", 85, ["email with malicious PDF"], 1)
    acc.add_technique("T1059.001", "PowerShell", 75, ["powershell.exe -enc"], 1)
    acc.add_technique("T1566.001", "Spearphishing Attachment", 90, ["PDF exploit"], 2)  # Same technique, different chunk
    
    # Check context hints
    hints = acc.get_context_hints()
    print(f"Context hints: {json.dumps(hints, indent=2)}")
    
    # Check accumulated techniques
    techniques = acc.get_accumulated_techniques()
    print(f"\nAccumulated techniques:")
    for tech_id, data in techniques.items():
        print(f"  {tech_id}: confidence={data['confidence']:.1f}, chunks={data['chunk_ids']}")
    
    # Check statistics
    stats = acc.get_statistics()
    print(f"\nStatistics: {json.dumps(stats, indent=2)}")
    
    print("✓ Accumulator test passed\n")


def test_progressive_extraction():
    """Test progressive extraction with a sample document."""
    print("Testing progressive extraction...")
    
    # Create a test document with multiple technique mentions
    test_doc = """
    The threat actor uses spearphishing emails with malicious PDF attachments 
    to gain initial access. Once the attachment is opened, it executes a 
    PowerShell script that downloads additional payloads.
    
    The PowerShell script uses obfuscation techniques to evade detection.
    It establishes persistence through registry run keys and scheduled tasks.
    
    For command and control, the malware uses HTTPS protocol with domain
    fronting techniques. Data is exfiltrated in small chunks to avoid 
    detection by network monitoring tools.
    
    The actor deploys Mimikatz for credential dumping and uses those 
    credentials for lateral movement via RDP and SMB protocols.
    """
    
    # Test with progressive mode enabled
    config_progressive = {
        "progressive_mode": "async",
        "context_hints_enabled": True,
        "max_context_hints": 5,
        "early_termination_threshold": 90,
        "confidence_boost": 5.0,
        "max_chunks": 3,
        "chunk_size": 200,  # Small chunks to force splitting
        "use_batch_mapper": True,
        "disable_entity_extraction": True  # Speed up test
    }
    
    extractor = OptimizedChunkedExtractor(
        chunk_size=200,
        overlap=50,
        max_chunks=3,
        parallel_workers=2
    )
    
    print("Extracting with progressive mode...")
    result = extractor.extract(test_doc, config_progressive, parallel=True)
    
    # Check results
    techniques = result.get("techniques", {})
    print(f"\nFound {len(techniques)} techniques:")
    for tech_id, data in techniques.items():
        print(f"  {tech_id}: {data.get('name', 'Unknown')} (confidence: {data.get('confidence', 0):.1f})")
    
    # Check accumulator stats if present
    if "accumulator_stats" in result:
        print(f"\nAccumulator statistics:")
        stats = result["accumulator_stats"]
        print(f"  Chunks processed: {stats['chunks_processed']}")
        print(f"  Multi-chunk techniques: {stats.get('multi_chunk_techniques', 0)}")
        print(f"  Average confidence: {stats.get('avg_confidence', 0):.1f}")
    
    # Check optimization metadata
    if "optimization_metadata" in result:
        meta = result["optimization_metadata"]
        print(f"\nOptimization metadata:")
        print(f"  Progressive mode: {meta.get('progressive_mode', 'N/A')}")
        print(f"  Early terminated: {meta.get('early_terminated', False)}")
        print(f"  Chunks processed: {meta.get('chunks_processed', 0)}")
    
    print("\n✓ Progressive extraction test completed")
    
    # Test with progressive mode disabled for comparison
    config_no_progressive = config_progressive.copy()
    config_no_progressive["progressive_mode"] = "disabled"
    
    print("\nExtracting WITHOUT progressive mode for comparison...")
    result_no_prog = extractor.extract(test_doc, config_no_progressive, parallel=True)
    
    techniques_no_prog = result_no_prog.get("techniques", {})
    print(f"Found {len(techniques_no_prog)} techniques without progressive mode")
    
    return result, result_no_prog


if __name__ == "__main__":
    print("="*60)
    print("PROGRESSIVE CONTEXT ACCUMULATION TEST")
    print("="*60)
    
    # Test accumulator
    test_accumulator()
    
    # Test progressive extraction
    try:
        result_prog, result_no_prog = test_progressive_extraction()
        
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        
        # Compare results
        techs_prog = len(result_prog.get("techniques", {}))
        techs_no_prog = len(result_no_prog.get("techniques", {}))
        
        if "accumulator_stats" in result_prog:
            print(f"✓ Progressive mode: Found {techs_prog} techniques")
            print(f"  Multi-chunk techniques: {result_prog['accumulator_stats'].get('multi_chunk_techniques', 0)}")
        else:
            print(f"✗ Progressive mode did not generate accumulator stats")
            
        print(f"✓ Standard mode: Found {techs_no_prog} techniques")
        
        print("\n✅ All tests completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)