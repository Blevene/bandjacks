#!/usr/bin/env python
"""Test script for optimized vector search in Task 1.3."""

import sys
import time
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from bandjacks.llm.optimized_chunked_extractor import OptimizedChunkedExtractor
from bandjacks.llm.batch_retriever import BatchRetrieverAgent, _cache_hits, _cache_misses

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def test_batch_retrieval_with_caching():
    """Test that batch retrieval with caching works correctly."""
    print("\n" + "="*60)
    print("Testing Batch Retrieval with Caching")
    print("="*60)
    
    # Sample threat report text with repeated phrases
    test_text = """
    APT29, also known as Cozy Bear, is a sophisticated threat actor that has been active since 2008.
    The group uses spear phishing emails to gain initial access. APT29 employs spear phishing campaigns
    targeting government organizations. They use PowerShell scripts for execution and persistence.
    
    The threat actor leverages Windows Management Instrumentation (WMI) for lateral movement.
    APT29 uses WMI to move laterally through the network. The group also uses credential dumping
    techniques to harvest passwords. Credential dumping allows them to escalate privileges.
    
    For command and control, APT29 uses encrypted channels. The group establishes command and control
    infrastructure using compromised web servers. Data exfiltration is performed using custom tools.
    APT29 performs data exfiltration through encrypted channels to avoid detection.
    
    The group uses spear phishing as their primary initial access vector. Spear phishing emails
    often contain malicious attachments. APT29's spear phishing campaigns are highly targeted.
    """
    
    # Create extractor with optimizations enabled
    extractor = OptimizedChunkedExtractor(
        chunk_size=1000,  # Small chunks to test multiple chunks
        overlap=100,
        max_chunks=10
    )
    
    # Configuration for extraction
    config = {
        "use_batch_mapper": True,
        "use_batch_entity_extraction": True,
        "skip_vector_search": False,  # Enable vector search
        "use_embedding_cache": True,  # Enable caching
        "top_k": 5
    }
    
    print(f"Test text length: {len(test_text)} characters")
    
    # Track metrics
    start_time = time.time()
    
    # First run - populate cache
    print("\n--- First Extraction Run (Cold Cache) ---")
    result1 = extractor.extract(test_text, config)
    first_run_time = time.time() - start_time
    
    # Get cache stats after first run
    from bandjacks.llm import batch_retriever
    hits_after_first = batch_retriever._cache_hits
    misses_after_first = batch_retriever._cache_misses
    
    print(f"First run completed in {first_run_time:.2f}s")
    print(f"Techniques found: {len(result1.get('techniques', {}))}")
    print(f"Cache stats: {hits_after_first} hits, {misses_after_first} misses")
    
    # Second run - should use cache
    print("\n--- Second Extraction Run (Warm Cache) ---")
    start_time = time.time()
    result2 = extractor.extract(test_text, config)
    second_run_time = time.time() - start_time
    
    # Get cache stats after second run
    hits_after_second = batch_retriever._cache_hits
    misses_after_second = batch_retriever._cache_misses
    
    print(f"Second run completed in {second_run_time:.2f}s")
    print(f"Techniques found: {len(result2.get('techniques', {}))}")
    print(f"Cache stats: {hits_after_second} hits, {misses_after_second} misses")
    print(f"New cache hits: {hits_after_second - hits_after_first}")
    
    # Analyze optimization metadata
    if "optimization_metadata" in result1:
        meta = result1["optimization_metadata"]
        print("\n--- Optimization Metadata ---")
        print(f"Method: {meta.get('method')}")
        print(f"Total spans detected: {meta.get('total_spans_detected')}")
        print(f"Chunks processed: {meta.get('chunks_processed')}")
        print(f"Spans per chunk: {meta.get('spans_per_chunk')}")
    
    # Calculate improvements
    speedup = (first_run_time - second_run_time) / first_run_time * 100
    cache_hit_rate = hits_after_second / (hits_after_second + misses_after_second) * 100 if (hits_after_second + misses_after_second) > 0 else 0
    
    print("\n--- Performance Analysis ---")
    print(f"Speedup from caching: {speedup:.1f}%")
    print(f"Cache hit rate: {cache_hit_rate:.1f}%")
    
    # Verify results are consistent
    techniques1 = set(result1.get('techniques', {}).keys())
    techniques2 = set(result2.get('techniques', {}).keys())
    
    if techniques1 == techniques2:
        print("✅ Results are consistent between runs")
    else:
        print("❌ Results differ between runs!")
        print(f"  First run: {techniques1}")
        print(f"  Second run: {techniques2}")
    
    return result1, result2


def test_deduplication():
    """Test that span text deduplication works correctly."""
    print("\n" + "="*60)
    print("Testing Span Text Deduplication")
    print("="*60)
    
    from bandjacks.llm.batch_retriever import BatchRetrieverAgent
    
    agent = BatchRetrieverAgent()
    
    # Test with duplicate texts
    texts = [
        "APT29 uses spear phishing",
        "The group employs credential dumping",
        "APT29 uses spear phishing",  # Duplicate
        "Lateral movement through WMI",
        "The group employs credential dumping",  # Duplicate
        "Data exfiltration via custom tools"
    ]
    
    unique_texts, text_to_indices = agent._deduplicate_texts(texts)
    
    print(f"Original texts: {len(texts)}")
    print(f"Unique texts: {len(unique_texts)}")
    print(f"Deduplication ratio: {(1 - len(unique_texts)/len(texts)) * 100:.1f}%")
    
    # Verify mapping
    print("\nText to unique index mapping:")
    for i, text in enumerate(texts):
        unique_idx = text_to_indices[i]
        print(f"  [{i}] '{text[:30]}...' -> unique[{unique_idx}]")
    
    # Verify correctness
    assert len(unique_texts) == 4, f"Expected 4 unique texts, got {len(unique_texts)}"
    assert text_to_indices == [0, 1, 0, 2, 1, 3], f"Unexpected mapping: {text_to_indices}"
    
    print("\n✅ Deduplication test passed!")


def main():
    """Run all tests."""
    print("="*60)
    print("Task 1.3: Optimized Vector Search Testing")
    print("="*60)
    
    # Test deduplication
    test_deduplication()
    
    # Test batch retrieval with caching
    result1, result2 = test_batch_retrieval_with_caching()
    
    print("\n" + "="*60)
    print("All tests completed!")
    print("="*60)


if __name__ == "__main__":
    main()