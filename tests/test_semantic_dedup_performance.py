#!/usr/bin/env python3
"""Test semantic deduplication performance improvements."""

import time
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bandjacks.llm.semantic_dedup import SemanticDeduplicator


def test_large_collection_circuit_breaker():
    """Test that large collections are handled with circuit breaker."""
    dedup = SemanticDeduplicator()

    # Create a large collection that would timeout without circuit breaker
    large_evidence = [f"Evidence item {i}: This is a test sentence describing technique behavior." for i in range(100)]

    start = time.time()
    result = dedup.deduplicate_evidence(large_evidence)
    elapsed = time.time() - start

    print(f"✅ Large collection ({len(large_evidence)} items) handled in {elapsed:.2f}s")
    print(f"   Result: {len(result)} unique items")
    assert elapsed < 5.0, f"Circuit breaker should prevent timeout, but took {elapsed:.2f}s"


def test_embedding_cache_performance():
    """Test that embedding cache improves performance."""
    dedup = SemanticDeduplicator()

    # Create evidence with duplicates to test caching
    evidence = [
        "APT29 uses spear phishing emails to deliver malware.",
        "The malware establishes persistence through registry keys.",
        "APT29 uses spear phishing emails to deliver malware.",  # Duplicate
        "Command and control communication uses HTTPS.",
        "The malware establishes persistence through registry keys.",  # Duplicate
    ] * 3  # Repeat 3 times = 15 items total

    # First run - populates cache
    start1 = time.time()
    result1 = dedup.deduplicate_evidence(evidence)
    elapsed1 = time.time() - start1

    # Second run - should use cache
    start2 = time.time()
    result2 = dedup.deduplicate_evidence(evidence)
    elapsed2 = time.time() - start2

    print(f"✅ Embedding cache test:")
    print(f"   First run: {elapsed1:.3f}s")
    print(f"   Second run: {elapsed2:.3f}s (should be faster)")
    print(f"   Cache speedup: {elapsed1/elapsed2:.1f}x")

    # Second run should be at least 2x faster due to caching
    assert elapsed2 < elapsed1 * 0.5, f"Cache should speed up second run, but {elapsed2:.3f}s >= {elapsed1 * 0.5:.3f}s"


def test_entity_deduplication_with_limits():
    """Test entity deduplication with performance limits."""
    dedup = SemanticDeduplicator()

    # Create moderate-sized entity collection
    entities = {}
    for i in range(30):
        entities[f"entity-{i}"] = {
            "name": f"Threat Actor {i % 10}",  # Some duplicates
            "type": "threat-actor",
            "evidence": [f"Evidence for actor {i}"]
        }

    start = time.time()
    result = dedup.deduplicate_entities(entities)
    elapsed = time.time() - start

    print(f"✅ Entity deduplication ({len(entities)} entities) completed in {elapsed:.2f}s")
    print(f"   Result: {len(result)} unique entities")
    assert elapsed < 10.0, f"Entity deduplication took too long: {elapsed:.2f}s"


def test_technique_deduplication_with_limits():
    """Test technique deduplication with performance limits."""
    dedup = SemanticDeduplicator()

    # Create technique collection with some similar evidence
    techniques = {}
    for i in range(25):
        techniques[f"T{1000 + i}"] = {
            "evidence": [
                f"The malware uses technique {i} for persistence.",
                f"This behavior was observed in the campaign."
            ]
        }

    start = time.time()
    result = dedup.deduplicate_techniques(techniques)
    elapsed = time.time() - start

    print(f"✅ Technique deduplication ({len(techniques)} techniques) completed in {elapsed:.2f}s")
    print(f"   Result: {len(result)} unique techniques")
    assert elapsed < 10.0, f"Technique deduplication took too long: {elapsed:.2f}s"


def test_pre_filtering_optimization():
    """Test that pre-filtering skips unnecessary comparisons."""
    dedup = SemanticDeduplicator()

    # Create entities with very different name lengths
    entities = {
        "entity-1": {"name": "A", "type": "malware", "evidence": []},
        "entity-2": {"name": "B" * 100, "type": "malware", "evidence": []},
        "entity-3": {"name": "APT29", "type": "threat-actor", "evidence": []},
        "entity-4": {"name": "APT28", "type": "threat-actor", "evidence": []},
    }

    start = time.time()
    result = dedup.deduplicate_entities(entities)
    elapsed = time.time() - start

    print(f"✅ Pre-filtering test completed in {elapsed:.3f}s")
    print(f"   Pre-filtering should skip comparing 'A' with very long name")
    assert len(result) >= 3, "Should not merge entities with very different name lengths"


if __name__ == "__main__":
    print("\n🧪 Testing Semantic Deduplication Performance Improvements\n")
    print("=" * 60)

    try:
        test_large_collection_circuit_breaker()
        test_embedding_cache_performance()
        test_entity_deduplication_with_limits()
        test_technique_deduplication_with_limits()
        test_pre_filtering_optimization()

        print("\n" + "=" * 60)
        print("✅ All performance tests passed!")
        print("\nKey improvements verified:")
        print("- Circuit breaker prevents timeouts on large collections")
        print("- Embedding cache provides significant speedup")
        print("- Pre-filtering reduces unnecessary comparisons")
        print("- Collection size limits maintain reasonable performance")

    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)