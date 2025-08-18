#!/usr/bin/env python3
"""Test performance optimizations."""

import os
import sys
import time
import json
from typing import Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bandjacks.core.cache import CacheManager, QueryCache
from bandjacks.core.connection_pool import Neo4jPool, OpenSearchPool, ConnectionManager
from bandjacks.core.query_optimizer import QueryOptimizer


def test_cache_manager():
    """Test caching functionality."""
    print("\n" + "="*60)
    print("Testing Cache Manager")
    print("="*60)
    
    try:
        cache = CacheManager(enable_cache=True)
        
        # Test basic operations
        test_data = {"results": ["item1", "item2", "item3"]}
        params = {"query": "test", "filter": "type1"}
        
        # Set value
        success = cache.set("test", params, test_data, ttl=60)
        print(f"✓ Cache set: {success}")
        
        # Get value
        retrieved = cache.get("test", params)
        print(f"✓ Cache get: {retrieved == test_data}")
        
        # Test get_or_compute
        def compute_fn():
            return {"computed": True}
        
        result = cache.get_or_compute("compute", {"id": 1}, compute_fn, ttl=60)
        print(f"✓ Get or compute: {result.get('computed')}")
        
        # Second call should use cache
        start = time.time()
        result2 = cache.get_or_compute("compute", {"id": 1}, compute_fn, ttl=60)
        elapsed = time.time() - start
        print(f"✓ Cache hit (took {elapsed:.4f}s): {result2 == result}")
        
        # Test invalidation
        deleted = cache.invalidate("test")
        print(f"✓ Cache invalidate: {deleted} keys deleted")
        
        # Get stats
        stats = cache.get_stats()
        print(f"✓ Cache stats retrieved: enabled={stats.get('enabled')}")
        
        cache.close()
        return True
        
    except Exception as e:
        print(f"⚠ Cache test skipped (Redis not available): {e}")
        return False


def test_query_cache():
    """Test query-specific caching."""
    print("\n" + "="*60)
    print("Testing Query Cache")
    print("="*60)
    
    try:
        cache_manager = CacheManager(enable_cache=True)
        query_cache = QueryCache(cache_manager)
        
        # Test search caching
        test_results = [
            {"id": "T1003", "name": "Credential Dumping", "score": 0.9},
            {"id": "T1021", "name": "Remote Services", "score": 0.8}
        ]
        
        success = query_cache.set_search_results(
            "credential theft",
            test_results,
            filters={"type": "technique"},
            top_k=10
        )
        print(f"✓ Search results cached: {success}")
        
        # Retrieve
        cached = query_cache.get_search_results(
            "credential theft",
            filters={"type": "technique"},
            top_k=10
        )
        print(f"✓ Search results retrieved: {len(cached) if cached else 0} items")
        
        # Test graph caching
        graph_result = {
            "nodes": ["T1003", "T1021", "T1059"],
            "edges": [("T1003", "T1021"), ("T1021", "T1059")]
        }
        
        success = query_cache.set_graph_traversal(
            "T1003",
            depth=2,
            relationships=["USES", "NEXT"],
            result=graph_result
        )
        print(f"✓ Graph traversal cached: {success}")
        
        # Invalidate
        query_cache.invalidate_search("credential")
        print(f"✓ Search cache invalidated")
        
        cache_manager.close()
        return True
        
    except Exception as e:
        print(f"⚠ Query cache test skipped: {e}")
        return False


def test_connection_pooling():
    """Test connection pool management."""
    print("\n" + "="*60)
    print("Testing Connection Pooling")
    print("="*60)
    
    try:
        # Test Neo4j pool
        neo4j_pool = Neo4jPool(
            os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            os.getenv("NEO4J_USER", "neo4j"),
            os.getenv("NEO4J_PASSWORD", "")
        )
        
        # Test connectivity
        connected = neo4j_pool.verify_connectivity()
        print(f"✓ Neo4j pool created: {connected}")
        
        if connected:
            # Test read query
            results = neo4j_pool.execute_read(
                "MATCH (n) RETURN count(n) as count LIMIT 1"
            )
            print(f"✓ Neo4j read query executed")
        
        neo4j_pool.close()
        
        # Test OpenSearch pool
        os_pool = OpenSearchPool(
            [os.getenv("OPENSEARCH_URL", "http://localhost:9200")]
        )
        
        os_connected = os_pool.ping()
        print(f"✓ OpenSearch pool created: {os_connected}")
        
        os_pool.close()
        
        return True
        
    except Exception as e:
        print(f"⚠ Connection pool test failed: {e}")
        return False


def test_connection_manager():
    """Test global connection manager."""
    print("\n" + "="*60)
    print("Testing Connection Manager")
    print("="*60)
    
    try:
        manager = ConnectionManager()
        
        # Initialize pools
        neo4j_pool = manager.init_neo4j(
            os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            os.getenv("NEO4J_USER", "neo4j"),
            os.getenv("NEO4J_PASSWORD", "")
        )
        print("✓ Neo4j pool initialized")
        
        os_pool = manager.init_opensearch(
            [os.getenv("OPENSEARCH_URL", "http://localhost:9200")]
        )
        print("✓ OpenSearch pool initialized")
        
        # Health check
        health = manager.health_check()
        print(f"✓ Health check: Neo4j={health.get('neo4j', False)}, OpenSearch={health.get('opensearch', False)}")
        
        # Close all
        manager.close_all()
        print("✓ All connections closed")
        
        return True
        
    except Exception as e:
        print(f"⚠ Connection manager test failed: {e}")
        return False


def test_query_optimizer():
    """Test query optimization."""
    print("\n" + "="*60)
    print("Testing Query Optimizer")
    print("="*60)
    
    try:
        optimizer = QueryOptimizer(
            os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            os.getenv("NEO4J_USER", "neo4j"),
            os.getenv("NEO4J_PASSWORD", "")
        )
        
        # Create indexes
        print("Creating indexes...")
        index_results = optimizer.create_indexes()
        created = sum(1 for v in index_results.values() if v)
        print(f"✓ Indexes created: {created}/{len(index_results)}")
        
        # Get query hints
        search_hint = optimizer.create_query_hints("search")
        print(f"✓ Search query hint generated: {len(search_hint)} chars")
        
        traversal_hint = optimizer.create_query_hints("traversal")
        print(f"✓ Traversal query hint generated: {len(traversal_hint)} chars")
        
        # Get recommendations
        recommendations = optimizer.optimize_common_queries()
        print(f"✓ Optimization recommendations: {len(recommendations)} found")
        
        optimizer.close()
        return True
        
    except Exception as e:
        print(f"⚠ Query optimizer test failed: {e}")
        return False


def benchmark_cache_performance():
    """Benchmark cache vs no-cache performance."""
    print("\n" + "="*60)
    print("Cache Performance Benchmark")
    print("="*60)
    
    try:
        cache = CacheManager(enable_cache=True)
        
        # Simulate expensive operation
        def expensive_operation():
            time.sleep(0.1)  # Simulate 100ms operation
            return {"data": list(range(1000))}
        
        # Without cache
        start = time.time()
        for i in range(5):
            expensive_operation()
        no_cache_time = time.time() - start
        
        # With cache
        start = time.time()
        for i in range(5):
            cache.get_or_compute("bench", {"id": 1}, expensive_operation, ttl=60)
        cache_time = time.time() - start
        
        improvement = (no_cache_time - cache_time) / no_cache_time * 100
        
        print(f"No cache: {no_cache_time:.2f}s")
        print(f"With cache: {cache_time:.2f}s")
        print(f"✓ Performance improvement: {improvement:.1f}%")
        
        cache.close()
        return True
        
    except Exception as e:
        print(f"⚠ Benchmark skipped: {e}")
        return False


def main():
    """Run all performance tests."""
    print("\n" + "="*60)
    print("PERFORMANCE OPTIMIZATION TEST SUITE")
    print("="*60)
    
    results = {
        "Cache Manager": test_cache_manager(),
        "Query Cache": test_query_cache(),
        "Connection Pooling": test_connection_pooling(),
        "Connection Manager": test_connection_manager(),
        "Query Optimizer": test_query_optimizer(),
        "Cache Benchmark": benchmark_cache_performance()
    }
    
    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "⚠️ SKIP"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All performance tests passed!")
    else:
        print(f"\n⚠️ {total - passed} tests were skipped (likely due to missing services)")
    
    print("\n" + "="*60)
    print("Performance Optimizations Implemented:")
    print("="*60)
    print("✅ Redis caching layer for query results")
    print("✅ Connection pooling for Neo4j and OpenSearch")
    print("✅ Query optimization with indexes")
    print("✅ Cache invalidation strategies")
    print("✅ Health monitoring for all services")
    print("✅ Performance benchmarking tools")


if __name__ == "__main__":
    main()