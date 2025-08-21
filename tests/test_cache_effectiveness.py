#!/usr/bin/env python3
"""Test cache effectiveness by running the same extraction twice."""

import requests
import json
import time


def run_extraction(content: str, run_name: str) -> float:
    """Run extraction and return time taken."""
    
    config = {
        "use_async": True,
        "cache_llm_responses": True,
        "single_pass_threshold": 500
    }
    
    payload = {
        "method": "agentic_v2",
        "content": content,
        "title": run_name,
        "config": config
    }
    
    start_time = time.time()
    
    response = requests.post(
        "http://localhost:8000/v1/extract/runs",
        json=payload
    )
    
    if response.status_code != 200:
        print(f"Failed to start: {response.status_code}")
        return 0
    
    run_id = response.json().get("run_id")
    
    # Poll for completion
    for i in range(60):
        time.sleep(0.5)
        
        status_resp = requests.get(
            f"http://localhost:8000/v1/extract/runs/{run_id}/status"
        )
        
        if status_resp.status_code == 200:
            status = status_resp.json()
            
            if status.get("state") == "finished":
                end_time = time.time()
                return end_time - start_time
    
    return 0


def main():
    """Test cache effectiveness."""
    
    test_content = """
    The attackers used PowerShell for initial execution and established
    persistence through registry modifications. They performed lateral
    movement using RDP connections to critical infrastructure.
    """
    
    print("CACHE EFFECTIVENESS TEST")
    print("=" * 50)
    
    # Clear cache first
    print("\nClearing cache...")
    requests.post("http://localhost:8000/v1/cache/clear")
    
    # First run (cold cache)
    print("\nRun 1 (cold cache)...")
    time1 = run_extraction(test_content, "Cache Test Run 1")
    print(f"  Time: {time1:.2f} seconds")
    
    # Check cache stats
    stats = requests.get("http://localhost:8000/v1/cache/stats").json()
    print(f"  Cache stats: {stats['size']} entries, {stats['hit_rate']} hit rate")
    
    # Second run (warm cache)
    print("\nRun 2 (warm cache)...")
    time2 = run_extraction(test_content, "Cache Test Run 2")
    print(f"  Time: {time2:.2f} seconds")
    
    # Check cache stats again
    stats = requests.get("http://localhost:8000/v1/cache/stats").json()
    print(f"  Cache stats: {stats['size']} entries, {stats['hit_rate']} hit rate")
    
    # Third run (should be even more cached)
    print("\nRun 3 (fully cached)...")
    time3 = run_extraction(test_content, "Cache Test Run 3")
    print(f"  Time: {time3:.2f} seconds")
    
    # Final cache stats
    stats = requests.get("http://localhost:8000/v1/cache/stats").json()
    print(f"  Cache stats: {stats['size']} entries, {stats['hit_rate']} hit rate")
    
    # Summary
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    
    if time1 > 0 and time2 > 0:
        speedup = (time1 - time2) / time1 * 100
        print(f"Run 2 was {speedup:.1f}% faster than Run 1")
    
    if time1 > 0 and time3 > 0:
        speedup = (time1 - time3) / time1 * 100
        print(f"Run 3 was {speedup:.1f}% faster than Run 1")
    
    print(f"\nFinal cache statistics:")
    print(f"  Hits: {stats['hits']}")
    print(f"  Misses: {stats['misses']}")
    print(f"  Hit rate: {stats['hit_rate']}")
    print(f"  Cache size: {stats['size']} entries")


if __name__ == "__main__":
    main()