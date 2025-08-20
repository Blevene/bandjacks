#!/usr/bin/env python3
"""Test and compare extraction performance: original vs optimized."""

import requests
import json
import time
from typing import Dict, Any


def run_extraction(content: str, config: Dict[str, Any], description: str) -> Dict[str, Any]:
    """Run an extraction and measure performance."""
    
    payload = {
        "method": "agentic_v2",
        "content": content,
        "title": f"Performance Test - {description}",
        "config": config
    }
    
    print(f"\n{'='*60}")
    print(f"Testing: {description}")
    print(f"Config: {json.dumps(config, indent=2)}")
    print(f"{'='*60}")
    
    start_time = time.time()
    
    # Start extraction
    response = requests.post(
        "http://localhost:8000/v1/extract/runs",
        json=payload
    )
    
    if response.status_code != 200:
        print(f"Failed to start extraction: {response.status_code}")
        return None
    
    run_id = response.json().get("run_id")
    print(f"Run ID: {run_id}")
    
    # Poll for completion
    max_wait = 120
    check_interval = 1
    elapsed = 0
    
    while elapsed < max_wait:
        time.sleep(check_interval)
        elapsed += check_interval
        
        # Check status
        status_resp = requests.get(
            f"http://localhost:8000/v1/extract/runs/{run_id}/status"
        )
        
        if status_resp.status_code == 200:
            status = status_resp.json()
            state = status.get("state", "unknown")
            stage = status.get("stage", "unknown")
            
            if elapsed % 5 == 0:  # Print every 5 seconds
                print(f"  [{elapsed}s] State: {state}, Stage: {stage}")
            
            if state == "finished":
                # Get final result
                result_resp = requests.get(
                    f"http://localhost:8000/v1/extract/runs/{run_id}/result"
                )
                
                if result_resp.status_code == 200:
                    end_time = time.time()
                    total_time = end_time - start_time
                    
                    result = result_resp.json()
                    metrics = result.get("metrics", {})
                    
                    print(f"\n✓ Completed in {total_time:.2f} seconds")
                    print(f"  Spans processed: {metrics.get('spans_processed', 0)}")
                    print(f"  Techniques found: {metrics.get('counters', {}).get('techniques', 0)}")
                    print(f"  LLM calls: {metrics.get('counters', {}).get('llm_calls', 0)}")
                    
                    # Show techniques found
                    techniques = result.get("techniques", {})
                    if techniques:
                        print(f"\n  Techniques extracted:")
                        for tech_id, tech_data in techniques.items():
                            print(f"    - {tech_id}: {tech_data.get('name')} (confidence: {tech_data.get('confidence')}%)")
                    
                    return {
                        "time": total_time,
                        "metrics": metrics,
                        "techniques_count": len(techniques),
                        "success": True
                    }
                break
    
    return {
        "time": elapsed,
        "success": False,
        "error": "Timeout"
    }


def main():
    """Run performance comparison tests."""
    
    # Test content - simple but meaningful
    test_content = """
    The attackers used PowerShell scripts for execution.
    They established persistence through registry modifications.
    Lateral movement was achieved via RDP connections.
    Data was exfiltrated to cloud storage services.
    The ransomware encrypted files using AES-256.
    """
    
    results = []
    
    # Test 1: Original pipeline (unoptimized)
    print("\n" + "="*60)
    print("TEST 1: ORIGINAL PIPELINE (UNOPTIMIZED)")
    print("="*60)
    
    config_original = {
        "use_optimized": False,  # Use original pipeline
        "top_k": 8,
        "disable_discovery": False,
        "max_discovery_per_span": 10,
        "min_quotes": 2
    }
    
    result1 = run_extraction(test_content, config_original, "Original Pipeline")
    if result1:
        results.append(("Original", result1))
    
    # Test 2: Partially optimized
    print("\n" + "="*60)
    print("TEST 2: PARTIALLY OPTIMIZED")
    print("="*60)
    
    config_partial = {
        "use_optimized": True,
        "use_batch_mapper": False,  # Still using sequential mapper
        "disable_discovery": True,
        "disable_targeted_extraction": False,
        "top_k": 5,
        "max_spans": 10,
        "span_score_threshold": 0.7,
        "min_quotes": 1
    }
    
    result2 = run_extraction(test_content, config_partial, "Partial Optimization")
    if result2:
        results.append(("Partial", result2))
    
    # Test 3: Fully optimized
    print("\n" + "="*60)
    print("TEST 3: FULLY OPTIMIZED")
    print("="*60)
    
    config_optimized = {
        "use_optimized": True,
        "use_batch_mapper": True,  # Batch all spans
        "disable_discovery": True,
        "disable_targeted_extraction": True,
        "top_k": 3,
        "max_spans": 5,
        "span_score_threshold": 0.8,
        "max_tool_iterations": 2,
        "min_quotes": 1
    }
    
    result3 = run_extraction(test_content, config_optimized, "Fully Optimized")
    if result3:
        results.append(("Optimized", result3))
    
    # Test 4: Ultra-fast mode
    print("\n" + "="*60)
    print("TEST 4: ULTRA-FAST MODE")
    print("="*60)
    
    config_ultrafast = {
        "use_optimized": True,
        "use_batch_mapper": True,
        "disable_discovery": True,
        "disable_targeted_extraction": True,
        "skip_verification": True,  # Skip evidence verification
        "top_k": 2,
        "max_spans": 3,
        "span_score_threshold": 0.85,
        "max_tool_iterations": 1,
        "min_quotes": 1
    }
    
    result4 = run_extraction(test_content, config_ultrafast, "Ultra-Fast Mode")
    if result4:
        results.append(("Ultra-Fast", result4))
    
    # Print comparison summary
    print("\n" + "="*60)
    print("PERFORMANCE COMPARISON SUMMARY")
    print("="*60)
    
    if results:
        baseline_time = results[0][1]["time"] if results else 0
        
        print(f"\n{'Mode':<15} {'Time (s)':<12} {'Speedup':<12} {'Techniques':<12} {'Status'}")
        print("-" * 60)
        
        for mode, result in results:
            speedup = baseline_time / result["time"] if result["time"] > 0 else 0
            status = "✓" if result["success"] else "✗"
            print(f"{mode:<15} {result['time']:<12.2f} {speedup:<12.2f}x {result.get('techniques_count', 0):<12} {status}")
        
        # Calculate improvements
        if len(results) > 1:
            original_time = results[0][1]["time"]
            optimized_time = results[-1][1]["time"]
            improvement = ((original_time - optimized_time) / original_time) * 100
            
            print(f"\n🚀 Performance Improvement: {improvement:.1f}% faster")
            print(f"   Original: {original_time:.2f}s → Optimized: {optimized_time:.2f}s")
    
    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60)


if __name__ == "__main__":
    main()