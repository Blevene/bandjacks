#!/usr/bin/env python3
"""Compare performance of original, optimized, and async extraction pipelines."""

import requests
import json
import time
from typing import Dict, Any, Tuple


def run_extraction(config: Dict[str, Any], test_content: str) -> Tuple[float, Dict[str, Any]]:
    """Run extraction with given config and return time and result."""
    
    payload = {
        "method": "agentic_v2",
        "content": test_content,
        "title": "Pipeline Comparison Test",
        "config": config
    }
    
    start_time = time.time()
    
    # Start extraction
    response = requests.post(
        "http://localhost:8000/v1/extract/runs",
        json=payload
    )
    
    if response.status_code != 200:
        print(f"Failed to start: {response.status_code}")
        return 0, {}
    
    run_id = response.json().get("run_id")
    
    # Poll for completion
    for i in range(120):  # 2 minutes max
        time.sleep(0.5)
        
        status_resp = requests.get(
            f"http://localhost:8000/v1/extract/runs/{run_id}/status"
        )
        
        if status_resp.status_code == 200:
            status = status_resp.json()
            
            if status.get("state") == "finished":
                result_resp = requests.get(
                    f"http://localhost:8000/v1/extract/runs/{run_id}/result"
                )
                
                if result_resp.status_code == 200:
                    end_time = time.time()
                    result = result_resp.json()
                    return end_time - start_time, result
    
    return 0, {"error": "Timeout"}


def main():
    """Compare all three pipelines."""
    
    # Test content - moderate complexity
    test_content = """
    The threat actor deployed a sophisticated attack chain beginning with spear-phishing emails
    containing malicious Excel documents. When opened, these documents executed PowerShell scripts
    that established persistence through Windows registry modifications and scheduled tasks.
    
    The attackers then performed extensive reconnaissance, scanning the internal network for
    vulnerable systems. They used Mimikatz to harvest credentials from memory and employed
    Pass-the-Hash techniques for lateral movement across the domain.
    
    Remote desktop protocol (RDP) connections were established to critical servers, where the
    attackers deployed custom backdoors for long-term access. Data was staged in encrypted
    archives before being exfiltrated through legitimate cloud storage services to avoid detection.
    
    The campaign showed clear signs of advanced planning, with attackers maintaining operational
    security by using Tor for command and control communications and regularly rotating their
    infrastructure.
    """
    
    print("=" * 80)
    print("EXTRACTION PIPELINE PERFORMANCE COMPARISON")
    print("=" * 80)
    print(f"\nTest content: {len(test_content)} characters, {len(test_content.split())} words\n")
    
    # Configuration for each pipeline
    configs = [
        {
            "name": "Original Pipeline",
            "config": {
                "use_async": False,
                "use_optimized": False,
                "top_k": 8
            }
        },
        {
            "name": "Optimized Pipeline",
            "config": {
                "use_async": False,
                "use_optimized": True,
                "use_batch_mapper": True,
                "disable_targeted_extraction": True,
                "max_spans": 10,
                "span_score_threshold": 0.8,
                "top_k": 5
            }
        },
        {
            "name": "Async Pipeline",
            "config": {
                "use_async": True,
                "use_async_retriever": True,
                "single_pass_threshold": 500,
                "early_termination_confidence": 90,
                "cache_llm_responses": True,
                "top_k": 5
            }
        }
    ]
    
    results = []
    
    for pipeline in configs:
        print(f"\n{'=' * 40}")
        print(f"Testing: {pipeline['name']}")
        print(f"{'=' * 40}")
        
        elapsed_time, result = run_extraction(pipeline['config'], test_content)
        
        if elapsed_time > 0:
            metrics = result.get("metrics", {})
            techniques = result.get("techniques", {})
            
            print(f"✓ Completed in {elapsed_time:.2f} seconds")
            print(f"  Spans processed: {metrics.get('spans_processed', 'N/A')}")
            print(f"  Techniques found: {metrics.get('counters', {}).get('techniques', 0)}")
            
            # Show stage timings if available
            stage_timings = metrics.get("stage_timings", {})
            if stage_timings:
                print("\n  Stage timings:")
                for stage, timing in stage_timings.items():
                    if timing > 0:
                        print(f"    {stage}: {timing:.2f}s")
            
            results.append({
                "pipeline": pipeline['name'],
                "time": elapsed_time,
                "techniques": len(techniques),
                "spans": metrics.get('spans_processed', 0)
            })
            
            if techniques:
                print(f"\n  Techniques extracted:")
                for tech_id, tech in list(techniques.items())[:5]:  # Show first 5
                    print(f"    - {tech_id}: {tech.get('name', 'Unknown')}")
                if len(techniques) > 5:
                    print(f"    ... and {len(techniques) - 5} more")
        else:
            print("✗ Failed to complete")
            results.append({
                "pipeline": pipeline['name'],
                "time": 0,
                "techniques": 0,
                "spans": 0
            })
    
    # Summary comparison
    print(f"\n{'=' * 80}")
    print("SUMMARY COMPARISON")
    print(f"{'=' * 80}\n")
    
    if len(results) > 1 and results[0]["time"] > 0:
        baseline_time = results[0]["time"]
        
        print(f"{'Pipeline':<25} {'Time (s)':<12} {'Speedup':<12} {'Techniques':<12} {'Spans'}")
        print("-" * 80)
        
        for r in results:
            if r["time"] > 0:
                speedup = baseline_time / r["time"]
                print(f"{r['pipeline']:<25} {r['time']:<12.2f} {speedup:<12.2f}x {r['techniques']:<12} {r['spans']}")
            else:
                print(f"{r['pipeline']:<25} {'Failed':<12} {'-':<12} {r['techniques']:<12} {r['spans']}")
        
        # Calculate improvements
        if len(results) >= 3:
            orig = results[0]
            opt = results[1]
            async_res = results[2]
            
            if opt["time"] > 0 and orig["time"] > 0:
                opt_improvement = ((orig["time"] - opt["time"]) / orig["time"]) * 100
                print(f"\nOptimized pipeline: {opt_improvement:.1f}% faster than original")
            
            if async_res["time"] > 0 and orig["time"] > 0:
                async_improvement = ((orig["time"] - async_res["time"]) / orig["time"]) * 100
                print(f"Async pipeline: {async_improvement:.1f}% faster than original")
            
            if async_res["time"] > 0 and opt["time"] > 0:
                async_vs_opt = ((opt["time"] - async_res["time"]) / opt["time"]) * 100
                print(f"Async pipeline: {async_vs_opt:.1f}% faster than optimized")


if __name__ == "__main__":
    main()