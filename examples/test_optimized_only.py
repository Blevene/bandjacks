#!/usr/bin/env python3
"""Test only the optimized extraction to verify improvements."""

import requests
import json
import time


def main():
    """Test optimized extraction."""
    
    test_content = """
    The attackers used PowerShell scripts for execution.
    They established persistence through registry modifications.
    Lateral movement was achieved via RDP connections.
    """
    
    # Fully optimized config
    config = {
        "use_optimized": True,
        "use_batch_mapper": True,
        "disable_discovery": True,
        "disable_targeted_extraction": True,
        "skip_verification": False,
        "top_k": 3,
        "max_spans": 5,
        "span_score_threshold": 0.8,
        "max_tool_iterations": 2,
        "min_quotes": 1
    }
    
    payload = {
        "method": "agentic_v2",
        "content": test_content,
        "title": "Optimized Test",
        "config": config
    }
    
    print("Testing optimized extraction...")
    print(f"Config: {json.dumps(config, indent=2)}\n")
    
    start_time = time.time()
    
    # Start extraction
    response = requests.post(
        "http://localhost:8000/v1/extract/runs",
        json=payload
    )
    
    if response.status_code != 200:
        print(f"Failed to start: {response.status_code}")
        return
    
    run_id = response.json().get("run_id")
    print(f"Run ID: {run_id}")
    
    # Poll for completion
    for i in range(60):
        time.sleep(1)
        
        status_resp = requests.get(
            f"http://localhost:8000/v1/extract/runs/{run_id}/status"
        )
        
        if status_resp.status_code == 200:
            status = status_resp.json()
            
            if i % 2 == 0:
                print(f"  [{i+1}s] State: {status.get('state')}, Stage: {status.get('stage')}")
            
            if status.get("state") == "finished":
                result_resp = requests.get(
                    f"http://localhost:8000/v1/extract/runs/{run_id}/result"
                )
                
                if result_resp.status_code == 200:
                    end_time = time.time()
                    result = result_resp.json()
                    
                    print(f"\n✓ Completed in {end_time - start_time:.2f} seconds")
                    
                    metrics = result.get("metrics", {})
                    print(f"  Spans: {metrics.get('spans_processed', 0)}")
                    print(f"  Techniques: {metrics.get('counters', {}).get('techniques', 0)}")
                    
                    techniques = result.get("techniques", {})
                    if techniques:
                        print("\nTechniques found:")
                        for tech_id, tech in techniques.items():
                            print(f"  - {tech_id}: {tech.get('name')}")
                    
                    return
    
    print("Timeout after 60 seconds")


if __name__ == "__main__":
    main()