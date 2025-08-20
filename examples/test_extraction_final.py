#!/usr/bin/env python3
"""Test the extraction pipeline end-to-end."""

import requests
import json
import time

def test_extraction():
    """Test extraction with simple content."""
    
    # Simple test content with obvious techniques
    test_content = """
    The attackers used PowerShell scripts for execution.
    They established persistence through registry modifications.
    Lateral movement was achieved via RDP connections.
    """
    
    # Create payload for extraction
    payload = {
        "method": "agentic_v2",
        "content": test_content,
        "title": "Simple Test",
        "config": {
            "top_k": 3,
            "disable_discovery": True,  # Speed up extraction
            "max_discovery_per_span": 0,
            "min_quotes": 1
        }
    }
    
    print("Starting extraction...")
    
    # Send request to start extraction
    try:
        response = requests.post(
            "http://localhost:8000/v1/extract/runs",
            json=payload
        )
        
        if response.status_code != 200:
            print(f"Failed to start extraction: {response.status_code}")
            print(response.text)
            return
            
        result = response.json()
        run_id = result.get("run_id")
        print(f"✓ Extraction started with run_id: {run_id}")
        
        # Poll for completion
        max_wait = 60  # Wait up to 60 seconds
        check_interval = 2
        elapsed = 0
        
        while elapsed < max_wait:
            time.sleep(check_interval)
            elapsed += check_interval
            
            # Check status
            status_resp = requests.get(
                f"http://localhost:8000/v1/extract/runs/{run_id}/status"
            )
            
            if status_resp.status_code != 200:
                print(f"Failed to get status: {status_resp.status_code}")
                continue
                
            status = status_resp.json()
            state = status.get("state", "unknown")
            stage = status.get("stage", "unknown")
            
            print(f"  [{elapsed}s] State: {state}, Stage: {stage}")
            
            if state == "finished":
                # Get final result
                result_resp = requests.get(
                    f"http://localhost:8000/v1/extract/runs/{run_id}/result"
                )
                
                if result_resp.status_code == 200:
                    final_result = result_resp.json()
                    
                    print("\n✓ Extraction complete!")
                    print(f"\nMetrics:")
                    metrics = final_result.get("metrics", {})
                    print(f"  - Duration: {metrics.get('duration_seconds', 0):.2f}s")
                    print(f"  - Spans processed: {metrics.get('spans_processed', 0)}")
                    print(f"  - Techniques found: {metrics.get('counters', {}).get('techniques', 0)}")
                    
                    print(f"\nExtracted Techniques:")
                    techniques = final_result.get("techniques", [])
                    for tech in techniques:
                        print(f"  - {tech.get('external_id')}: {tech.get('name')}")
                        print(f"    Confidence: {tech.get('confidence', 0)}%")
                        print(f"    Evidence: {tech.get('evidence', {}).get('quotes', ['N/A'])[0][:80]}...")
                    
                    return final_result
                else:
                    print(f"Failed to get result: {result_resp.status_code}")
                    print(result_resp.text)
                break
        
        if elapsed >= max_wait:
            print(f"\n✗ Extraction timed out after {max_wait} seconds")
            
    except Exception as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    result = test_extraction()
    if result and "error" not in result:
        print("\n✓ Extraction test passed!")
    else:
        print("\n✗ Extraction test failed")