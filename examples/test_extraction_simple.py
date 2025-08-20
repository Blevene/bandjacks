#!/usr/bin/env python3
"""Test extraction endpoint with simple content."""

import requests
import json
import time

# Very simple test content with obvious techniques
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
        "disable_discovery": True,  # Disable discovery to speed up
        "max_discovery_per_span": 0,
        "min_quotes": 1
    }
}

# Send request to extraction endpoint
print("Sending extraction request...")
try:
    response = requests.post(
        "http://localhost:8000/v1/extract/runs",
        json=payload,
        timeout=5  # Short timeout for initial response
    )
    
    if response.status_code == 200:
        result = response.json()
        run_id = result.get("run_id")
        print(f"Extraction started with run_id: {run_id}")
        
        # Poll for status
        for i in range(30):  # Wait up to 30 seconds
            time.sleep(1)
            status_resp = requests.get(f"http://localhost:8000/v1/extract/runs/{run_id}/status")
            if status_resp.status_code == 200:
                status = status_resp.json()
                print(f"Status: {status.get('state')} - Stage: {status.get('stage')}")
                if status.get('state') == 'finished':
                    # Get result
                    result_resp = requests.get(f"http://localhost:8000/v1/extract/runs/{run_id}/result")
                    if result_resp.status_code == 200:
                        print("\nExtraction complete!")
                        print(json.dumps(result_resp.json(), indent=2))
                    break
            else:
                print(f"Status check failed: {status_resp.status_code}")
    else:
        print(f"Error {response.status_code}: {response.text}")
        
except requests.exceptions.RequestException as e:
    print(f"Request failed: {e}")