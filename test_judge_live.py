#!/usr/bin/env python3
"""Test the LLM Judge endpoint with real technique pairs."""

import requests
import json
import sys

# API endpoint
BASE_URL = "http://localhost:8000/v1"

def test_judge_endpoint():
    """Test the judge endpoint with some common technique pairs."""
    
    # Some common technique pairs that often appear together
    # Using technique names for clarity, but we'll need STIX IDs
    test_pairs = [
        # Initial Access -> Execution
        ["T1566", "T1204"],  # Phishing -> User Execution
        # Execution -> Persistence  
        ["T1059", "T1547"],  # Command/Scripting Interpreter -> Boot/Logon Autostart
        # Discovery -> Collection
        ["T1057", "T1005"],  # Process Discovery -> Data from Local System
    ]
    
    print("Testing LLM Judge endpoint...")
    print("=" * 60)
    
    # First, get the PTG model to extract some real STIX IDs
    print("\n1. Getting PTG model for technique STIX IDs...")
    response = requests.post(
        f"{BASE_URL}/sequence/infer",
        json={"scope": "global", "use_judge": False}
    )
    
    if response.status_code != 200:
        print(f"Error getting PTG model: {response.status_code}")
        return
    
    ptg_data = response.json()
    print(f"PTG model created: {ptg_data['model_id']}")
    print(f"Total edges available: {ptg_data['total_edges']}")
    
    # Get model details to extract some pairs
    model_response = requests.get(
        f"{BASE_URL}/sequence/models/{ptg_data['model_id']}"
    )
    
    if model_response.status_code != 200:
        print(f"Error getting model details: {model_response.status_code}")
        # Use hardcoded STIX IDs as fallback
        stix_pairs = [
            ["attack-pattern--7b211ac6-c815-4189-93a9-ab415deca926", 
             "attack-pattern--03d7999c-1f4c-42cc-8373-e7690d318104"]
        ]
    else:
        model_data = model_response.json()
        # Extract first 3 edges as test pairs
        edges = model_data.get("edges", [])[:3]
        stix_pairs = [[edge["from_technique"], edge["to_technique"]] for edge in edges]
        
        if not stix_pairs:
            # Fallback to hardcoded
            stix_pairs = [
                ["attack-pattern--7b211ac6-c815-4189-93a9-ab415deca926", 
                 "attack-pattern--03d7999c-1f4c-42cc-8373-e7690d318104"]
            ]
    
    print(f"\n2. Testing judge endpoint with {len(stix_pairs)} pairs...")
    
    # Test the judge endpoint - send pairs as list directly
    judge_response = requests.post(
        f"{BASE_URL}/sequence/judge?scope=global&max_pairs=10&use_cache=false",
        json=stix_pairs  # Send pairs list directly in body
    )
    
    if judge_response.status_code != 200:
        print(f"Error calling judge endpoint: {judge_response.status_code}")
        print(f"Response: {judge_response.text}")
        return
    
    judge_data = judge_response.json()
    
    print("\n3. Judge Results:")
    print("-" * 60)
    print(f"Total verdicts: {judge_data.get('total_verdicts', 0)}")
    print(f"Cache used: {judge_data.get('cache_used', False)}")
    
    if "verdicts" in judge_data:
        for verdict in judge_data["verdicts"]:
            print(f"\nPair: {verdict['from_technique'][:20]}... -> {verdict['to_technique'][:20]}...")
            print(f"  Verdict: {verdict['verdict']}")
            print(f"  Confidence: {verdict['confidence']:.2f}")
            print(f"  Reasoning: {verdict['reasoning'][:100]}...")
            if verdict.get("evidence_ids"):
                print(f"  Evidence citations: {len(verdict['evidence_ids'])} pieces")
    
    print("\n" + "=" * 60)
    
    # Now test PTG building with judge enabled
    print("\n4. Testing PTG build with judge integration...")
    ptg_judge_response = requests.post(
        f"{BASE_URL}/sequence/infer",
        json={
            "scope": "global", 
            "use_judge": True,
            "parameters": {
                "use_judge": True,
                "epsilon": 1.0
            }
        }
    )
    
    if ptg_judge_response.status_code != 200:
        print(f"Error building PTG with judge: {ptg_judge_response.status_code}")
        print(f"Response: {ptg_judge_response.text}")
        return
    
    ptg_judge_data = ptg_judge_response.json()
    print(f"PTG with judge created: {ptg_judge_data['model_id']}")
    
    if "parameters" in ptg_judge_data:
        params = ptg_judge_data["parameters"]
        if "judge_integration" in params:
            judge_info = params["judge_integration"]
            print(f"  Judge enabled: {judge_info.get('judge_enabled', False)}")
            print(f"  Total verdicts used: {judge_info.get('total_verdicts', 0)}")
            print(f"  Forward verdicts: {judge_info.get('forward_verdicts', 0)}")
            print(f"  Reverse verdicts: {judge_info.get('reverse_verdicts', 0)}")
            print(f"  Average confidence: {judge_info.get('avg_confidence', 0):.2f}")
    
    print("\nJudge integration test complete!")

if __name__ == "__main__":
    try:
        test_judge_endpoint()
    except Exception as e:
        print(f"Test failed with error: {e}")
        sys.exit(1)