#!/usr/bin/env python3
"""Test extraction endpoint directly."""

import requests
import json

# Simple test text
test_content = """
The Wizards APT group has been observed using SLAAC spoofing techniques to perform 
adversary-in-the-middle attacks. They utilize T1557.002 (ARP Cache Poisoning) and 
T1040 (Network Sniffing) to intercept network traffic. The group also employs 
T1055 (Process Injection) for persistence and T1070.004 (File Deletion) to cover their tracks.

Their recent campaign involved:
1. Initial access through spearphishing attachments (T1566.001)
2. Establishing persistence via registry run keys (T1547.001)
3. Lateral movement using Windows Admin Shares (T1021.002)
4. Data exfiltration over C2 channel (T1041)
"""

# Create payload for extraction
payload = {
    "method": "agentic_v2",
    "content": test_content,
    "title": "Wizards APT Test",
    "config": {
        "top_k": 5,
        "disable_discovery": False,
        "max_discovery_per_span": 1,
        "min_quotes": 2
    }
}

# Send request to extraction endpoint
print("Sending extraction request...")
try:
    response = requests.post(
        "http://localhost:8000/v1/extract/runs",
        json=payload,
        timeout=30
    )
    
    if response.status_code == 200:
        result = response.json()
        print("Extraction successful!")
        print(json.dumps(result, indent=2))
    else:
        print(f"Error {response.status_code}: {response.text}")
        
except requests.exceptions.RequestException as e:
    print(f"Request failed: {e}")