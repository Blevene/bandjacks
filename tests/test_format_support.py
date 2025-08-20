#!/usr/bin/env python3
"""Test extraction support for plaintext and markdown formats."""

import requests
import json
import time


def test_format(content: str, format_name: str, title: str) -> dict:
    """Test extraction with given content and return results."""
    
    # Start extraction
    response = requests.post(
        "http://localhost:8000/v1/extract/runs",
        json={
            "method": "agentic_v2",
            "content": content,
            "title": title,
            "config": {
                "cache_llm_responses": True,
                "single_pass_threshold": 500
            }
        }
    )
    
    if response.status_code != 200:
        print(f"Failed to start extraction: {response.status_code}")
        return {}
    
    run_id = response.json()["run_id"]
    print(f"Started {format_name} extraction: {run_id}")
    
    # Poll for completion
    for i in range(60):
        time.sleep(1)
        
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
                    return result_resp.json()
    
    return {"error": "Timeout"}


def main():
    """Test extraction with different text formats."""
    
    print("=" * 80)
    print("TESTING EXTRACTION FORMAT SUPPORT")
    print("=" * 80)
    
    # Test 1: Plain text
    plaintext_content = """
Threat Actor APT29 Campaign Analysis

The threat actors initiated their campaign using spearphishing emails containing 
malicious Word documents. Upon opening, these documents executed PowerShell scripts 
that established persistence through Windows registry modifications.

The attackers performed extensive reconnaissance using built-in Windows commands
like whoami, netstat, and ipconfig. They then deployed Mimikatz to harvest 
credentials from memory.

For lateral movement, the group utilized RDP connections and WMI commands to 
spread across the network. Data was staged in encrypted archives before 
exfiltration through legitimate cloud storage services.
"""
    
    print("\n1. Testing PLAINTEXT extraction...")
    plaintext_result = test_format(
        plaintext_content,
        "plaintext",
        "Plaintext Threat Report"
    )
    
    if "techniques" in plaintext_result:
        print(f"✓ Extracted {len(plaintext_result['techniques'])} techniques from plaintext")
        for tech_id in list(plaintext_result['techniques'].keys())[:3]:
            tech = plaintext_result['techniques'][tech_id]
            print(f"  - {tech_id}: {tech.get('name', 'Unknown')}")
    
    # Test 2: Markdown
    markdown_content = """
# APT28 Threat Analysis Report

## Executive Summary

APT28, also known as **Fancy Bear**, has been observed conducting a sophisticated 
campaign targeting government organizations.

## Attack Chain

### Initial Access
- **Spearphishing Attachment** (T1566.001)
  - Malicious PDF documents sent via email
  - Exploits CVE-2024-1234 vulnerability

### Execution
The threat actors used several execution methods:
1. **PowerShell** scripts for initial payload execution
2. **Windows Command Shell** for reconnaissance
3. **Scheduled Tasks** for persistence

### Persistence Mechanisms
```
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d C:\malware.exe
```

### Credential Access
- Deployed **Mimikatz** for credential dumping
- Used `sekurlsa::logonpasswords` to extract credentials
- Performed **Kerberoasting** attacks

### Lateral Movement
| Technique | Tool | Description |
|-----------|------|-------------|
| RDP | mstsc.exe | Remote desktop connections |
| PsExec | sysinternals | Remote command execution |
| WMI | wmic.exe | Windows Management Instrumentation |

### Exfiltration
> Data was compressed using 7-zip and exfiltrated through HTTPS to attacker-controlled infrastructure

## Indicators of Compromise

- `malware.exe` - SHA256: abc123...
- C2 Server: `evil.example.com`
- Registry Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater`
"""
    
    print("\n2. Testing MARKDOWN extraction...")
    markdown_result = test_format(
        markdown_content,
        "markdown",
        "Markdown Threat Report"
    )
    
    if "techniques" in markdown_result:
        print(f"✓ Extracted {len(markdown_result['techniques'])} techniques from markdown")
        for tech_id in list(markdown_result['techniques'].keys())[:3]:
            tech = markdown_result['techniques'][tech_id]
            print(f"  - {tech_id}: {tech.get('name', 'Unknown')}")
    
    # Test 3: Mixed format (plaintext with some structure)
    mixed_content = """
===========================================
INCIDENT RESPONSE REPORT - RANSOMWARE ATTACK
===========================================

Date: 2024-01-15
Severity: CRITICAL

EXECUTIVE SUMMARY:
The organization suffered a ransomware attack that encrypted critical systems.

TECHNICAL DETAILS:

* Initial Vector:
  - Exploitation of ProxyLogon vulnerability (CVE-2021-26855)
  - Web shell installation on Exchange server
  
* Post-Exploitation:
  - Cobalt Strike beacon deployment
  - Living off the land using certutil and bitsadmin
  - Credential harvesting with procdump
  
* Persistence:
  - WMI event subscriptions created
  - Scheduled tasks configured
  - Service installation for backdoor
  
* Impact:
  - 500+ endpoints encrypted
  - Domain controllers compromised
  - Backup systems targeted and destroyed

RECOMMENDATIONS:
1. Patch all Exchange servers immediately
2. Reset all domain credentials
3. Implement EDR solution
4. Enable PowerShell logging
"""
    
    print("\n3. Testing MIXED FORMAT extraction...")
    mixed_result = test_format(
        mixed_content,
        "mixed",
        "Mixed Format Report"
    )
    
    if "techniques" in mixed_result:
        print(f"✓ Extracted {len(mixed_result['techniques'])} techniques from mixed format")
        for tech_id in list(mixed_result['techniques'].keys())[:3]:
            tech = mixed_result['techniques'][tech_id]
            print(f"  - {tech_id}: {tech.get('name', 'Unknown')}")
    
    # Test 4: Minimal text
    minimal_content = "The attackers used PowerShell and RDP."
    
    print("\n4. Testing MINIMAL TEXT extraction...")
    minimal_result = test_format(
        minimal_content,
        "minimal",
        "Minimal Text"
    )
    
    if "techniques" in minimal_result:
        print(f"✓ Extracted {len(minimal_result['techniques'])} techniques from minimal text")
        for tech_id, tech in minimal_result['techniques'].items():
            print(f"  - {tech_id}: {tech.get('name', 'Unknown')}")
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    formats_tested = [
        ("Plaintext", plaintext_result),
        ("Markdown", markdown_result),
        ("Mixed Format", mixed_result),
        ("Minimal Text", minimal_result)
    ]
    
    all_success = True
    for format_name, result in formats_tested:
        if "techniques" in result:
            count = len(result['techniques'])
            time_taken = result.get('metrics', {}).get('dur_sec', 'N/A')
            print(f"✓ {format_name:15} - {count:2} techniques in {time_taken} seconds")
        else:
            print(f"✗ {format_name:15} - Failed")
            all_success = False
    
    if all_success:
        print("\n✅ All formats supported successfully!")
    else:
        print("\n⚠️ Some formats failed extraction")
    
    # Test caching benefit
    print("\n" + "=" * 80)
    print("CACHE EFFECTIVENESS TEST")
    print("=" * 80)
    
    # Get cache stats
    cache_stats = requests.get("http://localhost:8000/v1/cache/stats").json()
    print(f"Cache stats: {cache_stats['hits']} hits, {cache_stats['misses']} misses")
    print(f"Hit rate: {cache_stats['hit_rate']}")
    
    # Run same content again to test cache
    print("\nRe-running minimal text to test cache...")
    start_time = time.time()
    cached_result = test_format(
        minimal_content,
        "minimal-cached",
        "Minimal Text (Cached)"
    )
    cache_time = time.time() - start_time
    
    if "techniques" in cached_result:
        print(f"✓ Cache test completed in {cache_time:.2f} seconds")
        
    # Final cache stats
    cache_stats = requests.get("http://localhost:8000/v1/cache/stats").json()
    print(f"\nFinal cache stats: {cache_stats['hit_rate']} hit rate")


if __name__ == "__main__":
    main()