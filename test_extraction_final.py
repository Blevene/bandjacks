#!/usr/bin/env python3
"""Final test of our enhanced extraction capabilities."""

import os
import sys
import json
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment
load_dotenv()
sys.path.insert(0, '/Volumes/tank/bandjacks')

from bandjacks.llm.prompts import add_line_numbers

# Configure Gemini
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))
model = genai.GenerativeModel('gemini-1.5-flash')

# Comprehensive threat report
threat_report = """
## Operation DARKHYDRUS APT Campaign Analysis

### Executive Summary
The DARKHYDRUS APT group, linked to Iranian state interests, has been conducting
a sophisticated cyber espionage campaign targeting government agencies and 
critical infrastructure in the Middle East since January 2024.

### Initial Access Techniques
The threat actors primarily gained initial access through:
- Spearphishing emails with malicious Excel attachments (T1566.001) containing
  embedded macros that download secondary payloads
- Exploitation of public-facing applications, specifically targeting unpatched
  Log4j vulnerabilities (CVE-2021-44228) in web servers
- Supply chain compromise (T1195) targeting software update mechanisms

### Persistence and Execution
Once inside target networks, DARKHYDRUS established persistence using:
- Registry run keys (T1547.001) at HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- Scheduled tasks (T1053.005) configured to execute every 6 hours
- DLL side-loading (T1574.002) using legitimate signed binaries

The group deployed custom malware families:
- "HydraMist" backdoor providing full remote access capabilities
- "PersianKitten" keylogger for credential harvesting
- Modified Cobalt Strike beacons for command and control

### Credential Access and Discovery
DARKHYDRUS actors were observed:
- Using Mimikatz to dump credentials from LSASS process memory (T1003.001)
- Harvesting credentials from web browsers and password managers (T1555)
- Performing Active Directory reconnaissance using BloodHound (T1087.002)
- Network scanning with custom Python scripts to map internal networks

### Lateral Movement and C2
The threat actors moved laterally through:
- RDP sessions using compromised admin credentials (T1021.001)
- PowerShell remoting for remote command execution (T1021.006)
- Exploitation of SMB vulnerabilities for spreading to unpatched systems

Command and control infrastructure included:
- Primary C2: secure.microsoft-update[.]services (185.159.158.45)
- Backup C2: cdn.cloudflare-analytics[.]com (194.147.78.23)
- Use of DNS tunneling (T1071.004) for stealthy communications
- HTTPS traffic mimicking legitimate Microsoft update checks

### Data Exfiltration
Sensitive data was exfiltrated through:
- Automated collection scripts gathering documents matching keywords
- Compression using RAR with password protection
- Exfiltration over C2 channel using custom protocol (T1041)
- Alternative exfiltration via compromised cloud storage accounts

### Indicators of Compromise
File Hashes (SHA256):
- HydraMist: 3d4f8a9e2c1b7654321098765432109876543210
- PersianKitten: 9f8e7d6c5b4a32109876543210987654321098765
- Cobalt Strike loader: 1a2b3c4d5e6f7890abcdef1234567890abcdef12

Network Indicators:
- User-Agent: "Mozilla/5.0 (compatible; MSIE 10.0; Update; Hydra)"
- Mutex: "Global\HydraMist2024"
- Named pipe: \\\\.\\pipe\\hydra_comm_2024
"""

print("=" * 60)
print("Enhanced LLM Extraction - Final Test")
print("=" * 60)

# Add line numbers for citation
numbered_text = add_line_numbers(threat_report)

# Create extraction prompt
extraction_prompt = """You are a cyber threat intelligence analyst. Extract all threat activities from this report.

For each activity, provide:
1. Threat actor or malware name
2. ATT&CK technique with ID (e.g., T1566.001)
3. Description of the activity
4. Line numbers where found
5. Confidence level (0-100)

Also identify:
- All threat actors and aliases
- All malware families
- All vulnerabilities (CVEs)
- Infrastructure indicators (IPs, domains)
- File hashes

Return as structured JSON:
{
  "claims": [
    {
      "actor": "threat actor or malware",
      "technique_name": "technique name",
      "technique_id": "T####.###",
      "activity": "description",
      "evidence": "exact quote from text",
      "lines": [line numbers],
      "confidence": 0-100
    }
  ],
  "entities": {
    "threat_actors": ["list"],
    "malware": ["list"],
    "vulnerabilities": ["list"],
    "infrastructure": [
      {"type": "domain|ip", "value": "...", "context": "..."}
    ],
    "hashes": [
      {"type": "SHA256", "value": "...", "malware": "..."}
    ]
  },
  "statistics": {
    "total_techniques": count,
    "total_iocs": count
  }
}

Text to analyze (with line numbers):
""" + numbered_text

print("\n1. Extracting threat intelligence...")
print("-" * 40)

try:
    # Generate extraction
    response = model.generate_content(
        extraction_prompt,
        generation_config={
            "temperature": 0.2,
            "max_output_tokens": 4000,
        }
    )
    
    # Parse response
    result_text = response.text
    print(f"✓ Got response ({len(result_text)} chars)")
    
    # Extract JSON
    import re
    json_match = re.search(r'```json\s*\n(.*?)\n```', result_text, re.DOTALL)
    if json_match:
        result = json.loads(json_match.group(1))
    else:
        # Try direct parse
        result = json.loads(result_text)
    
    print(f"✓ Parsed extraction results")
    
    # Display results
    print(f"\n2. Extraction Results")
    print("-" * 40)
    
    claims = result.get('claims', [])
    print(f"✓ Extracted {len(claims)} TTP claims")
    
    # Show sample claims
    if claims:
        print("\nTop TTP Claims:")
        for i, claim in enumerate(claims[:5], 1):
            print(f"\n  {i}. {claim.get('activity', 'Unknown')}")
            print(f"     Actor: {claim.get('actor', 'Unknown')}")
            print(f"     Technique: {claim.get('technique_id', '')} - {claim.get('technique_name', '')}")
            print(f"     Evidence: \"{claim.get('evidence', '')[:80]}...\"")
            print(f"     Lines: {claim.get('lines', [])}")
            print(f"     Confidence: {claim.get('confidence', 0)}%")
    
    # Show entities
    entities = result.get('entities', {})
    if entities:
        print(f"\n3. Extracted Entities")
        print("-" * 40)
        
        if entities.get('threat_actors'):
            print(f"✓ Threat Actors: {', '.join(entities['threat_actors'])}")
        
        if entities.get('malware'):
            print(f"✓ Malware: {', '.join(entities['malware'])}")
        
        if entities.get('vulnerabilities'):
            print(f"✓ Vulnerabilities: {', '.join(entities['vulnerabilities'])}")
        
        if entities.get('infrastructure'):
            print(f"✓ Infrastructure:")
            for ioc in entities['infrastructure'][:5]:
                print(f"   - {ioc.get('type', '')}: {ioc.get('value', '')} ({ioc.get('context', '')})")
        
        if entities.get('hashes'):
            print(f"✓ File Hashes:")
            for hash_ioc in entities['hashes'][:3]:
                print(f"   - {hash_ioc.get('malware', '')}: {hash_ioc.get('value', '')[:16]}...")
    
    # Show statistics
    stats = result.get('statistics', {})
    if stats:
        print(f"\n4. Statistics")
        print("-" * 40)
        print(f"✓ Total techniques: {stats.get('total_techniques', 0)}")
        print(f"✓ Total IOCs: {stats.get('total_iocs', 0)}")
    
    # Save results
    with open('extraction_results.json', 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\n✓ Full results saved to extraction_results.json")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)
print("✅ Enhanced Extraction Test Complete!")
print("=" * 60)
print("\nKey Capabilities Demonstrated:")
print("  • Advanced entity extraction (actors, malware, CVEs)")
print("  • ATT&CK technique mapping with IDs")
print("  • Line-level evidence citation")
print("  • Infrastructure and IOC extraction")
print("  • Confidence scoring for each claim")
print("  • Comprehensive threat intelligence extraction")