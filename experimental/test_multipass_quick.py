#!/usr/bin/env python3
"""
Quick test of multi-pass extraction with limited chunks.
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from bandjacks.llm.multipass_extractor import MultiPassExtractor, ExtractionPass

# Simple test text with obvious techniques
TEST_TEXT = """
DarkCloud Stealer Analysis Report

The attack begins with a phishing email containing a malicious RAR archive attachment.
When the user opens the attachment and executes the JavaScript file inside, it downloads
a PowerShell script from http://176.65.142.190/payload.ps1.

The PowerShell script is heavily obfuscated using Base64 encoding and AES encryption.
It uses Invoke-Expression to execute the decoded payload. The script then drops a 
ConfuserEx-protected executable to C:\\Temp with a random filename.

The malware performs process hollowing, injecting its payload into RegAsm.exe to evade
detection. Once running, it begins collecting sensitive data including browser credentials,
credit card information, and files from the local system.

The collected data is exfiltrated to the attacker's command and control server using
the Telegram API at https://api.telegram.org/bot/sendMessage. The malware establishes
persistence by creating registry keys that execute on system startup.
"""

def test_quick_multipass():
    """Quick test of multi-pass extraction."""
    
    print("="*60)
    print("QUICK MULTI-PASS TEST")
    print("="*60)
    
    # Create extractor
    extractor = MultiPassExtractor(model="gpt-4o-mini")
    
    # Run extraction (will use default passes)
    result = extractor.extract_multi_pass(
        source_id="quick-test",
        source_type="text",
        inline_text=TEST_TEXT
    )
    
    # Show results
    print(f"\nTotal claims: {result.get('total_claims', 0)}")
    
    if 'multi_pass_analysis' in result:
        analysis = result['multi_pass_analysis']
        techniques = analysis.get('cumulative_techniques', {})
        print(f"Techniques found: {len(techniques)}")
        
        for tech_id, info in techniques.items():
            print(f"  - {tech_id}: {info.get('name', 'Unknown')} (confidence: {info.get('confidence_max', 0)}%)")
    
    # Save results
    output_file = Path("/tmp/quick_multipass_results.json")
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved to: {output_file}")
    
    return len(techniques) > 5  # Success if found > 5 techniques


if __name__ == "__main__":
    success = test_quick_multipass()
    print(f"\n{'✅ SUCCESS' if success else '❌ NEEDS IMPROVEMENT'}")
    sys.exit(0 if success else 1)