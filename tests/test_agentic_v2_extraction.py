#!/usr/bin/env python3
"""Test the enhanced agentic_v2 extraction pipeline."""

import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, List

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from bandjacks.loaders.parse_text import extract_text
from bandjacks.llm.extraction_pipeline import run_extraction_pipeline


def test_agentic_v2_direct():
    """Test agentic_v2 extraction directly without API."""
    
    print("="*80)
    print("AGENTIC V2 EXTRACTION TEST")
    print("="*80)
    
    # Test with DarkCloud PDF content
    pdf_path = Path(__file__).parent.parent / "samples" / "reports" / "new-darkcloud-stealer-infection-chain.pdf"
    
    if not pdf_path.exists():
        print(f"❌ PDF not found at {pdf_path}")
        # Use sample text instead
        sample_text = """
        DarkCloud Stealer Analysis Report
        
        The threat actors behind DarkCloud use spearphishing emails with malicious attachments
        to target executives. The attachment contains a JavaScript file that executes PowerShell
        commands to download additional payloads. The malware uses ConfuserEx obfuscation to
        evade detection and performs process hollowing via RegAsm.exe for persistence.
        
        The stealer communicates with C2 servers at 176.65.142.190 using Telegram API for
        data exfiltration. It steals credentials from browsers using 3DES and RC4 decryption.
        The malware creates scheduled tasks for persistence and modifies registry keys.
        
        Indicators:
        - IP: 176.65.142.190
        - Hash: bd8c0b0503741c17d75ce560a10eeeaa0cdd21dff323d9f1644c62b7b8eb43d9
        - File: malicious.js
        """
        print("Using sample text for testing")
    else:
        print(f"✅ Found PDF: {pdf_path.name}")
        # Extract text from PDF
        try:
            import PyPDF2
            text_content = []
            with open(pdf_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                for page in pdf_reader.pages:
                    text_content.append(page.extract_text())
            sample_text = '\n'.join(text_content)
            print(f"   - Extracted {len(sample_text)} characters from PDF")
        except Exception as e:
            print(f"❌ PDF extraction failed: {e}")
            return False
    
    # Configure extraction
    import os
    config = {
        "neo4j_uri": os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        "neo4j_user": os.getenv("NEO4J_USER", "neo4j"),
        "neo4j_password": os.getenv("NEO4J_PASSWORD", ""),
        "model": "gemini/gemini-2.5-flash",
        "title": "DarkCloud Stealer Analysis",
        "url": "https://unit42.paloaltonetworks.com/darkcloud-stealer",
        "ts": time.time(),
        "discovery_model": "gemini/gemini-2.5-flash",
        "mapper_model": "gemini/gemini-2.5-flash",
        "min_quotes": 1,  # Relax for testing
        "max_discovery_per_span": 10,  # Allow more proposals
        "top_k": 10  # More retrieval candidates
    }
    
    print("\n1. Running agentic_v2 extraction pipeline...")
    print("   - Using Gemini 2.5 Flash model")
    print("   - Multi-pass extraction enabled")
    print("   - Enhanced behavioral patterns")
    
    try:
        start_time = time.time()
        result = run_extraction_pipeline(sample_text, config)
        elapsed = time.time() - start_time
        
        print(f"   ✅ Extraction completed in {elapsed:.1f} seconds")
        
        # Analyze results
        techniques = result.get("techniques", {})
        bundle = result.get("bundle", {})
        notes = result.get("notes", [])
        
        print(f"\n2. Extraction Results:")
        print(f"   - Techniques found: {len(techniques)}")
        print(f"   - STIX objects created: {len(bundle.get('objects', []))}")
        print(f"   - Notes: {', '.join(notes[:3])}")
        
        # Expected techniques for DarkCloud
        expected_techniques = {
            "T1566": "Phishing",
            "T1566.001": "Spearphishing Attachment", 
            "T1059.001": "PowerShell",
            "T1059.007": "JavaScript",
            "T1027": "Obfuscated Files or Information",
            "T1055": "Process Injection",
            "T1055.012": "Process Hollowing",
            "T1140": "Deobfuscate/Decode Files or Information",
            "T1071": "Application Layer Protocol",
            "T1071.001": "Web Protocols",
            "T1204": "User Execution",
            "T1204.002": "Malicious File",
            "T1547": "Boot or Logon Autostart Execution",
            "T1053": "Scheduled Task/Job",
            "T1112": "Modify Registry",
            "T1555": "Credentials from Password Stores",
            "T1555.003": "Credentials from Web Browsers",
            "T1041": "Exfiltration Over C2 Channel"
        }
        
        print(f"\n3. Technique Analysis:")
        found_count = 0
        for tech_id, tech_name in expected_techniques.items():
            # Check if technique or parent technique found
            found = False
            for found_id in techniques.keys():
                if tech_id in found_id or found_id in tech_id:
                    found = True
                    found_count += 1
                    break
            
            status = "✅" if found else "❌"
            confidence = techniques.get(tech_id, {}).get("confidence", 0) if tech_id in techniques else 0
            print(f"   {status} {tech_id}: {tech_name} (confidence: {confidence}%)")
        
        recall = (found_count / len(expected_techniques)) * 100 if expected_techniques else 0
        print(f"\n   Recall: {recall:.1f}% ({found_count}/{len(expected_techniques)})")
        
        # Show top extracted techniques
        print(f"\n4. Top Extracted Techniques:")
        sorted_techniques = sorted(
            techniques.items(), 
            key=lambda x: x[1].get("confidence", 0), 
            reverse=True
        )
        for tech_id, info in sorted_techniques[:10]:
            print(f"   - {tech_id}: {info['name']} (confidence: {info['confidence']}%)")
            if info.get("evidence"):
                print(f"     Evidence: {info['evidence'][0][:100]}...")
        
        # Save results
        output_file = Path("/tmp/agentic_v2_results.json")
        with open(output_file, "w") as f:
            json.dump({
                "techniques": techniques,
                "bundle": bundle,
                "notes": notes,
                "recall": recall,
                "elapsed_seconds": elapsed
            }, f, indent=2)
        print(f"\n   Saved results to {output_file}")
        
        return recall >= 75.0
        
    except Exception as e:
        print(f"   ❌ Extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_agentic_v2_via_api():
    """Test agentic_v2 extraction via API."""
    
    print("\n" + "="*80)
    print("AGENTIC V2 API TEST")
    print("="*80)
    
    # Prepare test document
    test_content = """
    APT29 Campaign Analysis
    
    APT29, also known as Cozy Bear, conducted a sophisticated campaign targeting government agencies.
    The initial compromise occurred through spearphishing emails containing malicious Word documents
    with embedded macros. Upon execution, the macro drops a PowerShell script that establishes
    persistence via scheduled tasks and registry modifications.
    
    The attackers used Mimikatz to dump credentials from LSASS memory and performed lateral movement
    using WMI and PSExec. They established command and control through HTTPS connections to
    compromised WordPress sites, using domain fronting to evade detection.
    
    Data was collected using automated scripts that compressed files with 7zip before exfiltration.
    The threat actors used timestomping to modify file timestamps and cleared Windows event logs
    to cover their tracks.
    """
    
    try:
        with httpx.Client(base_url="http://localhost:8000/v1", timeout=300.0) as client:
            print("1. Calling extraction API with method=agentic_v2...")
            
            response = client.post(
                "/extract/report",
                json={
                    "source_url": "https://example.com/apt29-report",
                    "source_type": "md",
                    "content": test_content,
                    "title": "APT29 Campaign Analysis",
                    "method": "agentic_v2",
                    "confidence_threshold": 50.0,
                    "auto_ingest": False
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"   ✅ Extraction successful!")
                print(f"   - Extraction ID: {result['extraction_id']}")
                print(f"   - Techniques found: {result['stats'].get('claims_extracted', 0)}")
                print(f"   - STIX objects: {result['stats'].get('stix_objects_created', 0)}")
                
                # Analyze bundle
                bundle = result['bundle']
                attack_patterns = [
                    obj for obj in bundle.get('objects', []) 
                    if obj.get('type') == 'attack-pattern'
                ]
                
                print(f"\n2. Extracted Techniques:")
                for pattern in attack_patterns[:10]:
                    ext_refs = pattern.get('external_references', [])
                    mitre_id = None
                    for ref in ext_refs:
                        if ref.get('source_name') == 'mitre-attack':
                            mitre_id = ref.get('external_id')
                            break
                    confidence = pattern.get('x_bj_confidence', 0)
                    print(f"   - {mitre_id}: {pattern.get('name')} (confidence: {confidence}%)")
                
                return True
            else:
                print(f"   ❌ API call failed: {response.status_code}")
                print(f"   Response: {response.text[:500]}")
                return False
                
    except httpx.ConnectError:
        print("   ⚠️ API not running. Start the API server and try again.")
        return False
    except Exception as e:
        print(f"   ❌ Test failed: {e}")
        return False


def main():
    """Run all tests."""
    
    # Test direct extraction
    direct_success = test_agentic_v2_direct()
    
    # Test via API
    api_success = test_agentic_v2_via_api()
    
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    if direct_success:
        print("✅ Direct agentic_v2 extraction achieved target recall (≥75%)")
    else:
        print("⚠️ Direct extraction needs improvement")
    
    if api_success:
        print("✅ API integration working correctly")
    else:
        print("⚠️ API integration needs attention")
    
    return 0 if (direct_success or api_success) else 1


if __name__ == "__main__":
    sys.exit(main())