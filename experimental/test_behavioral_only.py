#!/usr/bin/env python3
"""Test behavioral discovery without vector search."""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

def test_behavioral_extraction():
    """Test behavioral extraction on DarkCloud PDF."""
    
    print("Testing behavioral extraction on DarkCloud PDF...")
    
    # Read the saved results from our test
    results_file = Path("/tmp/single_improved_test.json")
    
    if not results_file.exists():
        # Run a simplified extraction
        from bandjacks.llm.improved_extractor import ImprovedExtractor
        
        extractor = ImprovedExtractor(
            model="gpt-4o-mini",
            os_url="http://localhost:9200",
            os_index="ttx"
        )
        
        pdf_path = Path("samples/reports/new-darkcloud-stealer-infection-chain.pdf")
        
        try:
            results = extractor.extract_from_report(
                source_id="darkcloud_test",
                source_type="pdf",
                content_url=str(pdf_path)
            )
        except Exception as e:
            print(f"Extraction error (expected): {e}")
            # Use partial results
            results = {
                "techniques_found": extractor.context.techniques_found,
                "entities": {
                    "malware": list(set(extractor.context.malware)),
                    "tools": list(set(extractor.context.tools))
                },
                "relationships": extractor.context.relationships
            }
    else:
        with open(results_file) as f:
            results = json.load(f)
    
    # Analyze what was found through behavioral discovery
    print("\n=== BEHAVIORAL DISCOVERY RESULTS ===")
    
    # Expected techniques for DarkCloud
    expected = {
        "T1566": "Phishing",
        "T1059": "Command and Scripting Interpreter", 
        "T1059.001": "PowerShell",
        "T1059.007": "JavaScript",
        "T1027": "Obfuscated Files",
        "T1140": "Deobfuscate/Decode",
        "T1055": "Process Injection",
        "T1071": "Application Layer Protocol",
        "T1547": "Boot or Logon Autostart",
        "T1555": "Credentials from Password Stores",
        "T1005": "Data from Local System",
        "T1041": "Exfiltration Over C2",
        "T1083": "File and Directory Discovery",
        "T1057": "Process Discovery",
        "T1105": "Ingress Tool Transfer",
        "T1204": "User Execution"
    }
    
    # Check techniques found
    techniques_found = results.get("techniques_found", {})
    if not techniques_found and "claims" in results:
        # Extract from claims
        techniques_found = {}
        for claim in results.get("claims", []):
            for mapping in claim.get("mappings", []):
                tech_id = mapping.get("external_id")
                if tech_id:
                    techniques_found[tech_id] = {
                        "name": mapping.get("name", tech_id),
                        "confidence": mapping.get("confidence", 0)
                    }
    
    print(f"\nTechniques found: {len(techniques_found)}")
    for tech_id, info in list(techniques_found.items())[:15]:
        name = info.get("name", "") if isinstance(info, dict) else tech_id
        conf = info.get("confidence", 0) if isinstance(info, dict) else 0
        status = "✓" if tech_id in expected else "?"
        print(f"  {status} {tech_id}: {name} (confidence: {conf})")
    
    # Calculate recall
    found_expected = set(techniques_found.keys()) & set(expected.keys())
    recall = len(found_expected) / len(expected) if expected else 0
    
    print(f"\nRecall: {recall:.1%} ({len(found_expected)}/{len(expected)})")
    print(f"Found from expected: {', '.join(sorted(found_expected))}")
    
    # Check critical techniques
    critical = ["T1566", "T1059", "T1055", "T1071", "T1547"]
    print(f"\nCritical techniques:")
    for tech_id in critical:
        status = "✓" if tech_id in techniques_found else "✗"
        print(f"  {status} {tech_id}: {expected.get(tech_id, 'Unknown')}")
    
    # Check entities
    entities = results.get("entities", {})
    if entities:
        print(f"\nEntities found:")
        print(f"  Malware: {', '.join(entities.get('malware', []))}")
        print(f"  Tools: {', '.join(entities.get('tools', []))}")
    
    return recall

if __name__ == "__main__":
    recall = test_behavioral_extraction()
    print(f"\nFinal recall: {recall:.1%}")
    print(f"Target: 75%")
    print(f"Status: {'✓ PASS' if recall >= 0.75 else '✗ FAIL'}")
    sys.exit(0 if recall >= 0.75 else 1)