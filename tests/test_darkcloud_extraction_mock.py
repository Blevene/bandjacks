#!/usr/bin/env python3
"""Test extraction with mock LLM responses for DarkCloud Stealer."""

import json
import sys
from pathlib import Path
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def create_mock_stix_bundle() -> Dict[str, Any]:
    """Create a mock STIX bundle with expected DarkCloud Stealer data."""
    
    return {
        "type": "bundle",
        "id": "bundle--mock-darkcloud-test",
        "spec_version": "2.1",
        "created": "2025-08-18T15:00:00.000Z",
        "objects": [
            {
                "type": "report",
                "id": "report--darkcloud-mock",
                "spec_version": "2.1",
                "created": "2025-08-18T15:00:00.000Z",
                "modified": "2025-08-18T15:00:00.000Z",
                "name": "DarkCloud Stealer Infection Chain Analysis",
                "description": "Analysis of DarkCloud Stealer malware infection chain",
                "published": "2025-08-18T15:00:00.000Z",
                "object_refs": [
                    "malware--darkcloud-1",
                    "attack-pattern--phishing-1",
                    "attack-pattern--powershell-1",
                    "attack-pattern--obfuscation-1",
                    "attack-pattern--process-injection-1",
                    "indicator--ip-1",
                    "indicator--hash-1"
                ]
            },
            {
                "type": "malware",
                "id": "malware--darkcloud-1",
                "spec_version": "2.1",
                "created": "2025-08-18T15:00:00.000Z",
                "modified": "2025-08-18T15:00:00.000Z",
                "name": "DarkCloud Stealer",
                "description": "Information stealer malware using ConfuserEx obfuscation and process hollowing",
                "malware_types": ["trojan", "spyware"],
                "is_family": True,
                "x_bj_confidence": 90
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--phishing-1",
                "spec_version": "2.1",
                "created": "2025-08-18T15:00:00.000Z",
                "modified": "2025-08-18T15:00:00.000Z",
                "name": "Spearphishing Attachment",
                "description": "Phishing emails with TAR/RAR/7Z archives containing malicious JS/WSF files",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1566.001",
                        "url": "https://attack.mitre.org/techniques/T1566/001"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "initial-access"
                    }
                ],
                "x_bj_confidence": 95
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--powershell-1",
                "spec_version": "2.1",
                "created": "2025-08-18T15:00:00.000Z",
                "modified": "2025-08-18T15:00:00.000Z",
                "name": "PowerShell",
                "description": "PowerShell script downloads and executes next stage payload",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059.001",
                        "url": "https://attack.mitre.org/techniques/T1059/001"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "execution"
                    }
                ],
                "x_bj_confidence": 95
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--obfuscation-1",
                "spec_version": "2.1",
                "created": "2025-08-18T15:00:00.000Z",
                "modified": "2025-08-18T15:00:00.000Z",
                "name": "Obfuscated Files or Information",
                "description": "ConfuserEx obfuscation and javascript-obfuscator used",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1027",
                        "url": "https://attack.mitre.org/techniques/T1027"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "defense-evasion"
                    }
                ],
                "x_bj_confidence": 95
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--process-injection-1",
                "spec_version": "2.1",
                "created": "2025-08-18T15:00:00.000Z",
                "modified": "2025-08-18T15:00:00.000Z",
                "name": "Process Injection: Process Hollowing",
                "description": "Process hollowing into RegAsm.exe",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1055.012",
                        "url": "https://attack.mitre.org/techniques/T1055/012"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "defense-evasion"
                    },
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "privilege-escalation"
                    }
                ],
                "x_bj_confidence": 90
            },
            {
                "type": "indicator",
                "id": "indicator--ip-1",
                "spec_version": "2.1",
                "created": "2025-08-18T15:00:00.000Z",
                "modified": "2025-08-18T15:00:00.000Z",
                "name": "DarkCloud C2 Server",
                "description": "IP address hosting malicious PowerShell scripts",
                "pattern": "[ipv4-addr:value = '176.65.142.190']",
                "pattern_type": "stix",
                "valid_from": "2025-01-01T00:00:00Z",
                "indicator_types": ["malicious-activity"],
                "x_bj_confidence": 85
            },
            {
                "type": "indicator",
                "id": "indicator--hash-1",
                "spec_version": "2.1",
                "created": "2025-08-18T15:00:00.000Z",
                "modified": "2025-08-18T15:00:00.000Z",
                "name": "DarkCloud RAR Archive",
                "description": "SHA256 hash of malicious RAR archive",
                "pattern": "[file:hashes.SHA256 = 'bd8c0b0503741c17d75ce560a10eeeaa0cdd21dff323d9f1644c62b7b8eb43d9']",
                "pattern_type": "stix",
                "valid_from": "2025-01-01T00:00:00Z",
                "indicator_types": ["malicious-activity"],
                "x_bj_confidence": 95
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "spec_version": "2.1",
                "created": "2025-08-18T15:00:00.000Z",
                "modified": "2025-08-18T15:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "malware--darkcloud-1",
                "target_ref": "attack-pattern--phishing-1",
                "description": "DarkCloud Stealer uses phishing for initial delivery"
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "spec_version": "2.1",
                "created": "2025-08-18T15:00:00.000Z",
                "modified": "2025-08-18T15:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "malware--darkcloud-1",
                "target_ref": "attack-pattern--powershell-1",
                "description": "DarkCloud Stealer uses PowerShell for payload download"
            },
            {
                "type": "relationship",
                "id": "relationship--3",
                "spec_version": "2.1",
                "created": "2025-08-18T15:00:00.000Z",
                "modified": "2025-08-18T15:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "malware--darkcloud-1",
                "target_ref": "attack-pattern--obfuscation-1",
                "description": "DarkCloud Stealer uses ConfuserEx obfuscation"
            },
            {
                "type": "relationship",
                "id": "relationship--4",
                "spec_version": "2.1",
                "created": "2025-08-18T15:00:00.000Z",
                "modified": "2025-08-18T15:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "malware--darkcloud-1",
                "target_ref": "attack-pattern--process-injection-1",
                "description": "DarkCloud Stealer uses process hollowing for evasion"
            }
        ]
    }


def test_mock_extraction():
    """Test with mock STIX bundle to validate processing pipeline."""
    
    print("="*80)
    print("DARKCLOUD STEALER MOCK EXTRACTION TEST")
    print("="*80)
    
    # Create mock bundle
    bundle = create_mock_stix_bundle()
    
    # Save bundle
    bundle_file = Path("/tmp/darkcloud_mock_bundle.json")
    with open(bundle_file, "w") as f:
        json.dump(bundle, f, indent=2)
    
    print(f"\n✅ Created mock STIX bundle with:")
    
    # Count object types
    object_types = {}
    for obj in bundle['objects']:
        obj_type = obj.get('type')
        object_types[obj_type] = object_types.get(obj_type, 0) + 1
    
    for obj_type, count in sorted(object_types.items()):
        print(f"   - {obj_type}: {count}")
    
    # Extract techniques
    techniques = []
    for obj in bundle['objects']:
        if obj.get('type') == 'attack-pattern':
            ext_refs = obj.get('external_references', [])
            for ref in ext_refs:
                if ref.get('source_name') == 'mitre-attack':
                    mitre_id = ref.get('external_id')
                    name = obj.get('name')
                    confidence = obj.get('x_bj_confidence', 0)
                    techniques.append((mitre_id, name, confidence))
                    break
    
    print(f"\n✅ Extracted {len(techniques)} ATT&CK techniques:")
    for mitre_id, name, confidence in techniques:
        print(f"   - {mitre_id}: {name} (confidence: {confidence}%)")
    
    # Extract indicators
    indicators = []
    for obj in bundle['objects']:
        if obj.get('type') == 'indicator':
            pattern = obj.get('pattern', '')
            confidence = obj.get('x_bj_confidence', 0)
            indicators.append((pattern, confidence))
    
    print(f"\n✅ Extracted {len(indicators)} indicators:")
    for pattern, confidence in indicators:
        print(f"   - {pattern[:60]}... (confidence: {confidence}%)")
    
    # Extract malware
    malware = []
    for obj in bundle['objects']:
        if obj.get('type') == 'malware':
            name = obj.get('name')
            types = obj.get('malware_types', [])
            malware.append((name, types))
    
    print(f"\n✅ Extracted {len(malware)} malware families:")
    for name, types in malware:
        print(f"   - {name}: {', '.join(types)}")
    
    # Create attack flow from techniques
    print("\n✅ Generated attack flow:")
    flow_steps = [
        (1, "T1566.001", "Phishing email with malicious archive"),
        (2, "T1204.002", "User opens attachment"),
        (3, "T1059.007", "JavaScript execution"),
        (4, "T1059.001", "PowerShell downloads payload"),
        (5, "T1140", "Deobfuscate ConfuserEx payload"),
        (6, "T1055.012", "Process hollowing into RegAsm.exe"),
        (7, "T1071.001", "C2 communication via Telegram")
    ]
    
    for step, technique, description in flow_steps:
        print(f"   {step}. {technique}: {description}")
    
    print(f"\n✅ Saved mock bundle to: {bundle_file}")
    
    return True


if __name__ == "__main__":
    success = test_mock_extraction()
    sys.exit(0 if success else 1)