#!/usr/bin/env python3
"""Test STIX bundle validation for graph upsert compatibility."""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from bandjacks.llm.bundle_validator import validate_bundle_for_upsert, print_validation_report


def test_valid_bundle():
    """Test a valid bundle."""
    
    print("="*80)
    print("TEST 1: Valid Bundle")
    print("="*80)
    
    valid_bundle = {
        "type": "bundle",
        "id": "bundle--12345678-1234-1234-1234-123456789abc",
        "spec_version": "2.1",
        "created": "2024-01-01T00:00:00.000Z",
        "objects": [
            {
                "type": "report",
                "id": "report--12345678-1234-1234-1234-123456789abc",
                "spec_version": "2.1",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "name": "Test Report",
                "object_refs": ["attack-pattern--12345678-1234-1234-1234-123456789abc"]
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--12345678-1234-1234-1234-123456789abc",
                "spec_version": "2.1",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "name": "PowerShell",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": "T1059.001",
                        "url": "https://attack.mitre.org/techniques/T1059/001/"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": "execution"
                    }
                ],
                "x_bj_confidence": 85,
                "x_bj_evidence": "PowerShell commands were executed"
            }
        ]
    }
    
    is_valid = print_validation_report(valid_bundle)
    assert is_valid, "Valid bundle should pass validation"
    

def test_invalid_bundle():
    """Test an invalid bundle."""
    
    print("\n" + "="*80)
    print("TEST 2: Invalid Bundle (Missing Required Fields)")
    print("="*80)
    
    invalid_bundle = {
        "type": "bundle",
        "id": "bundle--12345678-1234-1234-1234-123456789abc",
        "spec_version": "2.1",
        "created": "2024-01-01T00:00:00.000Z",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--12345678-1234-1234-1234-123456789abc",
                # Missing spec_version, created, modified
                "name": "PowerShell",
                # Missing external_references with MITRE ID
            }
        ]
    }
    
    is_valid = print_validation_report(invalid_bundle)
    assert not is_valid, "Invalid bundle should fail validation"


def test_agentic_v2_bundle():
    """Test a bundle from agentic_v2 extraction."""
    
    print("\n" + "="*80)
    print("TEST 3: Agentic_v2 Generated Bundle")
    print("="*80)
    
    # Simulate output from AssemblerAgent
    from bandjacks.llm.memory import WorkingMemory
    from bandjacks.llm.agents_v2 import AssemblerAgent
    
    # Create mock memory with techniques
    mem = WorkingMemory()
    mem.techniques = {
        "T1566.001": {
            "name": "Spearphishing Attachment",
            "confidence": 90,
            "evidence": ["APT29 used spearphishing emails"],
            "line_refs": [1, 2],
            "tactic": "initial-access"
        },
        "T1059.001": {
            "name": "PowerShell",
            "confidence": 85,
            "evidence": ["executed PowerShell commands"],
            "line_refs": [5, 6],
            "tactic": "execution"
        }
    }
    
    # Create config
    config = {
        "neo4j_uri": "bolt://localhost:7687",
        "neo4j_user": "neo4j",
        "neo4j_password": "password",
        "title": "Test Report",
        "url": "https://example.com/report",
        "model": "gemini/gemini-2.5-flash",
        "build_flow": False
    }
    
    # Run assembler
    assembler = AssemblerAgent()
    result = assembler.run(mem, config)
    
    bundle = result["bundle"]
    
    # Validate
    is_valid = print_validation_report(bundle)
    
    if is_valid:
        print("\n✅ Agentic_v2 bundle is valid for graph upsert")
    else:
        print("\n❌ Agentic_v2 bundle needs fixes")
        
        # Save for debugging
        with open("/tmp/agentic_v2_bundle.json", "w") as f:
            json.dump(bundle, f, indent=2)
        print("   Bundle saved to /tmp/agentic_v2_bundle.json for debugging")
    
    return is_valid


def main():
    """Run all validation tests."""
    
    print("STIX BUNDLE VALIDATION TESTS")
    print("="*80)
    
    try:
        test_valid_bundle()
        print("✅ Test 1 passed")
    except AssertionError as e:
        print(f"❌ Test 1 failed: {e}")
        return 1
    
    try:
        test_invalid_bundle()
        print("✅ Test 2 passed")
    except AssertionError as e:
        print(f"❌ Test 2 failed: {e}")
        return 1
    
    agentic_valid = test_agentic_v2_bundle()
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    if agentic_valid:
        print("✅ All tests passed - bundles are compatible with graph upsert")
    else:
        print("⚠️ Agentic_v2 bundles need adjustment")
    
    return 0 if agentic_valid else 1


if __name__ == "__main__":
    sys.exit(main())