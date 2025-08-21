#!/usr/bin/env python3
"""Non-mocked acceptance tests for D3FEND defense integration."""

import os
import sys
import uuid
import time
import requests
from typing import Dict, Any

# Ensure bandjacks is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from bandjacks.loaders.d3fend_verifier import D3FENDVerifier
from bandjacks.monitoring.defense_metrics import get_defense_metrics, reset_defense_metrics


# Test configuration
API_BASE_URL = "http://localhost:8000/v1"
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")


def test_d3fend_initialization():
    """Test D3FEND ontology initialization."""
    print("\n" + "="*60)
    print("TEST: D3FEND Initialization")
    print("="*60)
    
    # Initialize D3FEND
    response = requests.post(f"{API_BASE_URL}/defense/initialize")
    assert response.status_code == 200, f"Failed to initialize D3FEND: {response.text}"
    
    result = response.json()
    assert result["success"], "D3FEND initialization failed"
    assert result["d3fend_techniques"] > 0, "No D3FEND techniques loaded"
    assert result["nodes_created"] > 0, "No nodes created"
    assert result["relationships_created"] > 0, "No relationships created"
    
    print(f"✓ Loaded {result['d3fend_techniques']} D3FEND techniques")
    print(f"✓ Created {result['nodes_created']} nodes")
    print(f"✓ Created {result['relationships_created']} relationships")
    
    return True


def test_d3fend_verification():
    """Test D3FEND coverage verification for critical techniques."""
    print("\n" + "="*60)
    print("TEST: D3FEND Coverage Verification")
    print("="*60)
    
    verifier = D3FENDVerifier(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
    
    try:
        # Run verification
        report = verifier.run_full_verification()
        
        # Check coverage report
        coverage = report["coverage"]
        print(f"\nCoverage Report:")
        print(f"  Checked: {len(coverage['checked_techniques'])} techniques")
        print(f"  Covered: {len(coverage['covered_techniques'])} techniques")
        print(f"  Coverage: {coverage['coverage_percentage']:.1f}%")
        
        # Show sample covered techniques
        for tech in coverage['checked_techniques'][:3]:
            print(f"  - {tech['id']}: {tech['name']} ({tech['counter_count']} counters)")
        
        # Check quality metrics
        quality = report["quality"]
        print(f"\nQuality Metrics:")
        print(f"  Avg counters per technique: {quality['avg_counters_per_technique']}")
        print(f"  Adequacy percentage: {quality['adequacy_percentage']:.1f}%")
        
        # Assert critical techniques are covered
        assert coverage["verification_passed"], "Critical techniques lack defensive counters"
        assert coverage["coverage_percentage"] >= 80, f"Coverage too low: {coverage['coverage_percentage']}%"
        
        print(f"\n✓ D3FEND verification {'PASSED' if report['overall_passed'] else 'FAILED'}")
        
        return report["overall_passed"]
        
    finally:
        verifier.close()


def test_build_small_flow():
    """Build a small attack flow for testing."""
    print("\n" + "="*60)
    print("TEST: Build Small Attack Flow")
    print("="*60)
    
    # Define a simple flow with known techniques
    flow_data = {
        "extraction": {
            "techniques": {
                "T1566.001": {
                    "name": "Spearphishing Attachment",
                    "confidence": 95,
                    "evidence": ["Malicious email with PDF attachment"]
                },
                "T1059.001": {
                    "name": "PowerShell",
                    "confidence": 90,
                    "evidence": ["PowerShell scripts executed"]
                },
                "T1003.001": {
                    "name": "LSASS Memory",
                    "confidence": 85,
                    "evidence": ["Mimikatz used to dump credentials"]
                }
            }
        },
        "source_id": f"test-source-{uuid.uuid4()}"
    }
    
    # Build the flow
    response = requests.post(
        f"{API_BASE_URL}/flows/build",
        json=flow_data
    )
    
    assert response.status_code == 200, f"Failed to build flow: {response.text}"
    
    result = response.json()
    flow_id = result["flow_id"]
    
    print(f"✓ Built flow: {flow_id}")
    print(f"  Steps: {result['steps_count']}")
    print(f"  Edges: {result['edges_count']}")
    
    return flow_id


def test_defense_overlay(flow_id: str):
    """Test defense overlay returns non-empty defenses."""
    print("\n" + "="*60)
    print("TEST: Defense Overlay")
    print("="*60)
    
    # Reset metrics before test
    reset_defense_metrics()
    
    # Get defense overlay
    response = requests.get(f"{API_BASE_URL}/defense/overlay/{flow_id}")
    assert response.status_code == 200, f"Failed to get overlay: {response.text}"
    
    overlay = response.json()
    
    print(f"Flow: {flow_id}")
    print(f"  Total actions: {overlay['total_actions']}")
    print(f"  Defended actions: {overlay['defended_actions']}")
    print(f"  Coverage: {overlay['coverage_percentage']:.1f}%")
    
    # Assert we have defenses
    assert overlay["defended_actions"] > 0, "No actions have defenses"
    assert overlay["coverage_percentage"] > 0, "Zero coverage percentage"
    
    # Check specific defenses
    total_defenses = 0
    for action in overlay["defenses_by_action"]:
        defense_count = action["defense_count"]
        total_defenses += defense_count
        
        if defense_count > 0:
            print(f"\n  Action: {action['attack_technique']['name']}")
            print(f"    Defenses: {defense_count}")
            for defense in action["defenses"][:2]:  # Show first 2
                print(f"    - {defense['name']} ({defense['category']})")
    
    assert total_defenses > 0, "No defenses returned across all actions"
    
    print(f"\n✓ Total defenses returned: {total_defenses}")
    
    return overlay


def test_mincut_improvement(flow_id: str):
    """Test mincut improves coverage."""
    print("\n" + "="*60)
    print("TEST: Minimal Defense Set (Mincut)")
    print("="*60)
    
    # Get mincut recommendations
    response = requests.post(
        f"{API_BASE_URL}/defense/mincut",
        json={"flow_id": flow_id, "budget": 5}
    )
    
    assert response.status_code == 200, f"Failed to compute mincut: {response.text}"
    
    mincut = response.json()
    
    print(f"Flow: {flow_id}")
    print(f"  Attack techniques: {mincut['total_attack_techniques']}")
    print(f"  Covered techniques: {mincut['covered_techniques']}")
    print(f"  Coverage: {mincut['coverage_percentage']:.1f}%")
    print(f"  Recommendations: {mincut['defense_count']}")
    
    # Assert coverage improvement
    assert mincut["covered_techniques"] > 0, "No techniques covered"
    assert mincut["coverage_percentage"] > 0, "Zero coverage"
    assert len(mincut["recommendations"]) > 0, "No recommendations provided"
    
    # Show recommendations
    print("\nRecommended defenses:")
    for rec in mincut["recommendations"]:
        print(f"  - {rec['name']} ({rec['category']})")
        print(f"    Covers {rec['covers_count']} techniques")
    
    # Assert high impact
    assert mincut["expected_impact"]["high"] or mincut["coverage_percentage"] >= 60, \
        f"Low impact: only {mincut['coverage_percentage']:.1f}% coverage"
    
    print(f"\n✓ Mincut provides {mincut['coverage_percentage']:.1f}% coverage with {mincut['defense_count']} defenses")
    
    return mincut


def test_defense_metrics():
    """Test that metrics are collected properly."""
    print("\n" + "="*60)
    print("TEST: Defense Metrics Collection")
    print("="*60)
    
    # Get current metrics
    response = requests.get(f"{API_BASE_URL}/defense/metrics")
    assert response.status_code == 200, f"Failed to get metrics: {response.text}"
    
    metrics = response.json()
    
    print("Metrics collected:")
    print(f"  Overlay calls: {metrics['overlay_calls_total']}")
    print(f"  Mincut calls: {metrics['mincut_calls_total']}")
    print(f"  Defenses returned: {metrics['defenses_returned_total']}")
    print(f"  Avg counters per step: {metrics['avg_counters_per_step']:.2f}")
    print(f"  Mincut coverage delta: {metrics['mincut_coverage_delta']:.1f}%")
    print(f"  Mincut recommendation size: {metrics['mincut_recommendation_size']:.1f}")
    
    # Assert metrics were collected
    assert metrics["overlay_calls_total"] > 0, "No overlay calls recorded"
    assert metrics["mincut_calls_total"] > 0, "No mincut calls recorded"
    assert metrics["defenses_returned_total"] > 0, "No defenses recorded"
    
    # Check latencies
    print(f"\nLatencies:")
    print(f"  Overlay P50: {metrics['overlay_latency_p50']:.1f}ms")
    print(f"  Overlay P95: {metrics['overlay_latency_p95']:.1f}ms")
    print(f"  Mincut P50: {metrics['mincut_latency_p50']:.1f}ms")
    print(f"  Mincut P95: {metrics['mincut_latency_p95']:.1f}ms")
    
    print("\n✓ Metrics are being collected correctly")
    
    return metrics


def test_attack_flow_export(flow_id: str):
    """Test Attack Flow 2.0 export functionality."""
    print("\n" + "="*60)
    print("TEST: Attack Flow Export")
    print("="*60)
    
    # Export the flow
    response = requests.get(f"{API_BASE_URL}/flows/{flow_id}/export")
    assert response.status_code == 200, f"Failed to export flow: {response.text}"
    
    export_data = response.json()
    attack_flow = export_data["attack_flow"]
    metadata = export_data["export_metadata"]
    
    print(f"Exported flow: {flow_id}")
    print(f"  Format: {metadata['format']}")
    print(f"  Spec version: {metadata['spec_version']}")
    print(f"  Objects: {metadata['object_count']}")
    print(f"  Warnings: {len(metadata['warnings'])}")
    
    # Validate structure
    assert attack_flow["type"] == "bundle", "Not a valid bundle"
    assert attack_flow["spec_version"] == "2.1", "Wrong spec version"
    assert len(attack_flow["objects"]) > 0, "No objects in bundle"
    
    # Check for required object types
    has_flow = False
    has_actions = False
    
    for obj in attack_flow["objects"]:
        if obj["type"] == "attack-flow":
            has_flow = True
        elif obj["type"] == "attack-action":
            has_actions = True
    
    assert has_flow, "No attack-flow object in export"
    assert has_actions, "No attack-action objects in export"
    
    if metadata["warnings"]:
        print("\nExport warnings:")
        for warning in metadata["warnings"]:
            print(f"  ⚠ {warning}")
    
    print(f"\n✓ Successfully exported to Attack Flow 2.0 format")
    
    return attack_flow


def run_all_tests():
    """Run all acceptance tests."""
    print("\n" + "="*80)
    print("DEFENSE INTEGRATION ACCEPTANCE TESTS")
    print("="*80)
    
    try:
        # Test 1: Initialize D3FEND
        test_d3fend_initialization()
        
        # Test 2: Verify coverage
        test_d3fend_verification()
        
        # Test 3: Build a flow
        flow_id = test_build_small_flow()
        
        # Wait for flow to be fully persisted
        time.sleep(1)
        
        # Test 4: Get defense overlay
        overlay = test_defense_overlay(flow_id)
        
        # Test 5: Compute mincut
        mincut = test_mincut_improvement(flow_id)
        
        # Test 6: Check metrics
        metrics = test_defense_metrics()
        
        # Test 7: Export flow
        attack_flow = test_attack_flow_export(flow_id)
        
        print("\n" + "="*80)
        print("✅ ALL ACCEPTANCE TESTS PASSED")
        print("="*80)
        
        # Summary
        print("\nTest Summary:")
        print(f"  Flow ID: {flow_id}")
        print(f"  Defense coverage: {overlay['coverage_percentage']:.1f}%")
        print(f"  Mincut improvement: {mincut['coverage_percentage']:.1f}%")
        print(f"  Metrics collected: {metrics['overlay_calls_total'] + metrics['mincut_calls_total']} API calls")
        print(f"  Export objects: {len(attack_flow['objects'])}")
        
        return True
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return False
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    # Check if services are running
    try:
        response = requests.get(f"{API_BASE_URL}/health")
        if response.status_code != 200:
            print("⚠️  API server not responding. Please start the server first:")
            print("   uv run uvicorn bandjacks.services.api.main:app --reload --port 8000")
            sys.exit(1)
    except:
        print("⚠️  Cannot connect to API server at http://localhost:8000")
        print("   Please start the server first:")
        print("   uv run uvicorn bandjacks.services.api.main:app --reload --port 8000")
        sys.exit(1)
    
    # Run tests
    success = run_all_tests()
    sys.exit(0 if success else 1)