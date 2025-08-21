#!/usr/bin/env python3
"""Examples for Sprint 5 detection management features."""

import requests
import json
from typing import Dict, Any, List

BASE_URL = "http://localhost:8000/v1"


def ingest_detection_bundle():
    """Example: Ingest a detection strategies bundle."""
    
    bundle = {
        "type": "bundle",
        "id": "bundle--detection-001",
        "spec_version": "2.1",
        "objects": [
            {
                "type": "x-mitre-detection-strategy",
                "id": "x-mitre-detection-strategy--12345678-1234-5678-1234-567812345678",
                "spec_version": "2.1",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "name": "Process Injection Detection",
                "description": "Detects various process injection techniques",
                "x_mitre_version": "1.0",
                "x_mitre_analytics": [
                    "x-mitre-analytic--23456789-2345-6789-2345-678923456789"
                ]
            },
            {
                "type": "x-mitre-analytic",
                "id": "x-mitre-analytic--23456789-2345-6789-2345-678923456789",
                "spec_version": "2.1",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "name": "Sysmon Process Access Events",
                "description": "Analyzes Sysmon Event ID 10",
                "x_mitre_version": "1.0",
                "x_mitre_platforms": ["Windows"],
                "x_mitre_detects": ["attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d"],
                "x_mitre_log_sources": [
                    "x-mitre-log-source--34567890-3456-7890-3456-789034567890"
                ]
            },
            {
                "type": "x-mitre-log-source",
                "id": "x-mitre-log-source--34567890-3456-7890-3456-789034567890",
                "spec_version": "2.1",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "name": "Windows Sysmon",
                "x_mitre_version": "1.0",
                "x_mitre_log_source_type": "application",
                "x_mitre_log_source_permutations": [
                    {
                        "event_id": 10,
                        "event_name": "ProcessAccess"
                    }
                ]
            },
            {
                "type": "relationship",
                "id": "relationship--45678901-4567-8901-4567-890145678901",
                "spec_version": "2.1",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "relationship_type": "detects",
                "source_ref": "x-mitre-detection-strategy--12345678-1234-5678-1234-567812345678",
                "target_ref": "attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d"
            }
        ]
    }
    
    response = requests.post(
        f"{BASE_URL}/detections/ingest",
        json={
            "bundle": bundle,
            "collection": "custom-detections",
            "version": "1.0",
            "strict_validation": True
        }
    )
    
    if response.status_code == 201:
        result = response.json()
        print(f"✓ Ingested {result['detection_strategies']} strategies")
        print(f"✓ Ingested {result['analytics']} analytics")
        print(f"✓ Ingested {result['log_sources']} log sources")
        print(f"✓ Created {result['detects_relationships']} DETECTS relationships")
    else:
        print(f"✗ Failed: {response.status_code}")
        print(response.json())


def query_detection_strategies():
    """Example: Query detection strategies for a technique."""
    
    params = {
        "technique": "T1055",  # Process Injection
        "platform": "windows",
        "include_revoked": False,
        "limit": 10
    }
    
    response = requests.get(
        f"{BASE_URL}/detections/strategies",
        params=params
    )
    
    if response.status_code == 200:
        strategies = response.json()
        print(f"\nFound {len(strategies)} detection strategies for T1055:")
        
        for strategy in strategies:
            print(f"\n- {strategy['name']}")
            print(f"  ID: {strategy['stix_id']}")
            print(f"  Analytics: {len(strategy.get('analytics', []))}")
            print(f"  Confidence: {strategy.get('confidence', 'N/A')}")
    else:
        print(f"✗ Failed: {response.status_code}")


def get_analytic_details():
    """Example: Get detailed information about an analytic."""
    
    analytic_id = "x-mitre-analytic--23456789-2345-6789-2345-678923456789"
    
    response = requests.get(
        f"{BASE_URL}/detections/analytics/{analytic_id}"
    )
    
    if response.status_code == 200:
        analytic = response.json()
        print(f"\nAnalytic: {analytic['name']}")
        print(f"Description: {analytic['description']}")
        print(f"Platforms: {', '.join(analytic.get('platforms', []))}")
        print(f"Log Sources: {len(analytic.get('log_sources', []))}")
        print(f"Detects: {len(analytic.get('detects_techniques', []))}")
    else:
        print(f"✗ Failed: {response.status_code}")


def check_technique_coverage():
    """Example: Check complete coverage for a technique."""
    
    technique_id = "T1055"
    
    response = requests.get(
        f"{BASE_URL}/coverage/technique/{technique_id}"
    )
    
    if response.status_code == 200:
        coverage = response.json()
        print(f"\nCoverage Analysis for {technique_id}:")
        print(f"Technique: {coverage['technique_name']}")
        print(f"Coverage Score: {coverage['coverage_score']:.1%}")
        
        print("\nDetection Coverage:")
        det = coverage['detection_coverage']
        print(f"  - Strategies: {det['strategy_count']}")
        print(f"  - Analytics: {det['analytic_count']}")
        print(f"  - Log Sources: {det['log_source_count']}")
        print(f"  - Has Detections: {det['has_detections']}")
        
        print("\nMitigation Coverage:")
        mit = coverage['mitigation_coverage']
        print(f"  - Mitigations: {mit['mitigation_count']}")
        print(f"  - Has Mitigations: {mit['has_mitigations']}")
        
        print("\nD3FEND Coverage:")
        d3f = coverage['d3fend_coverage']
        print(f"  - Techniques: {d3f['d3fend_count']}")
        print(f"  - Artifacts: {d3f['artifact_count']}")
        print(f"  - Has D3FEND: {d3f['has_d3fend']}")
        
        if coverage['coverage_gaps']:
            print("\nCoverage Gaps:")
            for gap in coverage['coverage_gaps']:
                print(f"  - {gap}")
        
        if coverage['recommendations']:
            print("\nRecommendations:")
            for rec in coverage['recommendations']:
                print(f"  - {rec}")
    else:
        print(f"✗ Failed: {response.status_code}")


def analyze_coverage_gaps():
    """Example: Analyze coverage gaps across the framework."""
    
    request_body = {
        "scope": "tactics",
        "threshold": 0.5,
        "priority_tactics": ["initial-access", "execution", "persistence"]
    }
    
    response = requests.post(
        f"{BASE_URL}/coverage/gap-analysis",
        json=request_body
    )
    
    if response.status_code == 200:
        analysis = response.json()
        
        print("\nCritical Coverage Gaps:")
        for gap in analysis['critical_gaps'][:5]:
            print(f"- {gap['technique_name']} ({gap['technique_id']})")
            print(f"  Gap Type: {gap['gap_type']}")
            print(f"  Priority: {gap['priority']}")
        
        print("\nPriority Improvements:")
        for improvement in analysis['priority_improvements'][:3]:
            print(f"- {improvement['recommended_action']}")
            print(f"  Techniques: {improvement['techniques_count']}")
            print(f"  Expected Impact: +{improvement['expected_coverage_increase']}%")
        
        print("\nEstimated Impact:")
        impact = analysis['estimated_impact']
        print(f"  Total Coverage Increase: {impact['total_coverage_increase']}%")
        print(f"  Techniques Addressed: {impact['techniques_addressed']}")
        print(f"  Effort Estimate: {impact['effort_estimate']}")
    else:
        print(f"✗ Failed: {response.status_code}")


if __name__ == "__main__":
    print("Sprint 5 Detection Management Examples")
    print("=" * 50)
    
    # Run examples
    print("\n1. Ingesting Detection Bundle")
    ingest_detection_bundle()
    
    print("\n2. Querying Detection Strategies")
    query_detection_strategies()
    
    print("\n3. Getting Analytic Details")
    get_analytic_details()
    
    print("\n4. Checking Technique Coverage")
    check_technique_coverage()
    
    print("\n5. Analyzing Coverage Gaps")
    analyze_coverage_gaps()