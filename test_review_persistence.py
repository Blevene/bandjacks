#!/usr/bin/env python3
"""Test script to verify review decision persistence."""

import requests
import json
import sys

# Configuration
BASE_URL = "http://localhost:8000/v1"
REPORT_ID = sys.argv[1] if len(sys.argv) > 1 else None

if not REPORT_ID:
    print("Usage: python test_review_persistence.py <report_id>")
    print("\nFetching available reports...")

    response = requests.get(f"{BASE_URL}/reports")
    if response.ok:
        reports = response.json().get('reports', [])
        if reports:
            print("\nAvailable reports:")
            for report in reports[:5]:
                print(f"  - {report['report_id']}: {report['name']}")
            print("\nRun again with a report ID to test persistence")
    else:
        print("Failed to fetch reports")
    sys.exit(1)

print(f"\nTesting review persistence for report: {REPORT_ID}")

# Step 1: Get the report
print("\n1. Fetching report...")
response = requests.get(f"{BASE_URL}/reports/{REPORT_ID}")
if not response.ok:
    print(f"Failed to fetch report: {response.status_code}")
    sys.exit(1)

report = response.json()
print(f"   Report name: {report.get('name', 'Unknown')}")

# Check extraction data
extraction = report.get('extraction', {})
claims = extraction.get('claims', [])
entities_data = extraction.get('entities', {})
entities = entities_data.get('entities', []) if isinstance(entities_data, dict) else []
flow = extraction.get('flow', {})
flow_steps = flow.get('steps', [])

print(f"\n   Extraction summary:")
print(f"   - Entities: {len(entities)}")
print(f"   - Techniques: {len(claims)}")
print(f"   - Flow steps: {len(flow_steps)}")

# Step 2: Test saving a review decision for each type
test_decisions = []

if entities:
    entity = entities[0]
    print(f"\n2. Testing entity review persistence...")
    print(f"   Entity: {entity.get('name')} (type: {entity.get('type')})")
    print(f"   Current status: {entity.get('review_status', 'pending')}")

    decision = {
        "item_id": f"entity-{entity.get('type')}-0",
        "action": "approved",
        "notes": "Test approval",
        "timestamp": "2024-01-01T00:00:00Z"
    }

    response = requests.patch(
        f"{BASE_URL}/reports/{REPORT_ID}/review-decision",
        json=decision
    )

    if response.ok:
        print("   ✓ Entity decision saved successfully")
        test_decisions.append(("entity", 0))
    else:
        print(f"   ✗ Failed to save entity decision: {response.text}")

if claims:
    claim = claims[0]
    print(f"\n3. Testing technique review persistence...")
    print(f"   Technique: {claim.get('external_id')} - {claim.get('name')}")
    print(f"   Current status: {claim.get('review_status', 'pending')}")

    decision = {
        "item_id": "technique-0",
        "action": "rejected",
        "notes": "Test rejection",
        "timestamp": "2024-01-01T00:00:01Z"
    }

    response = requests.patch(
        f"{BASE_URL}/reports/{REPORT_ID}/review-decision",
        json=decision
    )

    if response.ok:
        print("   ✓ Technique decision saved successfully")
        test_decisions.append(("technique", 0))
    else:
        print(f"   ✗ Failed to save technique decision: {response.text}")

if flow_steps:
    step = flow_steps[0]
    step_id = step.get('action_id') or step.get('step_id', 'step-0')
    print(f"\n4. Testing flow step review persistence...")
    print(f"   Step: {step.get('name')}")
    print(f"   Current status: {step.get('review_status', 'pending')}")

    decision = {
        "item_id": f"flow-{step_id}",
        "action": "approved",
        "notes": "Test flow approval",
        "timestamp": "2024-01-01T00:00:02Z"
    }

    response = requests.patch(
        f"{BASE_URL}/reports/{REPORT_ID}/review-decision",
        json=decision
    )

    if response.ok:
        print("   ✓ Flow step decision saved successfully")
        test_decisions.append(("flow", 0))
    else:
        print(f"   ✗ Failed to save flow step decision: {response.text}")

# Step 3: Verify persistence by fetching the report again
print(f"\n5. Verifying persistence by re-fetching report...")
response = requests.get(f"{BASE_URL}/reports/{REPORT_ID}")
if not response.ok:
    print(f"Failed to re-fetch report: {response.status_code}")
    sys.exit(1)

updated_report = response.json()
updated_extraction = updated_report.get('extraction', {})

# Check if review statuses are persisted
print("\n   Checking persisted review statuses:")

for item_type, index in test_decisions:
    if item_type == "entity":
        updated_entities_data = updated_extraction.get('entities', {})
        updated_entities = updated_entities_data.get('entities', []) if isinstance(updated_entities_data, dict) else []
        if index < len(updated_entities):
            entity = updated_entities[index]
            status = entity.get('review_status', 'pending')
            notes = entity.get('review_notes', '')
            print(f"   - Entity[{index}]: status='{status}', notes='{notes}'")
            if status == 'approved':
                print("     ✓ Entity review status persisted correctly!")
            else:
                print("     ✗ Entity review status NOT persisted")

    elif item_type == "technique":
        updated_claims = updated_extraction.get('claims', [])
        if index < len(updated_claims):
            claim = updated_claims[index]
            status = claim.get('review_status', 'pending')
            notes = claim.get('review_notes', '')
            print(f"   - Technique[{index}]: status='{status}', notes='{notes}'")
            if status == 'rejected':
                print("     ✓ Technique review status persisted correctly!")
            else:
                print("     ✗ Technique review status NOT persisted")

    elif item_type == "flow":
        updated_flow = updated_extraction.get('flow', {})
        updated_steps = updated_flow.get('steps', [])
        if index < len(updated_steps):
            step = updated_steps[index]
            status = step.get('review_status', 'pending')
            notes = step.get('review_notes', '')
            print(f"   - Flow Step[{index}]: status='{status}', notes='{notes}'")
            if status == 'approved':
                print("     ✓ Flow step review status persisted correctly!")
            else:
                print("     ✗ Flow step review status NOT persisted")

print("\n✅ Review persistence test complete!")