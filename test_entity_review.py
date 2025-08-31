#!/usr/bin/env python3
"""Test entity review workflow"""

import json
import requests
from datetime import datetime

# Configuration
API_BASE = "http://localhost:8000/v1"
REPORT_ID = "report--36db1e66-54c8-4aee-a2bc-a6993d3c2a58"

def test_entity_review():
    """Test the entity review workflow"""
    
    # 1. Get the report with entities
    print("1. Fetching report with entities...")
    response = requests.get(f"{API_BASE}/reports/{REPORT_ID}")
    if response.status_code != 200:
        print(f"Failed to fetch report: {response.status_code}")
        return
    
    report = response.json()
    entities = report.get("extraction", {}).get("entities", {})
    
    if not entities:
        print("No entities found in report")
        return
    
    print(f"Found entities: {json.dumps(entities, indent=2)}")
    
    # 2. Review the entities (approve DarkCloud, edit one)
    print("\n2. Submitting entity review...")
    reviewed_entities = entities.copy()
    
    # Mark DarkCloud as approved
    if reviewed_entities.get("malware"):
        for entity in reviewed_entities["malware"]:
            if isinstance(entity, dict):
                if entity.get("name") == "DarkCloud":
                    entity["review_status"] = "approved"
                    entity["verified"] = True
                    entity["review_notes"] = "Confirmed as primary malware"
                elif entity.get("name") == "DarkCloud Stealer":
                    entity["review_status"] = "approved"
                    entity["verified"] = True
                else:
                    entity["review_status"] = "rejected"
                    entity["review_notes"] = "Likely false positive"
    
    review_request = {
        "entities": reviewed_entities,
        "reviewer_id": "test-user",
        "timestamp": datetime.utcnow().isoformat(),
        "notes": "Test review of DarkCloud entities"
    }
    
    response = requests.post(
        f"{API_BASE}/reports/{REPORT_ID}/entities/review",
        json=review_request
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"Review submitted successfully:")
        print(f"  - Entities reviewed: {result.get('entities_reviewed')}")
        print(f"  - Approved: {result.get('entities_approved')}")
        print(f"  - Rejected: {result.get('entities_rejected')}")
    else:
        print(f"Failed to submit review: {response.status_code}")
        print(f"Error: {response.text}")
    
    # 3. Verify the review was saved
    print("\n3. Verifying review was saved...")
    response = requests.get(f"{API_BASE}/reports/{REPORT_ID}")
    if response.status_code == 200:
        updated_report = response.json()
        entity_review = updated_report.get("extraction", {}).get("entity_review", {})
        if entity_review:
            print(f"Entity review saved:")
            print(f"  - Reviewer: {entity_review.get('reviewer_id')}")
            print(f"  - Reviewed at: {entity_review.get('reviewed_at')}")
            print(f"  - Statistics: {entity_review.get('statistics')}")
        else:
            print("No entity review found in updated report")
    
    print("\n✅ Entity review workflow test completed!")

if __name__ == "__main__":
    test_entity_review()
