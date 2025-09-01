"""Unit tests for bundle validator with updated STIX compliance."""

import pytest
from bandjacks.llm.bundle_validator import (
    validate_bundle_for_upsert,
    validate_stix_object,
    validate_report,
    validate_relationship,
    validate_stix_id
)


class TestReportValidation:
    """Test Report SDO validation with object_refs requirements."""
    
    def test_report_requires_object_refs(self):
        """Report must have object_refs array."""
        report = {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--12345678-1234-1234-1234-123456789012",
            "name": "Test Report",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z"
            # Missing object_refs
        }
        
        errors = validate_report(report)
        assert any("object_refs" in err and "missing" in err.lower() for err in errors)
    
    def test_report_object_refs_must_be_non_empty(self):
        """Report object_refs must be non-empty."""
        report = {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--12345678-1234-1234-1234-123456789012",
            "name": "Test Report",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "object_refs": []  # Empty array
        }
        
        errors = validate_report(report)
        assert any("object_refs" in err and "non-empty" in err for err in errors)
    
    def test_report_validates_object_ref_ids(self):
        """Report object_refs must contain valid STIX IDs."""
        report = {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--12345678-1234-1234-1234-123456789012",
            "name": "Test Report",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "object_refs": [
                "attack-pattern--12345678-1234-1234-1234-123456789012",  # Valid
                "invalid-id",  # Invalid
                "campaign--not-a-uuid"  # Invalid UUID
            ]
        }
        
        errors = validate_report(report)
        assert any("Invalid STIX ID" in err for err in errors)
    
    def test_valid_report_passes(self):
        """Valid report with object_refs passes validation."""
        report = {
            "type": "report",
            "spec_version": "2.1",
            "id": "report--12345678-1234-1234-1234-123456789012",
            "name": "Test Report",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "object_refs": [
                "attack-pattern--12345678-1234-1234-1234-123456789012",
                "campaign--87654321-4321-4321-4321-210987654321"
            ]
        }
        
        errors = validate_report(report)
        assert len(errors) == 0


class TestRelationshipValidation:
    """Test STIX relationship validation with ADM compliance."""
    
    def test_attributed_to_is_allowed(self):
        """attributed-to relationship type is now allowed."""
        relationship = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--12345678-1234-1234-1234-123456789012",
            "relationship_type": "attributed-to",
            "source_ref": "campaign--12345678-1234-1234-1234-123456789012",
            "target_ref": "intrusion-set--87654321-4321-4321-4321-210987654321",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z"
        }
        
        errors = validate_relationship(relationship)
        # Should not have errors about relationship_type
        assert not any("relationship_type" in err for err in errors)
    
    def test_describes_is_disallowed(self):
        """describes relationship type is explicitly disallowed."""
        relationship = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--12345678-1234-1234-1234-123456789012",
            "relationship_type": "describes",
            "source_ref": "report--12345678-1234-1234-1234-123456789012",
            "target_ref": "attack-pattern--87654321-4321-4321-4321-210987654321",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z"
        }
        
        errors = validate_relationship(relationship)
        assert any("describes" in err and "disallowed" in err.lower() for err in errors)
    
    def test_time_bounded_relationships(self):
        """Relationships can have start_time and stop_time."""
        relationship = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--12345678-1234-1234-1234-123456789012",
            "relationship_type": "uses",
            "source_ref": "campaign--12345678-1234-1234-1234-123456789012",
            "target_ref": "attack-pattern--87654321-4321-4321-4321-210987654321",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "start_time": "2024-01-01T00:00:00Z",
            "stop_time": "2024-12-31T23:59:59Z"
        }
        
        errors = validate_relationship(relationship)
        # Should not have errors about time fields
        assert not any("start_time" in err or "stop_time" in err for err in errors)
    
    def test_invalid_time_fields_type(self):
        """Time fields must be strings."""
        relationship = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--12345678-1234-1234-1234-123456789012",
            "relationship_type": "uses",
            "source_ref": "campaign--12345678-1234-1234-1234-123456789012",
            "target_ref": "attack-pattern--87654321-4321-4321-4321-210987654321",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "start_time": 123456,  # Should be string
            "stop_time": ["2024-12-31"]  # Should be string
        }
        
        errors = validate_relationship(relationship)
        assert any("start_time" in err and "string" in err for err in errors)
        assert any("stop_time" in err and "string" in err for err in errors)


class TestBundleValidation:
    """Test full bundle validation."""
    
    def test_bundle_with_report_and_references(self):
        """Bundle with Report using object_refs instead of describes relationships."""
        bundle = {
            "type": "bundle",
            "id": "bundle--12345678-1234-1234-1234-123456789012",
            "objects": [
                {
                    "type": "report",
                    "spec_version": "2.1",
                    "id": "report--12345678-1234-1234-1234-123456789012",
                    "name": "APT Campaign Report",
                    "created": "2024-01-01T00:00:00Z",
                    "modified": "2024-01-01T00:00:00Z",
                    "object_refs": [
                        "campaign--87654321-4321-4321-4321-210987654321",
                        "attack-pattern--11111111-1111-1111-1111-111111111111"
                    ]
                },
                {
                    "type": "campaign",
                    "spec_version": "2.1",
                    "id": "campaign--87654321-4321-4321-4321-210987654321",
                    "name": "Operation Test",
                    "created": "2024-01-01T00:00:00Z",
                    "modified": "2024-01-01T00:00:00Z"
                },
                {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": "attack-pattern--11111111-1111-1111-1111-111111111111",
                    "name": "PowerShell",
                    "created": "2024-01-01T00:00:00Z",
                    "modified": "2024-01-01T00:00:00Z",
                    "external_references": [{
                        "source_name": "mitre-attack",
                        "external_id": "T1059.001",
                        "url": "https://attack.mitre.org/techniques/T1059/001"
                    }]
                },
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--22222222-2222-2222-2222-222222222222",
                    "relationship_type": "attributed-to",
                    "source_ref": "campaign--87654321-4321-4321-4321-210987654321",
                    "target_ref": "intrusion-set--33333333-3333-3333-3333-333333333333",
                    "created": "2024-01-01T00:00:00Z",
                    "modified": "2024-01-01T00:00:00Z",
                    "start_time": "2024-01-01T00:00:00Z",
                    "stop_time": "2024-06-30T00:00:00Z"
                }
            ]
        }
        
        is_valid, errors = validate_bundle_for_upsert(bundle)
        # Print errors for debugging if validation fails
        if not is_valid:
            print(f"Validation errors: {errors}")
        assert is_valid
        assert len(errors) == 0
    
    def test_bundle_rejects_describes_relationship(self):
        """Bundle with describes relationship should be rejected."""
        bundle = {
            "type": "bundle",
            "id": "bundle--12345678-1234-1234-1234-123456789012",
            "objects": [
                {
                    "type": "report",
                    "spec_version": "2.1",
                    "id": "report--12345678-1234-1234-1234-123456789012",
                    "name": "Test Report",
                    "created": "2024-01-01T00:00:00Z",
                    "modified": "2024-01-01T00:00:00Z",
                    "object_refs": ["attack-pattern--11111111-1111-1111-1111-111111111111"]
                },
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": "relationship--22222222-2222-2222-2222-222222222222",
                    "relationship_type": "describes",  # This should be rejected
                    "source_ref": "report--12345678-1234-1234-1234-123456789012",
                    "target_ref": "attack-pattern--11111111-1111-1111-1111-111111111111",
                    "created": "2024-01-01T00:00:00Z",
                    "modified": "2024-01-01T00:00:00Z"
                }
            ]
        }
        
        is_valid, errors = validate_bundle_for_upsert(bundle)
        assert not is_valid
        assert any("describes" in err and "disallowed" in err.lower() for err in errors)


class TestSTIXIDValidation:
    """Test STIX ID format validation."""
    
    def test_valid_stix_ids(self):
        """Valid STIX IDs pass validation."""
        valid_ids = [
            "attack-pattern--12345678-1234-1234-1234-123456789012",
            "campaign--87654321-4321-4321-4321-210987654321",
            "report--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "intrusion-set--00000000-0000-0000-0000-000000000000",
            "x-mitre-detection-strategy--12345678-1234-1234-1234-123456789012"
        ]
        
        for stix_id in valid_ids:
            assert validate_stix_id(stix_id), f"Failed to validate: {stix_id}"
    
    def test_invalid_stix_ids(self):
        """Invalid STIX IDs fail validation."""
        invalid_ids = [
            "not-a-stix-id",
            "attack-pattern-12345678-1234-1234-1234-123456789012",  # Single dash
            "attack-pattern--not-a-uuid",
            "attack-pattern--12345678-1234-1234-1234",  # Incomplete UUID
            "AttackPattern--12345678-1234-1234-1234-123456789012",  # Capital letters
            "--12345678-1234-1234-1234-123456789012",  # Missing type
        ]
        
        for stix_id in invalid_ids:
            assert not validate_stix_id(stix_id), f"Should not validate: {stix_id}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])