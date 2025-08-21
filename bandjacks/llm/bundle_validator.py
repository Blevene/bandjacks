"""Validate STIX bundles before graph upsert."""

import re
from typing import Dict, Any, List, Tuple


def validate_bundle_for_upsert(bundle: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate that a STIX bundle is properly formatted for graph upsert.
    
    Args:
        bundle: STIX 2.1 bundle to validate
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    # Check bundle structure
    if not isinstance(bundle, dict):
        errors.append("Bundle must be a dictionary")
        return False, errors
    
    if bundle.get("type") != "bundle":
        errors.append("Bundle must have type='bundle'")
    
    if "objects" not in bundle:
        errors.append("Bundle must have 'objects' array")
        return False, errors
    
    objects = bundle.get("objects", [])
    if not isinstance(objects, list):
        errors.append("Bundle 'objects' must be an array")
        return False, errors
    
    # Validate each object
    for i, obj in enumerate(objects):
        obj_errors = validate_stix_object(obj)
        for err in obj_errors:
            errors.append(f"Object {i} ({obj.get('type', 'unknown')}): {err}")
    
    return len(errors) == 0, errors


def validate_stix_object(obj: Dict[str, Any]) -> List[str]:
    """
    Validate a single STIX object with strict ADM compliance.
    
    Args:
        obj: STIX object to validate
        
    Returns:
        List of validation errors
    """
    errors = []
    
    # Required fields for all STIX objects
    if not obj.get("type"):
        errors.append("Missing 'type' field")
    
    if not obj.get("id"):
        errors.append("Missing 'id' field")
    elif not validate_stix_id(obj["id"], obj.get("type")):
        errors.append(f"Invalid STIX ID format: {obj['id']}")
    
    # STRICT: Enforce spec_version == "2.1" for all SDO/SRO
    if not obj.get("spec_version"):
        errors.append("Missing 'spec_version' field (STIX 2.1 required)")
    elif obj["spec_version"] != "2.1":
        errors.append(f"Invalid spec_version: {obj['spec_version']} (must be exactly '2.1' for ADM compliance)")
    
    if not obj.get("created"):
        errors.append("Missing 'created' timestamp")
    
    if not obj.get("modified"):
        errors.append("Missing 'modified' timestamp")
    
    # Type-specific validation
    obj_type = obj.get("type")
    
    if obj_type == "attack-pattern":
        errors.extend(validate_attack_pattern(obj))
    elif obj_type == "report":
        errors.extend(validate_report(obj))
    elif obj_type == "intrusion-set":
        errors.extend(validate_intrusion_set(obj))
    elif obj_type == "malware":
        errors.extend(validate_malware(obj))
    elif obj_type == "tool":
        errors.extend(validate_tool(obj))
    elif obj_type == "indicator":
        errors.extend(validate_indicator(obj))
    elif obj_type == "vulnerability":
        errors.extend(validate_vulnerability(obj))
    elif obj_type == "relationship":
        errors.extend(validate_relationship(obj))
    
    return errors


def validate_stix_id(stix_id: str, obj_type: str = None) -> bool:
    """
    Validate STIX ID format.
    
    Args:
        stix_id: STIX ID to validate
        obj_type: Expected object type
        
    Returns:
        True if valid
    """
    # STIX ID format: type--uuid
    pattern = r"^[a-z][a-z-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    if not re.match(pattern, stix_id):
        return False
    
    if obj_type:
        id_type = stix_id.split("--")[0]
        return id_type == obj_type
    
    return True


def validate_attack_pattern(obj: Dict[str, Any]) -> List[str]:
    """Validate attack-pattern specific fields with strict ADM compliance."""
    errors = []
    
    if not obj.get("name"):
        errors.append("Attack pattern missing 'name'")
    
    # Check for external_references with MITRE ID (ADM requirement)
    ext_refs = obj.get("external_references", [])
    if not ext_refs:
        errors.append("Attack pattern missing 'external_references' array (required by ADM)")
    
    has_mitre_ref = False
    
    for ref in ext_refs:
        if ref.get("source_name") == "mitre-attack":
            has_mitre_ref = True
            
            # Validate required fields in MITRE reference
            if not ref.get("external_id"):
                errors.append("MITRE reference missing 'external_id'")
            elif not re.match(r"^T\d{4}(\.\d{3})?$", ref["external_id"]):
                errors.append(f"Invalid MITRE technique ID format: {ref['external_id']} (expected Txxxx or Txxxx.yyy)")
            
            if not ref.get("url"):
                errors.append("MITRE reference missing 'url' field")
            elif not ref["url"].startswith("https://attack.mitre.org/"):
                errors.append(f"Invalid MITRE URL: {ref['url']} (must start with https://attack.mitre.org/)")
    
    if not has_mitre_ref:
        errors.append("Attack pattern missing MITRE ATT&CK external reference (required by ADM)")
    
    # Validate kill_chain_phases if present
    if "kill_chain_phases" in obj:
        phases = obj["kill_chain_phases"]
        if not isinstance(phases, list):
            errors.append("kill_chain_phases must be an array")
        else:
            for phase in phases:
                if not phase.get("kill_chain_name"):
                    errors.append("kill_chain_phase missing 'kill_chain_name'")
                if not phase.get("phase_name"):
                    errors.append("kill_chain_phase missing 'phase_name'")
    
    return errors


def validate_report(obj: Dict[str, Any]) -> List[str]:
    """Validate report specific fields."""
    errors = []
    
    if not obj.get("name"):
        errors.append("Report missing 'name'")
    
    if "object_refs" in obj and not isinstance(obj["object_refs"], list):
        errors.append("Report 'object_refs' must be an array")
    
    return errors


def validate_intrusion_set(obj: Dict[str, Any]) -> List[str]:
    """Validate intrusion-set specific fields."""
    errors = []
    
    if not obj.get("name"):
        errors.append("Intrusion set missing 'name'")
    
    return errors


def validate_malware(obj: Dict[str, Any]) -> List[str]:
    """Validate malware specific fields."""
    errors = []
    
    if not obj.get("name"):
        errors.append("Malware missing 'name'")
    
    if "is_family" not in obj:
        errors.append("Malware missing 'is_family' field")
    
    return errors


def validate_tool(obj: Dict[str, Any]) -> List[str]:
    """Validate tool specific fields."""
    errors = []
    
    if not obj.get("name"):
        errors.append("Tool missing 'name'")
    
    return errors


def validate_indicator(obj: Dict[str, Any]) -> List[str]:
    """Validate indicator specific fields."""
    errors = []
    
    if not obj.get("pattern"):
        errors.append("Indicator missing 'pattern'")
    
    if not obj.get("pattern_type"):
        errors.append("Indicator missing 'pattern_type'")
    elif obj["pattern_type"] != "stix":
        errors.append(f"Unsupported pattern_type: {obj['pattern_type']} (expected 'stix')")
    
    if not obj.get("valid_from"):
        errors.append("Indicator missing 'valid_from'")
    
    return errors


def validate_vulnerability(obj: Dict[str, Any]) -> List[str]:
    """Validate vulnerability specific fields."""
    errors = []
    
    if not obj.get("name"):
        errors.append("Vulnerability missing 'name'")
    
    # Check for CVE in external_references
    ext_refs = obj.get("external_references", [])
    has_cve = any(ref.get("source_name") == "cve" for ref in ext_refs)
    
    if not has_cve:
        errors.append("Vulnerability missing CVE external reference")
    
    return errors


def validate_relationship(obj: Dict[str, Any]) -> List[str]:
    """Validate relationship specific fields with ADM compliance."""
    errors = []
    
    # ADM-compliant relationship types
    ALLOWED_RELATIONSHIP_TYPES = [
        "uses",       # Actor/Software uses Technique
        "mitigates",  # Mitigation mitigates Technique
        "detects",    # DataComponent detects Technique
        "subtechnique-of",  # Subtechnique relationship
        "revoked-by",       # Version control
        "related-to"        # General relationship
    ]
    
    if not obj.get("relationship_type"):
        errors.append("Relationship missing 'relationship_type'")
    else:
        rel_type = obj["relationship_type"]
        if rel_type not in ALLOWED_RELATIONSHIP_TYPES:
            errors.append(f"Invalid relationship_type '{rel_type}'. Allowed types: {', '.join(ALLOWED_RELATIONSHIP_TYPES)}")
    
    if not obj.get("source_ref"):
        errors.append("Relationship missing 'source_ref'")
    elif not validate_stix_id(obj["source_ref"]):
        errors.append(f"Invalid source_ref: {obj['source_ref']}")
    
    if not obj.get("target_ref"):
        errors.append("Relationship missing 'target_ref'")
    elif not validate_stix_id(obj["target_ref"]):
        errors.append(f"Invalid target_ref: {obj['target_ref']}")
    
    return errors


def print_validation_report(bundle: Dict[str, Any]) -> bool:
    """
    Print a validation report for a bundle.
    
    Args:
        bundle: STIX bundle to validate
        
    Returns:
        True if valid
    """
    is_valid, errors = validate_bundle_for_upsert(bundle)
    
    if is_valid:
        print("✅ Bundle is valid for graph upsert")
        
        # Print summary
        objects = bundle.get("objects", [])
        type_counts = {}
        for obj in objects:
            obj_type = obj.get("type", "unknown")
            type_counts[obj_type] = type_counts.get(obj_type, 0) + 1
        
        print(f"\nBundle contains {len(objects)} objects:")
        for obj_type, count in sorted(type_counts.items()):
            print(f"  • {obj_type}: {count}")
        
        # Check for attack patterns with external IDs
        attack_patterns = [o for o in objects if o.get("type") == "attack-pattern"]
        if attack_patterns:
            print(f"\nAttack patterns with MITRE IDs:")
            for ap in attack_patterns[:5]:  # Show first 5
                ext_refs = ap.get("external_references", [])
                mitre_id = None
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        mitre_id = ref.get("external_id")
                        break
                if mitre_id:
                    print(f"  • {mitre_id}: {ap.get('name', 'Unknown')}")
    else:
        print("❌ Bundle validation failed")
        print(f"\nFound {len(errors)} errors:")
        for error in errors[:10]:  # Show first 10 errors
            print(f"  • {error}")
        if len(errors) > 10:
            print(f"  ... and {len(errors) - 10} more errors")
    
    return is_valid