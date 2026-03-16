"""
Detection strategy, analytic, and log source validator for STIX 2.1 compliance.

Validates against ATT&CK Data Model (ADM) requirements for detection objects.
References:
- Analytic schema: https://mitre-attack.github.io/attack-data-model/docs/sdo/analytic.schema/
- Detection Strategy schema: https://mitre-attack.github.io/attack-data-model/docs/sdo/detection-strategy.schema/
"""

import re
import json
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime


class DetectionValidator:
    """Validator for detection-related STIX 2.1 objects."""
    
    # Version regex patterns per ADM
    VERSION_PATTERN = re.compile(r'^\d+\.\d+(\.\d+)?$')
    ATTACK_SPEC_VERSION_PATTERN = re.compile(r'^\d+\.\d+$')
    EXTERNAL_ID_PATTERN = re.compile(r'^(T\d{4}(\.\d{3})?|DET\d{4}|ANA\d{4})$')
    STIX_ID_PATTERN = re.compile(r'^[a-z0-9][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')
    
    # Valid ATT&CK domains
    VALID_DOMAINS = ["enterprise-attack", "mobile-attack", "ics-attack"]
    
    # Valid platforms per domain
    VALID_PLATFORMS = {
        "enterprise-attack": ["Windows", "macOS", "Linux", "Cloud", "Network", 
                             "Containers", "Office 365", "SaaS", "Google Workspace", 
                             "Azure AD", "PRE"],
        "mobile-attack": ["Android", "iOS"],
        "ics-attack": ["Control Systems", "Engineering Workstation", "Human-Machine Interface",
                      "Input/Output Server", "Safety Instrumented System"]
    }
    
    def __init__(self):
        """Initialize the validator."""
        self.errors = []
        self.warnings = []
        self.rejected = []
    
    def validate_bundle(self, bundle: Dict[str, Any]) -> Tuple[bool, List[Dict], List[Dict], List[str]]:
        """
        Validate a STIX 2.1 bundle containing detection objects.
        
        Args:
            bundle: STIX 2.1 bundle
            
        Returns:
            Tuple of (is_valid, rejected_objects, warnings, errors)
        """
        self.errors = []
        self.warnings = []
        self.rejected = []
        
        # Validate bundle structure
        if not isinstance(bundle, dict):
            self.errors.append("Bundle must be a JSON object")
            return False, [], [], self.errors
        
        if bundle.get("type") != "bundle":
            self.errors.append("Bundle type must be 'bundle'")
        
        if bundle.get("spec_version") != "2.1":
            self.errors.append("Bundle spec_version must be '2.1'")
        
        objects = bundle.get("objects", [])
        if not objects:
            self.warnings.append("Bundle contains no objects")
        
        # Process each object
        for obj in objects:
            self._validate_object(obj)
        
        is_valid = len(self.errors) == 0 and len(self.rejected) == 0
        return is_valid, self.rejected, self.warnings, self.errors
    
    def _validate_object(self, obj: Dict[str, Any]):
        """Validate a single STIX object based on its type."""
        obj_type = obj.get("type")
        obj_id = obj.get("id", "unknown")
        
        # Universal STIX 2.1 requirements
        if not self._validate_stix_common(obj):
            return
        
        # Type-specific validation
        if obj_type == "x-mitre-detection-strategy":
            self._validate_detection_strategy(obj)
        elif obj_type == "x-mitre-analytic":
            self._validate_analytic(obj)
        elif obj_type == "x-mitre-log-source":
            self._validate_log_source(obj)
        elif obj_type == "relationship":
            self._validate_detection_relationship(obj)
        elif obj_type in ["identity", "marking-definition"]:
            # These are valid support objects
            pass
        else:
            self.warnings.append(f"Object {obj_id}: Unknown type '{obj_type}'")
    
    def _validate_stix_common(self, obj: Dict[str, Any]) -> bool:
        """Validate common STIX 2.1 fields."""
        obj_id = obj.get("id", "unknown")
        obj_type = obj.get("type", "unknown")
        
        # Check spec_version
        if obj.get("spec_version") != "2.1":
            self.rejected.append({
                "id": obj_id,
                "type": obj_type,
                "reason": "spec_version must be '2.1'"
            })
            return False
        
        # Check required fields
        if not obj.get("id"):
            self.rejected.append({
                "id": obj_id,
                "type": obj_type,
                "reason": "Missing required field 'id'"
            })
            return False
        
        # Validate STIX ID format
        if not self.STIX_ID_PATTERN.match(obj["id"]):
            self.rejected.append({
                "id": obj_id,
                "type": obj_type,
                "reason": f"Invalid STIX ID format: {obj['id']}"
            })
            return False
        
        # Check timestamps
        for field in ["created", "modified"]:
            if field in obj:
                try:
                    datetime.fromisoformat(obj[field].replace('Z', '+00:00'))
                except Exception:
                    self.warnings.append(f"Object {obj_id}: Invalid {field} timestamp format")
        
        return True
    
    def _validate_detection_strategy(self, obj: Dict[str, Any]):
        """Validate x-mitre-detection-strategy object."""
        obj_id = obj.get("id")
        
        # Required fields
        required = ["name", "x_mitre_attack_spec_version", "x_mitre_version", 
                   "x_mitre_domains", "x_mitre_analytics", "external_references"]
        
        for field in required:
            if field not in obj:
                self.rejected.append({
                    "id": obj_id,
                    "type": "x-mitre-detection-strategy",
                    "reason": f"Missing required field '{field}'"
                })
                return
        
        # Validate x_mitre_attack_spec_version format
        if not self.ATTACK_SPEC_VERSION_PATTERN.match(obj.get("x_mitre_attack_spec_version", "")):
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-detection-strategy",
                "reason": f"Invalid x_mitre_attack_spec_version format: {obj.get('x_mitre_attack_spec_version')}"
            })
        
        # Validate x_mitre_version format
        if not self.VERSION_PATTERN.match(obj.get("x_mitre_version", "")):
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-detection-strategy",
                "reason": f"Invalid x_mitre_version format: {obj.get('x_mitre_version')}"
            })
        
        # Validate domains
        domains = obj.get("x_mitre_domains", [])
        if not domains:
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-detection-strategy",
                "reason": "x_mitre_domains must contain at least one domain"
            })
        else:
            for domain in domains:
                if domain not in self.VALID_DOMAINS:
                    self.warnings.append(f"Object {obj_id}: Unknown domain '{domain}'")
        
        # Validate analytics references
        analytics = obj.get("x_mitre_analytics", [])
        if not analytics:
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-detection-strategy",
                "reason": "x_mitre_analytics must contain at least one analytic reference"
            })
        
        # Validate external references
        ext_refs = obj.get("external_references", [])
        if ext_refs:
            first_ref = ext_refs[0]
            ext_id = first_ref.get("external_id", "")
            if not ext_id.startswith("DET"):
                self.warnings.append(f"Object {obj_id}: First external_reference should have DET ID, got '{ext_id}'")
    
    def _validate_analytic(self, obj: Dict[str, Any]):
        """Validate x-mitre-analytic object."""
        obj_id = obj.get("id")
        
        # Required fields
        required = ["name", "x_mitre_attack_spec_version", "x_mitre_version",
                   "x_mitre_platforms", "x_mitre_detects", "x_mitre_log_sources",
                   "x_mitre_mutable_elements", "x_mitre_domains", "external_references"]
        
        for field in required:
            if field not in obj:
                self.rejected.append({
                    "id": obj_id,
                    "type": "x-mitre-analytic",
                    "reason": f"Missing required field '{field}'"
                })
                return
        
        # Validate version fields
        if not self.ATTACK_SPEC_VERSION_PATTERN.match(obj.get("x_mitre_attack_spec_version", "")):
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-analytic",
                "reason": f"Invalid x_mitre_attack_spec_version format"
            })
        
        if not self.VERSION_PATTERN.match(obj.get("x_mitre_version", "")):
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-analytic",
                "reason": f"Invalid x_mitre_version format"
            })
        
        # Validate platforms
        platforms = obj.get("x_mitre_platforms", [])
        if not platforms:
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-analytic",
                "reason": "x_mitre_platforms must contain at least one platform"
            })
        
        # Validate x_mitre_detects
        if not obj.get("x_mitre_detects"):
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-analytic",
                "reason": "x_mitre_detects must be non-empty"
            })
        
        # Validate log sources
        log_sources = obj.get("x_mitre_log_sources", [])
        if not log_sources:
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-analytic",
                "reason": "x_mitre_log_sources must contain at least one log source"
            })
        else:
            for i, ls in enumerate(log_sources):
                if not ls.get("log_source_ref"):
                    self.rejected.append({
                        "id": obj_id,
                        "type": "x-mitre-analytic",
                        "reason": f"x_mitre_log_sources[{i}].log_source_ref missing"
                    })
                if not ls.get("keys") or not isinstance(ls["keys"], list) or len(ls["keys"]) == 0:
                    self.rejected.append({
                        "id": obj_id,
                        "type": "x-mitre-analytic",
                        "reason": f"x_mitre_log_sources[{i}].keys must be non-empty array"
                    })
        
        # Validate mutable elements
        mutable_elements = obj.get("x_mitre_mutable_elements", [])
        if not mutable_elements:
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-analytic",
                "reason": "x_mitre_mutable_elements must contain at least one element"
            })
        else:
            for i, elem in enumerate(mutable_elements):
                if not elem.get("field"):
                    self.rejected.append({
                        "id": obj_id,
                        "type": "x-mitre-analytic",
                        "reason": f"x_mitre_mutable_elements[{i}].field missing"
                    })
                if not elem.get("description"):
                    self.warnings.append(f"Object {obj_id}: x_mitre_mutable_elements[{i}].description missing")
        
        # Validate domains
        domains = obj.get("x_mitre_domains", [])
        if not domains:
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-analytic",
                "reason": "x_mitre_domains must contain at least one domain"
            })
        
        # Validate external references
        ext_refs = obj.get("external_references", [])
        if not ext_refs:
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-analytic",
                "reason": "external_references must contain at least one reference"
            })
        elif ext_refs:
            first_ref = ext_refs[0]
            ext_id = first_ref.get("external_id", "")
            if not (ext_id.startswith("ANA") or ext_id.startswith("T")):
                self.warnings.append(f"Object {obj_id}: First external_reference should have ANA or technique ID")
    
    def _validate_log_source(self, obj: Dict[str, Any]):
        """Validate x-mitre-log-source object."""
        obj_id = obj.get("id")
        
        # Required fields
        required = ["name", "x_mitre_log_source_permutations", "x_mitre_domains"]
        
        for field in required:
            if field not in obj:
                self.rejected.append({
                    "id": obj_id,
                    "type": "x-mitre-log-source",
                    "reason": f"Missing required field '{field}'"
                })
                return
        
        # Validate permutations
        permutations = obj.get("x_mitre_log_source_permutations", [])
        if not permutations:
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-log-source",
                "reason": "x_mitre_log_source_permutations must contain at least one permutation"
            })
        else:
            for i, perm in enumerate(permutations):
                if not perm.get("name"):
                    self.warnings.append(f"Object {obj_id}: permutation[{i}].name missing")
                if not perm.get("channel") and not perm.get("data_component_name"):
                    self.warnings.append(f"Object {obj_id}: permutation[{i}] should have channel or data_component_name")
        
        # Validate domains
        domains = obj.get("x_mitre_domains", [])
        if not domains:
            self.rejected.append({
                "id": obj_id,
                "type": "x-mitre-log-source",
                "reason": "x_mitre_domains must contain at least one domain"
            })
    
    def _validate_detection_relationship(self, obj: Dict[str, Any]):
        """Validate detection-related relationship objects."""
        obj_id = obj.get("id")
        rel_type = obj.get("relationship_type")
        
        # Only accept "detects" relationships from DetectionStrategy
        if rel_type == "detects":
            source_ref = obj.get("source_ref", "")
            target_ref = obj.get("target_ref", "")
            
            # Source must be a detection strategy
            if not source_ref.startswith("x-mitre-detection-strategy--"):
                self.rejected.append({
                    "id": obj_id,
                    "type": "relationship",
                    "reason": "detects relationship must originate from x-mitre-detection-strategy"
                })
            
            # Target must be an attack pattern
            if not target_ref.startswith("attack-pattern--"):
                self.rejected.append({
                    "id": obj_id,
                    "type": "relationship",
                    "reason": "detects relationship must target attack-pattern"
                })
        
        # Validate required fields for relationships
        if not obj.get("source_ref"):
            self.rejected.append({
                "id": obj_id,
                "type": "relationship",
                "reason": "Missing required field 'source_ref'"
            })
        
        if not obj.get("target_ref"):
            self.rejected.append({
                "id": obj_id,
                "type": "relationship",
                "reason": "Missing required field 'target_ref'"
            })
    
    def validate_revoked_deprecated(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check and return revoked/deprecated status.
        
        Args:
            obj: STIX object to check
            
        Returns:
            Dict with revoked and x_mitre_deprecated status
        """
        return {
            "revoked": obj.get("revoked", False),
            "x_mitre_deprecated": obj.get("x_mitre_deprecated", False)
        }