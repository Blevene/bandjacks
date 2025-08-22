"""Attack Flow 2.0 JSON schema validation module."""

import json
import os
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import jsonschema
from jsonschema import Draft7Validator, validators


class AttackFlowValidator:
    """Validator for Attack Flow 2.0 JSON documents."""
    
    def __init__(self, schema_path: Optional[str] = None):
        """
        Initialize validator with Attack Flow 2.0 schema.
        
        Args:
            schema_path: Path to Attack Flow schema JSON file.
                        If None, uses default location.
        """
        if schema_path is None:
            # Default to bundled schema
            base_dir = Path(__file__).parent.parent
            schema_path = base_dir / "schemas" / "attack-flow-schema-2.0.0.json"
        
        self.schema_path = Path(schema_path)
        self.schema = self._load_schema()
        self.validator = self._create_validator()
    
    def _load_schema(self) -> Dict[str, Any]:
        """Load Attack Flow schema from file."""
        if not self.schema_path.exists():
            raise FileNotFoundError(f"Schema file not found: {self.schema_path}")
        
        with open(self.schema_path, 'r') as f:
            return json.load(f)
    
    def _create_validator(self) -> Draft7Validator:
        """Create JSON schema validator with custom extensions."""
        # Use Draft7Validator for Attack Flow 2.0 compatibility
        validator_class = validators.create(
            meta_schema=Draft7Validator.META_SCHEMA,
            validators=Draft7Validator.VALIDATORS
        )
        return validator_class(self.schema)
    
    def validate(self, attack_flow: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate an Attack Flow JSON document.
        
        Args:
            attack_flow: Attack Flow JSON to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Basic structure validation
        if not isinstance(attack_flow, dict):
            return False, ["Attack Flow must be a JSON object"]
        
        # Validate against schema
        try:
            self.validator.validate(attack_flow)
            
            # Additional Attack Flow specific validations
            custom_errors = self._validate_attack_flow_constraints(attack_flow)
            if custom_errors:
                return False, custom_errors
                
            return True, []
            
        except jsonschema.ValidationError as e:
            # Format validation errors
            error_path = " -> ".join(str(p) for p in e.path) if e.path else "root"
            errors.append(f"Validation error at {error_path}: {e.message}")
            
            # Collect all validation errors
            for error in self.validator.iter_errors(attack_flow):
                error_path = " -> ".join(str(p) for p in error.path) if error.path else "root"
                errors.append(f"At {error_path}: {error.message}")
            
            return False, errors
    
    def _validate_attack_flow_constraints(self, attack_flow: Dict[str, Any]) -> List[str]:
        """
        Validate Attack Flow specific constraints not covered by JSON schema.
        
        Args:
            attack_flow: Attack Flow JSON document
            
        Returns:
            List of constraint violation messages
        """
        errors = []
        
        # Check if it's a STIX bundle
        if attack_flow.get("type") != "bundle":
            errors.append("Attack Flow must be a STIX bundle (type='bundle')")
            return errors
        
        objects = attack_flow.get("objects", [])
        if not objects:
            errors.append("Bundle must contain objects")
            return errors
        
        # Track object IDs for reference validation
        object_ids = {obj.get("id") for obj in objects if obj.get("id")}
        
        # Check for required attack-flow object
        flow_objects = [obj for obj in objects if obj.get("type") == "attack-flow"]
        if not flow_objects:
            errors.append("Bundle must contain at least one 'attack-flow' object")
        
        # Validate attack-flow objects
        for flow in flow_objects:
            flow_errors = self._validate_flow_object(flow, object_ids)
            errors.extend(flow_errors)
        
        # Validate attack-action objects
        action_objects = [obj for obj in objects if obj.get("type") == "attack-action"]
        for action in action_objects:
            action_errors = self._validate_action_object(action)
            errors.extend(action_errors)
        
        # Validate attack-condition objects
        condition_objects = [obj for obj in objects if obj.get("type") == "attack-condition"]
        for condition in condition_objects:
            condition_errors = self._validate_condition_object(condition, object_ids)
            errors.extend(condition_errors)
        
        # Validate attack-operator objects
        operator_objects = [obj for obj in objects if obj.get("type") == "attack-operator"]
        for operator in operator_objects:
            operator_errors = self._validate_operator_object(operator, object_ids)
            errors.extend(operator_errors)
        
        # Validate relationships
        relationships = [obj for obj in objects if obj.get("type") == "relationship"]
        for rel in relationships:
            rel_errors = self._validate_relationship(rel, object_ids)
            errors.extend(rel_errors)
        
        return errors
    
    def _validate_flow_object(self, flow: Dict[str, Any], object_ids: set) -> List[str]:
        """Validate attack-flow object."""
        errors = []
        
        # Check required properties
        if not flow.get("name"):
            errors.append(f"Attack flow {flow.get('id', 'unknown')} missing required 'name'")
        
        if not flow.get("scope"):
            errors.append(f"Attack flow {flow.get('id', 'unknown')} missing required 'scope'")
        elif flow["scope"] not in ["incident", "campaign", "global"]:
            errors.append(f"Attack flow {flow.get('id', 'unknown')} has invalid scope: {flow['scope']}")
        
        # Validate start_refs
        start_refs = flow.get("start_refs", [])
        if not start_refs:
            errors.append(f"Attack flow {flow.get('id', 'unknown')} has no start_refs")
        else:
            for ref in start_refs:
                if ref not in object_ids:
                    errors.append(f"Attack flow references non-existent object: {ref}")
        
        return errors
    
    def _validate_action_object(self, action: Dict[str, Any]) -> List[str]:
        """Validate attack-action object."""
        errors = []
        
        # Check required properties
        if not action.get("name"):
            errors.append(f"Attack action {action.get('id', 'unknown')} missing required 'name'")
        
        # Validate technique reference format
        technique_id = action.get("technique_id")
        if technique_id and not self._is_valid_technique_id(technique_id):
            errors.append(f"Attack action {action.get('id', 'unknown')} has invalid technique_id format: {technique_id}")
        
        # Validate confidence if present
        if "confidence" in action:
            confidence = action["confidence"]
            if not isinstance(confidence, (int, float)) or confidence < 0 or confidence > 100:
                errors.append(f"Attack action {action.get('id', 'unknown')} has invalid confidence: {confidence}")
        
        return errors
    
    def _validate_condition_object(self, condition: Dict[str, Any], object_ids: set) -> List[str]:
        """Validate attack-condition object."""
        errors = []
        
        # Check required properties
        if not condition.get("description"):
            errors.append(f"Attack condition {condition.get('id', 'unknown')} missing required 'description'")
        
        # Validate on_true_refs and on_false_refs
        for ref_type in ["on_true_refs", "on_false_refs"]:
            refs = condition.get(ref_type, [])
            for ref in refs:
                if ref not in object_ids:
                    errors.append(f"Attack condition {condition.get('id', 'unknown')} references non-existent object in {ref_type}: {ref}")
        
        return errors
    
    def _validate_operator_object(self, operator: Dict[str, Any], object_ids: set) -> List[str]:
        """Validate attack-operator object."""
        errors = []
        
        # Check required properties
        if not operator.get("operator"):
            errors.append(f"Attack operator {operator.get('id', 'unknown')} missing required 'operator'")
        elif operator["operator"] not in ["AND", "OR"]:
            errors.append(f"Attack operator {operator.get('id', 'unknown')} has invalid operator: {operator['operator']}")
        
        # Validate effect_refs
        effect_refs = operator.get("effect_refs", [])
        if len(effect_refs) < 2:
            errors.append(f"Attack operator {operator.get('id', 'unknown')} must have at least 2 effect_refs")
        
        for ref in effect_refs:
            if ref not in object_ids:
                errors.append(f"Attack operator references non-existent object: {ref}")
        
        return errors
    
    def _validate_relationship(self, rel: Dict[str, Any], object_ids: set) -> List[str]:
        """Validate relationship object."""
        errors = []
        
        # Check references exist
        source_ref = rel.get("source_ref")
        target_ref = rel.get("target_ref")
        
        if source_ref and source_ref not in object_ids:
            errors.append(f"Relationship {rel.get('id', 'unknown')} references non-existent source: {source_ref}")
        
        if target_ref and target_ref not in object_ids:
            errors.append(f"Relationship {rel.get('id', 'unknown')} references non-existent target: {target_ref}")
        
        # Validate relationship type
        rel_type = rel.get("relationship_type")
        valid_types = ["followed-by", "preceded-by", "related-to"]
        if rel_type and rel_type not in valid_types:
            # Allow custom relationship types but warn
            pass  # No error, just informational
        
        return errors
    
    def _is_valid_technique_id(self, technique_id: str) -> bool:
        """Check if technique ID follows MITRE ATT&CK format."""
        # Basic format: T1234 or T1234.001
        import re
        pattern = r'^T\d{4}(\.\d{3})?$'
        return bool(re.match(pattern, technique_id))
    
    def validate_file(self, file_path: str) -> Tuple[bool, List[str]]:
        """
        Validate an Attack Flow JSON file.
        
        Args:
            file_path: Path to Attack Flow JSON file
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        try:
            with open(file_path, 'r') as f:
                attack_flow = json.load(f)
            return self.validate(attack_flow)
        except FileNotFoundError:
            return False, [f"File not found: {file_path}"]
        except json.JSONDecodeError as e:
            return False, [f"Invalid JSON: {e}"]
    
    def get_schema_info(self) -> Dict[str, Any]:
        """
        Get information about the loaded schema.
        
        Returns:
            Dictionary with schema metadata
        """
        return {
            "schema_path": str(self.schema_path),
            "schema_id": self.schema.get("$id", "unknown"),
            "schema_version": self.schema.get("version", "unknown"),
            "title": self.schema.get("title", "Attack Flow Schema"),
            "description": self.schema.get("description", "")
        }


def validate_attack_flow(attack_flow: Dict[str, Any], schema_path: Optional[str] = None) -> Tuple[bool, List[str]]:
    """
    Convenience function to validate an Attack Flow document.
    
    Args:
        attack_flow: Attack Flow JSON to validate
        schema_path: Optional path to schema file
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    validator = AttackFlowValidator(schema_path)
    return validator.validate(attack_flow)


def validate_attack_flow_file(file_path: str, schema_path: Optional[str] = None) -> Tuple[bool, List[str]]:
    """
    Convenience function to validate an Attack Flow JSON file.
    
    Args:
        file_path: Path to Attack Flow JSON file
        schema_path: Optional path to schema file
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    validator = AttackFlowValidator(schema_path)
    return validator.validate_file(file_path)