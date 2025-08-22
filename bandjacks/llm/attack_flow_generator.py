"""Attack Flow 2.0 generation module."""

import uuid
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from neo4j import GraphDatabase

from bandjacks.llm.attack_flow_validator import AttackFlowValidator


class AttackFlowGenerator:
    """Generate valid Attack Flow 2.0 JSON documents."""
    
    def __init__(self, neo4j_uri: Optional[str] = None, neo4j_user: Optional[str] = None, 
                 neo4j_password: Optional[str] = None):
        """
        Initialize generator with optional Neo4j connection.
        
        Args:
            neo4j_uri: Neo4j connection URI (for technique lookups)
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = None
        if neo4j_uri and neo4j_user and neo4j_password:
            self.driver = GraphDatabase.driver(
                neo4j_uri,
                auth=(neo4j_user, neo4j_password)
            )
        self.validator = AttackFlowValidator()
    
    def generate(
        self,
        techniques: List[str],
        name: str = "Generated Attack Flow",
        description: str = "",
        conditions: Optional[List[Dict[str, Any]]] = None,
        operators: Optional[List[Dict[str, Any]]] = None,
        assets: Optional[List[Dict[str, Any]]] = None,
        sequence: Optional[List[Tuple[str, str]]] = None,
        scope: str = "incident",
        marking_refs: Optional[List[str]] = None,
        granular_markings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Generate an Attack Flow 2.0 JSON document.
        
        Args:
            techniques: List of technique IDs (e.g., ["T1003", "T1059", "T1071"])
            name: Name for the attack flow
            description: Description of the attack flow
            conditions: Optional list of condition definitions
            operators: Optional list of operator definitions (AND/OR)
            assets: Optional list of asset definitions
            sequence: Optional list of (source, target) tuples for flow edges
            scope: Flow scope ("incident", "campaign", or "global")
            marking_refs: Optional list of marking definition references
            granular_markings: Optional list of granular marking objects
            
        Returns:
            Valid Attack Flow 2.0 JSON bundle
        """
        # Initialize bundle
        bundle_id = f"bundle--{uuid.uuid4()}"
        flow_id = f"attack-flow--{uuid.uuid4()}"
        
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "objects": []
        }
        
        # Create attack-flow object
        flow_obj = {
            "type": "attack-flow",
            "id": flow_id,
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": name,
            "description": description,
            "scope": scope,
            "start_refs": [],
            "created_by_ref": "identity--bandjacks-generator"
        }
        
        # Add markings if provided
        if marking_refs:
            flow_obj["object_marking_refs"] = marking_refs
        if granular_markings:
            flow_obj["granular_markings"] = granular_markings
        
        # Add identity object
        identity_obj = {
            "type": "identity",
            "id": "identity--bandjacks-generator",
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": "Bandjacks Attack Flow Generator",
            "identity_class": "system"
        }
        bundle["objects"].append(identity_obj)
        
        # Create attack-action objects for techniques
        action_map = {}  # Map technique ID to action STIX ID
        for i, technique_id in enumerate(techniques):
            action_id = f"attack-action--{uuid.uuid4()}"
            action_map[technique_id] = action_id
            
            # Look up technique details if Neo4j connected
            technique_info = self._lookup_technique(technique_id) if self.driver else {}
            
            action_obj = {
                "type": "attack-action",
                "id": action_id,
                "spec_version": "2.1",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": technique_info.get("name", f"Action: {technique_id}"),
                "technique_id": technique_id,
                "description": technique_info.get("description", f"Execution of technique {technique_id}")[:500],
                "confidence": 75,  # Default confidence
                "execution_start": i,
                "execution_end": i + 1
            }
            
            # Add tactic references if available
            if technique_info.get("tactics"):
                action_obj["tactic_refs"] = [f"x-mitre-tactic--{t}" for t in technique_info["tactics"]]
            
            # Add to start_refs if it's the first action
            if i == 0:
                flow_obj["start_refs"].append(action_id)
            
            bundle["objects"].append(action_obj)
        
        # Add conditions if provided
        condition_map = {}
        if conditions:
            for condition in conditions:
                condition_id = f"attack-condition--{uuid.uuid4()}"
                condition_map[condition.get("name", condition_id)] = condition_id
                
                condition_obj = {
                    "type": "attack-condition",
                    "id": condition_id,
                    "spec_version": "2.1",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "description": condition.get("description", "Condition"),
                    "pattern": condition.get("pattern", ""),
                    "on_true_refs": [],
                    "on_false_refs": []
                }
                
                # Map condition outcomes to actions
                if condition.get("on_true"):
                    true_ref = action_map.get(condition["on_true"])
                    if true_ref:
                        condition_obj["on_true_refs"].append(true_ref)
                
                if condition.get("on_false"):
                    false_ref = action_map.get(condition["on_false"])
                    if false_ref:
                        condition_obj["on_false_refs"].append(false_ref)
                
                bundle["objects"].append(condition_obj)
        
        # Add operators if provided
        operator_map = {}
        if operators:
            for operator in operators:
                operator_id = f"attack-operator--{uuid.uuid4()}"
                operator_map[operator.get("name", operator_id)] = operator_id
                
                operator_obj = {
                    "type": "attack-operator",
                    "id": operator_id,
                    "spec_version": "2.1",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "operator": operator.get("operator", "AND"),
                    "effect_refs": []
                }
                
                # Map operator inputs to actions or conditions
                for input_ref in operator.get("inputs", []):
                    if input_ref in action_map:
                        operator_obj["effect_refs"].append(action_map[input_ref])
                    elif input_ref in condition_map:
                        operator_obj["effect_refs"].append(condition_map[input_ref])
                
                # Ensure minimum 2 effects for valid operator
                if len(operator_obj["effect_refs"]) < 2:
                    # Add placeholder if needed
                    operator_obj["effect_refs"].append(action_map.get(techniques[0], ""))
                    if len(techniques) > 1:
                        operator_obj["effect_refs"].append(action_map.get(techniques[1], ""))
                
                bundle["objects"].append(operator_obj)
        
        # Add assets if provided
        asset_map = {}
        if assets:
            for asset in assets:
                asset_id = f"attack-asset--{uuid.uuid4()}"
                asset_map[asset.get("name", asset_id)] = asset_id
                
                asset_obj = {
                    "type": "attack-asset",
                    "id": asset_id,
                    "spec_version": "2.1",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "name": asset.get("name", "Asset"),
                    "description": asset.get("description", ""),
                    "object_ref": asset.get("object_ref", "")
                }
                
                bundle["objects"].append(asset_obj)
        
        # Create relationships based on sequence
        if sequence:
            for source, target in sequence:
                # Map technique IDs to action IDs
                source_ref = action_map.get(source, source)
                target_ref = action_map.get(target, target)
                
                # Check if they're condition or operator references
                if source in condition_map:
                    source_ref = condition_map[source]
                if target in condition_map:
                    target_ref = condition_map[target]
                if source in operator_map:
                    source_ref = operator_map[source]
                if target in operator_map:
                    target_ref = operator_map[target]
                
                rel_obj = {
                    "type": "relationship",
                    "id": f"relationship--{uuid.uuid4()}",
                    "spec_version": "2.1",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "relationship_type": "followed-by",
                    "source_ref": source_ref,
                    "target_ref": target_ref,
                    "confidence": 80
                }
                
                bundle["objects"].append(rel_obj)
        else:
            # Create default linear sequence if not specified
            for i in range(len(techniques) - 1):
                source_ref = action_map[techniques[i]]
                target_ref = action_map[techniques[i + 1]]
                
                rel_obj = {
                    "type": "relationship",
                    "id": f"relationship--{uuid.uuid4()}",
                    "spec_version": "2.1",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "relationship_type": "followed-by",
                    "source_ref": source_ref,
                    "target_ref": target_ref,
                    "confidence": 80
                }
                
                bundle["objects"].append(rel_obj)
        
        # Add the flow object last
        bundle["objects"].append(flow_obj)
        
        # Add attack-pattern objects for referenced techniques
        for technique_id in techniques:
            technique_info = self._lookup_technique(technique_id) if self.driver else {}
            if technique_info:
                # Handle potential None values for dates
                created = technique_info.get("created")
                if created is None:
                    created = datetime.utcnow()
                elif not isinstance(created, datetime):
                    created = datetime.utcnow()
                    
                modified = technique_info.get("modified")
                if modified is None:
                    modified = datetime.utcnow()
                elif not isinstance(modified, datetime):
                    modified = datetime.utcnow()
                
                pattern_obj = {
                    "type": "attack-pattern",
                    "id": technique_info.get("stix_id", f"attack-pattern--{uuid.uuid4()}"),
                    "spec_version": "2.1",
                    "created": created.isoformat() + "Z",
                    "modified": modified.isoformat() + "Z",
                    "name": technique_info.get("name", technique_id),
                    "description": technique_info.get("description", "")[:500],
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": technique_id,
                            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
                        }
                    ]
                }
                
                if technique_info.get("kill_chain_phases"):
                    pattern_obj["kill_chain_phases"] = technique_info["kill_chain_phases"]
                
                bundle["objects"].append(pattern_obj)
        
        return bundle
    
    def _lookup_technique(self, technique_id: str) -> Dict[str, Any]:
        """
        Look up technique details from Neo4j.
        
        Args:
            technique_id: MITRE ATT&CK technique ID
            
        Returns:
            Technique information dictionary
        """
        if not self.driver:
            return {}
        
        with self.driver.session() as session:
            result = session.run("""
                MATCH (t:AttackPattern)
                WHERE t.external_id = $technique_id
                OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
                RETURN t.stix_id as stix_id,
                       t.name as name,
                       t.description as description,
                       t.created as created,
                       t.modified as modified,
                       collect(DISTINCT tac.shortname) as tactics,
                       collect(DISTINCT {
                           kill_chain_name: 'mitre-attack',
                           phase_name: tac.shortname
                       }) as kill_chain_phases
            """, technique_id=technique_id)
            
            record = result.single()
            if record:
                return dict(record)
            
        return {}
    
    def generate_from_template(
        self,
        template_name: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate flow from a predefined template.
        
        Args:
            template_name: Name of template to use
            parameters: Template-specific parameters
            
        Returns:
            Valid Attack Flow 2.0 JSON bundle
        """
        templates = {
            "linear": self._template_linear,
            "branching": self._template_branching,
            "conditional": self._template_conditional,
            "complex": self._template_complex
        }
        
        if template_name not in templates:
            raise ValueError(f"Unknown template: {template_name}")
        
        return templates[template_name](parameters)
    
    def _template_linear(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a simple linear flow."""
        techniques = params.get("techniques", ["T1003", "T1059", "T1071"])
        name = params.get("name", "Linear Attack Flow")
        description = params.get("description", "A straightforward attack progression")
        
        return self.generate(
            techniques=techniques,
            name=name,
            description=description,
            scope="incident"
        )
    
    def _template_branching(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a flow with branching paths."""
        techniques = params.get("techniques", ["T1003", "T1055", "T1059", "T1071"])
        name = params.get("name", "Branching Attack Flow")
        description = params.get("description", "Attack with multiple possible paths")
        
        # Create OR operator for branching
        operators = [
            {
                "name": "path_choice",
                "operator": "OR",
                "inputs": [techniques[1], techniques[2]]
            }
        ]
        
        # Define sequence with branching
        sequence = [
            (techniques[0], techniques[1]),
            (techniques[0], techniques[2]),
            (techniques[1], techniques[3]),
            (techniques[2], techniques[3])
        ]
        
        return self.generate(
            techniques=techniques,
            name=name,
            description=description,
            operators=operators,
            sequence=sequence,
            scope="incident"
        )
    
    def _template_conditional(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a flow with conditional execution."""
        techniques = params.get("techniques", ["T1003", "T1055", "T1548"])
        name = params.get("name", "Conditional Attack Flow")
        description = params.get("description", "Attack with conditional branches")
        
        # Create conditions
        conditions = [
            {
                "name": "cred_success",
                "description": "Credential theft successful",
                "pattern": "event_type == 'credential_access' AND status == 'success'",
                "on_true": techniques[1],
                "on_false": techniques[2]
            }
        ]
        
        # Define conditional sequence
        sequence = [
            (techniques[0], "cred_success")
        ]
        
        return self.generate(
            techniques=techniques,
            name=name,
            description=description,
            conditions=conditions,
            sequence=sequence,
            scope="incident"
        )
    
    def _template_complex(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a complex flow with all elements."""
        techniques = params.get("techniques", ["T1190", "T1003", "T1055", "T1059", "T1071", "T1486"])
        name = params.get("name", "Complex Multi-Stage Attack")
        description = params.get("description", "Sophisticated attack with conditions, operators, and assets")
        
        # Define assets
        assets = [
            {
                "name": "web_server",
                "description": "Public-facing web server",
                "object_ref": "infrastructure--web-01"
            },
            {
                "name": "domain_controller",
                "description": "Active Directory domain controller",
                "object_ref": "infrastructure--dc-01"
            }
        ]
        
        # Define conditions
        conditions = [
            {
                "name": "initial_access",
                "description": "Initial access achieved",
                "pattern": "asset == 'web_server' AND compromised == true",
                "on_true": techniques[1]
            },
            {
                "name": "privilege_check",
                "description": "Check for elevated privileges",
                "pattern": "user_context == 'SYSTEM' OR user_context == 'Administrator'",
                "on_true": techniques[3],
                "on_false": techniques[2]
            }
        ]
        
        # Define operators
        operators = [
            {
                "name": "persistence_and_c2",
                "operator": "AND",
                "inputs": [techniques[3], techniques[4]]
            }
        ]
        
        # Complex sequence
        sequence = [
            (techniques[0], "initial_access"),
            (techniques[1], "privilege_check"),
            (techniques[2], techniques[3]),
            ("persistence_and_c2", techniques[5])
        ]
        
        return self.generate(
            techniques=techniques,
            name=name,
            description=description,
            conditions=conditions,
            operators=operators,
            assets=assets,
            sequence=sequence,
            scope="campaign"
        )
    
    def validate_generated(self, attack_flow: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate a generated Attack Flow.
        
        Args:
            attack_flow: Generated Attack Flow JSON
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        return self.validator.validate(attack_flow)
    
    def close(self):
        """Close Neo4j connection if exists."""
        if self.driver:
            self.driver.close()


def generate_attack_flow(
    techniques: List[str],
    name: str = "Generated Attack Flow",
    neo4j_uri: Optional[str] = None,
    neo4j_user: Optional[str] = None,
    neo4j_password: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience function to generate an Attack Flow.
    
    Args:
        techniques: List of technique IDs
        name: Flow name
        neo4j_uri: Optional Neo4j URI for technique lookups
        neo4j_user: Optional Neo4j username
        neo4j_password: Optional Neo4j password
        
    Returns:
        Valid Attack Flow 2.0 JSON bundle
    """
    generator = AttackFlowGenerator(neo4j_uri, neo4j_user, neo4j_password)
    try:
        flow = generator.generate(techniques, name)
        return flow
    finally:
        generator.close()