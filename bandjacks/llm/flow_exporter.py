"""Export internal attack flows to Attack Flow 2.0 JSON format."""

import uuid
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from neo4j import GraphDatabase

from bandjacks.llm.attack_flow_validator import AttackFlowValidator

logger = logging.getLogger(__name__)


class AttackFlowExporter:
    """Export internal flow format to ATT&CK Flow 2.0 JSON."""

    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize exporter with Neo4j connection.

        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
        self.validator = AttackFlowValidator()

    @classmethod
    def from_driver(cls, driver, validator=None):
        """Create exporter sharing an existing Neo4j driver."""
        instance = cls.__new__(cls)
        instance.driver = driver
        instance.validator = validator or AttackFlowValidator()
        return instance

    def export_to_attack_flow(self, flow_id: str) -> Dict[str, Any]:
        """
        Export an internal flow to Attack Flow 2.0 format.
        
        Args:
            flow_id: Internal flow ID
            
        Returns:
            Attack Flow 2.0 JSON bundle
        """
        with self.driver.session() as session:
            # Get episode and actions
            episode_result = session.run("""
                MATCH (e:AttackEpisode {flow_id: $flow_id})
                OPTIONAL MATCH (e)-[:CONTAINS]->(a:AttackAction)
                OPTIONAL MATCH (a)-[:OF_TECHNIQUE]->(t:AttackPattern)
                RETURN e, collect({
                    action: a,
                    technique: t
                }) as actions
            """, flow_id=flow_id)
            
            record = episode_result.single()
            if not record:
                raise ValueError(f"Flow {flow_id} not found")
            
            episode = dict(record["e"])
            actions = record["actions"]
            
            # Build Attack Flow 2.0 bundle
            bundle = {
                "type": "bundle",
                "id": f"bundle--{uuid.uuid4()}",
                "spec_version": "2.1",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "objects": []
            }
            
            # Create attack-flow object
            flow_obj = {
                "type": "attack-flow",
                "id": f"attack-flow--{uuid.uuid4()}",
                "spec_version": "2.1",
                "created": episode.get("created", datetime.utcnow()).isoformat() + "Z",
                "modified": episode.get("modified", datetime.utcnow()).isoformat() + "Z",
                "name": episode.get("name", "Exported Flow"),
                "description": episode.get("description", "Flow exported from Bandjacks"),
                "scope": "incident",
                "start_refs": [],
                "created_by_ref": "identity--bandjacks-exporter"
            }
            
            bundle["objects"].append(flow_obj)
            
            # Add identity object
            bundle["objects"].append({
                "type": "identity",
                "id": "identity--bandjacks-exporter",
                "spec_version": "2.1",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": "Bandjacks Flow Exporter",
                "identity_class": "system"
            })
            
            # Create attack-action objects
            action_id_map = {}  # Map internal IDs to STIX IDs
            
            for action_data in actions:
                if action_data["action"]:
                    action = dict(action_data["action"])
                    technique = dict(action_data["technique"]) if action_data["technique"] else None
                    
                    stix_id = f"attack-action--{uuid.uuid4()}"
                    action_id_map[action["action_id"]] = stix_id
                    
                    action_obj = {
                        "type": "attack-action",
                        "id": stix_id,
                        "spec_version": "2.1",
                        "created": datetime.utcnow().isoformat() + "Z",
                        "modified": datetime.utcnow().isoformat() + "Z",
                        "name": action.get("name", "Action"),
                        "technique_id": action.get("technique_id", ""),
                        "confidence": int(action.get("confidence", 50)),
                        "description": action.get("description", "")
                    }
                    
                    # Add technique reference if available
                    if technique:
                        action_obj["technique_ref"] = technique.get("stix_id", "")
                        action_obj["tactic_refs"] = self._get_tactic_refs(session, technique["stix_id"])
                    
                    # Add execution order if available
                    if "order" in action:
                        action_obj["execution_start"] = action["order"]
                        action_obj["execution_end"] = action["order"] + 1
                    
                    bundle["objects"].append(action_obj)
                    
                    # Add to start_refs if it's a first action
                    if action.get("order", 999) == 0:
                        flow_obj["start_refs"].append(stix_id)
            
            # Get and create relationship objects (NEXT edges)
            edges_result = session.run("""
                MATCH (e:AttackEpisode {flow_id: $flow_id})
                MATCH (e)-[:CONTAINS]->(a1:AttackAction)
                MATCH (a1)-[n:NEXT]->(a2:AttackAction)
                RETURN a1.action_id as source, a2.action_id as target, 
                       n.probability as probability
            """, flow_id=flow_id)
            
            for edge in edges_result:
                if edge["source"] in action_id_map and edge["target"] in action_id_map:
                    rel_obj = {
                        "type": "relationship",
                        "id": f"relationship--{uuid.uuid4()}",
                        "spec_version": "2.1",
                        "created": datetime.utcnow().isoformat() + "Z",
                        "modified": datetime.utcnow().isoformat() + "Z",
                        "relationship_type": "followed-by",
                        "source_ref": action_id_map[edge["source"]],
                        "target_ref": action_id_map[edge["target"]]
                    }
                    
                    if edge["probability"]:
                        rel_obj["confidence"] = int(edge["probability"] * 100)
                    
                    bundle["objects"].append(rel_obj)
            
            # Add any referenced techniques as attack-pattern objects
            for action_data in actions:
                if action_data["technique"]:
                    technique = dict(action_data["technique"])
                    
                    pattern_obj = {
                        "type": "attack-pattern",
                        "id": technique.get("stix_id", f"attack-pattern--{uuid.uuid4()}"),
                        "spec_version": "2.1",
                        "created": technique.get("created", datetime.utcnow()).isoformat() + "Z",
                        "modified": technique.get("modified", datetime.utcnow()).isoformat() + "Z",
                        "name": technique.get("name", "Unknown Technique"),
                        "description": technique.get("description", "")[:500] if technique.get("description") else "",
                        "external_references": []
                    }
                    
                    # Add MITRE reference
                    if technique.get("external_id"):
                        pattern_obj["external_references"].append({
                            "source_name": "mitre-attack",
                            "external_id": technique["external_id"],
                            "url": f"https://attack.mitre.org/techniques/{technique['external_id'].replace('.', '/')}"
                        })
                    
                    # Add kill chain phases
                    kill_chain_phases = self._get_kill_chain_phases(session, technique["stix_id"])
                    if kill_chain_phases:
                        pattern_obj["kill_chain_phases"] = kill_chain_phases
                    
                    bundle["objects"].append(pattern_obj)
            
            return bundle
    
    def _get_tactic_refs(self, session, technique_stix_id: str) -> List[str]:
        """Get tactic references for a technique."""
        result = session.run("""
            MATCH (t:AttackPattern {stix_id: $stix_id})-[:HAS_TACTIC]->(tactic:Tactic)
            RETURN collect(DISTINCT tactic.shortname) as tactics
        """, stix_id=technique_stix_id)
        
        record = result.single()
        if record and record["tactics"]:
            return [f"x-mitre-tactic--{tactic}" for tactic in record["tactics"]]
        return []
    
    def _get_kill_chain_phases(self, session, technique_stix_id: str) -> List[Dict[str, str]]:
        """Get kill chain phases for a technique."""
        result = session.run("""
            MATCH (t:AttackPattern {stix_id: $stix_id})-[:HAS_TACTIC]->(tactic:Tactic)
            RETURN collect(DISTINCT {
                kill_chain_name: 'mitre-attack',
                phase_name: tactic.shortname
            }) as phases
        """, stix_id=technique_stix_id)
        
        record = result.single()
        if record and record["phases"]:
            return record["phases"]
        return []
    
    def export_multiple_flows(self, flow_ids: List[str]) -> Dict[str, Any]:
        """
        Export multiple flows into a single Attack Flow bundle.
        
        Args:
            flow_ids: List of flow IDs to export
            
        Returns:
            Combined Attack Flow 2.0 JSON bundle
        """
        combined_bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "objects": []
        }
        
        seen_objects = set()  # Deduplicate objects
        
        for flow_id in flow_ids:
            try:
                flow_bundle = self.export_to_attack_flow(flow_id)
                
                for obj in flow_bundle.get("objects", []):
                    obj_id = obj.get("id")
                    if obj_id and obj_id not in seen_objects:
                        combined_bundle["objects"].append(obj)
                        seen_objects.add(obj_id)
                        
            except Exception as e:
                # Log error but continue with other flows
                print(f"Failed to export flow {flow_id}: {e}")
        
        return combined_bundle
    
    def validate_export(self, attack_flow_json: Dict[str, Any]) -> List[str]:
        """
        Validate exported Attack Flow JSON.
        
        Args:
            attack_flow_json: Attack Flow JSON to validate
            
        Returns:
            List of validation warnings (empty if valid)
        """
        warnings = []
        
        # Check bundle structure
        if attack_flow_json.get("type") != "bundle":
            warnings.append("Root object is not a bundle")
        
        if not attack_flow_json.get("objects"):
            warnings.append("Bundle has no objects")
            return warnings
        
        # Check for required object types
        has_flow = False
        has_actions = False
        
        for obj in attack_flow_json["objects"]:
            if obj.get("type") == "attack-flow":
                has_flow = True
            elif obj.get("type") == "attack-action":
                has_actions = True
        
        if not has_flow:
            warnings.append("No attack-flow object found")
        if not has_actions:
            warnings.append("No attack-action objects found")
        
        # Check spec_version on all objects
        for obj in attack_flow_json["objects"]:
            if obj.get("spec_version") != "2.1":
                warnings.append(f"Object {obj.get('id', 'unknown')} has invalid spec_version")
        
        return warnings
    
    def export_to_stix_attack_flow(
        self,
        flow_data: Dict[str, Any],
        scope: str = "incident",
        marking_refs: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Export flow to STIX Attack Flow 2.0 format.

        Args:
            flow_data: Internal flow data
            scope: Flow scope ("incident", "campaign", or "global")
            marking_refs: Optional list of marking definition references

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
            "created": flow_data.get("created_at", datetime.utcnow().isoformat() + "Z"),
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": flow_data.get("name", "Generated Attack Flow"),
            "description": flow_data.get("description", f"Attack flow with {len(flow_data['actions'])} steps"),
            "scope": scope,
            "start_refs": [],
            "created_by_ref": "identity--bandjacks-generator"
        }

        # Add markings if provided
        if marking_refs:
            flow_obj["object_marking_refs"] = marking_refs

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
        action_stix_map = {}  # Map internal action_id to STIX action ID
        for i, action in enumerate(flow_data["actions"]):
            stix_action_id = f"attack-action--{uuid.uuid4()}"
            action_stix_map[action["action_id"]] = stix_action_id

            # Look up technique details if available
            technique_ref = action.get("attack_pattern_ref", action.get("technique_id", "unknown"))
            technique_info = self._lookup_technique(technique_ref) if self.driver else {}

            action_obj = {
                "type": "attack-action",
                "id": stix_action_id,
                "spec_version": "2.1",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": action.get("name", technique_info.get("name", f"Action: {technique_ref}")),
                "technique_id": technique_ref,
                "description": (action.get("description", "") or technique_info.get("description", ""))[:500],
                "confidence": int(action.get("confidence", 75)),
                "execution_start": action.get("order", i),
                "execution_end": action.get("order", i) + 1
            }

            # Add tactic references if available
            if technique_info.get("tactics"):
                action_obj["tactic_refs"] = [f"x-mitre-tactic--{t}" for t in technique_info["tactics"]]

            # Add to start_refs if it's the first action
            if i == 0:
                flow_obj["start_refs"].append(stix_action_id)

            bundle["objects"].append(action_obj)

        # Create relationships for edges
        for edge in flow_data.get("edges", []):
            if edge["source"] in action_stix_map and edge["target"] in action_stix_map:
                relationship = {
                    "type": "relationship",
                    "id": f"relationship--{uuid.uuid4()}",
                    "spec_version": "2.1",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "relationship_type": "followed-by",
                    "source_ref": action_stix_map[edge["source"]],
                    "target_ref": action_stix_map[edge["target"]],
                    "confidence": int(edge.get("probability", 0.5) * 100),
                    "x_rationale": edge.get("rationale", "sequential")
                }
                bundle["objects"].append(relationship)

        # Add the flow object
        bundle["objects"].append(flow_obj)

        # Validate the bundle
        is_valid, errors = self.validator.validate(bundle)
        if not is_valid:
            logger.warning("Generated Attack Flow has validation issues: %s", errors)

        return bundle

    def _lookup_technique(self, technique_id: str) -> Dict[str, Any]:
        """
        Look up technique details from Neo4j.

        Args:
            technique_id: Technique STIX ID or external ID

        Returns:
            Technique info dict
        """
        if not self.driver:
            return {}

        with self.driver.session() as session:
            # Try STIX ID first
            if technique_id.startswith("attack-pattern--"):
                result = session.run(
                    """
                    MATCH (t:AttackPattern {stix_id: $id})
                    OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
                    RETURN t.name as name, t.description as description,
                           collect(DISTINCT tac.shortname) as tactics
                    """,
                    id=technique_id
                )
            else:
                # Try external ID
                result = session.run(
                    """
                    MATCH (t:AttackPattern)
                    WHERE t.external_id = $id OR $id IN t.external_ids
                    OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
                    RETURN t.name as name, t.description as description,
                           collect(DISTINCT tac.shortname) as tactics
                    LIMIT 1
                    """,
                    id=technique_id
                )

            record = result.single()
            if record:
                return {
                    "name": record["name"],
                    "description": record["description"],
                    "tactics": record["tactics"]
                }

        return {}

    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()


def export_flow_to_json_file(
    flow_id: str,
    output_path: str,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str
) -> bool:
    """
    Convenience function to export a flow to a JSON file.
    
    Args:
        flow_id: Flow ID to export
        output_path: Path to write JSON file
        neo4j_uri: Neo4j connection URI
        neo4j_user: Neo4j username
        neo4j_password: Neo4j password
        
    Returns:
        True if successful, False otherwise
    """
    exporter = AttackFlowExporter(neo4j_uri, neo4j_user, neo4j_password)
    
    try:
        attack_flow = exporter.export_to_attack_flow(flow_id)
        
        # Validate before writing
        warnings = exporter.validate_export(attack_flow)
        if warnings:
            print(f"Export warnings: {warnings}")
        
        # Write to file
        with open(output_path, 'w') as f:
            json.dump(attack_flow, f, indent=2)
        
        print(f"Flow exported to {output_path}")
        return True
        
    except Exception as e:
        print(f"Export failed: {e}")
        return False
        
    finally:
        exporter.close()