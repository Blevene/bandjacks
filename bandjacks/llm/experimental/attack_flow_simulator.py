"""Attack Flow 2.0 simulation engine."""

import json
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime
from enum import Enum
from neo4j import GraphDatabase


class SimulationState(Enum):
    """Simulation execution states."""
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class AttackFlowSimulator:
    """Simulate execution of Attack Flow 2.0 documents."""
    
    def __init__(self, neo4j_uri: Optional[str] = None, neo4j_user: Optional[str] = None,
                 neo4j_password: Optional[str] = None):
        """
        Initialize simulator with optional Neo4j connection.
        
        Args:
            neo4j_uri: Neo4j connection URI (for coverage lookups)
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = None
        if neo4j_uri and neo4j_user and neo4j_password:
            self.driver = GraphDatabase.driver(
                neo4j_uri,
                auth=(neo4j_user, neo4j_password)
            )
    
    def simulate(
        self,
        attack_flow: Dict[str, Any],
        initial_conditions: Optional[Dict[str, Any]] = None,
        max_steps: int = 100,
        check_coverage: bool = False
    ) -> Dict[str, Any]:
        """
        Simulate an Attack Flow execution.
        
        Args:
            attack_flow: Attack Flow 2.0 JSON bundle
            initial_conditions: Initial state/conditions for simulation
            max_steps: Maximum simulation steps (prevent infinite loops)
            check_coverage: Check detection coverage for each step
            
        Returns:
            Simulation result with execution path and outcomes
        """
        # Initialize simulation state
        state = {
            "conditions": initial_conditions or {},
            "executed_actions": [],
            "current_step": 0,
            "execution_path": [],
            "outcomes": [],
            "coverage_gaps": [],
            "status": SimulationState.READY
        }
        
        # Parse Attack Flow structure
        flow_structure = self._parse_flow_structure(attack_flow)
        if not flow_structure:
            return {
                "status": "failed",
                "error": "Invalid Attack Flow structure",
                "state": state
            }
        
        # Find starting points
        start_refs = flow_structure["flow_object"].get("start_refs", [])
        if not start_refs:
            return {
                "status": "failed",
                "error": "No starting points defined",
                "state": state
            }
        
        # Begin simulation
        state["status"] = SimulationState.RUNNING
        execution_queue = start_refs.copy()
        visited = set()
        
        while execution_queue and state["current_step"] < max_steps:
            current_id = execution_queue.pop(0)
            
            # Skip if already visited (prevent loops)
            if current_id in visited:
                continue
            visited.add(current_id)
            
            # Get object
            current_obj = flow_structure["objects_by_id"].get(current_id)
            if not current_obj:
                continue
            
            # Process based on object type
            obj_type = current_obj.get("type")
            
            if obj_type == "attack-action":
                result = self._simulate_action(current_obj, state, flow_structure, check_coverage)
                execution_queue.extend(result["next_refs"])
                
            elif obj_type == "attack-condition":
                result = self._simulate_condition(current_obj, state, flow_structure)
                execution_queue.extend(result["next_refs"])
                
            elif obj_type == "attack-operator":
                result = self._simulate_operator(current_obj, state, flow_structure)
                execution_queue.extend(result["next_refs"])
                
            elif obj_type == "attack-asset":
                result = self._simulate_asset(current_obj, state, flow_structure)
                execution_queue.extend(result["next_refs"])
            
            state["current_step"] += 1
        
        # Finalize simulation
        if state["current_step"] >= max_steps:
            state["status"] = SimulationState.FAILED
            state["outcomes"].append({
                "type": "error",
                "message": f"Simulation exceeded maximum steps ({max_steps})"
            })
        else:
            state["status"] = SimulationState.COMPLETED
            state["outcomes"].append({
                "type": "success",
                "message": "Attack flow simulation completed",
                "total_steps": state["current_step"],
                "actions_executed": len(state["executed_actions"])
            })
        
        # Generate simulation report
        return self._generate_report(state, flow_structure, check_coverage)
    
    def _parse_flow_structure(self, attack_flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse Attack Flow bundle into structured format."""
        if attack_flow.get("type") != "bundle":
            return None
        
        objects = attack_flow.get("objects", [])
        if not objects:
            return None
        
        # Find flow object
        flow_object = None
        for obj in objects:
            if obj.get("type") == "attack-flow":
                flow_object = obj
                break
        
        if not flow_object:
            return None
        
        # Index objects by ID
        objects_by_id = {obj.get("id"): obj for obj in objects if obj.get("id")}
        
        # Build relationship map
        relationships = {}
        for obj in objects:
            if obj.get("type") == "relationship":
                source = obj.get("source_ref")
                target = obj.get("target_ref")
                if source and target:
                    if source not in relationships:
                        relationships[source] = []
                    relationships[source].append(target)
        
        return {
            "flow_object": flow_object,
            "objects_by_id": objects_by_id,
            "relationships": relationships,
            "all_objects": objects
        }
    
    def _simulate_action(
        self,
        action: Dict[str, Any],
        state: Dict[str, Any],
        flow_structure: Dict[str, Any],
        check_coverage: bool
    ) -> Dict[str, Any]:
        """Simulate execution of an attack-action."""
        action_id = action.get("id")
        technique_id = action.get("technique_id", "")
        
        # Record execution
        execution_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "action",
            "id": action_id,
            "name": action.get("name", "Unknown Action"),
            "technique_id": technique_id,
            "confidence": action.get("confidence", 50)
        }
        
        state["executed_actions"].append(action_id)
        state["execution_path"].append(execution_record)
        
        # Check detection coverage if requested
        if check_coverage and technique_id and self.driver:
            coverage = self._check_technique_coverage(technique_id)
            if not coverage["has_detection"]:
                state["coverage_gaps"].append({
                    "action_id": action_id,
                    "technique_id": technique_id,
                    "gap_type": "no_detection"
                })
            execution_record["coverage"] = coverage
        
        # Determine next actions
        next_refs = flow_structure["relationships"].get(action_id, [])
        
        # Add outcome
        state["outcomes"].append({
            "type": "action_executed",
            "action_id": action_id,
            "technique_id": technique_id,
            "success": True,
            "next_actions": next_refs
        })
        
        return {"next_refs": next_refs}
    
    def _simulate_condition(
        self,
        condition: Dict[str, Any],
        state: Dict[str, Any],
        flow_structure: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Simulate evaluation of an attack-condition."""
        condition_id = condition.get("id")
        pattern = condition.get("pattern", "")
        
        # Evaluate condition (simplified - in production would use pattern matching)
        evaluation_result = self._evaluate_condition(pattern, state["conditions"])
        
        # Record evaluation
        execution_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "condition",
            "id": condition_id,
            "description": condition.get("description", ""),
            "pattern": pattern,
            "evaluated_to": evaluation_result
        }
        
        state["execution_path"].append(execution_record)
        
        # Determine next refs based on evaluation
        if evaluation_result:
            next_refs = condition.get("on_true_refs", [])
        else:
            next_refs = condition.get("on_false_refs", [])
        
        # Add outcome
        state["outcomes"].append({
            "type": "condition_evaluated",
            "condition_id": condition_id,
            "result": evaluation_result,
            "branch_taken": "true" if evaluation_result else "false",
            "next_refs": next_refs
        })
        
        return {"next_refs": next_refs}
    
    def _simulate_operator(
        self,
        operator: Dict[str, Any],
        state: Dict[str, Any],
        flow_structure: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Simulate evaluation of an attack-operator."""
        operator_id = operator.get("id")
        op_type = operator.get("operator", "AND")
        effect_refs = operator.get("effect_refs", [])
        
        # For simulation, we'll process all effects
        # In a real scenario, AND would require all, OR would require any
        execution_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "operator",
            "id": operator_id,
            "operator": op_type,
            "effects": effect_refs
        }
        
        state["execution_path"].append(execution_record)
        
        # For simulation, continue with all effects
        next_refs = effect_refs
        
        # Add outcome
        state["outcomes"].append({
            "type": "operator_evaluated",
            "operator_id": operator_id,
            "operator_type": op_type,
            "next_refs": next_refs
        })
        
        return {"next_refs": next_refs}
    
    def _simulate_asset(
        self,
        asset: Dict[str, Any],
        state: Dict[str, Any],
        flow_structure: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Simulate interaction with an attack-asset."""
        asset_id = asset.get("id")
        
        # Record asset interaction
        execution_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": "asset",
            "id": asset_id,
            "name": asset.get("name", "Unknown Asset"),
            "description": asset.get("description", "")
        }
        
        state["execution_path"].append(execution_record)
        
        # Assets typically don't have next refs, check relationships
        next_refs = flow_structure["relationships"].get(asset_id, [])
        
        # Add outcome
        state["outcomes"].append({
            "type": "asset_accessed",
            "asset_id": asset_id,
            "asset_name": asset.get("name", ""),
            "next_refs": next_refs
        })
        
        return {"next_refs": next_refs}
    
    def _evaluate_condition(self, pattern: str, conditions: Dict[str, Any]) -> bool:
        """
        Evaluate a condition pattern against current state.
        
        This is a simplified implementation. In production, you'd want
        a proper pattern matching engine.
        """
        # Simple key=value matching
        if "==" in pattern:
            parts = pattern.split("==")
            if len(parts) == 2:
                key = parts[0].strip()
                expected_value = parts[1].strip().strip("'\"")
                actual_value = conditions.get(key)
                return str(actual_value) == expected_value
        
        # AND logic
        if " AND " in pattern:
            sub_patterns = pattern.split(" AND ")
            return all(self._evaluate_condition(sp, conditions) for sp in sub_patterns)
        
        # OR logic
        if " OR " in pattern:
            sub_patterns = pattern.split(" OR ")
            return any(self._evaluate_condition(sp, conditions) for sp in sub_patterns)
        
        # Default to true for undefined patterns
        return True
    
    def _check_technique_coverage(self, technique_id: str) -> Dict[str, Any]:
        """Check detection coverage for a technique."""
        if not self.driver:
            return {"has_detection": False, "has_mitigation": False}
        
        with self.driver.session() as session:
            result = session.run("""
                MATCH (t:AttackPattern)
                WHERE t.external_id = $technique_id
                OPTIONAL MATCH (t)<-[:DETECTS]-(d:DetectionStrategy)
                OPTIONAL MATCH (t)<-[:MITIGATES]-(m:Mitigation)
                RETURN count(DISTINCT d) > 0 as has_detection,
                       count(DISTINCT m) > 0 as has_mitigation,
                       collect(DISTINCT d.name)[..3] as detections,
                       collect(DISTINCT m.name)[..3] as mitigations
            """, technique_id=technique_id)
            
            record = result.single()
            if record:
                return {
                    "has_detection": record["has_detection"],
                    "has_mitigation": record["has_mitigation"],
                    "detections": record["detections"],
                    "mitigations": record["mitigations"]
                }
        
        return {"has_detection": False, "has_mitigation": False}
    
    def _generate_report(
        self,
        state: Dict[str, Any],
        flow_structure: Dict[str, Any],
        check_coverage: bool
    ) -> Dict[str, Any]:
        """Generate simulation report."""
        report = {
            "simulation_id": f"sim-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "flow_name": flow_structure["flow_object"].get("name", "Unknown Flow"),
            "status": state["status"].value,
            "summary": {
                "total_steps": state["current_step"],
                "actions_executed": len(state["executed_actions"]),
                "conditions_evaluated": len([e for e in state["execution_path"] if e["type"] == "condition"]),
                "operators_processed": len([e for e in state["execution_path"] if e["type"] == "operator"]),
                "assets_accessed": len([e for e in state["execution_path"] if e["type"] == "asset"])
            },
            "execution_path": state["execution_path"],
            "outcomes": state["outcomes"]
        }
        
        if check_coverage:
            report["coverage_analysis"] = {
                "gaps_identified": len(state["coverage_gaps"]),
                "coverage_gaps": state["coverage_gaps"],
                "coverage_percentage": self._calculate_coverage_percentage(state)
            }
        
        # Add path visualization data
        report["visualization"] = self._generate_visualization_data(state, flow_structure)
        
        return report
    
    def _calculate_coverage_percentage(self, state: Dict[str, Any]) -> float:
        """Calculate overall coverage percentage."""
        if not state["executed_actions"]:
            return 0.0
        
        covered = len(state["executed_actions"]) - len(state["coverage_gaps"])
        return round(100.0 * covered / len(state["executed_actions"]), 2)
    
    def _generate_visualization_data(
        self,
        state: Dict[str, Any],
        flow_structure: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate data for visualization of simulation results."""
        # Mark executed nodes
        executed_ids = set()
        for record in state["execution_path"]:
            executed_ids.add(record["id"])
        
        # Build visualization nodes
        nodes = []
        for obj in flow_structure["all_objects"]:
            obj_id = obj.get("id")
            if not obj_id:
                continue
            
            node = {
                "id": obj_id,
                "type": obj.get("type"),
                "label": obj.get("name", obj.get("description", obj_id)[:30]),
                "executed": obj_id in executed_ids,
                "properties": {}
            }
            
            # Add type-specific properties
            if obj.get("type") == "attack-action":
                node["properties"]["technique_id"] = obj.get("technique_id", "")
            elif obj.get("type") == "attack-condition":
                node["properties"]["pattern"] = obj.get("pattern", "")
            elif obj.get("type") == "attack-operator":
                node["properties"]["operator"] = obj.get("operator", "")
            
            nodes.append(node)
        
        # Build edges from relationships
        edges = []
        for source, targets in flow_structure["relationships"].items():
            for target in targets:
                edge = {
                    "source": source,
                    "target": target,
                    "executed": source in executed_ids and target in executed_ids
                }
                edges.append(edge)
        
        return {
            "nodes": nodes,
            "edges": edges,
            "executed_path": list(executed_ids)
        }
    
    def simulate_step(
        self,
        attack_flow: Dict[str, Any],
        current_state: Dict[str, Any],
        step_id: str
    ) -> Dict[str, Any]:
        """
        Simulate a single step in the attack flow.
        
        Useful for interactive/step-by-step simulation.
        
        Args:
            attack_flow: Attack Flow 2.0 JSON bundle
            current_state: Current simulation state
            step_id: ID of the step to execute
            
        Returns:
            Updated state after step execution
        """
        flow_structure = self._parse_flow_structure(attack_flow)
        if not flow_structure:
            return current_state
        
        obj = flow_structure["objects_by_id"].get(step_id)
        if not obj:
            return current_state
        
        # Process the specific step
        obj_type = obj.get("type")
        
        if obj_type == "attack-action":
            result = self._simulate_action(obj, current_state, flow_structure, False)
        elif obj_type == "attack-condition":
            result = self._simulate_condition(obj, current_state, flow_structure)
        elif obj_type == "attack-operator":
            result = self._simulate_operator(obj, current_state, flow_structure)
        elif obj_type == "attack-asset":
            result = self._simulate_asset(obj, current_state, flow_structure)
        else:
            result = {"next_refs": []}
        
        current_state["current_step"] += 1
        current_state["next_options"] = result["next_refs"]
        
        return current_state
    
    def close(self):
        """Close Neo4j connection if exists."""
        if self.driver:
            self.driver.close()


def simulate_attack_flow(
    attack_flow: Dict[str, Any],
    initial_conditions: Optional[Dict[str, Any]] = None,
    neo4j_uri: Optional[str] = None,
    neo4j_user: Optional[str] = None,
    neo4j_password: Optional[str] = None
) -> Dict[str, Any]:
    """
    Convenience function to simulate an Attack Flow.
    
    Args:
        attack_flow: Attack Flow 2.0 JSON bundle
        initial_conditions: Initial conditions for simulation
        neo4j_uri: Optional Neo4j URI for coverage checks
        neo4j_user: Optional Neo4j username
        neo4j_password: Optional Neo4j password
        
    Returns:
        Simulation report
    """
    simulator = AttackFlowSimulator(neo4j_uri, neo4j_user, neo4j_password)
    try:
        report = simulator.simulate(attack_flow, initial_conditions)
        return report
    finally:
        simulator.close()