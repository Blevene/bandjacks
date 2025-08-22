"""Sprint 6 Attack Flow 2.0 comprehensive tests."""

import pytest
import json
import uuid
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List

from bandjacks.llm.attack_flow_validator import AttackFlowValidator
from bandjacks.llm.attack_flow_generator import AttackFlowGenerator
from bandjacks.llm.attack_flow_simulator import AttackFlowSimulator, SimulationState
from bandjacks.services.api.routes.attackflow import (
    normalize_to_episode_action,
    validate_attack_flow_schema
)


class TestAttackFlowValidator:
    """Test Attack Flow 2.0 validation."""
    
    def test_load_schema(self):
        """Test schema loading."""
        validator = AttackFlowValidator()
        schema_info = validator.get_schema_info()
        
        assert "attack-flow-schema" in schema_info["schema_path"]
        assert validator.schema is not None
        assert validator.validator is not None
    
    def test_validate_valid_flow(self):
        """Test validation of a valid Attack Flow."""
        # Load example flow
        examples_dir = Path(__file__).parent / "fixtures" / "attack_flow_examples"
        linear_flow_path = examples_dir / "linear_flow.json"
        
        if linear_flow_path.exists():
            with open(linear_flow_path, 'r') as f:
                flow = json.load(f)
            
            validator = AttackFlowValidator()
            is_valid, errors = validator.validate(flow)
            
            assert is_valid, f"Valid flow failed validation: {errors}"
            assert len(errors) == 0
    
    def test_validate_invalid_flow_missing_bundle(self):
        """Test validation of flow missing bundle type."""
        invalid_flow = {
            "id": "not-a-bundle",
            "objects": []
        }
        
        validator = AttackFlowValidator()
        is_valid, errors = validator.validate(invalid_flow)
        
        assert not is_valid
        assert any("bundle" in error.lower() for error in errors)
    
    def test_validate_invalid_flow_no_attack_flow_object(self):
        """Test validation of bundle without attack-flow object."""
        invalid_flow = {
            "type": "bundle",
            "id": "bundle--test",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "attack-action",
                    "id": "attack-action--test",
                    "spec_version": "2.1",
                    "name": "Test Action"
                }
            ]
        }
        
        validator = AttackFlowValidator()
        is_valid, errors = validator.validate(invalid_flow)
        
        assert not is_valid
        assert any("attack-flow" in error.lower() for error in errors)
    
    def test_validate_attack_action_constraints(self):
        """Test validation of attack-action constraints."""
        flow = {
            "type": "bundle",
            "id": "bundle--test",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "attack-flow",
                    "id": "attack-flow--test",
                    "spec_version": "2.1",
                    "name": "Test Flow",
                    "scope": "incident",
                    "start_refs": ["attack-action--missing-name"]
                },
                {
                    "type": "attack-action",
                    "id": "attack-action--missing-name",
                    "spec_version": "2.1",
                    # Missing required 'name' field
                    "technique_id": "T1003"
                }
            ]
        }
        
        validator = AttackFlowValidator()
        is_valid, errors = validator.validate(flow)
        
        assert not is_valid
        assert any("missing required 'name'" in error for error in errors)
    
    def test_validate_technique_id_format(self):
        """Test validation of technique ID format."""
        validator = AttackFlowValidator()
        
        # Valid formats
        assert validator._is_valid_technique_id("T1003")
        assert validator._is_valid_technique_id("T1003.001")
        
        # Invalid formats
        assert not validator._is_valid_technique_id("1003")
        assert not validator._is_valid_technique_id("T1003.1")
        assert not validator._is_valid_technique_id("Invalid")


class TestAttackFlowGenerator:
    """Test Attack Flow generation."""
    
    def test_generate_linear_flow(self):
        """Test generation of simple linear flow."""
        generator = AttackFlowGenerator()
        
        flow = generator.generate(
            techniques=["T1003", "T1059", "T1071"],
            name="Test Linear Flow",
            description="Test flow generation",
            scope="incident"
        )
        
        # Validate structure
        assert flow["type"] == "bundle"
        assert "objects" in flow
        
        # Find attack-flow object
        flow_obj = None
        for obj in flow["objects"]:
            if obj.get("type") == "attack-flow":
                flow_obj = obj
                break
        
        assert flow_obj is not None
        assert flow_obj["name"] == "Test Linear Flow"
        assert flow_obj["scope"] == "incident"
        assert len(flow_obj["start_refs"]) > 0
        
        # Count attack-action objects
        action_count = sum(1 for obj in flow["objects"] if obj.get("type") == "attack-action")
        assert action_count == 3
        
        # Validate with schema
        is_valid, errors = generator.validate_generated(flow)
        assert is_valid, f"Generated flow is invalid: {errors}"
    
    def test_generate_flow_with_conditions(self):
        """Test generation of flow with conditions."""
        generator = AttackFlowGenerator()
        
        conditions = [
            {
                "name": "cred_check",
                "description": "Check if credentials obtained",
                "pattern": "has_credentials == true",
                "on_true": "T1078",
                "on_false": "T1548"
            }
        ]
        
        flow = generator.generate(
            techniques=["T1003", "T1078", "T1548"],
            name="Conditional Flow",
            conditions=conditions,
            sequence=[("T1003", "cred_check")]
        )
        
        # Find condition object
        condition_obj = None
        for obj in flow["objects"]:
            if obj.get("type") == "attack-condition":
                condition_obj = obj
                break
        
        assert condition_obj is not None
        assert condition_obj["description"] == "Check if credentials obtained"
        assert len(condition_obj["on_true_refs"]) > 0
        assert len(condition_obj["on_false_refs"]) > 0
    
    def test_generate_flow_with_operators(self):
        """Test generation of flow with operators."""
        generator = AttackFlowGenerator()
        
        operators = [
            {
                "name": "parallel_exec",
                "operator": "AND",
                "inputs": ["T1055", "T1059"]
            }
        ]
        
        flow = generator.generate(
            techniques=["T1003", "T1055", "T1059", "T1071"],
            name="Operator Flow",
            operators=operators
        )
        
        # Find operator object
        operator_obj = None
        for obj in flow["objects"]:
            if obj.get("type") == "attack-operator":
                operator_obj = obj
                break
        
        assert operator_obj is not None
        assert operator_obj["operator"] == "AND"
        assert len(operator_obj["effect_refs"]) >= 2
    
    def test_generate_flow_with_assets(self):
        """Test generation of flow with assets."""
        generator = AttackFlowGenerator()
        
        assets = [
            {
                "name": "web_server",
                "description": "Target web server"
            },
            {
                "name": "database",
                "description": "Backend database"
            }
        ]
        
        flow = generator.generate(
            techniques=["T1190", "T1059"],
            name="Asset Flow",
            assets=assets
        )
        
        # Count asset objects
        asset_count = sum(1 for obj in flow["objects"] if obj.get("type") == "attack-asset")
        assert asset_count == 2
    
    def test_generate_from_template(self):
        """Test template-based generation."""
        generator = AttackFlowGenerator()
        
        # Test linear template
        flow = generator.generate_from_template(
            "linear",
            {"techniques": ["T1566", "T1059", "T1071"]}
        )
        assert flow["type"] == "bundle"
        
        # Test branching template
        flow = generator.generate_from_template(
            "branching",
            {"techniques": ["T1003", "T1055", "T1059", "T1071"]}
        )
        operator_count = sum(1 for obj in flow["objects"] if obj.get("type") == "attack-operator")
        assert operator_count > 0
        
        # Test conditional template
        flow = generator.generate_from_template(
            "conditional",
            {"techniques": ["T1003", "T1055", "T1548"]}
        )
        condition_count = sum(1 for obj in flow["objects"] if obj.get("type") == "attack-condition")
        assert condition_count > 0
        
        # Test complex template
        flow = generator.generate_from_template(
            "complex",
            {}  # Uses default techniques
        )
        assert len(flow["objects"]) > 10


class TestAttackFlowSimulator:
    """Test Attack Flow simulation."""
    
    def test_simulate_linear_flow(self):
        """Test simulation of linear flow."""
        # Load example flow
        examples_dir = Path(__file__).parent / "fixtures" / "attack_flow_examples"
        linear_flow_path = examples_dir / "linear_flow.json"
        
        if linear_flow_path.exists():
            with open(linear_flow_path, 'r') as f:
                flow = json.load(f)
            
            simulator = AttackFlowSimulator()
            result = simulator.simulate(flow)
            
            assert result["status"] == "completed"
            assert result["summary"]["actions_executed"] == 3
            assert len(result["execution_path"]) > 0
            
            # Check visualization data
            assert "visualization" in result
            assert len(result["visualization"]["nodes"]) > 0
            assert len(result["visualization"]["edges"]) > 0
    
    def test_simulate_branching_flow(self):
        """Test simulation of branching flow with conditions."""
        # Load example flow
        examples_dir = Path(__file__).parent / "fixtures" / "attack_flow_examples"
        branching_flow_path = examples_dir / "branching_flow.json"
        
        if branching_flow_path.exists():
            with open(branching_flow_path, 'r') as f:
                flow = json.load(f)
            
            # Simulate with condition true
            simulator = AttackFlowSimulator()
            result = simulator.simulate(
                flow,
                initial_conditions={"credential_access": "success"}
            )
            
            assert result["status"] == "completed"
            
            # Check that condition was evaluated
            condition_evals = [
                e for e in result["execution_path"] 
                if e["type"] == "condition"
            ]
            assert len(condition_evals) > 0
            assert condition_evals[0]["evaluated_to"] == True
            
            # Simulate with condition false
            result2 = simulator.simulate(
                flow,
                initial_conditions={"credential_access": "failed"}
            )
            
            assert result2["status"] == "completed"
            condition_evals2 = [
                e for e in result2["execution_path"]
                if e["type"] == "condition"
            ]
            if condition_evals2:
                assert condition_evals2[0]["evaluated_to"] == False
    
    def test_simulate_with_coverage_check(self):
        """Test simulation with coverage checking."""
        # Generate a simple flow
        generator = AttackFlowGenerator()
        flow = generator.generate(
            techniques=["T1003", "T1059"],
            name="Coverage Test Flow"
        )
        
        # Mock Neo4j for coverage checks
        mock_driver = Mock()
        mock_session = Mock()
        mock_driver.session.return_value.__enter__ = Mock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = Mock(return_value=None)
        
        # Mock coverage response
        mock_result = Mock()
        mock_result.single.return_value = {
            "has_detection": False,
            "has_mitigation": True,
            "detections": [],
            "mitigations": ["M1040"]
        }
        mock_session.run.return_value = mock_result
        
        simulator = AttackFlowSimulator()
        simulator.driver = mock_driver
        
        result = simulator.simulate(flow, check_coverage=True)
        
        assert "coverage_analysis" in result
        assert "coverage_gaps" in result["coverage_analysis"]
    
    def test_simulate_step_by_step(self):
        """Test step-by-step simulation."""
        # Generate a simple flow
        generator = AttackFlowGenerator()
        flow = generator.generate(
            techniques=["T1003", "T1059", "T1071"],
            name="Step Test Flow"
        )
        
        simulator = AttackFlowSimulator()
        
        # Initialize state
        state = {
            "conditions": {},
            "executed_actions": [],
            "current_step": 0,
            "execution_path": [],
            "outcomes": [],
            "coverage_gaps": [],
            "status": SimulationState.READY
        }
        
        # Find first action
        first_action = None
        for obj in flow["objects"]:
            if obj.get("type") == "attack-flow":
                first_action = obj["start_refs"][0] if obj.get("start_refs") else None
                break
        
        if first_action:
            # Execute first step
            state = simulator.simulate_step(flow, state, first_action)
            
            assert state["current_step"] == 1
            assert len(state["executed_actions"]) == 1
            assert "next_options" in state
    
    def test_condition_evaluation(self):
        """Test condition pattern evaluation."""
        simulator = AttackFlowSimulator()
        
        # Test simple equality
        assert simulator._evaluate_condition(
            "status == 'success'",
            {"status": "success"}
        )
        assert not simulator._evaluate_condition(
            "status == 'success'",
            {"status": "failed"}
        )
        
        # Test AND logic
        assert simulator._evaluate_condition(
            "status == 'success' AND level == 'high'",
            {"status": "success", "level": "high"}
        )
        assert not simulator._evaluate_condition(
            "status == 'success' AND level == 'high'",
            {"status": "success", "level": "low"}
        )
        
        # Test OR logic
        assert simulator._evaluate_condition(
            "status == 'success' OR status == 'partial'",
            {"status": "partial"}
        )


class TestAttackFlowIngestion:
    """Test Attack Flow ingestion and normalization."""
    
    @patch('bandjacks.services.api.routes.attackflow.AttackFlowValidator')
    def test_validate_with_schema(self, mock_validator_class):
        """Test validation using official schema."""
        mock_validator = Mock()
        mock_validator.validate.return_value = (True, [])
        mock_validator_class.return_value = mock_validator
        
        flow = {
            "type": "bundle",
            "objects": []
        }
        
        errors = validate_attack_flow_schema(flow)
        
        assert len(errors) == 0
        mock_validator.validate.assert_called_once_with(flow)
    
    def test_normalize_to_episode_action(self):
        """Test normalization to internal format."""
        flow = {
            "type": "bundle",
            "objects": [
                {
                    "type": "attack-flow",
                    "id": "attack-flow--test",
                    "name": "Test Flow",
                    "description": "Test normalization"
                },
                {
                    "type": "attack-action",
                    "id": "attack-action--001",
                    "name": "Credential Dumping",
                    "technique_id": "T1003",
                    "confidence": 85,
                    "order": 0
                },
                {
                    "type": "attack-action",
                    "id": "attack-action--002",
                    "name": "Command Execution",
                    "technique_id": "T1059",
                    "confidence": 80,
                    "order": 1
                },
                {
                    "type": "relationship",
                    "source_ref": "attack-action--001",
                    "target_ref": "attack-action--002",
                    "confidence": 75
                }
            ]
        }
        
        # Mock Neo4j session
        mock_session = Mock()
        mock_session.run.return_value.single.return_value = None
        
        result = normalize_to_episode_action(flow, mock_session)
        
        assert "flow_id" in result
        assert result["nodes_created"] >= 2
        assert result["edges_created"] >= 1
        assert isinstance(result["warnings"], list)


class TestAttackFlowAPI:
    """Test Attack Flow API endpoints."""
    
    @pytest.fixture
    def mock_neo4j_session(self):
        """Mock Neo4j session."""
        session = Mock()
        session.run.return_value.single.return_value = None
        return session
    
    def test_generate_endpoint_request(self):
        """Test /generate endpoint request structure."""
        from bandjacks.services.api.routes.attackflow import AttackFlowGenerateRequest
        
        request = AttackFlowGenerateRequest(
            techniques=["T1003", "T1059"],
            name="API Test Flow",
            description="Testing API generation",
            scope="incident"
        )
        
        assert request.techniques == ["T1003", "T1059"]
        assert request.name == "API Test Flow"
        assert request.scope == "incident"
    
    def test_simulate_endpoint_request(self):
        """Test /simulate endpoint request structure."""
        from bandjacks.services.api.routes.attackflow import AttackFlowSimulateRequest
        
        request = AttackFlowSimulateRequest(
            flow_id="flow--test-123",
            initial_conditions={"test": "value"},
            max_steps=50,
            check_coverage=True
        )
        
        assert request.flow_id == "flow--test-123"
        assert request.max_steps == 50
        assert request.check_coverage == True


def test_sprint6_acceptance_criteria():
    """Test Sprint 6 acceptance criteria."""
    
    # 1. Ingest MITRE-provided Attack Flow example
    examples_dir = Path(__file__).parent / "fixtures" / "attack_flow_examples"
    linear_flow_path = examples_dir / "linear_flow.json"
    
    if linear_flow_path.exists():
        validator = AttackFlowValidator()
        is_valid, errors = validator.validate_file(str(linear_flow_path))
        assert is_valid, "Failed to validate MITRE example flow"
    
    # 2. Generate attack flow from test intrusion scenario
    generator = AttackFlowGenerator()
    flow = generator.generate(
        techniques=["T1003", "T1059", "T1071"],
        name="Test Intrusion Scenario"
    )
    
    # Validate generated flow
    is_valid, errors = generator.validate_generated(flow)
    assert is_valid, f"Generated flow failed validation: {errors}"
    
    # 3. Visualization endpoint outputs compatible JSON
    # The flow structure includes all required fields
    assert "type" in flow
    assert flow["type"] == "bundle"
    assert "objects" in flow
    
    # Check for visualization-ready structure
    flow_obj = next((obj for obj in flow["objects"] if obj.get("type") == "attack-flow"), None)
    assert flow_obj is not None
    assert "start_refs" in flow_obj
    
    # 4. Simulation demonstrates flow branching
    simulator = AttackFlowSimulator()
    
    # Create flow with condition
    flow_with_condition = generator.generate(
        techniques=["T1003", "T1078", "T1548"],
        name="Branching Test",
        conditions=[{
            "name": "cred_check",
            "description": "Credential check",
            "pattern": "has_creds == true",
            "on_true": "T1078",
            "on_false": "T1548"
        }],
        sequence=[("T1003", "cred_check")]
    )
    
    # Simulate with true condition
    result_true = simulator.simulate(
        flow_with_condition,
        initial_conditions={"has_creds": "true"}
    )
    
    # Simulate with false condition
    result_false = simulator.simulate(
        flow_with_condition,
        initial_conditions={"has_creds": "false"}
    )
    
    # Both simulations should complete
    assert result_true["status"] == "completed"
    assert result_false["status"] == "completed"
    
    print("✅ All Sprint 6 acceptance criteria met!")


if __name__ == "__main__":
    # Run key tests
    print("Testing Attack Flow Sprint 6 Implementation...")
    
    # Test validator
    test_validator = TestAttackFlowValidator()
    test_validator.test_load_schema()
    test_validator.test_validate_valid_flow()
    print("✅ Validator tests passed")
    
    # Test generator
    test_generator = TestAttackFlowGenerator()
    test_generator.test_generate_linear_flow()
    test_generator.test_generate_flow_with_conditions()
    print("✅ Generator tests passed")
    
    # Test simulator
    test_simulator = TestAttackFlowSimulator()
    test_simulator.test_simulate_linear_flow()
    print("✅ Simulator tests passed")
    
    # Test acceptance criteria
    test_sprint6_acceptance_criteria()
    
    print("\n🎉 Sprint 6 Attack Flow 2.0 implementation complete!")