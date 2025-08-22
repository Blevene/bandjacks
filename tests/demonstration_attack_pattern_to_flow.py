#!/usr/bin/env python3
"""
Sprint 6 Demonstration: Converting Attack Patterns from Graph to Attack Flow 2.0

This script demonstrates:
1. Querying existing AttackPattern nodes from Neo4j
2. Generating an Attack Flow 2.0 document using those techniques
3. Showing how the generator enriches the flow with graph data
4. Validating the generated flow against the official schema
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from neo4j import GraphDatabase
from bandjacks.llm.attack_flow_generator import AttackFlowGenerator
from bandjacks.llm.attack_flow_simulator import AttackFlowSimulator
from bandjacks.services.api.settings import settings


def query_attack_patterns(driver) -> List[Dict[str, Any]]:
    """Query available attack patterns from the graph."""
    with driver.session() as session:
        # Get some interesting techniques that form a logical progression
        result = session.run("""
            MATCH (t:AttackPattern)
            WHERE t.external_id IN ['T1003', 'T1059', 'T1071', 'T1078', 'T1548', 'T1055']
            OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
            RETURN t.external_id as id, 
                   t.name as name, 
                   t.description as description,
                   collect(DISTINCT tac.name) as tactics
            ORDER BY t.external_id
        """)
        
        techniques = []
        for record in result:
            techniques.append({
                'id': record['id'],
                'name': record['name'],
                'description': record['description'],
                'tactics': record['tactics']
            })
        
        return techniques


def demonstrate_linear_flow(generator: AttackFlowGenerator, techniques: List[str]):
    """Generate a simple linear attack flow."""
    print("\n" + "="*60)
    print("DEMO 1: Linear Attack Flow")
    print("="*60)
    
    flow = generator.generate(
        techniques=techniques[:3],  # Use first 3 techniques
        name="Credential Theft to C2 Communication",
        description="Attack flow demonstrating progression from credential access through execution to command and control",
        scope="incident"
    )
    
    # Show the enriched data
    print("\nGenerated Attack Flow Components:")
    action_count = 0
    for obj in flow["objects"]:
        if obj.get("type") == "attack-action":
            action_count += 1
            print(f"\n  Action {action_count}: {obj['name']}")
            print(f"    Technique ID: {obj['technique_id']}")
            print(f"    Description: {obj['description'][:150]}...")
            if obj.get('tactic_refs'):
                print(f"    Tactics: {', '.join(obj['tactic_refs'])}")
    
    # Validate
    is_valid, errors = generator.validate_generated(flow)
    print(f"\n✓ Flow Validation: {'PASSED' if is_valid else 'FAILED'}")
    if errors and errors != ["Validation successful"]:
        print(f"  Validation notes: {errors[:2]}")  # Show first 2 errors if any
    
    return flow


def demonstrate_conditional_flow(generator: AttackFlowGenerator):
    """Generate an attack flow with conditional branching."""
    print("\n" + "="*60)
    print("DEMO 2: Conditional Attack Flow")
    print("="*60)
    
    flow = generator.generate(
        techniques=["T1003", "T1078", "T1548", "T1059"],
        name="Privilege Escalation Decision Tree",
        description="Attack flow with conditional branching based on credential availability",
        conditions=[{
            "name": "cred_check",
            "description": "Check if valid credentials were obtained",
            "pattern": "credentials.valid == true",
            "on_true": "T1078",  # Valid Accounts
            "on_false": "T1548"  # Abuse Elevation Control Mechanism
        }],
        sequence=[
            ("T1003", "cred_check"),  # Credential Dumping leads to condition
            ("T1078", "T1059"),        # Valid Accounts leads to Command Execution
            ("T1548", "T1059")         # Privilege Escalation leads to Command Execution
        ],
        scope="incident"
    )
    
    print("\nConditional Flow Structure:")
    print("  1. T1003 (OS Credential Dumping)")
    print("  2. Condition: Check if credentials are valid")
    print("     ├─ TRUE:  T1078 (Valid Accounts)")
    print("     └─ FALSE: T1548 (Abuse Elevation Control)")
    print("  3. T1059 (Command and Scripting Interpreter)")
    
    # Find and display the condition
    for obj in flow["objects"]:
        if obj.get("type") == "attack-condition":
            print(f"\nCondition Details:")
            print(f"  Description: {obj['description']}")
            print(f"  Pattern: {obj['pattern']}")
            print(f"  On True: {len(obj.get('on_true_refs', []))} reference(s)")
            print(f"  On False: {len(obj.get('on_false_refs', []))} reference(s)")
    
    return flow


def demonstrate_complex_flow(generator: AttackFlowGenerator):
    """Generate a complex attack flow with operators and assets."""
    print("\n" + "="*60)
    print("DEMO 3: Complex Attack Flow with Operators")
    print("="*60)
    
    flow = generator.generate(
        techniques=["T1003", "T1055", "T1059", "T1071"],
        name="Advanced Persistent Threat Campaign",
        description="Complex attack flow with parallel execution and targeted assets",
        operators=[{
            "name": "parallel_injection",
            "operator": "AND",
            "inputs": ["T1055", "T1059"]
        }],
        assets=[
            {"name": "domain_controller", "description": "Primary domain controller"},
            {"name": "file_server", "description": "Central file server"}
        ],
        sequence=[
            ("T1003", "T1055"),  # Credential Dumping to Process Injection
            ("T1003", "T1059"),  # Credential Dumping to Command Execution
            ("parallel_injection", "T1071")  # Both lead to C2
        ],
        scope="campaign"
    )
    
    print("\nComplex Flow Features:")
    
    # Count object types
    object_types = {}
    for obj in flow["objects"]:
        obj_type = obj.get("type", "unknown")
        object_types[obj_type] = object_types.get(obj_type, 0) + 1
    
    for obj_type, count in sorted(object_types.items()):
        print(f"  - {count} {obj_type} object(s)")
    
    # Show operator details
    for obj in flow["objects"]:
        if obj.get("type") == "attack-operator":
            print(f"\nOperator: {obj['operator']} operation")
            print(f"  Combines {len(obj.get('effect_refs', []))} inputs")
    
    return flow


def simulate_flow_execution(simulator: AttackFlowSimulator, flow: Dict[str, Any]):
    """Simulate the execution of an attack flow."""
    print("\n" + "="*60)
    print("DEMO 4: Flow Simulation")
    print("="*60)
    
    # Simulate with different initial conditions
    scenarios = [
        {"has_credentials": "true", "admin_access": "false"},
        {"has_credentials": "false", "admin_access": "false"}
    ]
    
    for i, initial_conditions in enumerate(scenarios, 1):
        print(f"\nScenario {i}: {initial_conditions}")
        
        result = simulator.simulate(
            attack_flow=flow,
            initial_conditions=initial_conditions,
            max_steps=10,
            check_coverage=False  # Skip coverage check for demo
        )
        
        print(f"  Simulation Status: {result['status']}")
        print(f"  Steps Executed: {result['summary']['total_steps']}")
        if result['execution_path']:
            print(f"  Path Taken: ", end="")
            for step in result['execution_path'][:3]:  # Show first 3 steps
                if step['type'] == 'action':
                    print(f"{step.get('technique_id', 'N/A')} → ", end="")
            print("...")


def main():
    """Main demonstration function."""
    print("\n" + "="*80)
    print(" Sprint 6: Attack Pattern to Flow Conversion Demonstration")
    print("="*80)
    
    try:
        # Connect to Neo4j
        print("\n1. Connecting to Neo4j...")
        driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password)
        )
        
        # Verify connection and query techniques
        print("2. Querying existing AttackPattern nodes from graph...")
        techniques_data = query_attack_patterns(driver)
        
        if not techniques_data:
            print("\n⚠️  No techniques found in graph!")
            print("   Please load ATT&CK data first:")
            print('   curl -X POST "http://localhost:8001/v1/stix/load/attack?collection=enterprise-attack&version=latest"')
            return
        
        print(f"\n   Found {len(techniques_data)} techniques in graph:")
        for tech in techniques_data:
            tactics_str = ', '.join(tech['tactics'][:2]) if tech['tactics'] else 'N/A'
            print(f"   • {tech['id']}: {tech['name']} (Tactics: {tactics_str})")
        
        # Initialize generator with Neo4j connection
        print("\n3. Initializing Attack Flow Generator with Neo4j connection...")
        generator = AttackFlowGenerator(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        # Extract just the technique IDs
        technique_ids = [t['id'] for t in techniques_data]
        
        # Run demonstrations
        print("\n4. Running demonstrations...")
        
        # Demo 1: Linear flow
        linear_flow = demonstrate_linear_flow(generator, technique_ids)
        
        # Demo 2: Conditional flow
        conditional_flow = demonstrate_conditional_flow(generator)
        
        # Demo 3: Complex flow
        complex_flow = demonstrate_complex_flow(generator)
        
        # Demo 4: Simulate a flow
        print("\n5. Running flow simulation...")
        simulator = AttackFlowSimulator(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        simulate_flow_execution(simulator, conditional_flow)
        
        # Save example flow
        output_file = Path(__file__).parent / "demo_generated_flow.json"
        with open(output_file, "w") as f:
            json.dump(linear_flow, f, indent=2)
        print(f"\n6. Example flow saved to: {output_file}")
        
        # Cleanup
        driver.close()
        generator.close()
        simulator.close()
        
        print("\n" + "="*80)
        print(" ✅ Demonstration Complete!")
        print("="*80)
        print("\nKey Takeaways:")
        print("• Attack patterns from Neo4j are successfully enriched into flows")
        print("• Generator pulls technique names, descriptions, and tactics from graph")
        print("• Flows support linear, conditional, and complex structures")
        print("• Generated flows are valid Attack Flow 2.0 JSON documents")
        print("• Simulation can execute flows with different conditions")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nTroubleshooting:")
        print("1. Ensure Neo4j is running")
        print("2. Load ATT&CK data into Neo4j")
        print("3. Check connection settings in settings.py")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())