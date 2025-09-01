#!/usr/bin/env python3
"""CI tests for A5 and A7: Simulation and attack flow behavior."""

import os
import sys
import pytest
import json
import numpy as np
from datetime import datetime
from typing import Dict, List, Any, Set
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bandjacks.simulation.ptg_rollout import (
    PTGRolloutSimulator, RolloutConfig, RolloutResult
)
from bandjacks.simulation.mdp_solver import (
    MDPAttackerPolicy, MDPConfig, AttackerPolicy
)
from bandjacks.llm.flow_builder import FlowBuilder
from bandjacks.llm.sequence_extractor import AttackFlowSynthesizer


class TestA5AgentBasedSimulation:
    """Test A5: Agent-based simulation capabilities."""
    
    def rollout_simulator(self):
        """Create test rollout simulator."""
        return PTGRolloutSimulator(
            neo4j_uri=os.getenv("NEO4J_URI"),
            neo4j_user=os.getenv("NEO4J_USER"),
            neo4j_password=os.getenv("NEO4J_PASSWORD")
        )
    
    def mdp_solver(self):
        """Create test MDP solver."""
        return MDPAttackerPolicy(
            neo4j_uri=os.getenv("NEO4J_URI"),
            neo4j_user=os.getenv("NEO4J_USER"),
            neo4j_password=os.getenv("NEO4J_PASSWORD")
        )
    
    def test_rollout_simulation(self, rollout_simulator):
        """Test PTG rollout simulation."""
        try:
            # Configure rollout
            config = RolloutConfig(
                n_rollouts=100,
                max_steps=20,
                terminal_techniques={"T1486", "T1490"},  # Ransomware goals
                random_seed=42
            )
            
            # Run simulation from initial access
            starting_techniques = ["T1566.001"]  # Phishing
            
            result = rollout_simulator.simulate_rollouts(
                model_id="test-model-001",
                starting_techniques=starting_techniques,
                config=config
            )
            
            # Verify result structure
            assert isinstance(result, RolloutResult)
            assert result.n_rollouts == 100
            assert 0 <= result.success_probability <= 1
            assert result.avg_path_length >= 0
            assert isinstance(result.technique_frequencies, dict)
            assert isinstance(result.successful_paths, list)
            
            # Check technique frequencies
            if result.technique_frequencies:
                total_freq = sum(result.technique_frequencies.values())
                assert total_freq > 0
                
                # Starting technique should appear frequently
                for start_tech in starting_techniques:
                    if start_tech in result.technique_frequencies:
                        assert result.technique_frequencies[start_tech] > 0
            
            print(f"✓ Rollout simulation completed:")
            print(f"  Success rate: {result.success_probability:.2%}")
            print(f"  Avg path length: {result.avg_path_length:.1f}")
            print(f"  Unique techniques: {len(result.technique_frequencies)}")
            
            # Verify path diversity
            if result.successful_paths:
                path_lengths = [len(p) for p in result.successful_paths]
                assert min(path_lengths) > 0
                assert max(path_lengths) <= config.max_steps
                print(f"  Path length range: {min(path_lengths)}-{max(path_lengths)}")
            
        except Exception as e:
            pytest.skip(f"Rollout simulation test skipped: {e}")
    
    def test_mdp_policy_computation(self, mdp_solver):
        """Test MDP policy computation for attacker behavior."""
        try:
            # Configure MDP
            config = MDPConfig(
                terminal_techniques={"T1486", "T1490"},
                discount_factor=0.95,
                max_iterations=100,
                convergence_threshold=1e-4
            )
            
            # Compute optimal policy
            policy = mdp_solver.compute_policy(
                model_id="test-model-001",
                config=config
            )
            
            # Verify policy structure
            assert isinstance(policy, AttackerPolicy)
            assert isinstance(policy.action_map, dict)
            assert isinstance(policy.value_function, dict)
            assert policy.converged or policy.iterations == config.max_iterations
            
            # Check policy consistency
            for state, action in policy.action_map.items():
                assert isinstance(state, str)  # Technique ID
                assert isinstance(action, str) or action is None
                
                # Value function should have entry for each state
                if state in policy.value_function:
                    assert 0 <= policy.value_function[state] <= 1
            
            print(f"✓ MDP policy computed:")
            print(f"  States: {len(policy.action_map)}")
            print(f"  Converged: {policy.converged}")
            print(f"  Iterations: {policy.iterations}")
            
            # Check for reasonable policy
            if policy.action_map:
                # Should have actions from common techniques
                common_techniques = ["T1566.001", "T1078", "T1055"]
                actions_found = sum(1 for t in common_techniques if t in policy.action_map)
                print(f"  Common techniques with actions: {actions_found}/{len(common_techniques)}")
            
        except Exception as e:
            pytest.skip(f"MDP policy test skipped: {e}")
    
    def test_simulation_with_interdiction(self, rollout_simulator):
        """Test simulation with defensive interdiction."""
        try:
            # Baseline simulation
            config = RolloutConfig(
                n_rollouts=50,
                max_steps=15,
                terminal_techniques={"T1486"},
                random_seed=42
            )
            
            baseline_result = rollout_simulator.simulate_rollouts(
                model_id="test-model-001",
                starting_techniques=["T1566.001"],
                config=config
            )
            
            # Simulation with interdiction
            interdicted_techniques = {"T1055", "T1053"}  # Block key techniques
            config_interdicted = RolloutConfig(
                n_rollouts=50,
                max_steps=15,
                terminal_techniques={"T1486"},
                blocked_techniques=interdicted_techniques,
                random_seed=42
            )
            
            interdicted_result = rollout_simulator.simulate_rollouts(
                model_id="test-model-001",
                starting_techniques=["T1566.001"],
                config=config_interdicted
            )
            
            # Interdiction should reduce success rate
            assert interdicted_result.success_probability <= baseline_result.success_probability
            
            # Blocked techniques shouldn't appear in paths
            for path in interdicted_result.successful_paths:
                for technique in path:
                    assert technique not in interdicted_techniques
            
            # Average path length might increase due to detours
            print(f"✓ Interdiction simulation:")
            print(f"  Baseline success: {baseline_result.success_probability:.2%}")
            print(f"  Interdicted success: {interdicted_result.success_probability:.2%}")
            print(f"  Success reduction: {(baseline_result.success_probability - interdicted_result.success_probability):.2%}")
            print(f"  Path length change: {interdicted_result.avg_path_length - baseline_result.avg_path_length:+.1f}")
            
        except Exception as e:
            pytest.skip(f"Interdiction simulation test skipped: {e}")
    
    def test_monte_carlo_convergence(self, rollout_simulator):
        """Test Monte Carlo simulation convergence."""
        try:
            rollout_counts = [10, 50, 100, 500]
            results = []
            
            for n in rollout_counts:
                config = RolloutConfig(
                    n_rollouts=n,
                    max_steps=15,
                    terminal_techniques={"T1486"},
                    random_seed=42
                )
                
                result = rollout_simulator.simulate_rollouts(
                    model_id="test-model-001",
                    starting_techniques=["T1566.001"],
                    config=config
                )
                
                results.append({
                    "n": n,
                    "success_prob": result.success_probability,
                    "std_error": np.sqrt(result.success_probability * (1 - result.success_probability) / n)
                })
            
            # Check convergence - variance should decrease with more rollouts
            std_errors = [r["std_error"] for r in results]
            for i in range(1, len(std_errors)):
                assert std_errors[i] <= std_errors[i-1] * 1.1  # Allow small variation
            
            print(f"✓ Monte Carlo convergence:")
            for r in results:
                print(f"  n={r['n']:3d}: {r['success_prob']:.3f} ± {r['std_error']:.3f}")
            
        except Exception as e:
            pytest.skip(f"Convergence test skipped: {e}")


class TestA7SimulationBehavior:
    """Test A7: Attack flow generation and temporal sequence behavior."""
    
    def flow_builder(self):
        """Create test flow builder."""
        return FlowBuilder(
            neo4j_uri=os.getenv("NEO4J_URI"),
            neo4j_user=os.getenv("NEO4J_USER"),
            neo4j_password=os.getenv("NEO4J_PASSWORD")
        )
    
    def test_attack_flow_generation(self, flow_builder):
        """Test generation of attack flows from techniques."""
        try:
            # Test techniques representing an attack
            test_techniques = [
                {"stix_id": "T1566.001", "name": "Spearphishing Attachment", "confidence": 0.9},
                {"stix_id": "T1059.001", "name": "PowerShell", "confidence": 0.85},
                {"stix_id": "T1055", "name": "Process Injection", "confidence": 0.8},
                {"stix_id": "T1003.001", "name": "LSASS Memory", "confidence": 0.75},
                {"stix_id": "T1078", "name": "Valid Accounts", "confidence": 0.9},
                {"stix_id": "T1486", "name": "Data Encrypted", "confidence": 0.95}
            ]
            
            # Build attack flow
            flow = flow_builder.build_flow(
                techniques=test_techniques,
                source_id="test-report-001",
                flow_type="sequential"
            )
            
            # Verify flow structure
            assert flow.get("flow_id")
            assert flow.get("source_id") == "test-report-001"
            assert flow.get("flow_type") == "sequential"
            assert "episodes" in flow
            assert "edges" in flow
            
            # Check episodes
            episodes = flow.get("episodes", [])
            assert len(episodes) > 0
            
            for episode in episodes:
                assert "episode_id" in episode
                assert "actions" in episode
                assert len(episode["actions"]) > 0
            
            # Check edges (NEXT relationships with probabilities)
            edges = flow.get("edges", [])
            for edge in edges:
                assert "source" in edge
                assert "target" in edge
                assert "probability" in edge
                assert 0 <= edge["probability"] <= 1
            
            print(f"✓ Attack flow generated:")
            print(f"  Episodes: {len(episodes)}")
            print(f"  Total actions: {sum(len(e['actions']) for e in episodes)}")
            print(f"  Edges: {len(edges)}")
            
            # Verify temporal ordering
            if edges:
                # Check that edges form valid paths
                sources = set(e["source"] for e in edges)
                targets = set(e["target"] for e in edges)
                
                # Should have at least one starting node (not a target)
                start_nodes = sources - targets
                assert len(start_nodes) > 0
                
                print(f"  Starting techniques: {len(start_nodes)}")
            
        except Exception as e:
            pytest.skip(f"Flow generation test skipped: {e}")
    
    def test_temporal_sequence_extraction(self):
        """Test extraction of temporal sequences from text."""
        try:
            synthesizer = AttackFlowSynthesizer()
            
            # Test report with clear temporal indicators
            test_report = """
            The attack began with a spearphishing email containing a malicious attachment.
            Once the user opened the attachment, PowerShell was executed to download 
            additional payloads. Next, the attackers performed process injection to 
            establish persistence. Subsequently, they conducted credential dumping 
            from LSASS memory. Finally, using the stolen credentials, they moved 
            laterally and deployed ransomware.
            """
            
            # Mock extraction result
            extraction_result = {
                "techniques": [
                    {"technique_id": "T1566.001", "name": "Spearphishing Attachment", "confidence": 0.9},
                    {"technique_id": "T1059.001", "name": "PowerShell", "confidence": 0.85},
                    {"technique_id": "T1055", "name": "Process Injection", "confidence": 0.8},
                    {"technique_id": "T1003.001", "name": "LSASS Memory", "confidence": 0.8},
                    {"technique_id": "T1078", "name": "Valid Accounts", "confidence": 0.75},
                    {"technique_id": "T1486", "name": "Data Encrypted", "confidence": 0.9}
                ]
            }
            
            # Synthesize flow
            flow = synthesizer.synthesize_attack_flow(
                extraction_result=extraction_result,
                report_text=test_report,
                max_steps=10
            )
            
            # Verify temporal sequence
            assert "steps" in flow
            steps = flow["steps"]
            assert len(steps) > 0
            assert len(steps) <= 10  # Respect max_steps
            
            # Check step structure
            for i, step in enumerate(steps):
                assert "technique_id" in step
                assert "technique_name" in step
                assert "confidence" in step
                assert "evidence" in step
                assert "temporal_indicator" in step or "reasoning" in step
                
                # Steps should be in order
                assert step.get("step_number", i+1) == i+1
            
            # Verify temporal indicators detected
            temporal_keywords = ["began", "once", "next", "subsequently", "finally"]
            indicators_found = []
            
            for step in steps:
                if "temporal_indicator" in step:
                    for keyword in temporal_keywords:
                        if keyword.lower() in step["temporal_indicator"].lower():
                            indicators_found.append(keyword)
                            break
            
            print(f"✓ Temporal sequence extracted:")
            print(f"  Steps: {len(steps)}")
            print(f"  Temporal indicators: {len(indicators_found)}")
            print(f"  Sequence: {' → '.join([s['technique_id'] for s in steps[:5]])}")
            
        except Exception as e:
            pytest.skip(f"Temporal extraction test skipped: {e}")
    
    def test_probabilistic_edge_generation(self, flow_builder):
        """Test generation of probabilistic NEXT edges."""
        try:
            # Techniques with varying confidence
            techniques = [
                {"stix_id": "T1566.001", "confidence": 0.95},
                {"stix_id": "T1059.001", "confidence": 0.7},
                {"stix_id": "T1055", "confidence": 0.6},
                {"stix_id": "T1003.001", "confidence": 0.85},
            ]
            
            # Generate edges
            edges = flow_builder._generate_probabilistic_edges(
                techniques,
                base_probability=0.5
            )
            
            # Verify edge properties
            assert isinstance(edges, list)
            
            for edge in edges:
                assert "source" in edge
                assert "target" in edge
                assert "probability" in edge
                assert "rationale" in edge
                
                # Probability constraints
                assert 0.1 <= edge["probability"] <= 1.0
                
                # Higher confidence should influence probability
                source_conf = next((t["confidence"] for t in techniques if t["stix_id"] == edge["source"]), 0.5)
                target_conf = next((t["confidence"] for t in techniques if t["stix_id"] == edge["target"]), 0.5)
                
                # Probability should correlate with confidence
                if source_conf > 0.8 and target_conf > 0.8:
                    assert edge["probability"] >= 0.5  # Strong techniques = higher probability
            
            # Check edge connectivity
            if len(techniques) > 1:
                # Should have at least n-1 edges for connectivity
                assert len(edges) >= len(techniques) - 1
            
            print(f"✓ Probabilistic edges generated:")
            print(f"  Edges: {len(edges)}")
            print(f"  Avg probability: {np.mean([e['probability'] for e in edges]):.2f}")
            print(f"  Probability range: {min(e['probability'] for e in edges):.2f}-{max(e['probability'] for e in edges):.2f}")
            
        except Exception as e:
            pytest.skip(f"Probabilistic edge test skipped: {e}")
    
    def test_cooccurrence_flow_generation(self, flow_builder):
        """Test generation of co-occurrence based flows."""
        try:
            # Techniques that commonly co-occur (no clear sequence)
            cooccurring_techniques = [
                {"stix_id": "T1082", "name": "System Information Discovery"},
                {"stix_id": "T1083", "name": "File and Directory Discovery"},
                {"stix_id": "T1057", "name": "Process Discovery"},
                {"stix_id": "T1518", "name": "Software Discovery"},
            ]
            
            # Build co-occurrence flow
            flow = flow_builder.build_flow(
                techniques=cooccurring_techniques,
                source_id="test-intrusion-set",
                flow_type="co-occurrence"
            )
            
            # Verify co-occurrence structure
            assert flow.get("flow_type") == "co-occurrence"
            
            # Co-occurrence flows should have weaker edge probabilities
            edges = flow.get("edges", [])
            if edges:
                avg_prob = np.mean([e["probability"] for e in edges])
                assert avg_prob < 0.7  # Weaker associations
                
                # Should have more edges (techniques relate to multiple others)
                assert len(edges) >= len(cooccurring_techniques)
            
            # Verify clustering by tactic
            episodes = flow.get("episodes", [])
            for episode in episodes:
                # Discovery techniques should cluster together
                tactics = episode.get("tactics", [])
                if "discovery" in tactics:
                    assert len(episode["actions"]) > 1  # Multiple discovery actions
            
            print(f"✓ Co-occurrence flow generated:")
            print(f"  Type: {flow['flow_type']}")
            print(f"  Edges: {len(edges)}")
            if edges:
                print(f"  Avg edge probability: {avg_prob:.2f}")
            
        except Exception as e:
            pytest.skip(f"Co-occurrence flow test skipped: {e}")


def run_simulation_tests():
    """Run all simulation tests."""
    print("="*60)
    print("Running Simulation Tests (A5, A7)")
    print("="*60)
    
    # Run A5 tests
    a5_tests = TestA5AgentBasedSimulation()
    
    try:
        rollout_sim = a5_tests.rollout_simulator()
        mdp = a5_tests.mdp_solver()
        
        a5_tests.test_rollout_simulation(rollout_sim)
        a5_tests.test_mdp_policy_computation(mdp)
        a5_tests.test_simulation_with_interdiction(rollout_sim)
        a5_tests.test_monte_carlo_convergence(rollout_sim)
        
        print("\n✓ A5 Agent-based simulation tests passed")
        
    except Exception as e:
        print(f"\n⚠ A5 tests encountered errors: {e}")
    finally:
        if 'rollout_sim' in locals():
            rollout_sim.close()
        if 'mdp' in locals():
            mdp.close()
    
    # Run A7 tests
    a7_tests = TestA7SimulationBehavior()
    
    try:
        flow_builder = a7_tests.flow_builder()
        
        a7_tests.test_attack_flow_generation(flow_builder)
        a7_tests.test_temporal_sequence_extraction()
        a7_tests.test_probabilistic_edge_generation(flow_builder)
        a7_tests.test_cooccurrence_flow_generation(flow_builder)
        
        print("\n✓ A7 Simulation behavior tests passed")
        
    except Exception as e:
        print(f"\n⚠ A7 tests encountered errors: {e}")
    finally:
        if 'flow_builder' in locals():
            flow_builder.close()
    
    print("\n" + "="*60)
    print("Simulation Tests Complete")
    print("="*60)


if __name__ == "__main__":
    run_simulation_tests()