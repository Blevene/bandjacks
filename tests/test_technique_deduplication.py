"""Test to verify parent and subtechnique preservation in extraction pipeline."""

import pytest
from typing import Dict, List
from bandjacks.llm.chunked_extractor import ChunkedExtractor
from bandjacks.llm.optimized_chunked_extractor import OptimizedChunkedExtractor
from bandjacks.llm.agents_v2 import ConsolidatorAgent
from bandjacks.llm.memory import WorkingMemory


def create_test_document_with_subtechniques() -> str:
    """Create a test document mentioning parent and subtechniques."""
    return """
    Security Report: Advanced Threat Analysis
    
    The threat actor employed several obfuscation techniques during the campaign.
    They used T1027 (Obfuscated Files or Information) as their primary defense evasion method.
    
    Specifically, we observed T1027.002 (Software Packing) being used to compress the malware.
    The packed executable made static analysis significantly more difficult.
    
    Additionally, T1027.004 (Compile After Delivery) was observed in their PowerShell scripts.
    The scripts would dynamically compile C# code at runtime to evade detection.
    
    The group also utilized T1027.001 (Binary Padding) to alter file signatures.
    Extra bytes were appended to legitimate files to bypass hash-based detection.
    
    In another phase, they employed T1055 (Process Injection) for privilege escalation.
    The malware specifically used T1055.001 (Dynamic-link Library Injection) to hide in legitimate processes.
    
    We also found evidence of T1055.012 (Process Hollowing) in memory forensics.
    The attacker replaced legitimate process memory with malicious code.
    """


def create_test_claims_with_subtechniques() -> List[Dict]:
    """Create test claims that include parent and subtechniques."""
    return [
        {
            "external_id": "T1027",
            "name": "Obfuscated Files or Information",
            "quotes": ["They used T1027 (Obfuscated Files or Information) as their primary defense evasion method"],
            "line_refs": [5],
            "confidence": 90,
            "evidence_score": 80,
            "span_idx": 0,
            "chunk_id": 0
        },
        {
            "external_id": "T1027.002",
            "name": "Software Packing",
            "quotes": ["Specifically, we observed T1027.002 (Software Packing) being used to compress the malware"],
            "line_refs": [7],
            "confidence": 95,
            "evidence_score": 85,
            "span_idx": 1,
            "chunk_id": 0
        },
        {
            "external_id": "T1027.004",
            "name": "Compile After Delivery",
            "quotes": ["Additionally, T1027.004 (Compile After Delivery) was observed in their PowerShell scripts"],
            "line_refs": [10],
            "confidence": 92,
            "evidence_score": 82,
            "span_idx": 2,
            "chunk_id": 0
        },
        {
            "external_id": "T1027.001",
            "name": "Binary Padding",
            "quotes": ["The group also utilized T1027.001 (Binary Padding) to alter file signatures"],
            "line_refs": [13],
            "confidence": 88,
            "evidence_score": 78,
            "span_idx": 3,
            "chunk_id": 1
        },
        {
            "external_id": "T1055",
            "name": "Process Injection",
            "quotes": ["In another phase, they employed T1055 (Process Injection) for privilege escalation"],
            "line_refs": [16],
            "confidence": 91,
            "evidence_score": 81,
            "span_idx": 4,
            "chunk_id": 1
        },
        {
            "external_id": "T1055.001",
            "name": "Dynamic-link Library Injection",
            "quotes": ["The malware specifically used T1055.001 (Dynamic-link Library Injection) to hide in legitimate processes"],
            "line_refs": [17],
            "confidence": 93,
            "evidence_score": 83,
            "span_idx": 5,
            "chunk_id": 1
        },
        {
            "external_id": "T1055.012",
            "name": "Process Hollowing",
            "quotes": ["We also found evidence of T1055.012 (Process Hollowing) in memory forensics"],
            "line_refs": [19],
            "confidence": 89,
            "evidence_score": 79,
            "span_idx": 6,
            "chunk_id": 1
        }
    ]


def test_consolidator_preserves_subtechniques():
    """Test that ConsolidatorAgent preserves both parent and subtechniques."""
    mem = WorkingMemory()
    mem.claims = create_test_claims_with_subtechniques()
    mem.spans = [{"text": f"span{i}", "line_refs": [i]} for i in range(7)]
    mem.candidates = {}
    mem.techniques = {}
    
    consolidator = ConsolidatorAgent()
    consolidator.run(mem, {})
    
    # Verify all techniques are preserved
    assert len(mem.techniques) == 7, f"Expected 7 techniques, got {len(mem.techniques)}"
    
    # Verify parent techniques are present
    assert "T1027" in mem.techniques, "Parent technique T1027 missing"
    assert "T1055" in mem.techniques, "Parent technique T1055 missing"
    
    # Verify subtechniques are present
    assert "T1027.001" in mem.techniques, "Subtechnique T1027.001 missing"
    assert "T1027.002" in mem.techniques, "Subtechnique T1027.002 missing"
    assert "T1027.004" in mem.techniques, "Subtechnique T1027.004 missing"
    assert "T1055.001" in mem.techniques, "Subtechnique T1055.001 missing"
    assert "T1055.012" in mem.techniques, "Subtechnique T1055.012 missing"
    
    # Verify is_subtechnique flag is set correctly
    assert mem.techniques["T1027"]["is_subtechnique"] == False, "T1027 should not be marked as subtechnique"
    assert mem.techniques["T1027.001"]["is_subtechnique"] == True, "T1027.001 should be marked as subtechnique"
    assert mem.techniques["T1027.002"]["is_subtechnique"] == True, "T1027.002 should be marked as subtechnique"
    
    print(f"✅ ConsolidatorAgent correctly preserved all {len(mem.techniques)} techniques")
    for tid in sorted(mem.techniques.keys()):
        tech = mem.techniques[tid]
        print(f"  - {tid}: {tech['name']} (subtechnique: {tech['is_subtechnique']})")


def test_chunked_extractor_merge_preserves_subtechniques():
    """Test that ChunkedExtractor.merge_results preserves subtechniques."""
    extractor = ChunkedExtractor()
    
    # Create chunk results with parent and subtechniques
    chunk_results = [
        {
            "chunk_id": 0,
            "claims": [
                {"technique_id": "T1027", "name": "Obfuscated Files", "confidence": 90, "evidence": {"quotes": ["test1"]}},
                {"technique_id": "T1027.002", "name": "Software Packing", "confidence": 95, "evidence": {"quotes": ["test2"]}},
                {"technique_id": "T1027.004", "name": "Compile After Delivery", "confidence": 92, "evidence": {"quotes": ["test3"]}},
            ],
            "entities": {"entities": []}
        },
        {
            "chunk_id": 1,
            "claims": [
                {"technique_id": "T1027.001", "name": "Binary Padding", "confidence": 88, "evidence": {"quotes": ["test4"]}},
                {"technique_id": "T1055", "name": "Process Injection", "confidence": 91, "evidence": {"quotes": ["test5"]}},
                {"technique_id": "T1055.001", "name": "DLL Injection", "confidence": 93, "evidence": {"quotes": ["test6"]}},
                {"technique_id": "T1055.012", "name": "Process Hollowing", "confidence": 89, "evidence": {"quotes": ["test7"]}},
            ],
            "entities": {"entities": []}
        }
    ]
    
    merged = extractor.merge_results(chunk_results)
    
    # Check claims are preserved
    assert len(merged["claims"]) == 7, f"Expected 7 claims, got {len(merged['claims'])}"
    
    # Check techniques dict
    assert len(merged["techniques"]) == 7, f"Expected 7 techniques, got {len(merged['techniques'])}"
    
    # Verify all technique IDs are present
    technique_ids = set(merged["techniques"].keys())
    expected_ids = {"T1027", "T1027.001", "T1027.002", "T1027.004", "T1055", "T1055.001", "T1055.012"}
    assert technique_ids == expected_ids, f"Missing techniques: {expected_ids - technique_ids}"
    
    print(f"✅ ChunkedExtractor.merge_results preserved all {len(merged['techniques'])} techniques")
    for tid in sorted(merged["techniques"].keys()):
        print(f"  - {tid}: {merged['techniques'][tid]['name']}")


def test_optimized_extractor_preserves_subtechniques():
    """Test that OptimizedChunkedExtractor preserves subtechniques."""
    # This test would require more setup but verifies the optimized path
    # For now, we'll create a minimal test to ensure the structure is correct
    
    from bandjacks.llm.accumulator import ThreadSafeAccumulator
    
    accumulator = ThreadSafeAccumulator()
    
    # Add parent technique
    accumulator.add_technique("T1027", "Obfuscated Files", 90, ["evidence1"], 0)
    
    # Add subtechniques
    accumulator.add_technique("T1027.002", "Software Packing", 95, ["evidence2"], 0)
    accumulator.add_technique("T1027.004", "Compile After Delivery", 92, ["evidence3"], 1)
    
    # Get accumulated techniques
    techniques = accumulator.get_accumulated_techniques()
    
    # Verify all are preserved
    assert len(techniques) == 3, f"Expected 3 techniques, got {len(techniques)}"
    assert "T1027" in techniques
    assert "T1027.002" in techniques
    assert "T1027.004" in techniques
    
    print(f"✅ Accumulator preserved all {len(techniques)} techniques")
    for tid in sorted(techniques.keys()):
        print(f"  - {tid}: {techniques[tid]['name']}")


if __name__ == "__main__":
    print("Testing technique deduplication preservation...\n")
    
    print("Test 1: ConsolidatorAgent")
    test_consolidator_preserves_subtechniques()
    print()
    
    print("Test 2: ChunkedExtractor.merge_results")
    test_chunked_extractor_merge_preserves_subtechniques()
    print()
    
    print("Test 3: OptimizedChunkedExtractor Accumulator")
    test_optimized_extractor_preserves_subtechniques()
    print()
    
    print("✅ All tests passed! Parent and subtechniques are properly preserved.")