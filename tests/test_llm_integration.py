"""Integration tests for LLM extraction functionality."""

import json
from bandjacks.llm.client import validate_json_response
from bandjacks.llm.schemas import LLM_OUTPUT_SCHEMA
from bandjacks.llm.stix_converter import (
    llm_to_stix_bundle,
    apply_safeguards,
    validate_stix_ids,
    merge_with_vector_results
)
from bandjacks.llm.prompts import get_messages_for_chunk


def test_json_validation():
    """Test JSON response validation."""
    
    # Valid response
    valid_response = json.dumps({
        "chunk_id": "test#c0",
        "claims": [
            {
                "type": "activity",
                "span": {"text": "APT29 uses spearphishing"},
                "mappings": [
                    {
                        "stix_id": "attack-pattern--test",
                        "confidence": 80,
                        "rationale": "Clear spearphishing mention"
                    }
                ]
            }
        ]
    })
    
    result = validate_json_response(valid_response, LLM_OUTPUT_SCHEMA)
    assert result["chunk_id"] == "test#c0"
    assert len(result["claims"]) == 1
    
    # Invalid response (missing required field)
    invalid_response = json.dumps({
        "chunk_id": "test#c0",
        "claims": [
            {
                "type": "activity",
                "span": {"text": "test"}
                # Missing "mappings"
            }
        ]
    })
    
    try:
        validate_json_response(invalid_response, LLM_OUTPUT_SCHEMA)
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "doesn't match schema" in str(e)
    
    print("✓ JSON validation working")


def test_llm_to_stix_conversion():
    """Test conversion of LLM output to STIX bundle."""
    
    llm_extraction = {
        "chunks": [
            {
                "chunk_id": "doc1#c0",
                "claims": [
                    {
                        "type": "activity",
                        "span": {"text": "APT29 uses PowerShell for execution"},
                        "mappings": [
                            {
                                "stix_id": "attack-pattern--t1059-001",
                                "confidence": 85,
                                "rationale": "PowerShell execution technique"
                            }
                        ],
                        "subjects": [
                            {
                                "stix_id": "intrusion-set--apt29",
                                "confidence": 90
                            }
                        ],
                        "citations": ["vector_search_ttx", "graph_lookup"]
                    }
                ]
            }
        ],
        "metadata": {
            "llm_model": "test",
            "prompt_version": "1.0.0"
        }
    }
    
    # Mock KB validator (accepts all for test)
    def mock_validator(stix_id):
        return True
    
    bundle = llm_to_stix_bundle(llm_extraction, kb_validator=mock_validator)
    
    assert bundle["type"] == "bundle"
    assert "objects" in bundle
    
    # Should have technique, group, and relationship
    objects = bundle["objects"]
    techniques = [o for o in objects if o["type"] == "attack-pattern"]
    groups = [o for o in objects if o["type"] == "intrusion-set"]
    relationships = [o for o in objects if o["type"] == "relationship"]
    
    assert len(techniques) == 1
    assert len(groups) == 1
    assert len(relationships) == 1
    
    # Check relationship
    rel = relationships[0]
    assert rel["relationship_type"] == "uses"
    assert rel["source_ref"] == "intrusion-set--apt29"
    assert rel["target_ref"] == "attack-pattern--t1059-001"
    
    print("✓ LLM to STIX conversion working")


def test_safeguards():
    """Test safeguard application."""
    
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "confidence": 95,  # Should be capped
                "x_bj_evidence": "The malware executes commands"
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2",
                "confidence": 100,  # Should stay high due to T-code
                "x_bj_evidence": "Uses T1059.001 PowerShell"
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--3",
                "confidence": 80,
                "x_bj_evidence": "This technique was not observed"  # Should reduce
            }
        ]
    }
    
    safeguarded = apply_safeguards(bundle, max_confidence=85)
    
    # First object should be capped
    assert safeguarded["objects"][0]["confidence"] == 85
    assert safeguarded["objects"][0].get("x_bj_confidence_capped") == True
    
    # Second object should remain high (has T-code)
    assert safeguarded["objects"][1]["confidence"] == 100
    
    # Third object should be reduced (negation)
    assert safeguarded["objects"][2]["confidence"] < 80
    assert safeguarded["objects"][2].get("x_bj_negation_detected") == True
    
    print("✓ Safeguards working")


def test_id_validation():
    """Test STIX ID validation against KB."""
    
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "attack-pattern", "id": "attack-pattern--good"},
            {"type": "attack-pattern", "id": "attack-pattern--bad"},
            {
                "type": "relationship",
                "id": "relationship--1",
                "source_ref": "attack-pattern--good",
                "target_ref": "attack-pattern--good"
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "source_ref": "attack-pattern--good",
                "target_ref": "attack-pattern--bad"  # Should be rejected
            }
        ]
    }
    
    def mock_validator(stix_id):
        # Only accept IDs with "good" in them
        return "good" in stix_id
    
    validated = validate_stix_ids(bundle, mock_validator)
    
    # Debug output
    print(f"  Objects after validation: {len(validated['objects'])}")
    for obj in validated["objects"]:
        print(f"    - {obj['type']}: {obj['id']}")
    if "x_bj_rejected_ids" in validated:
        print(f"  Rejected: {validated['x_bj_rejected_ids']}")
    
    # Should have 1 valid attack-pattern and 1 valid relationship (both refs valid)
    assert len(validated["objects"]) == 2
    
    # Check we have the right objects
    valid_ids = [obj["id"] for obj in validated["objects"]]
    assert "attack-pattern--good" in valid_ids
    assert "relationship--1" in valid_ids  # Has both good refs
    
    # Should reject bad pattern and relationship with bad ref
    assert "x_bj_rejected_ids" in validated
    assert "attack-pattern--bad" in validated["x_bj_rejected_ids"]
    assert "relationship--2" in validated["x_bj_rejected_ids"]
    
    print("✓ ID validation working")


def test_result_merging():
    """Test merging LLM and vector results."""
    
    llm_bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "confidence": 80
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2",
                "confidence": 70
            }
        ]
    }
    
    vector_bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",  # Same as LLM
                "confidence": 60
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--3",  # Vector only
                "confidence": 75
            }
        ]
    }
    
    merged = merge_with_vector_results(llm_bundle, vector_bundle)
    
    # Should have all 3 unique objects
    assert len(merged["objects"]) == 3
    
    # Find merged object
    obj1 = next(o for o in merged["objects"] if o["id"] == "attack-pattern--1")
    
    # Check fused confidence (0.6 * 80 + 0.4 * 60 = 48 + 24 = 72)
    assert obj1["confidence"] == 72
    assert obj1["x_bj_source"] == "hybrid"
    assert obj1["x_bj_llm_confidence"] == 80
    assert obj1["x_bj_vector_confidence"] == 60
    
    # Check vector-only object
    obj3 = next(o for o in merged["objects"] if o["id"] == "attack-pattern--3")
    assert obj3["x_bj_source"] == "vector"
    
    print("✓ Result merging working")


def test_prompt_generation():
    """Test prompt generation for chunks."""
    
    messages = get_messages_for_chunk(
        chunk_id="test#c0",
        text="APT29 uses spearphishing emails to gain initial access."
    )
    
    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert "cyber threat TTP" in messages[0]["content"]
    assert messages[1]["role"] == "user"
    assert "test#c0" in messages[1]["content"]
    assert "spearphishing" in messages[1]["content"]
    
    print("✓ Prompt generation working")


def test_tool_definitions():
    """Test that tool definitions are properly formatted."""
    from bandjacks.llm.tools import get_tool_definitions
    
    tools = get_tool_definitions()
    
    assert len(tools) == 3  # vector_search, graph_lookup, list_tactics
    
    # Check vector_search tool
    vector_tool = next(t for t in tools if t["function"]["name"] == "vector_search_ttx")
    assert vector_tool["type"] == "function"
    assert "parameters" in vector_tool["function"]
    assert "text" in vector_tool["function"]["parameters"]["properties"]
    
    print("✓ Tool definitions working")


def test_confidence_scoring():
    """Test confidence scoring in safeguards."""
    
    # Test various confidence scenarios
    test_cases = [
        # (initial_confidence, evidence, expected_confidence, should_cap)
        (100, "Uses T1059.001 explicitly", 100, False),  # T-code keeps high
        (95, "Performs credential dumping", 85, True),    # Capped without high signal
        (80, "Was not observed to use", 50, False),       # Negation reduces
        (70, "Multiple confirmations", 70, False),        # Within cap already
    ]
    
    for initial, evidence, expected, should_cap in test_cases:
        bundle = {
            "type": "bundle",
            "objects": [{
                "type": "attack-pattern",
                "id": "test",
                "confidence": initial,
                "x_bj_evidence": evidence
            }]
        }
        
        result = apply_safeguards(bundle, max_confidence=85)
        obj = result["objects"][0]
        
        # Allow some flexibility in negation detection
        if "not observed" in evidence.lower():
            assert obj["confidence"] <= initial - 20  # Should reduce
        elif should_cap:
            assert obj["confidence"] == 85
        else:
            assert abs(obj["confidence"] - expected) <= 5  # Allow small variance
    
    print("✓ Confidence scoring working")


if __name__ == "__main__":
    print("Testing LLM Integration")
    print("-" * 40)
    
    test_json_validation()
    test_llm_to_stix_conversion()
    test_safeguards()
    test_id_validation()
    test_result_merging()
    test_prompt_generation()
    test_tool_definitions()
    test_confidence_scoring()
    
    print("-" * 40)
    print("✅ All LLM integration tests passed!")