"""Convert LLM extraction output to STIX bundles."""

import uuid
from typing import List, Dict, Any, Set
from datetime import datetime


def llm_to_stix_bundle(
    llm_extraction: Dict[str, Any],
    kb_validator: callable = None
) -> Dict[str, Any]:
    """
    Convert LLM extraction output to a STIX bundle.
    
    Args:
        llm_extraction: Output from LLM extractor
        kb_validator: Optional function to validate STIX IDs against KB
        
    Returns:
        STIX 2.1 bundle with techniques, subjects, and relationships
    """
    objects = []
    relationships = []
    seen_objects: Set[str] = set()
    
    # Process each chunk's claims
    for chunk_data in llm_extraction.get("chunks", []):
        chunk_id = chunk_data.get("chunk_id", "unknown")
        
        for claim in chunk_data.get("claims", []):
            # Process mappings (techniques)
            for mapping in claim.get("mappings", []):
                stix_id = mapping.get("stix_id")
                confidence = mapping.get("confidence", 50)
                rationale = mapping.get("rationale", "")
                
                # Validate against KB if validator provided
                if kb_validator and not kb_validator(stix_id):
                    continue  # Skip invalid IDs
                
                # Add technique object if not seen
                if stix_id not in seen_objects:
                    technique_obj = {
                        "type": "attack-pattern",
                        "id": stix_id,
                        "spec_version": "2.1",
                        "confidence": confidence,
                        "x_bj_source_chunk": chunk_id,
                        "x_bj_evidence": claim.get("span", {}).get("text", ""),
                        "x_bj_rationale": rationale,
                        "x_bj_claim_type": claim.get("type", "activity")
                    }
                    objects.append(technique_obj)
                    seen_objects.add(stix_id)
                
                # Process subjects (threat actors, malware)
                for subject in claim.get("subjects", []):
                    subject_id = subject.get("stix_id")
                    subject_confidence = subject.get("confidence", 50)
                    
                    # Validate subject
                    if kb_validator and not kb_validator(subject_id):
                        continue
                    
                    # Add subject if not seen
                    if subject_id not in seen_objects:
                        # Determine subject type from STIX ID
                        if "intrusion-set" in subject_id:
                            obj_type = "intrusion-set"
                        elif "malware" in subject_id:
                            obj_type = "malware"
                        elif "tool" in subject_id:
                            obj_type = "tool"
                        else:
                            obj_type = "identity"  # Fallback
                        
                        subject_obj = {
                            "type": obj_type,
                            "id": subject_id,
                            "spec_version": "2.1",
                            "confidence": subject_confidence,
                            "x_bj_source_chunk": chunk_id
                        }
                        objects.append(subject_obj)
                        seen_objects.add(subject_id)
                    
                    # Create relationship: subject USES technique
                    rel_id = f"relationship--{uuid.uuid4()}"
                    relationship = {
                        "type": "relationship",
                        "id": rel_id,
                        "spec_version": "2.1",
                        "relationship_type": "uses",
                        "source_ref": subject_id,
                        "target_ref": stix_id,
                        "confidence": min(confidence, subject_confidence),
                        "x_bj_provenance": {
                            "chunk": chunk_id,
                            "llm_confidence": confidence,
                            "evidence": claim.get("span", {}).get("text", ""),
                            "citations": claim.get("citations", [])
                        }
                    }
                    relationships.append(relationship)
    
    # Build STIX bundle
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "created": datetime.utcnow().isoformat() + "Z",
        "objects": objects + relationships
    }
    
    return bundle


def apply_safeguards(
    bundle: Dict[str, Any],
    kb_lookup: callable = None,
    max_confidence: int = 85
) -> Dict[str, Any]:
    """
    Apply safeguards to limit confidence and validate objects.
    
    Args:
        bundle: STIX bundle to process
        kb_lookup: Function to look up object details from KB
        max_confidence: Maximum allowed confidence without validation
        
    Returns:
        Bundle with safeguards applied
    """
    for obj in bundle.get("objects", []):
        # Cap confidence unless high signal
        confidence = obj.get("confidence", 0)
        
        # Check for high-signal indicators
        high_signal = False
        
        # Check for T-code in evidence
        evidence = obj.get("x_bj_evidence", "")
        import re
        if re.search(r'T\d{4}(?:\.\d{3})?', evidence):
            high_signal = True
        
        # Check for multiple tool confirmations
        citations = obj.get("x_bj_provenance", {}).get("citations", [])
        if len(citations) >= 2:
            high_signal = True
        
        # Apply confidence cap if not high signal
        if not high_signal and confidence > max_confidence:
            obj["confidence"] = max_confidence
            obj["x_bj_confidence_capped"] = True
        
        # Check for negation in evidence
        if evidence and any(neg in evidence.lower() for neg in ["not observed", "did not", "wasn't", "no evidence"]):
            obj["confidence"] = max(0, confidence - 30)
            obj["x_bj_negation_detected"] = True
    
    return bundle


def merge_with_vector_results(
    llm_bundle: Dict[str, Any],
    vector_bundle: Dict[str, Any],
    fusion_weights: Dict[str, float] = None
) -> Dict[str, Any]:
    """
    Merge LLM and vector-based extraction results.
    
    Args:
        llm_bundle: Bundle from LLM extraction
        vector_bundle: Bundle from vector-only extraction
        fusion_weights: Weights for confidence fusion (default: 0.6 LLM, 0.4 vector)
        
    Returns:
        Merged bundle with fused confidence scores
    """
    if not fusion_weights:
        fusion_weights = {"llm": 0.6, "vector": 0.4}
    
    # Index objects by ID for merging
    llm_objects = {obj["id"]: obj for obj in llm_bundle.get("objects", [])}
    vector_objects = {obj["id"]: obj for obj in vector_bundle.get("objects", [])}
    
    # Merge objects
    merged_objects = {}
    
    # Add all LLM objects
    for obj_id, obj in llm_objects.items():
        merged_objects[obj_id] = obj.copy()
        merged_objects[obj_id]["x_bj_source"] = "llm"
    
    # Merge or add vector objects
    for obj_id, obj in vector_objects.items():
        if obj_id in merged_objects:
            # Fuse confidence scores
            llm_conf = merged_objects[obj_id].get("confidence", 0)
            vec_conf = obj.get("confidence", 0)
            
            fused_conf = round(
                fusion_weights["llm"] * llm_conf +
                fusion_weights["vector"] * vec_conf
            )
            
            merged_objects[obj_id]["confidence"] = min(100, fused_conf)
            merged_objects[obj_id]["x_bj_source"] = "hybrid"
            merged_objects[obj_id]["x_bj_llm_confidence"] = llm_conf
            merged_objects[obj_id]["x_bj_vector_confidence"] = vec_conf
        else:
            # Add vector-only object
            merged_objects[obj_id] = obj.copy()
            merged_objects[obj_id]["x_bj_source"] = "vector"
    
    # Build merged bundle
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "created": datetime.utcnow().isoformat() + "Z",
        "objects": list(merged_objects.values())
    }


def validate_stix_ids(bundle: Dict[str, Any], kb_validator: callable) -> Dict[str, Any]:
    """
    Remove objects with invalid STIX IDs from bundle.
    
    Args:
        bundle: STIX bundle to validate
        kb_validator: Function that returns True if ID exists in KB
        
    Returns:
        Bundle with only valid objects
    """
    valid_objects = []
    rejected_ids = []
    
    for obj in bundle.get("objects", []):
        obj_id = obj.get("id")
        
        # Skip relationships for now (validate refs separately)
        if obj.get("type") == "relationship":
            source_ref = obj.get("source_ref")
            target_ref = obj.get("target_ref")
            
            # Only keep if both refs are valid
            if kb_validator(source_ref) and kb_validator(target_ref):
                valid_objects.append(obj)
            else:
                rejected_ids.append(obj_id)
        else:
            # Validate object ID
            if kb_validator(obj_id):
                valid_objects.append(obj)
            else:
                rejected_ids.append(obj_id)
    
    # Update bundle
    bundle["objects"] = valid_objects
    
    # Add metadata about rejected IDs
    if rejected_ids:
        bundle["x_bj_rejected_ids"] = rejected_ids
    
    return bundle