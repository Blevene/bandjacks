"""Proposal engine for mapping text chunks to ATT&CK techniques."""

import re
import uuid
from typing import List, Dict, Any, Optional, Tuple, Set
from datetime import datetime
from bandjacks.loaders.search_nodes import ttx_search, ttx_search_kb
from bandjacks.loaders.technique_phrases import (
    find_technique_phrases,
    find_tool_mentions,
    calculate_phrase_relevance,
    normalize_phrase
)
from opensearchpy import OpenSearch

# Tactic keyword → tactic shortname mapping for inference boost
TACTIC_HINTS = {
    "initial access": "initial-access",
    "persistence": "persistence",
    "privilege escalation": "privilege-escalation",
    "defense evasion": "defense-evasion",
    "credential access": "credential-access",
    "discovery": "discovery",
    "lateral movement": "lateral-movement",
    "collection": "collection",
    "command and control": "command-and-control",
    "c2": "command-and-control",  # Common abbreviation
    "c&c": "command-and-control",  # Alternative abbreviation
    "exfiltration": "exfiltration",
    "impact": "impact",
    "execution": "execution",
    "reconnaissance": "reconnaissance",
    "resource development": "resource-development"
}


def propose_bundle(
    chunks: List[Dict[str, Any]],
    max_candidates: int,
    os_url: str,
    os_index: str
) -> Dict[str, Any]:
    """
    Generate a STIX bundle proposal from text chunks.
    
    Args:
        chunks: List of text chunks with metadata
        max_candidates: Maximum candidates per chunk
        os_url: OpenSearch URL
        os_index: OpenSearch index name
        
    Returns:
        Dictionary with proposal_id, bundle, and stats
    """
    proposal_id = f"prop-{uuid.uuid4().hex[:8]}"
    
    all_objects = []
    all_relationships = []
    stats = {
        "chunks": len(chunks),
        "candidates_total": 0,
        "techniques_found": 0,
        "groups_found": 0,
        "software_found": 0,
        "relationships_proposed": 0
    }
    
    # Process each chunk
    for chunk in chunks:
        chunk_id = chunk["id"]
        chunk_text = chunk["text"]
        
        # Get candidate techniques
        technique_candidates = get_technique_candidates(
            chunk_text, max_candidates, os_url, os_index
        )
        
        # Get candidate groups/software if mentioned
        group_candidates = get_entity_candidates(
            chunk_text, "IntrusionSet", max_candidates, os_url, os_index
        )
        software_candidates = get_entity_candidates(
            chunk_text, "Software", max_candidates, os_url, os_index
        )
        
        # Score and filter candidates
        scored_techniques = score_candidates(chunk_text, technique_candidates, "technique")
        scored_groups = score_candidates(chunk_text, group_candidates, "group")
        scored_software = score_candidates(chunk_text, software_candidates, "software")
        
        # Add to objects (deduplicated later)
        for tech in scored_techniques:
            if tech["confidence"] >= 50:  # Minimum confidence threshold
                obj = create_technique_object(tech, chunk_id)
                all_objects.append(obj)
                stats["techniques_found"] += 1
        
        for group in scored_groups:
            if group["confidence"] >= 40:
                obj = create_group_object(group, chunk_id)
                all_objects.append(obj)
                stats["groups_found"] += 1
        
        for sw in scored_software:
            if sw["confidence"] >= 40:
                obj = create_software_object(sw, chunk_id)
                all_objects.append(obj)
                stats["software_found"] += 1
        
        # Synthesize relationships
        relationships = synthesize_relationships(
            chunk_text, chunk_id, scored_techniques, scored_groups, scored_software
        )
        all_relationships.extend(relationships)
        stats["relationships_proposed"] += len(relationships)
    
    stats["candidates_total"] = stats["techniques_found"] + stats["groups_found"] + stats["software_found"]
    
    # Deduplicate objects and relationships
    unique_objects = deduplicate_objects(all_objects)
    unique_relationships = deduplicate_relationships(all_relationships)
    
    # Build STIX bundle
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "created": datetime.utcnow().isoformat() + "Z",
        "objects": unique_objects + unique_relationships
    }
    
    return {
        "proposal_id": proposal_id,
        "bundle": bundle,
        "stats": stats
    }


def infer_tactic_shortnames(text: str) -> Set[str]:
    """Infer tactic shortnames from text based on keyword hints."""
    text_lower = text.lower()
    inferred = set()
    
    for phrase, shortname in TACTIC_HINTS.items():
        if phrase in text_lower:
            inferred.add(shortname)
    
    return inferred


def get_technique_candidates(text: str, max_candidates: int, os_url: str, os_index: str) -> List[Dict[str, Any]]:
    """Get candidate ATT&CK techniques for text using vector search."""
    # Use the new kb_types filtering function
    results = ttx_search_kb(os_url, os_index, text, max_candidates * 2, kb_types=["AttackPattern"])
    return results[:max_candidates]


def get_entity_candidates(text: str, kb_type: str, max_candidates: int, os_url: str, os_index: str) -> List[Dict[str, Any]]:
    """Get candidate entities (Groups/Software) using vector search."""
    # Use the new kb_types filtering function
    results = ttx_search_kb(os_url, os_index, text, max_candidates, kb_types=[kb_type])
    return results


def calculate_phrase_score(text: str, technique_id: str) -> float:
    """Calculate score based on technique phrase matching."""
    score, matching_phrase = calculate_phrase_relevance(text, technique_id)
    return score


def calculate_tool_hint_score(text: str, technique_id: str) -> float:
    """Calculate score based on tool mentions that hint at techniques."""
    tool_mentions = find_tool_mentions(text)
    
    if not tool_mentions:
        return 0.0
    
    # Extract base technique ID
    base_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
    
    for tool, techniques in tool_mentions.items():
        if technique_id in techniques:
            return 100.0
        elif base_id in techniques:
            return 50.0
    
    return 0.0


def score_candidates(text: str, candidates: List[Dict[str, Any]], entity_type: str) -> List[Dict[str, Any]]:
    """
    Score candidates based on multiple factors.
    
    Scoring weights:
    - Similarity score: 60% (reduced from 70%)
    - Phrase matching: 15% (new)
    - Keyword matching: 10% (reduced from 20%)
    - ID mentions: 10% (unchanged)
    - Tool hints: 5% (new)
    - Tactic inference boost: +6 points if tactic context matches
    """
    scored = []
    
    # Get inferred tactics for this chunk
    inferred_tactics = infer_tactic_shortnames(text)
    
    for candidate in candidates:
        stix_id = candidate.get("stix_id", "")
        name = candidate.get("name_or_snippet", "")
        sim_score = candidate.get("score", 0.0)
        
        # Extract technique ID from STIX ID if it's a technique
        technique_id = ""
        if entity_type == "technique" and "attack-pattern--" in stix_id:
            # This would need a mapping in production, but for now use name parsing
            # Look for T-codes in the name
            import re
            t_match = re.search(r'T\d{4}(?:\.\d{3})?', name)
            if t_match:
                technique_id = t_match.group()
        
        # Normalize similarity score to 0-100
        # OpenSearch cosine similarity scores typically range 0-1
        normalized_sim = min(100, sim_score * 100)
        
        # Calculate all scoring components
        kw_score = calculate_keyword_score(text, name, entity_type)
        id_score = calculate_id_score(text, stix_id, entity_type)
        
        # New scoring components for techniques
        phrase_score = 0.0
        tool_score = 0.0
        if entity_type == "technique" and technique_id:
            phrase_score = calculate_phrase_score(text, technique_id)
            tool_score = calculate_tool_hint_score(text, technique_id)
        
        # Combined confidence with new weights
        confidence = round(
            0.60 * normalized_sim + 
            0.15 * phrase_score +
            0.10 * kw_score + 
            0.10 * id_score +
            0.05 * tool_score
        )
        
        # Apply tactic inference boost if applicable
        tactic_boost = 0
        if inferred_tactics and entity_type == "technique":
            # Check if any inferred tactic appears in the candidate's text/name
            candidate_text = (name + " " + candidate.get("text", "")).lower()
            if any(tactic in candidate_text for tactic in inferred_tactics):
                tactic_boost = 6  # Conservative boost
        
        confidence = min(100, max(0, confidence + tactic_boost))
        
        scored.append({
            **candidate,
            "confidence": confidence,
            "scoring_details": {
                "similarity": normalized_sim,
                "phrase": phrase_score,
                "keyword": kw_score,
                "id_mention": id_score,
                "tool_hint": tool_score,
                "tactic_boost": tactic_boost
            }
        })
    
    # Sort by confidence
    scored.sort(key=lambda x: x["confidence"], reverse=True)
    return scored


def calculate_keyword_score(text: str, name: str, entity_type: str) -> float:
    """Calculate keyword matching score with phrase awareness."""
    if not name:
        return 0.0
    
    text_lower = text.lower()
    name_lower = name.lower()
    
    # Direct name match (full phrase)
    if name_lower in text_lower:
        return 100.0
    
    # Check normalized variations (handle hyphens, underscores, etc.)
    name_normalized = normalize_phrase(name)
    text_normalized = normalize_phrase(text)
    
    if name_normalized in text_normalized:
        return 95.0
    
    # Check if it's a known technique phrase
    phrase_matches = find_technique_phrases(text)
    for phrase in phrase_matches:
        if normalize_phrase(phrase) in name_normalized or name_normalized in normalize_phrase(phrase):
            return 85.0
    
    # Word-level matching as fallback
    name_words = set(name_normalized.split())
    text_words = set(text_normalized.split())
    
    if not name_words:
        return 0.0
    
    overlap = len(name_words & text_words)
    score = (overlap / len(name_words)) * 100
    
    return score


def calculate_id_score(text: str, stix_id: str, entity_type: str) -> float:
    """Calculate score for explicit ID mentions."""
    if not stix_id:
        return 0.0
    
    # Extract technique ID (e.g., T1059 from attack-pattern--...)
    if entity_type == "technique" and "attack-pattern--" in stix_id:
        # Look for T-codes
        t_code_pattern = r'T\d{4}(?:\.\d{3})?'
        if re.search(t_code_pattern, text, re.IGNORECASE):
            # Check if this specific T-code matches
            # This is simplified - would need full mapping in production
            return 100.0
    
    # Check for explicit STIX ID mention (rare but possible)
    if stix_id in text:
        return 100.0
    
    return 0.0


def create_technique_object(tech: Dict[str, Any], chunk_id: str) -> Dict[str, Any]:
    """Create a STIX AttackPattern object."""
    return {
        "type": "attack-pattern",
        "id": tech["stix_id"],
        "spec_version": "2.1",
        "name": tech.get("name_or_snippet", "Unknown Technique"),
        "confidence": tech["confidence"],
        "x_bj_source_chunk": chunk_id,
        "x_bj_scoring": tech.get("scoring_details", {})
    }


def create_group_object(group: Dict[str, Any], chunk_id: str) -> Dict[str, Any]:
    """Create a STIX IntrusionSet object."""
    return {
        "type": "intrusion-set",
        "id": group["stix_id"],
        "spec_version": "2.1",
        "name": group.get("name_or_snippet", "Unknown Group"),
        "confidence": group["confidence"],
        "x_bj_source_chunk": chunk_id,
        "x_bj_scoring": group.get("scoring_details", {})
    }


def create_software_object(sw: Dict[str, Any], chunk_id: str) -> Dict[str, Any]:
    """Create a STIX Software object (malware/tool)."""
    # Determine if malware or tool based on ID or name
    obj_type = "malware" if "malware" in sw.get("stix_id", "").lower() else "tool"
    
    return {
        "type": obj_type,
        "id": sw["stix_id"],
        "spec_version": "2.1",
        "name": sw.get("name_or_snippet", "Unknown Software"),
        "confidence": sw["confidence"],
        "x_bj_source_chunk": chunk_id,
        "x_bj_scoring": sw.get("scoring_details", {})
    }


def synthesize_relationships(
    text: str,
    chunk_id: str,
    techniques: List[Dict[str, Any]],
    groups: List[Dict[str, Any]],
    software: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Synthesize relationships between entities based on text context."""
    relationships = []
    
    # Check for mitigation keywords
    mitigation_keywords = ["prevent", "mitigate", "defend", "control", "block", "detect"]
    has_mitigation_context = any(kw in text.lower() for kw in mitigation_keywords)
    
    # Group/Software -> Technique relationships
    for group in groups:
        for tech in techniques:
            if group["confidence"] >= 50 and tech["confidence"] >= 60:
                # Create "uses" relationship
                rel_confidence = min(group["confidence"], tech["confidence"]) - 10
                relationships.append({
                    "type": "relationship",
                    "id": f"relationship--{uuid.uuid4()}",
                    "spec_version": "2.1",
                    "relationship_type": "uses",
                    "source_ref": group["stix_id"],
                    "target_ref": tech["stix_id"],
                    "confidence": rel_confidence,
                    "x_bj_provenance": {
                        "chunk": chunk_id,
                        "retrieval_scores": [group["score"], tech["score"]],
                        "ts": datetime.utcnow().isoformat() + "Z"
                    }
                })
    
    for sw in software:
        for tech in techniques:
            if sw["confidence"] >= 50 and tech["confidence"] >= 60:
                # Create "uses" relationship
                rel_confidence = min(sw["confidence"], tech["confidence"]) - 10
                relationships.append({
                    "type": "relationship",
                    "id": f"relationship--{uuid.uuid4()}",
                    "spec_version": "2.1",
                    "relationship_type": "uses",
                    "source_ref": sw["stix_id"],
                    "target_ref": tech["stix_id"],
                    "confidence": rel_confidence,
                    "x_bj_provenance": {
                        "chunk": chunk_id,
                        "retrieval_scores": [sw["score"], tech["score"]],
                        "ts": datetime.utcnow().isoformat() + "Z"
                    }
                })
    
    # TODO: Add mitigation relationships if mitigation context detected
    # This would require searching for Mitigation objects
    
    return relationships


def deduplicate_objects(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate objects, keeping highest confidence version."""
    seen = {}
    
    for obj in objects:
        obj_id = obj["id"]
        if obj_id not in seen or obj["confidence"] > seen[obj_id]["confidence"]:
            seen[obj_id] = obj
    
    return list(seen.values())


def deduplicate_relationships(relationships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate relationships based on source/target/type."""
    seen = set()
    unique = []
    
    for rel in relationships:
        key = (rel["source_ref"], rel["target_ref"], rel["relationship_type"])
        if key not in seen:
            seen.add(key)
            unique.append(rel)
    
    return unique