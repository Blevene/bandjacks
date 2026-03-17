"""Consolidated attack flow builder with LLM synthesis, STIX export, and OpenSearch integration.

Module Status: PRODUCTION
Core module for generating attack flows from extraction results.
Integrates with Neo4j, OpenSearch, and STIX generation systems.
"""

import logging
import uuid
import json
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from neo4j import GraphDatabase
from opensearchpy import OpenSearch

from bandjacks.llm.client import LLMClient
from bandjacks.llm.schemas import ATTACK_FLOW_SCHEMA
from bandjacks.llm.attack_flow_validator import AttackFlowValidator
from bandjacks.llm.batch_neo4j import BatchNeo4jHelper
from bandjacks.llm.constants import get_tactic_order
from bandjacks.llm.flow_synthesizer import FlowSynthesizer
from bandjacks.loaders.embedder import encode

logger = logging.getLogger(__name__)

# Flow builder constants
DEFAULT_CONFIDENCE = 50.0
HIGH_CONFIDENCE = 60.0
MEDIUM_CONFIDENCE = 55.0
DEFAULT_PROBABILITY = 0.3
LOW_PROBABILITY = 0.25
HIGH_PROBABILITY = 0.4


class FlowBuilder:
    """Consolidated attack flow builder with all generation capabilities."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str,
                 opensearch_client: Optional[OpenSearch] = None):
        """
        Initialize flow builder.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            opensearch_client: Optional OpenSearch client for text/embedding lookups
        """
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
        self.opensearch = opensearch_client
        self.llm_client = LLMClient()
        self.validator = AttackFlowValidator()
        self.batch_helper = BatchNeo4jHelper(self.driver)
        self.synthesizer = FlowSynthesizer()
    
    def build_from_extraction(
        self,
        extraction_data: Dict[str, Any],
        source_id: Optional[str] = None,
        report_text: Optional[str] = None,
        use_stored_text: bool = True
    ) -> Dict[str, Any]:
        """
        Build flow using LLM synthesis with stored text when available.
        
        Args:
            extraction_data: Results from LLMExtractor
            source_id: Optional source document ID (report ID)
            report_text: Optional original report text for context
            use_stored_text: Whether to fetch text from OpenSearch if available
            
        Returns:
            Flow data with episode and actions
        """
        # Try to get stored text and embeddings from OpenSearch if source_id is provided
        if use_stored_text and source_id and self.opensearch:
            stored_text = self._get_stored_text(source_id)
            if stored_text:
                report_text = stored_text
        
        # Extract primary entity for attribution
        primary_entity = extraction_data.get("primary_entity")
        entities = extraction_data.get("entities", {})
        
        # Use LLM synthesis with full context
        llm_flow = self.synthesizer.synthesize(
            extraction_result=extraction_data,
            report_text=report_text or "",
            max_steps=25
        )
        
        if not llm_flow:
            # Fallback to deterministic if LLM synthesis fails
            flow_result = self._build_deterministic(extraction_data, source_id)
        else:
            # Convert LLM flow format to episode/action format
            flow_result = self._convert_to_episode(llm_flow, source_id, llm_synthesized=True)
        
        # Add entity attribution to the flow
        if primary_entity and isinstance(primary_entity, dict) and flow_result:
            flow_result["primary_entity"] = primary_entity
            flow_result["attributed_to"] = primary_entity.get("name")
            flow_result["attribution_type"] = primary_entity.get("type")
            flow_result["attribution_confidence"] = primary_entity.get("confidence", 70)
            
            # Add all extracted entities for reference
            flow_result["entities"] = entities
        
        return flow_result
    
    def build_from_bundle(self, bundle: Dict[str, Any], source_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Build flow deterministically from STIX bundle.
        
        Args:
            bundle: STIX 2.1 bundle
            source_id: Optional source ID
            
        Returns:
            Flow data with episode and actions
        """
        steps = self._extract_steps_from_bundle(bundle)
        ordered_steps = self._order_steps(steps)
        edges = self._compute_next_edges(ordered_steps)
        
        flow_name = self._generate_flow_name(bundle, ordered_steps)
        
        return self._create_episode(
            name=flow_name,
            steps=ordered_steps,
            edges=edges,
            source_id=source_id,
            llm_synthesized=False
        )
    
    def build_from_source(self, source_id: str) -> Dict[str, Any]:
        """
        Build flow from a stored source (report or bundle).
        
        Args:
            source_id: ID of stored source
            
        Returns:
            Flow data with episode and actions
        """
        # Query Neo4j for the source
        with self.driver.session() as session:
            # Check if it's a Report
            report_query = """
                MATCH (r:Report {stix_id: $source_id})
                RETURN r
            """
            report_result = session.run(report_query, source_id=source_id)
            report = report_result.single()
            
            if report:
                # Extract techniques from report
                techniques_query = """
                    MATCH (r:Report {stix_id: $source_id})-[:EXTRACTED_FROM]-(t:AttackPattern)
                    RETURN t.stix_id as technique_id, t.name as name, 
                           t.description as description, t.x_bj_confidence as confidence
                    ORDER BY t.x_bj_confidence DESC
                """
                techniques_result = session.run(techniques_query, source_id=source_id)
                
                steps = []
                for tech in techniques_result:
                    steps.append({
                        "technique_id": tech["technique_id"],
                        "name": tech["name"] or "Unknown",
                        "description": tech["description"] or "",
                        "confidence": tech["confidence"] or DEFAULT_CONFIDENCE
                    })
                
                if not steps:
                    raise ValueError(f"No techniques found for source {source_id}")
                
                ordered_steps = self._order_steps(steps)
                edges = self._compute_next_edges(ordered_steps)
                
                return self._create_episode(
                    name=f"Flow from {source_id}",
                    steps=ordered_steps,
                    edges=edges,
                    source_id=source_id,
                    llm_synthesized=False
                )
            
            # If not a report, treat as bundle ID and load from storage
            raise ValueError(f"Source {source_id} not found")

    def build_from_intrusion_set(self, intrusion_set_id: str) -> Dict[str, Any]:
        """
        Build a flow from an Intrusion Set's known technique usages.
        
        Note: Intrusion sets don't have sequence information, so we model techniques
        as co-occurring rather than sequential. A future sequence inference module
        could attempt to infer likely orderings based on tactic alignment, 
        historical patterns, or ML models.
        
        Args:
            intrusion_set_id: STIX ID of the IntrusionSet (e.g., intrusion-set--...)
        
        Returns:
            Flow data with episode and actions (co-occurrence model)
        """
        with self.driver.session() as session:
            # Fetch group name and techniques with tactics
            combined_query = """
                MATCH (g:IntrusionSet {stix_id: $group_id})
                OPTIONAL MATCH (g)-[:USES]->(t:AttackPattern)
                OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
                WITH g, t, collect(DISTINCT tac.shortname) as tactics
                RETURN g.name as group_name,
                       collect(DISTINCT {
                           technique_id: t.stix_id,
                           name: t.name,
                           description: coalesce(t.description, ""),
                           tactics: tactics
                       }) as techniques
            """
            result = session.run(combined_query, group_id=intrusion_set_id)
            record = result.single()
            
            if not record:
                raise ValueError(f"Intrusion set {intrusion_set_id} not found")
            
            group_name = record["group_name"]
            techniques = [t for t in record["techniques"] if t["technique_id"] is not None]
            
        if not techniques:
            raise ValueError(f"No techniques found for intrusion set {intrusion_set_id}")

        # Create actions without sequential ordering
        actions = []
        for i, tech in enumerate(techniques):
            actions.append({
                "action_id": f"action--{uuid.uuid4()}",
                "order": i + 1,  # Arbitrary order for display purposes
                "technique_id": tech["technique_id"],
                "name": tech["name"] or "Unknown",
                "description": tech["description"][:200] if tech["description"] else "",
                "confidence": HIGH_CONFIDENCE,
                "tactics": tech["tactics"]
            })
        
        # Create co-occurrence edges (sparse connectivity to avoid explosion)
        # For now, we'll create a hub-and-spoke pattern with techniques grouped by tactic
        edges = self._create_cooccurrence_edges(actions)
        
        episode = self._create_episode(
            name=(f"Techniques used by {group_name}" if group_name else f"Techniques for {intrusion_set_id}"),
            steps=actions,
            edges=edges,
            source_id=intrusion_set_id,
            llm_synthesized=False,
            flow_type="co-occurrence"  # Mark as co-occurrence flow
        )
        
        # Stamp attribution metadata
        episode["attributed_group_id"] = intrusion_set_id
        if group_name:
            episode["attributed_group_name"] = group_name
        episode["flow_type"] = "co-occurrence"
        episode["sequence_inferred"] = False
        
        return episode

    def build_from_techniques(self, techniques: List[str], name: Optional[str] = None) -> Dict[str, Any]:
        """
        Build a flow from a list of technique identifiers.
        
        Each identifier may be a STIX ID (attack-pattern--...) or an ATT&CK ID (e.g., T1059.001).
        """
        if not techniques:
            raise ValueError("No techniques provided")

        # Resolve to STIX IDs and names
        steps: List[Dict[str, Any]] = []
        with self.driver.session() as session:
            for tech in techniques:
                stix_id, tech_name, desc = self._resolve_technique_identifier(session, tech)
                if not stix_id:
                    # Skip unknown techniques but continue
                    continue
                steps.append({
                    "technique_id": stix_id,
                    "name": tech_name or "Unknown",
                    "description": (desc or "")[:200],
                    "confidence": MEDIUM_CONFIDENCE
                })

        if not steps:
            raise ValueError("None of the techniques could be resolved in the knowledge base")

        ordered_steps = self._order_steps(steps)
        edges = self._compute_next_edges(ordered_steps)
        flow_name = name or self._generate_flow_name({"objects": []}, ordered_steps)
        return self._create_episode(
            name=flow_name,
            steps=ordered_steps,
            edges=edges,
            source_id=None,
            llm_synthesized=False
        )

    def build_from_campaign(self, campaign_id: str, mode: str = "sequential") -> Dict[str, Any]:
        """
        Build a flow from a Campaign's observed behaviors.

        mode:
          - "sequential": order by temporal hints and tactic order
          - "cooccurrence": treat as unordered; create weak NEXT edges
        """
        query = """
            MATCH (c:Campaign {stix_id: $entity_id})
            OPTIONAL MATCH (c)-[:USES]->(ap:AttackPattern)
            RETURN collect(DISTINCT ap) as techniques, c.name as entity_name
        """
        return self._build_from_graph_entity(
            query=query,
            entity_id=campaign_id,
            mode=mode,
            confidence=MEDIUM_CONFIDENCE,
            cooccurrence_probability=DEFAULT_PROBABILITY,
            entity_label="campaign"
        )

    def build_from_report(self, report_id: str, mode: str = "sequential") -> Dict[str, Any]:
        """
        Build a flow from a Report's described techniques (sequential or cooccurrence).
        Uses any described AttackPatterns linked via DESCRIBES.
        """
        query = """
            MATCH (r:Report {stix_id: $entity_id})-[:DESCRIBES]->(ap:AttackPattern)
            RETURN collect(DISTINCT ap) as techniques, r.name as entity_name
        """
        return self._build_from_graph_entity(
            query=query,
            entity_id=report_id,
            mode=mode,
            confidence=DEFAULT_CONFIDENCE,
            cooccurrence_probability=LOW_PROBABILITY,
            entity_label="report"
        )

    def _build_from_graph_entity(
        self,
        query: str,
        entity_id: str,
        mode: str,
        confidence: float,
        cooccurrence_probability: float,
        entity_label: str
    ) -> Dict[str, Any]:
        """
        Shared helper for building flows from graph entities (campaigns, reports, etc.).

        Args:
            query: Cypher query that returns ``techniques`` and ``entity_name`` columns.
                   Must accept an ``$entity_id`` parameter.
            entity_id: STIX ID of the source entity.
            mode: "sequential" or "cooccurrence".
            confidence: Default confidence score for extracted steps.
            cooccurrence_probability: Edge probability used in co-occurrence mode.
            entity_label: Human-readable label for error messages (e.g. "campaign").

        Returns:
            Flow data with episode and actions.
        """
        with self.driver.session() as session:
            result = session.run(query, entity_id=entity_id)
            rec = result.single()
            ap_nodes = rec["techniques"] if rec else []
            entity_name = rec["entity_name"] if rec else None

        steps: List[Dict[str, Any]] = []
        for ap in ap_nodes or []:
            if not ap:
                continue
            apd = dict(ap)
            steps.append({
                "technique_id": apd.get("stix_id"),
                "name": apd.get("name", "Unknown"),
                "description": (apd.get("description", "") or "")[:200],
                "confidence": confidence
            })

        if not steps:
            raise ValueError(f"No techniques found for {entity_label} {entity_id}")

        if mode == "sequential":
            ordered_steps = self._order_steps(steps)
            edges = self._compute_next_edges(ordered_steps)
        else:
            # co-occurrence: keep insertion order and create light edges between all pairs
            ordered_steps = []
            for i, s in enumerate(steps):
                s_copy = dict(s)
                s_copy["order"] = i + 1
                s_copy["action_id"] = f"action--{uuid.uuid4()}"
                ordered_steps.append(s_copy)
            edges: List[Dict[str, Any]] = []
            for i in range(len(ordered_steps)):
                for j in range(i + 1, len(ordered_steps)):
                    edges.append({
                        "source": ordered_steps[i]["action_id"],
                        "target": ordered_steps[j]["action_id"],
                        "probability": cooccurrence_probability,
                        "rationale": "co-occurrence"
                    })

        episode = self._create_episode(
            name=(entity_name or f"Flow from {entity_id}"),
            steps=ordered_steps,
            edges=edges,
            source_id=entity_id,
            llm_synthesized=False
        )
        return episode

    def _normalize_evidence(self, evidence):
        """
        Normalize evidence to always be a list.
        Handles both dict format (from optimized_chunked_extractor) and list format.
        """
        if not evidence:
            return []

        # If it's already a list, return it
        if isinstance(evidence, list):
            return evidence

        # If it's a dict (from optimized_chunked_extractor), convert to list format
        if isinstance(evidence, dict):
            # Extract quotes/text from dict format
            quotes = evidence.get("quotes", [])
            if quotes:
                return [{"text": quote, "line_refs": evidence.get("line_refs", [])} for quote in quotes]
            elif evidence.get("text"):
                return [{"text": evidence["text"], "line_refs": evidence.get("line_refs", [])}]
            else:
                return []

        # If it's a string, wrap in list
        if isinstance(evidence, str):
            return [evidence]

        return []

    def _resolve_technique_identifier(self, session, identifier: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Resolve a technique identifier (STIX ID or ATT&CK external ID) to (stix_id, name, description).
        """
        if identifier.startswith("attack-pattern--"):
            query = (
                """
                MATCH (t:AttackPattern {stix_id: $id})
                RETURN t.stix_id as stix_id, t.name as name, t.description as description
                """
            )
            rec = session.run(query, id=identifier).single()
            if rec:
                return rec["stix_id"], rec["name"], rec["description"]
            return None, None, None
        # Otherwise treat as external ATT&CK ID (e.g., T1059 or T1059.001)
        query = (
            """
            MATCH (t:AttackPattern)
            WHERE t.external_id = $ext OR $ext IN t.external_ids
            RETURN t.stix_id as stix_id, t.name as name, t.description as description
            LIMIT 1
            """
        )
        rec = session.run(query, ext=identifier).single()
        if rec:
            return rec["stix_id"], rec["name"], rec["description"]
        return None, None, None
    
    def _convert_to_episode(
        self,
        llm_flow: Dict[str, Any],
        source_id: Optional[str] = None,
        llm_synthesized: bool = True
    ) -> Dict[str, Any]:
        """
        Convert LLM flow format to AttackEpisode/AttackAction format.
        
        Args:
            llm_flow: Flow from AttackFlowSynthesizer
            source_id: Optional source ID
            llm_synthesized: Whether this was LLM-synthesized
            
        Returns:
            Standardized flow data
        """
        flow_id = f"flow--{uuid.uuid4()}"
        episode_id = f"episode--{uuid.uuid4()}"
        
        # Extract flow metadata (support multiple formats)
        flow_meta = llm_flow.get("flow", {}).get("properties", {})
        flow_name = (llm_flow.get("attack_flow_name") or 
                    llm_flow.get("flow_name") or 
                    flow_meta.get("name", "Unnamed Flow"))
        flow_description = flow_meta.get("description", "")
        
        # Convert steps to actions (support 'steps', 'attack_steps', or 'attack_flow')
        actions = []
        steps = (llm_flow.get("steps") or
                llm_flow.get("attack_steps") or
                llm_flow.get("attack_flow", []))

        # Batch-fetch all T-number technique IDs in one query (N+1 fix)
        t_number_ids = []
        for step in steps:
            entity = step.get("entity", {})
            tid = entity.get("pk") or entity.get("id", "")
            if isinstance(tid, str) and tid.startswith("T") and not tid.startswith("attack-pattern--"):
                t_number_ids.append(tid)

        technique_lookup: Dict[str, Dict[str, Any]] = {}
        if t_number_ids:
            with self.driver.session() as session:
                result = session.run(
                    "UNWIND $ext_ids AS ext_id "
                    "MATCH (t:AttackPattern) WHERE t.external_id = ext_id "
                    "RETURN t.external_id AS ext_id, t.stix_id AS stix_id, t.name AS name",
                    ext_ids=list(set(t_number_ids))
                )
                for rec in result:
                    technique_lookup[rec["ext_id"]] = {
                        "stix_id": rec["stix_id"],
                        "name": rec["name"]
                    }

        for step in steps:
            action_id = f"action--{uuid.uuid4()}"
            
            # Extract entity info
            entity = step.get("entity", {})
            # Support both 'pk' and 'id' fields
            technique_id = entity.get("pk") or entity.get("id", "unknown")
            
            # Try to get full STIX ID if it's just a technique number
            if technique_id.startswith("T") and not technique_id.startswith("attack-pattern--"):
                # Use batch-fetched lookup dict instead of per-step query
                if technique_id in technique_lookup:
                    info = technique_lookup[technique_id]
                    technique_id = info["stix_id"]
                    technique_name = info["name"]
                else:
                    technique_name = entity.get("label", "Unknown")
            else:
                technique_name = entity.get("label", "Unknown")
            
            actions.append({
                "action_id": action_id,
                "order": step.get("order", len(actions) + 1),
                "attack_pattern_ref": technique_id,
                "name": technique_name,
                "description": step.get("description", ""),
                "reason": step.get("reason", ""),
                "confidence": step.get("confidence", 70.0),
                "evidence": self._normalize_evidence(step.get("evidence", []))
            })
        
        # Create NEXT edges between consecutive steps
        edges = self._compute_next_edges(actions)
        
        return {
            "flow_id": flow_id,
            "episode_id": episode_id,
            "name": flow_name,
            "description": flow_description,
            "source_id": source_id,
            "actions": actions,
            "edges": edges,
            "llm_synthesized": llm_synthesized,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "stats": {
                "steps_count": len(actions),
                "edges_count": len(edges),
                "avg_confidence": sum(a["confidence"] for a in actions) / len(actions) if actions else 0
            }
        }
    
    def _build_deterministic(
        self,
        extraction_data: Dict[str, Any],
        source_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Build flow deterministically from extraction data.
        
        Args:
            extraction_data: Extraction results
            source_id: Optional source ID
            
        Returns:
            Flow data
        """
        # Extract techniques from claims
        steps = []
        seen_techniques = set()
        
        # Process chunks if present
        if "chunks" in extraction_data:
            for chunk in extraction_data["chunks"]:
                for claim in chunk.get("claims", []):
                    # Handle claims with mappings (old format)
                    if "mappings" in claim:
                        for mapping in claim.get("mappings", []):
                            tech_id = mapping.get("stix_id") or mapping.get("external_id")
                            if tech_id and tech_id not in seen_techniques:
                                steps.append({
                                    "technique_id": tech_id,
                                    "name": mapping.get("name", "Unknown"),
                                    "description": claim.get("span", {}).get("text", ""),
                                    "confidence": mapping.get("confidence", DEFAULT_CONFIDENCE),
                                    "evidence": [claim.get("span", {})]
                                })
                                seen_techniques.add(tech_id)
                    # Handle claims with direct external_id (new format)
                    elif "external_id" in claim or "technique_id" in claim:
                        tech_id = claim.get("external_id") or claim.get("technique_id")
                        if tech_id and tech_id not in seen_techniques:
                            steps.append({
                                "technique_id": tech_id,
                                "name": claim.get("name", tech_id),
                                "description": " ".join(claim.get("quotes", [])),
                                "confidence": claim.get("confidence", DEFAULT_CONFIDENCE),
                                "evidence": [{"text": " ".join(claim.get("quotes", [])), "line_refs": claim.get("line_refs", [])}]
                            })
                            seen_techniques.add(tech_id)
        
        # Also process techniques from extraction_result directly
        if "techniques" in extraction_data and not steps:
            techniques = extraction_data["techniques"]
            for tech_id, tech_data in techniques.items():
                if tech_id not in seen_techniques:
                    steps.append({
                        "technique_id": tech_id,
                        "name": tech_data.get("name", tech_id),
                        "description": tech_data.get("description", ""),
                        "confidence": tech_data.get("confidence", DEFAULT_CONFIDENCE),
                        "evidence": self._normalize_evidence(tech_data.get("evidence", []))
                    })
                    seen_techniques.add(tech_id)
        
        if not steps:
            raise ValueError("No techniques found in extraction data")
        
        ordered_steps = self._order_steps(steps)
        edges = self._compute_next_edges(ordered_steps)
        
        return self._create_episode(
            name=f"Flow from extraction",
            steps=ordered_steps,
            edges=edges,
            source_id=source_id,
            llm_synthesized=False
        )
    
    def _extract_steps_from_bundle(self, bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract attack steps from STIX bundle."""
        steps = []
        
        for obj in bundle.get("objects", []):
            if obj.get("type") == "attack-pattern":
                steps.append({
                    "technique_id": obj["id"],
                    "name": obj.get("name", "Unknown"),
                    "description": obj.get("description", "")[:200],
                    "confidence": obj.get("x_bj_confidence", DEFAULT_CONFIDENCE)
                })
        
        return steps
    
    def _order_steps(self, steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Order steps based on temporal hints, tactics, and confidence.
        
        Args:
            steps: Unordered steps
            
        Returns:
            Ordered steps with action_ids
        """
        # Look for temporal markers in descriptions
        temporal_keywords = {
            "initial": 1, "first": 1, "begin": 1,
            "then": 2, "next": 2, "subsequently": 2,
            "finally": 3, "last": 3, "end": 3
        }
        
        for step in steps:
            desc_lower = step.get("description", "").lower()
            for keyword, priority in temporal_keywords.items():
                if keyword in desc_lower:
                    step["temporal_priority"] = priority
                    break
            else:
                step["temporal_priority"] = 2  # Default middle
        
        # Get tactic order for techniques using batch query
        technique_ids = [step["technique_id"] for step in steps]
        tactics_map = self.batch_helper.batch_get_technique_tactics(technique_ids)
        
        for step in steps:
            tactics = tactics_map.get(step["technique_id"], [])
            if tactics:
                # Use first tactic for ordering
                primary_tactic = tactics[0]
                step["tactic_order"] = self.batch_helper.get_tactic_order(primary_tactic)
            else:
                step["tactic_order"] = 7  # Default middle
        
        # Sort by: temporal > tactic > confidence > name
        steps.sort(key=lambda x: (
            x.get("temporal_priority", 2),
            x.get("tactic_order", 7),
            -x.get("confidence", 50),
            x.get("name", "")
        ))
        
        # Add action IDs and order
        for i, step in enumerate(steps):
            step["action_id"] = f"action--{uuid.uuid4()}"
            step["order"] = i + 1
        
        return steps
    
    def _create_cooccurrence_edges(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Create co-occurrence edges for techniques without sequential ordering.
        
        Uses a sparse connectivity pattern to avoid edge explosion:
        - Groups techniques by tactic
        - Creates edges within tactic groups
        - Adds cross-tactic edges for common patterns
        
        Args:
            actions: List of action dictionaries with tactics
            
        Returns:
            List of co-occurrence edges
        """
        edges = []
        
        # Group actions by their primary tactic
        tactic_groups = {}
        for action in actions:
            tactics = action.get("tactics", [])
            primary_tactic = tactics[0] if tactics else "unknown"
            if primary_tactic not in tactic_groups:
                tactic_groups[primary_tactic] = []
            tactic_groups[primary_tactic].append(action)
        
        # Create edges within each tactic group (clique within small groups, hub-spoke for large)
        for tactic, group_actions in tactic_groups.items():
            if len(group_actions) <= 5:
                # Small group: create full mesh (clique)
                for i, action1 in enumerate(group_actions):
                    for action2 in group_actions[i+1:]:
                        edges.append({
                            "source": action1["action_id"],
                            "target": action2["action_id"],
                            "probability": DEFAULT_PROBABILITY,
                            "rationale": f"co-occurrence within {tactic}",
                            "edge_type": "co-occurrence"
                        })
            else:
                # Large group: hub-and-spoke with most common technique as hub
                # For now, just use first as hub
                hub = group_actions[0]
                for action in group_actions[1:]:
                    edges.append({
                        "source": hub["action_id"],
                        "target": action["action_id"],
                        "probability": LOW_PROBABILITY,
                        "rationale": f"co-occurrence within {tactic}",
                        "edge_type": "co-occurrence"
                    })
        
        # Add some cross-tactic edges for common patterns
        tactic_sequence = [
            "initial-access", "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery", "lateral-movement",
            "collection", "command-and-control", "exfiltration", "impact"
        ]
        
        for i, tactic1 in enumerate(tactic_sequence[:-1]):
            tactic2 = tactic_sequence[i + 1]
            if tactic1 in tactic_groups and tactic2 in tactic_groups:
                # Connect one technique from each adjacent tactic
                source = tactic_groups[tactic1][0]
                target = tactic_groups[tactic2][0]
                edges.append({
                    "source": source["action_id"],
                    "target": target["action_id"],
                    "probability": HIGH_PROBABILITY,
                    "rationale": f"cross-tactic pattern: {tactic1} → {tactic2}",
                    "edge_type": "co-occurrence"
                })
        
        return edges
    
    def _compute_next_edges(self, ordered_steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Compute NEXT edges with probabilities.
        
        Args:
            ordered_steps: Steps in order
            
        Returns:
            List of edges with probabilities
        """
        edges = []
        
        # Prepare all technique pairs for batch queries
        technique_pairs = []
        for i in range(len(ordered_steps) - 1):
            current = ordered_steps[i]
            next_step = ordered_steps[i + 1]
            tech1 = current.get("attack_pattern_ref") or current.get("technique_id")
            tech2 = next_step.get("attack_pattern_ref") or next_step.get("technique_id")
            if tech1 and tech2:
                technique_pairs.append((tech1, tech2))
        
        # Batch get adjacencies and tactic alignments
        adjacencies = self.batch_helper.batch_check_adjacencies(technique_pairs) if technique_pairs else {}
        tactic_alignments = self.batch_helper.batch_get_tactic_alignments(technique_pairs) if technique_pairs else {}
        
        # Compute edges with batch results
        for i in range(len(ordered_steps) - 1):
            current = ordered_steps[i]
            next_step = ordered_steps[i + 1]
            
            tech1 = current.get("attack_pattern_ref") or current.get("technique_id")
            tech2 = next_step.get("attack_pattern_ref") or next_step.get("technique_id")
            
            # Calculate probability using batch results
            base_p = 0.6
            
            if tech1 and tech2:
                pair = (tech1, tech2)
                
                # Check adjacency from batch results
                if adjacencies.get(pair, 0) > 0:
                    base_p += 0.2
                
                # Check tactic alignment from batch results
                alignment = tactic_alignments.get(pair, {})
                if alignment.get("same_tactic"):
                    base_p += 0.1
                elif alignment.get("source_tactics") and alignment.get("target_tactics"):
                    # Check for regression
                    for t1 in alignment["source_tactics"]:
                        for t2 in alignment["target_tactics"]:
                            if self._is_tactic_regression(t1, t2):
                                base_p -= 0.1
                                break
            
            # Factor in confidence
            avg_confidence = (current.get("confidence", 50) + next_step.get("confidence", 50)) / 2
            if avg_confidence > 80:
                base_p += 0.05
            elif avg_confidence < 40:
                base_p -= 0.05
            
            probability = min(1.0, max(0.1, base_p))
            
            edges.append({
                "source": current["action_id"],
                "target": next_step["action_id"],
                "probability": probability,
                "rationale": self._generate_rationale(current, next_step, probability)
            })
        
        return edges
    
    def _is_tactic_regression(self, tactic1: str, tactic2: str) -> bool:
        """Check if moving from tactic1 to tactic2 is a regression."""
        order1 = get_tactic_order(tactic1)
        order2 = get_tactic_order(tactic2)
        
        # Regression if going back more than 3 steps
        return order2 < order1 - 3
    
    def _generate_rationale(
        self,
        action1: Dict[str, Any],
        action2: Dict[str, Any],
        probability: float
    ) -> str:
        """Generate rationale for edge probability."""
        reasons = []
        
        if probability >= 0.8:
            reasons.append("high confidence")
        elif probability >= 0.6:
            reasons.append("moderate confidence")
        else:
            reasons.append("low confidence")
        
        if action1.get("tactic_order") == action2.get("tactic_order"):
            reasons.append("same tactic")
        elif action1.get("tactic_order", 0) < action2.get("tactic_order", 0):
            reasons.append("tactic progression")
        
        if action1.get("temporal_priority") < action2.get("temporal_priority"):
            reasons.append("temporal sequence")
        
        return ", ".join(reasons) if reasons else "sequential"
    
    def _create_episode(
        self,
        name: str,
        steps: List[Dict[str, Any]],
        edges: List[Dict[str, Any]],
        source_id: Optional[str] = None,
        llm_synthesized: bool = False,
        flow_type: str = "sequential"
    ) -> Dict[str, Any]:
        """Create episode structure from steps and edges."""
        flow_id = f"flow--{uuid.uuid4()}"
        episode_id = f"episode--{uuid.uuid4()}"
        
        # Format actions
        actions = []
        for step in steps:
            actions.append({
                "action_id": step.get("action_id", f"action--{uuid.uuid4()}"),
                "order": step.get("order", len(actions) + 1),
                "attack_pattern_ref": step.get("technique_id", "unknown"),
                "name": step.get("name", "Unknown"),
                "description": step.get("description", ""),
                "confidence": step.get("confidence", DEFAULT_CONFIDENCE),
                "evidence": self._normalize_evidence(step.get("evidence", [])),
                "reason": step.get("reason", "")
            })
        
        return {
            "flow_id": flow_id,
            "episode_id": episode_id,
            "name": name,
            "source_id": source_id,
            "actions": actions,
            "edges": edges,
            "llm_synthesized": llm_synthesized,
            "flow_type": flow_type,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "stats": {
                "steps_count": len(actions),
                "edges_count": len(edges),
                "avg_confidence": sum(a["confidence"] for a in actions) / len(actions) if actions else 0,
                "avg_probability": sum(e["probability"] for e in edges) / len(edges) if edges else 0
            }
        }
    
    def _generate_flow_name(self, bundle: Dict[str, Any], steps: List[Dict[str, Any]]) -> str:
        """Generate a name for the flow."""
        # Try to find threat actor in bundle
        for obj in bundle.get("objects", []):
            if obj.get("type") == "intrusion-set":
                return f"{obj.get('name', 'Unknown')} Attack Flow"
        
        # Use first and last techniques
        if steps:
            first = steps[0].get("name", "")
            last = steps[-1].get("name", "")
            if first and last:
                return f"Flow: {first} to {last}"
        
        return "Unknown Attack Flow"
    
    def _get_current_attack_version(self, session) -> str:
        """Get the current ATT&CK version in use."""
        result = session.run(
            """
            MATCH (n:AttackPattern)
            WHERE n.source_version IS NOT NULL
            RETURN n.source_version as version, n.source_collection as collection
            ORDER BY n.modified DESC
            LIMIT 1
            """
        )
        record = result.single()
        if record:
            return f"{record['collection']}-{record['version']}"
        return "unknown"
    
    def persist_to_neo4j(self, flow_data: Dict[str, Any]) -> bool:
        """
        Persist flow to Neo4j.
        
        Args:
            flow_data: Complete flow data
            
        Returns:
            Success boolean
        """
        with self.driver.session() as session:
            try:
                # Get current ATT&CK version for version freeze
                attack_version = self._get_current_attack_version(session)
                
                # Create AttackFlow node (main flow container)
                session.run(
                    """
                    CREATE (f:AttackFlow {
                        flow_id: $flow_id,
                        name: $name,
                        description: $description,
                        flow_type: $flow_type,
                        source_id: $source_id,
                        created: datetime(),
                        modified: datetime(),
                        llm_synthesized: $llm_synthesized,
                        created_with_release: $attack_version,
                        attributed_group_id: $attributed_group_id,
                        attributed_group_name: $attributed_group_name,
                        sequence_inferred: $sequence_inferred
                    })
                    """,
                    flow_id=flow_data["flow_id"],
                    name=flow_data["name"],
                    description=flow_data.get("description", f"Attack flow with {len(flow_data['actions'])} steps"),
                    flow_type=flow_data.get("flow_type", "sequential"),
                    source_id=flow_data.get("source_id"),
                    llm_synthesized=flow_data.get("llm_synthesized", False),
                    attack_version=attack_version,
                    attributed_group_id=flow_data.get("attributed_group_id"),
                    attributed_group_name=flow_data.get("attributed_group_name"),
                    sequence_inferred=flow_data.get("sequence_inferred", False)
                )
                
                # Create AttackEpisode linked to the flow
                session.run(
                    """
                    MATCH (f:AttackFlow {flow_id: $flow_id})
                    CREATE (e:AttackEpisode {
                        episode_id: $episode_id,
                        name: $name,
                        source_id: $source_id,
                        created: datetime(),
                        strategy: $strategy
                    })
                    CREATE (f)-[:CONTAINS_EPISODE]->(e)
                    """,
                    flow_id=flow_data["flow_id"],
                    episode_id=flow_data["episode_id"],
                    name=flow_data["name"],
                    source_id=flow_data.get("source_id"),
                    strategy=flow_data.get("flow_type", "sequential")
                )
                
                # Batch create AttackActions and CONTAINS edges
                if not self.batch_helper.batch_create_attack_actions(
                    flow_data["episode_id"], 
                    flow_data["actions"]
                ):
                    # Fallback to individual queries if batch fails
                    for action in flow_data["actions"]:
                        session.run(
                            """
                            MATCH (e:AttackEpisode {episode_id: $episode_id})
                            CREATE (a:AttackAction {
                                action_id: $action_id,
                                attack_pattern_ref: $attack_pattern_ref,
                                confidence: $confidence,
                                order: $order,
                                description: $description,
                                evidence: $evidence,
                                rationale: $rationale,
                                timestamp: datetime()
                            })
                            CREATE (e)-[:CONTAINS {order: $order}]->(a)
                            WITH a
                            MATCH (t:AttackPattern {stix_id: $attack_pattern_ref})
                            CREATE (a)-[:OF_TECHNIQUE]->(t)
                            """,
                            episode_id=flow_data["episode_id"],
                            action_id=action["action_id"],
                            attack_pattern_ref=action["attack_pattern_ref"],
                            confidence=action["confidence"],
                            order=action["order"],
                            description=action["description"],
                            evidence=json.dumps(action.get("evidence", [])),
                            rationale=action.get("reason", "")
                        )
                
                # Batch create NEXT edges
                if not self.batch_helper.batch_create_next_edges(flow_data["edges"]):
                    # Fallback to individual queries if batch fails
                    for edge in flow_data["edges"]:
                        session.run(
                            """
                            MATCH (a1:AttackAction {action_id: $source})
                            MATCH (a2:AttackAction {action_id: $target})
                            CREATE (a1)-[:NEXT {p: $probability, rationale: $rationale}]->(a2)
                            """,
                            source=edge["source"],
                            target=edge["target"],
                            probability=edge["probability"],
                            rationale=edge["rationale"]
                        )
                
                # Link to source if exists
                if flow_data.get("source_id"):
                    session.run(
                        """
                        MATCH (e:AttackEpisode {episode_id: $episode_id})
                        MATCH (s {stix_id: $source_id})
                        CREATE (e)-[:DERIVED_FROM]->(s)
                        """,
                        episode_id=flow_data["episode_id"],
                        source_id=flow_data["source_id"]
                    )

                # Add explicit actor attribution if provided
                if flow_data.get("attributed_group_id"):
                    session.run(
                        """
                        MATCH (e:AttackEpisode {episode_id: $episode_id})
                        MATCH (g:IntrusionSet {stix_id: $group_id})
                        CREATE (e)-[:ATTRIBUTED_TO]->(g)
                        """,
                        episode_id=flow_data["episode_id"],
                        group_id=flow_data["attributed_group_id"]
                    )
                
                return True
                
            except Exception as e:
                logger.error("Error persisting flow to Neo4j: %s", e)
                return False
    
    def generate_flow_embedding(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate embedding for flow (no truncation).
        
        Args:
            flow_data: Complete flow data
            
        Returns:
            Document for OpenSearch indexing
        """
        # Build comprehensive text representation
        flow_text_parts = [
            f"Attack Flow: {flow_data['name']}",
            f"Source: {flow_data.get('source_id', 'unknown')}",
            f"Created: {flow_data.get('created_at', '')}",
            ""
        ]
        
        # Add all steps with full details - NO TRUNCATION
        tactics_seen = set()
        techniques = []
        
        # Batch get tactics for all techniques
        technique_ids = [action["attack_pattern_ref"] for action in flow_data["actions"]]
        tactics_map = self.batch_helper.batch_get_technique_tactics(technique_ids)
        
        for action in flow_data["actions"]:
            flow_text_parts.append(
                f"Step {action['order']}: {action['name']}"
            )
            flow_text_parts.append(
                f"  Technique: {action['attack_pattern_ref']}"
            )
            flow_text_parts.append(
                f"  Description: {action['description']}"
            )
            flow_text_parts.append(
                f"  Confidence: {action['confidence']:.1f}%"
            )
            if action.get("reason"):
                flow_text_parts.append(
                    f"  Reason: {action['reason']}"
                )
            flow_text_parts.append("")  # Blank line
            
            techniques.append(action["attack_pattern_ref"])
            
            # Get tactics from batch results
            for tactic in tactics_map.get(action["attack_pattern_ref"], []):
                tactics_seen.add(tactic)
        
        # Add edge information
        if flow_data["edges"]:
            flow_text_parts.append("Flow transitions:")
            for edge in flow_data["edges"]:
                flow_text_parts.append(
                    f"  {edge['source'][-8:]} -> {edge['target'][-8:]}: "
                    f"p={edge['probability']:.2f} ({edge['rationale']})"
                )
        
        # NO TRUNCATION - use full text
        flow_text = "\n".join(flow_text_parts)
        
        # Generate embedding from full text
        embedding = encode(flow_text)
        
        if embedding is None:
            # Fallback to empty embedding if encoding fails
            embedding = [0.0] * 768
        
        return {
            "flow_id": flow_data["flow_id"],
            "episode_id": flow_data["episode_id"],
            "name": flow_data["name"],
            "source_id": flow_data.get("source_id"),
            "created": flow_data.get("created_at"),
            "flow_text": flow_text,  # Store full text, no truncation
            "flow_embedding": embedding,
            "techniques": techniques,
            "tactics": list(tactics_seen),
            "steps_count": len(flow_data["actions"]),
            "avg_confidence": flow_data["stats"]["avg_confidence"],
            "llm_synthesized": flow_data.get("llm_synthesized", False)
        }
    
    def _get_stored_text(self, report_id: str) -> Optional[str]:
        """
        Retrieve stored text from OpenSearch for a report.
        
        Args:
            report_id: Report/source ID
            
        Returns:
            Stored raw text or None
        """
        if not self.opensearch:
            return None
            
        try:
            from bandjacks.store.opensearch_report_store import OpenSearchReportStore
            store = OpenSearchReportStore(self.opensearch)
            report = store.get_report(report_id)
            
            if report:
                # Return raw text if available
                return report.get("raw_text")
        except Exception as e:
            logger.error("Error retrieving stored text: %s", e)
        
        return None

    def export_to_stix_attack_flow(
        self,
        flow_data: Dict[str, Any],
        scope: str = "incident",
        marking_refs: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Export flow to STIX Attack Flow 2.0 format (absorbed from AttackFlowGenerator).
        
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