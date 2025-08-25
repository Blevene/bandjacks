"""Attack flow builder with LLM integration and deterministic assembly."""

import uuid
import json
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from neo4j import GraphDatabase

from bandjacks.llm.flows import AttackFlowSynthesizer, synthesize_attack_flow
from bandjacks.loaders.embedder import encode


class FlowBuilder:
    """Build and persist attack flows from various sources."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize flow builder.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.synthesizer = AttackFlowSynthesizer()
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
    
    def build_from_extraction(
        self,
        extraction_data: Dict[str, Any],
        source_id: Optional[str] = None,
        report_text: str = ""
    ) -> Dict[str, Any]:
        """
        Build flow using AttackFlowSynthesizer for LLM synthesis.
        
        Args:
            extraction_data: Results from LLMExtractor
            source_id: Optional source document ID
            report_text: Optional original report text for context
            
        Returns:
            Flow data with episode and actions
        """
        # Use existing synthesize_attack_flow function
        llm_flow = synthesize_attack_flow(
            extraction_result=extraction_data,
            report_text=report_text,
            max_steps=25
        )
        
        if not llm_flow:
            # Fallback to deterministic if LLM synthesis fails
            return self._build_deterministic(extraction_data, source_id)
        
        # Convert LLM flow format to episode/action format
        return self._convert_to_episode(llm_flow, source_id, llm_synthesized=True)
    
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
                        "confidence": tech["confidence"] or 50.0
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
        
        Args:
            intrusion_set_id: STIX ID of the IntrusionSet (e.g., intrusion-set--...)
        
        Returns:
            Flow data with episode and actions
        """
        with self.driver.session() as session:
            # Fetch group name
            group_result = session.run(
                """
                MATCH (g:IntrusionSet {stix_id: $group_id})
                RETURN g.name as name
                """,
                group_id=intrusion_set_id
            )
            group_record = group_result.single()
            group_name = group_record["name"] if group_record else None

            # Fetch techniques used by the group
            techniques_query = (
                """
                MATCH (g:IntrusionSet {stix_id: $group_id})-[:USES]->(t:AttackPattern)
                RETURN t.stix_id as technique_id, t.name as name,
                       coalesce(t.description, "") as description
                """
            )
            result = session.run(techniques_query, group_id=intrusion_set_id)
            steps: List[Dict[str, Any]] = []
            for rec in result:
                steps.append({
                    "technique_id": rec["technique_id"],
                    "name": rec["name"] or "Unknown",
                    "description": rec["description"][:200],
                    "confidence": 60.0
                })
        if not steps:
            raise ValueError(f"No techniques found for intrusion set {intrusion_set_id}")

        ordered_steps = self._order_steps(steps)
        edges = self._compute_next_edges(ordered_steps)
        episode = self._create_episode(
            name=(f"Flow attributed to {group_name}" if group_name else f"Flow for {intrusion_set_id}"),
            steps=ordered_steps,
            edges=edges,
            source_id=intrusion_set_id,
            llm_synthesized=False
        )
        # Stamp attribution metadata
        episode["attributed_group_id"] = intrusion_set_id
        if group_name:
            episode["attributed_group_name"] = group_name
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
                    "confidence": 55.0
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
        
        # Extract flow metadata
        flow_meta = llm_flow.get("flow", {}).get("properties", {})
        flow_name = flow_meta.get("name", "Unnamed Flow")
        flow_description = flow_meta.get("description", "")
        
        # Convert steps to actions
        actions = []
        for step in llm_flow.get("steps", []):
            action_id = f"action--{uuid.uuid4()}"
            
            # Extract entity info
            entity = step.get("entity", {})
            technique_id = entity.get("pk", "unknown")
            
            # Try to get full STIX ID if it's just a technique number
            if technique_id.startswith("T") and not technique_id.startswith("attack-pattern--"):
                # Query Neo4j for full STIX ID
                with self.driver.session() as session:
                    result = session.run(
                        "MATCH (t:AttackPattern) WHERE t.external_id = $ext_id "
                        "RETURN t.stix_id as stix_id, t.name as name LIMIT 1",
                        ext_id=technique_id
                    )
                    record = result.single()
                    if record:
                        technique_id = record["stix_id"]
                        technique_name = record["name"]
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
                "evidence": step.get("evidence", [])
            })
        
        # Create NEXT edges between consecutive steps
        edges = []
        for i in range(len(actions) - 1):
            edges.append({
                "source": actions[i]["action_id"],
                "target": actions[i+1]["action_id"],
                "probability": self._calculate_probability(actions[i], actions[i+1]),
                "rationale": "LLM-inferred sequence" if llm_synthesized else "Sequential ordering"
            })
        
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
                    for mapping in claim.get("mappings", []):
                        tech_id = mapping.get("stix_id") or mapping.get("external_id")
                        if tech_id and tech_id not in seen_techniques:
                            steps.append({
                                "technique_id": tech_id,
                                "name": mapping.get("name", "Unknown"),
                                "description": claim.get("span", {}).get("text", ""),
                                "confidence": mapping.get("confidence", 50.0),
                                "evidence": [claim.get("span", {})]
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
                    "confidence": obj.get("x_bj_confidence", 50.0)
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
        
        # Get tactic order for techniques
        with self.driver.session() as session:
            for step in steps:
                result = session.run(
                    """
                    MATCH (t:AttackPattern {stix_id: $tech_id})-[:HAS_TACTIC]->(tac:Tactic)
                    RETURN tac.shortname as tactic
                    ORDER BY tac.shortname
                    LIMIT 1
                    """,
                    tech_id=step["technique_id"]
                )
                record = result.single()
                if record:
                    # Map tactics to rough order
                    tactic_order = {
                        "reconnaissance": 1, "resource-development": 2,
                        "initial-access": 3, "execution": 4,
                        "persistence": 5, "privilege-escalation": 6,
                        "defense-evasion": 7, "credential-access": 8,
                        "discovery": 9, "lateral-movement": 10,
                        "collection": 11, "command-and-control": 12,
                        "exfiltration": 13, "impact": 14
                    }
                    step["tactic_order"] = tactic_order.get(record["tactic"], 7)
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
    
    def _compute_next_edges(self, ordered_steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Compute NEXT edges with probabilities.
        
        Args:
            ordered_steps: Steps in order
            
        Returns:
            List of edges with probabilities
        """
        edges = []
        
        for i in range(len(ordered_steps) - 1):
            current = ordered_steps[i]
            next_step = ordered_steps[i + 1]
            
            probability = self._calculate_probability(current, next_step)
            
            edges.append({
                "source": current["action_id"],
                "target": next_step["action_id"],
                "probability": probability,
                "rationale": self._generate_rationale(current, next_step, probability)
            })
        
        return edges
    
    def _calculate_probability(self, action1: Dict[str, Any], action2: Dict[str, Any]) -> float:
        """
        Calculate transition probability between actions.
        
        Args:
            action1: Source action
            action2: Target action
            
        Returns:
            Probability between 0.1 and 1.0
        """
        base_p = 0.6
        
        # Check historical adjacency in Neo4j
        tech1 = action1.get("attack_pattern_ref") or action1.get("technique_id")
        tech2 = action2.get("attack_pattern_ref") or action2.get("technique_id")
        
        if tech1 and tech2:
            with self.driver.session() as session:
                # Check if these techniques have been seen together
                result = session.run(
                    """
                    MATCH (t1:AttackPattern {stix_id: $tech1})
                    MATCH (t2:AttackPattern {stix_id: $tech2})
                    OPTIONAL MATCH (t1)-[n:NEXT]-(t2)
                    RETURN count(n) as adjacency_count
                    """,
                    tech1=tech1,
                    tech2=tech2
                )
                record = result.single()
                if record and record["adjacency_count"] > 0:
                    base_p += 0.2
                
                # Check tactic alignment
                tactic_result = session.run(
                    """
                    MATCH (t1:AttackPattern {stix_id: $tech1})-[:HAS_TACTIC]->(tac1:Tactic)
                    MATCH (t2:AttackPattern {stix_id: $tech2})-[:HAS_TACTIC]->(tac2:Tactic)
                    RETURN tac1.shortname as tactic1, tac2.shortname as tactic2
                    """,
                    tech1=tech1,
                    tech2=tech2
                )
                tactic_record = tactic_result.single()
                if tactic_record:
                    if tactic_record["tactic1"] == tactic_record["tactic2"]:
                        base_p += 0.1
                    elif self._is_tactic_regression(tactic_record["tactic1"], tactic_record["tactic2"]):
                        base_p -= 0.1
        
        # Factor in confidence
        avg_confidence = (action1.get("confidence", 50) + action2.get("confidence", 50)) / 2
        if avg_confidence > 80:
            base_p += 0.05
        elif avg_confidence < 40:
            base_p -= 0.05
        
        return min(1.0, max(0.1, base_p))
    
    def _is_tactic_regression(self, tactic1: str, tactic2: str) -> bool:
        """Check if moving from tactic1 to tactic2 is a regression."""
        tactic_order = {
            "reconnaissance": 1, "resource-development": 2,
            "initial-access": 3, "execution": 4,
            "persistence": 5, "privilege-escalation": 6,
            "defense-evasion": 7, "credential-access": 8,
            "discovery": 9, "lateral-movement": 10,
            "collection": 11, "command-and-control": 12,
            "exfiltration": 13, "impact": 14
        }
        
        order1 = tactic_order.get(tactic1, 7)
        order2 = tactic_order.get(tactic2, 7)
        
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
        llm_synthesized: bool = False
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
                "confidence": step.get("confidence", 50.0),
                "evidence": step.get("evidence", []),
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
            RETURN DISTINCT n.source_version as version, n.source_collection as collection
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
                # Create AttackEpisode
                # Get current ATT&CK version for version freeze
                attack_version = self._get_current_attack_version(session)
                
                session.run(
                    """
                    CREATE (e:AttackEpisode {
                        episode_id: $episode_id,
                        flow_id: $flow_id,
                        name: $name,
                        source_id: $source_id,
                        created: datetime(),
                        strategy: $strategy,
                        llm_synthesized: $llm_synthesized,
                        created_with_release: $attack_version,
                        attributed_group_id: $attributed_group_id,
                        attributed_group_name: $attributed_group_name
                    })
                    """,
                    episode_id=flow_data["episode_id"],
                    flow_id=flow_data["flow_id"],
                    name=flow_data["name"],
                    source_id=flow_data.get("source_id"),
                    strategy=flow_data.get("strategy", "sequential"),
                    llm_synthesized=flow_data.get("llm_synthesized", False),
                    attack_version=attack_version,
                    attributed_group_id=flow_data.get("attributed_group_id"),
                    attributed_group_name=flow_data.get("attributed_group_name")
                )
                
                # Create AttackActions and CONTAINS edges
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
                
                # Create NEXT edges
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
                print(f"Error persisting flow to Neo4j: {e}")
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
            
            # Get tactic for this technique
            with self.driver.session() as session:
                result = session.run(
                    """
                    MATCH (t:AttackPattern {stix_id: $tech_id})-[:HAS_TACTIC]->(tac:Tactic)
                    RETURN tac.shortname as tactic
                    """,
                    tech_id=action["attack_pattern_ref"]
                )
                for record in result:
                    tactics_seen.add(record["tactic"])
        
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
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()