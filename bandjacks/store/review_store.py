"""Storage for analyst review decisions."""

import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
from neo4j import GraphDatabase


class ReviewStore:
    """Store and retrieve analyst review decisions in Neo4j."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self._ensure_constraints()
    
    def _ensure_constraints(self):
        """Ensure ReviewDecision constraints exist."""
        with self.driver.session() as session:
            # Create constraint for ReviewDecision nodes
            session.run("""
                CREATE CONSTRAINT review_decision_id IF NOT EXISTS
                FOR (r:ReviewDecision) REQUIRE r.id IS UNIQUE
            """)
    
    def record_mapping_decision(
        self,
        object_id: str,
        decision: str,
        note: Optional[str] = None,
        fields_patch: Optional[Dict[str, Any]] = None,
        analyst_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Record a mapping review decision.
        
        Args:
            object_id: STIX ID of the object being reviewed
            decision: accept/edit/reject
            note: Optional reviewer note
            fields_patch: Optional field edits (for edit decision)
            analyst_id: Optional analyst identifier
            
        Returns:
            Review record with ID and timestamp
        """
        review_id = f"review--{uuid.uuid4()}"
        ts = datetime.utcnow().isoformat() + "Z"
        
        with self.driver.session() as session:
            # Create ReviewDecision node
            query = """
                CREATE (r:ReviewDecision {
                    id: $review_id,
                    object_id: $object_id,
                    decision: $decision,
                    note: $note,
                    fields_patch: $fields_patch,
                    analyst_id: $analyst_id,
                    ts: $ts,
                    review_type: 'mapping'
                })
                RETURN r.id as id, r.ts as ts
            """
            
            result = session.run(
                query,
                review_id=review_id,
                object_id=object_id,
                decision=decision,
                note=note,
                fields_patch=fields_patch,
                analyst_id=analyst_id,
                ts=ts
            )
            
            record = result.single()
            
            # Also link to the reviewed object if it exists
            session.run("""
                MATCH (r:ReviewDecision {id: $review_id})
                MATCH (n) WHERE n.stix_id = $object_id
                CREATE (r)-[:REVIEWS]->(n)
            """, review_id=review_id, object_id=object_id)
            
            return {
                "review_id": review_id,
                "object_id": object_id,
                "decision": decision,
                "ts": ts
            }
    
    def record_object_decision(
        self,
        object_id: str,
        decision: str,
        note: Optional[str] = None,
        fields_patch: Optional[Dict[str, Any]] = None,
        analyst_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Record an object review decision.
        
        Similar to mapping decision but tagged as object review.
        """
        review_id = f"review--{uuid.uuid4()}"
        ts = datetime.utcnow().isoformat() + "Z"
        
        with self.driver.session() as session:
            # Create ReviewDecision node
            query = """
                CREATE (r:ReviewDecision {
                    id: $review_id,
                    object_id: $object_id,
                    decision: $decision,
                    note: $note,
                    fields_patch: $fields_patch,
                    analyst_id: $analyst_id,
                    ts: $ts,
                    review_type: 'object'
                })
                RETURN r.id as id, r.ts as ts
            """
            
            result = session.run(
                query,
                review_id=review_id,
                object_id=object_id,
                decision=decision,
                note=note,
                fields_patch=fields_patch,
                analyst_id=analyst_id,
                ts=ts
            )
            
            record = result.single()
            
            # Link to the reviewed object
            session.run("""
                MATCH (r:ReviewDecision {id: $review_id})
                MATCH (n) WHERE n.stix_id = $object_id
                CREATE (r)-[:REVIEWS]->(n)
            """, review_id=review_id, object_id=object_id)
            
            return {
                "review_id": review_id,
                "object_id": object_id,
                "decision": decision,
                "ts": ts
            }
    
    def get_object_with_provenance(self, object_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a STIX object with its provenance and relationships.
        
        Args:
            object_id: STIX ID to retrieve
            
        Returns:
            Object with provenance and relationships, or None if not found
        """
        with self.driver.session() as session:
            # Get the object and its source
            query = """
                MATCH (n)
                WHERE n.stix_id = $object_id
                OPTIONAL MATCH (n)-[:FROM_SOURCE]->(s:Source)
                RETURN n, s
            """
            
            result = session.run(query, object_id=object_id)
            record = result.single()
            
            if not record:
                return None
            
            node = dict(record["n"])
            source = dict(record["s"]) if record["s"] else {}
            
            # Get relationships where this object is source or target
            rel_query = """
                MATCH (n)
                WHERE n.stix_id = $object_id
                OPTIONAL MATCH (n)-[r:USES|MITIGATES|DETECTS]->(target)
                OPTIONAL MATCH (source)-[r2:USES|MITIGATES|DETECTS]->(n)
                RETURN 
                    collect(DISTINCT {
                        type: type(r),
                        target: target.stix_id,
                        target_name: target.name
                    }) as outgoing,
                    collect(DISTINCT {
                        type: type(r2),
                        source: source.stix_id,
                        source_name: source.name
                    }) as incoming
            """
            
            rel_result = session.run(rel_query, object_id=object_id)
            rel_record = rel_result.single()
            
            outgoing = [r for r in rel_record["outgoing"] if r["target"]]
            incoming = [r for r in rel_record["incoming"] if r["source"]]
            
            # Build response
            return {
                "object": self._build_stix_object(node),
                "provenance": {
                    "collection": source.get("collection"),
                    "version": source.get("version"),
                    "modified": source.get("modified"),
                    "url": source.get("url"),
                    "ingested": node.get("_ingested_at")
                },
                "relationships": outgoing + incoming
            }
    
    def _build_stix_object(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert Neo4j node to STIX object format."""
        # Map node type to STIX type
        type_mapping = {
            "AttackPattern": "attack-pattern",
            "IntrusionSet": "intrusion-set",
            "Software": "malware",  # or "tool" based on is_family
            "Mitigation": "course-of-action",
            "DataSource": "x-mitre-data-source",
            "Tactic": "x-mitre-tactic"
        }
        
        kb_type = node.get("kb_type", "")
        stix_type = type_mapping.get(kb_type, kb_type.lower())
        
        # Handle Software -> malware/tool distinction
        if kb_type == "Software" and not node.get("is_family", True):
            stix_type = "tool"
        
        obj = {
            "type": stix_type,
            "id": node.get("stix_id"),
            "spec_version": "2.1",
            "name": node.get("name"),
            "description": node.get("description")
        }
        
        # Add optional fields
        if node.get("created"):
            obj["created"] = node["created"]
        if node.get("modified"):
            obj["modified"] = node["modified"]
        if node.get("revoked"):
            obj["revoked"] = node["revoked"]
        if node.get("external_references"):
            obj["external_references"] = node["external_references"]
        
        # Add MITRE-specific fields
        if node.get("x_mitre_version"):
            obj["x_mitre_version"] = node["x_mitre_version"]
        if node.get("x_mitre_deprecated"):
            obj["x_mitre_deprecated"] = node["x_mitre_deprecated"]
        if node.get("x_mitre_platforms"):
            obj["x_mitre_platforms"] = node["x_mitre_platforms"]
        
        return obj
    
    def get_review_history(self, object_id: str) -> List[Dict[str, Any]]:
        """
        Get review history for an object.
        
        Args:
            object_id: STIX ID to get review history for
            
        Returns:
            List of review decisions
        """
        with self.driver.session() as session:
            query = """
                MATCH (r:ReviewDecision {object_id: $object_id})
                RETURN r
                ORDER BY r.ts DESC
            """
            
            result = session.run(query, object_id=object_id)
            
            reviews = []
            for record in result:
                review = dict(record["r"])
                reviews.append({
                    "review_id": review["id"],
                    "decision": review["decision"],
                    "note": review.get("note"),
                    "fields_patch": review.get("fields_patch"),
                    "analyst_id": review.get("analyst_id"),
                    "ts": review["ts"],
                    "review_type": review.get("review_type", "unknown")
                })
            
            return reviews
    
    def close(self):
        """Close the Neo4j driver connection."""
        self.driver.close()