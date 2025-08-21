"""Candidate node management for review queue."""

from typing import List, Dict, Any, Optional, Literal
from datetime import datetime
import uuid
import json
from neo4j import GraphDatabase


class CandidateStore:
    """Manage candidate nodes pending review before graph merge."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize candidate store with Neo4j connection.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
    
    def create_candidate(
        self,
        stix_object: Dict[str, Any],
        source_report: str,
        extraction_metadata: Dict[str, Any],
        auto_approve_threshold: float = 95.0
    ) -> str:
        """
        Create a candidate node from extracted data.
        
        Args:
            stix_object: STIX object to store as candidate
            source_report: Source report ID
            extraction_metadata: Extraction method, model, confidence
            auto_approve_threshold: Confidence threshold for auto-approval
            
        Returns:
            Candidate ID
        """
        candidate_id = f"candidate--{uuid.uuid4()}"
        
        # Check confidence for auto-approval
        confidence = extraction_metadata.get("confidence", 0)
        if confidence >= auto_approve_threshold:
            status = "auto_approved"
        else:
            status = "pending"
        
        with self.driver.session() as session:
            query = """
                CREATE (c:CandidateNode {
                    id: $candidate_id,
                    stix_id: $stix_id,
                    type: $type,
                    name: $name,
                    description: $description,
                    source_report: $source_report,
                    extraction_method: $method,
                    extraction_model: $model,
                    extraction_confidence: $confidence,
                    status: $status,
                    created_at: datetime(),
                    stix_object: $stix_object_json,
                    provenance: $provenance_json
                })
                RETURN c.id as id
            """
            
            result = session.run(
                query,
                candidate_id=candidate_id,
                stix_id=stix_object.get("id"),
                type=stix_object.get("type"),
                name=stix_object.get("name", ""),
                description=stix_object.get("description", ""),
                source_report=source_report,
                method=extraction_metadata.get("method", "unknown"),
                model=extraction_metadata.get("model", "unknown"),
                confidence=confidence,
                status=status,
                stix_object_json=json.dumps(stix_object),
                provenance_json=json.dumps(extraction_metadata.get("provenance", {}))
            )
            
            record = result.single()
            return record["id"] if record else candidate_id
    
    def get_queue(
        self,
        status: Optional[str] = None,
        entity_type: Optional[str] = None,
        min_confidence: Optional[float] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get candidates from the review queue.
        
        Args:
            status: Filter by status (pending, under_review, etc.)
            entity_type: Filter by STIX type
            min_confidence: Minimum confidence threshold
            limit: Maximum results
            offset: Pagination offset
            
        Returns:
            List of candidate objects
        """
        with self.driver.session() as session:
            # Build query with filters
            where_clauses = ["c:CandidateNode"]
            params = {"limit": limit, "offset": offset}
            
            if status:
                where_clauses.append("c.status = $status")
                params["status"] = status
            
            if entity_type:
                where_clauses.append("c.type = $entity_type")
                params["entity_type"] = entity_type
            
            if min_confidence is not None:
                where_clauses.append("c.extraction_confidence >= $min_confidence")
                params["min_confidence"] = min_confidence
            
            where_clause = " AND ".join(where_clauses)
            
            query = f"""
                MATCH (c)
                WHERE {where_clause}
                RETURN c
                ORDER BY c.created_at DESC
                SKIP $offset
                LIMIT $limit
            """
            
            result = session.run(query, **params)
            
            candidates = []
            for record in result:
                candidate = dict(record["c"])
                
                # Parse JSON fields
                if candidate.get("stix_object"):
                    try:
                        candidate["stix_object"] = json.loads(candidate["stix_object"])
                    except:
                        pass
                
                if candidate.get("provenance"):
                    try:
                        candidate["provenance"] = json.loads(candidate["provenance"])
                    except:
                        pass
                
                candidates.append(candidate)
            
            return candidates
    
    def get_candidate(self, candidate_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific candidate by ID.
        
        Args:
            candidate_id: Candidate ID
            
        Returns:
            Candidate object or None
        """
        with self.driver.session() as session:
            query = """
                MATCH (c:CandidateNode {id: $candidate_id})
                RETURN c
            """
            
            result = session.run(query, candidate_id=candidate_id)
            record = result.single()
            
            if record:
                candidate = dict(record["c"])
                
                # Parse JSON fields
                if candidate.get("stix_object"):
                    try:
                        candidate["stix_object"] = json.loads(candidate["stix_object"])
                    except:
                        pass
                
                if candidate.get("provenance"):
                    try:
                        candidate["provenance"] = json.loads(candidate["provenance"])
                    except:
                        pass
                
                return candidate
            
            return None
    
    def update_status(
        self,
        candidate_id: str,
        status: Literal["pending", "under_review", "approved", "rejected"],
        reviewer_id: Optional[str] = None,
        reason: Optional[str] = None
    ) -> bool:
        """
        Update candidate status.
        
        Args:
            candidate_id: Candidate ID
            status: New status
            reviewer_id: ID of reviewer
            reason: Reason for decision
            
        Returns:
            Success boolean
        """
        with self.driver.session() as session:
            query = """
                MATCH (c:CandidateNode {id: $candidate_id})
                SET c.status = $status,
                    c.reviewed_at = datetime(),
                    c.reviewed_by = $reviewer_id,
                    c.review_reason = $reason
                RETURN c.id as id
            """
            
            result = session.run(
                query,
                candidate_id=candidate_id,
                status=status,
                reviewer_id=reviewer_id,
                reason=reason
            )
            
            return result.single() is not None
    
    def approve_candidate(
        self,
        candidate_id: str,
        reviewer_id: str,
        merge_to_graph: bool = True
    ) -> Dict[str, Any]:
        """
        Approve a candidate and optionally merge to main graph.
        
        Args:
            candidate_id: Candidate ID
            reviewer_id: Reviewer ID
            merge_to_graph: Whether to merge to main graph
            
        Returns:
            Result with merged node ID if applicable
        """
        candidate = self.get_candidate(candidate_id)
        if not candidate:
            raise ValueError(f"Candidate {candidate_id} not found")
        
        # Update status
        self.update_status(candidate_id, "approved", reviewer_id)
        
        result = {
            "candidate_id": candidate_id,
            "status": "approved",
            "merged": False
        }
        
        if merge_to_graph:
            # Convert CandidateNode to proper node type
            stix_object = candidate.get("stix_object", {})
            stix_type = stix_object.get("type", "")
            
            # Map STIX type to Neo4j label
            label_map = {
                "attack-pattern": "AttackPattern",
                "intrusion-set": "IntrusionSet",
                "malware": "Software",
                "tool": "Software",
                "indicator": "Indicator",
                "vulnerability": "Vulnerability"
            }
            
            node_label = label_map.get(stix_type, "Entity")
            
            with self.driver.session() as session:
                # Create the actual node
                merge_query = f"""
                    MATCH (c:CandidateNode {{id: $candidate_id}})
                    MERGE (n:{node_label} {{stix_id: $stix_id}})
                    ON CREATE SET 
                        n.type = $type,
                        n.name = $name,
                        n.description = $description,
                        n.created_ts = timestamp(),
                        n.source_report = $source_report,
                        n.extraction_confidence = $confidence
                    SET n.approved_from_candidate = $candidate_id,
                        n.approved_by = $reviewer_id,
                        n.approved_at = datetime()
                    WITH n, c
                    // Link to source report if exists
                    OPTIONAL MATCH (r:Report {{stix_id: $source_report}})
                    FOREACH (_ IN CASE WHEN r IS NOT NULL THEN [1] ELSE [] END |
                        MERGE (n)-[:EXTRACTED_FROM]->(r)
                    )
                    // Remove candidate label but keep for audit
                    REMOVE c:CandidateNode
                    SET c:ReviewedCandidate
                    RETURN n.stix_id as merged_id
                """
                
                merge_result = session.run(
                    merge_query,
                    candidate_id=candidate_id,
                    stix_id=stix_object.get("id"),
                    type=stix_type,
                    name=stix_object.get("name", ""),
                    description=stix_object.get("description", ""),
                    source_report=candidate.get("source_report"),
                    confidence=candidate.get("extraction_confidence", 0),
                    reviewer_id=reviewer_id
                )
                
                merge_record = merge_result.single()
                if merge_record:
                    result["merged"] = True
                    result["merged_stix_id"] = merge_record["merged_id"]
        
        return result
    
    def reject_candidate(
        self,
        candidate_id: str,
        reviewer_id: str,
        reason: str
    ) -> Dict[str, Any]:
        """
        Reject a candidate with reason.
        
        Args:
            candidate_id: Candidate ID
            reviewer_id: Reviewer ID
            reason: Rejection reason
            
        Returns:
            Result dictionary
        """
        # Update status
        success = self.update_status(
            candidate_id,
            "rejected",
            reviewer_id,
            reason
        )
        
        if success:
            # Move to rejected archive
            with self.driver.session() as session:
                query = """
                    MATCH (c:CandidateNode {id: $candidate_id})
                    REMOVE c:CandidateNode
                    SET c:RejectedCandidate
                    RETURN c.id as id
                """
                
                session.run(query, candidate_id=candidate_id)
            
            return {
                "candidate_id": candidate_id,
                "status": "rejected",
                "reason": reason
            }
        else:
            raise ValueError(f"Failed to reject candidate {candidate_id}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get review queue statistics.
        
        Returns:
            Statistics dictionary
        """
        with self.driver.session() as session:
            # Count by status
            status_query = """
                MATCH (c:CandidateNode)
                RETURN c.status as status, count(*) as count
            """
            
            status_result = session.run(status_query)
            status_counts = {}
            for record in status_result:
                status_counts[record["status"]] = record["count"]
            
            # Count by type
            type_query = """
                MATCH (c:CandidateNode)
                RETURN c.type as type, count(*) as count
                ORDER BY count DESC
            """
            
            type_result = session.run(type_query)
            type_counts = {}
            for record in type_result:
                type_counts[record["type"]] = record["count"]
            
            # Average confidence by status
            confidence_query = """
                MATCH (c:CandidateNode)
                RETURN c.status as status, 
                       avg(c.extraction_confidence) as avg_confidence,
                       min(c.extraction_confidence) as min_confidence,
                       max(c.extraction_confidence) as max_confidence
            """
            
            confidence_result = session.run(confidence_query)
            confidence_stats = {}
            for record in confidence_result:
                confidence_stats[record["status"]] = {
                    "avg": record["avg_confidence"],
                    "min": record["min_confidence"],
                    "max": record["max_confidence"]
                }
            
            # Recent activity
            recent_query = """
                MATCH (c:CandidateNode)
                WHERE c.created_at > datetime() - duration('P1D')
                RETURN count(*) as recent_count
            """
            
            recent_result = session.run(recent_query)
            recent_count = recent_result.single()["recent_count"]
            
            return {
                "total_candidates": sum(status_counts.values()),
                "by_status": status_counts,
                "by_type": type_counts,
                "confidence_stats": confidence_stats,
                "recent_24h": recent_count,
                "pending_review": status_counts.get("pending", 0),
                "auto_approved": status_counts.get("auto_approved", 0)
            }
    
    def batch_approve(
        self,
        candidate_ids: List[str],
        reviewer_id: str,
        merge_to_graph: bool = True
    ) -> Dict[str, Any]:
        """
        Approve multiple candidates in batch.
        
        Args:
            candidate_ids: List of candidate IDs
            reviewer_id: Reviewer ID
            merge_to_graph: Whether to merge to graph
            
        Returns:
            Batch operation results
        """
        results = {
            "approved": [],
            "failed": [],
            "merged": []
        }
        
        for candidate_id in candidate_ids:
            try:
                result = self.approve_candidate(
                    candidate_id,
                    reviewer_id,
                    merge_to_graph
                )
                results["approved"].append(candidate_id)
                if result.get("merged"):
                    results["merged"].append(result.get("merged_stix_id"))
            except Exception as e:
                results["failed"].append({
                    "candidate_id": candidate_id,
                    "error": str(e)
                })
        
        return results
    
    def create_candidate_attack_pattern(
        self,
        name: str,
        description: str,
        source_text: str,
        source_report: str,
        extraction_metadata: Dict[str, Any],
        embedding: Optional[List[float]] = None
    ) -> str:
        """
        Create a candidate attack pattern for a potentially novel technique.
        
        Args:
            name: Technique name
            description: Technique description
            source_text: Original text that led to this extraction
            source_report: Source report ID
            extraction_metadata: Extraction method, model, confidence
            embedding: Optional pre-computed embedding vector
            
        Returns:
            Candidate pattern ID
        """
        candidate_id = f"candidate-pattern--{uuid.uuid4()}"
        
        with self.driver.session() as session:
            query = """
                CREATE (c:CandidateAttackPattern {
                    candidate_id: $candidate_id,
                    name: $name,
                    description: $description,
                    source_text: $source_text,
                    source_report: $source_report,
                    extraction_method: $extraction_method,
                    extraction_model: $extraction_model,
                    confidence: $confidence,
                    status: 'pending',
                    created_at: datetime()
                })
                RETURN c.candidate_id as id
            """
            
            result = session.run(
                query,
                candidate_id=candidate_id,
                name=name,
                description=description,
                source_text=source_text[:1000],  # Limit source text length
                source_report=source_report,
                extraction_method=extraction_metadata.get("method", "unknown"),
                extraction_model=extraction_metadata.get("model", "unknown"),
                confidence=extraction_metadata.get("confidence", 50.0)
            )
            
            if result.single():
                # Store embedding if provided
                if embedding:
                    self._store_candidate_embedding(candidate_id, embedding)
                
                return candidate_id
            
            raise ValueError("Failed to create candidate attack pattern")
    
    def _store_candidate_embedding(self, candidate_id: str, embedding: List[float]):
        """Store embedding for candidate pattern."""
        # In production, would store in OpenSearch
        # For now, store as property (limited by Neo4j property size)
        with self.driver.session() as session:
            session.run(
                """
                MATCH (c:CandidateAttackPattern {candidate_id: $candidate_id})
                SET c.has_embedding = true,
                    c.embedding_dim = $dim
                """,
                candidate_id=candidate_id,
                dim=len(embedding)
            )
    
    def get_candidate_patterns(
        self,
        status: Optional[str] = None,
        min_confidence: Optional[float] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get candidate attack patterns for review.
        
        Args:
            status: Filter by status
            min_confidence: Minimum confidence threshold
            limit: Maximum results
            
        Returns:
            List of candidate patterns
        """
        with self.driver.session() as session:
            where_clauses = []
            params = {"limit": limit}
            
            if status:
                where_clauses.append("c.status = $status")
                params["status"] = status
            
            if min_confidence:
                where_clauses.append("c.confidence >= $min_confidence")
                params["min_confidence"] = min_confidence
            
            where_clause = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            
            query = f"""
                MATCH (c:CandidateAttackPattern)
                {where_clause}
                RETURN c.candidate_id as id,
                       c.name as name,
                       c.description as description,
                       c.source_text as source_text,
                       c.source_report as source_report,
                       c.confidence as confidence,
                       c.status as status,
                       c.created_at as created_at,
                       c.reviewed_by as reviewed_by,
                       c.has_embedding as has_embedding
                ORDER BY c.confidence DESC, c.created_at DESC
                LIMIT $limit
            """
            
            result = session.run(query, **params)
            
            patterns = []
            for record in result:
                patterns.append({
                    "id": record["id"],
                    "name": record["name"],
                    "description": record["description"],
                    "source_text": record["source_text"],
                    "source_report": record["source_report"],
                    "confidence": record["confidence"],
                    "status": record["status"],
                    "created_at": record["created_at"].isoformat() if record["created_at"] else None,
                    "reviewed_by": record["reviewed_by"],
                    "has_embedding": record["has_embedding"] or False
                })
            
            return patterns
    
    def promote_candidate_pattern(
        self,
        candidate_id: str,
        reviewer_id: str,
        attack_id: Optional[str] = None,
        external_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Promote a candidate pattern to a full AttackPattern.
        
        Args:
            candidate_id: Candidate pattern ID
            reviewer_id: Reviewer ID
            attack_id: Optional STIX ID to assign
            external_id: Optional MITRE ID (e.g., T1234.001)
            
        Returns:
            Promotion result
        """
        with self.driver.session() as session:
            # Get candidate details
            get_query = """
                MATCH (c:CandidateAttackPattern {candidate_id: $candidate_id})
                RETURN c
            """
            
            result = session.run(get_query, candidate_id=candidate_id)
            candidate = result.single()
            
            if not candidate:
                raise ValueError(f"Candidate pattern {candidate_id} not found")
            
            # Generate or use provided STIX ID
            if not attack_id:
                attack_id = f"attack-pattern--{uuid.uuid4()}"
            
            # Create AttackPattern node
            create_query = """
                MATCH (c:CandidateAttackPattern {candidate_id: $candidate_id})
                CREATE (a:AttackPattern {
                    stix_id: $attack_id,
                    name: c.name,
                    description: c.description,
                    type: 'attack-pattern',
                    created: datetime(),
                    modified: datetime(),
                    x_mitre_version: '1.0',
                    x_bj_novel: true,
                    x_bj_promoted_from: $candidate_id,
                    x_bj_promoted_by: $reviewer_id,
                    x_bj_confidence: c.confidence
                })
                WITH a, c
                // Link to source report if exists
                OPTIONAL MATCH (r:Report {stix_id: c.source_report})
                FOREACH (_ IN CASE WHEN r IS NOT NULL THEN [1] ELSE [] END |
                    MERGE (a)-[:EXTRACTED_FROM]->(r)
                )
                // Update candidate status
                SET c.status = 'promoted',
                    c.promoted_to = $attack_id,
                    c.reviewed_by = $reviewer_id,
                    c.reviewed_at = datetime()
                RETURN a.stix_id as attack_id, a.name as name
            """
            
            # Add external ID if provided
            if external_id:
                create_query = create_query.replace(
                    "x_bj_confidence: c.confidence",
                    f"x_bj_confidence: c.confidence, external_id: '{external_id}'"
                )
            
            promote_result = session.run(
                create_query,
                candidate_id=candidate_id,
                attack_id=attack_id,
                reviewer_id=reviewer_id
            )
            
            promoted = promote_result.single()
            
            if promoted:
                return {
                    "success": True,
                    "candidate_id": candidate_id,
                    "attack_id": promoted["attack_id"],
                    "name": promoted["name"],
                    "status": "promoted"
                }
            
            raise ValueError("Failed to promote candidate pattern")
    
    def find_similar_patterns(
        self,
        candidate_id: str,
        threshold: float = 0.8
    ) -> List[Dict[str, Any]]:
        """
        Find existing attack patterns similar to a candidate.
        
        Args:
            candidate_id: Candidate pattern ID
            threshold: Similarity threshold (0-1)
            
        Returns:
            List of similar patterns with scores
        """
        with self.driver.session() as session:
            # Get candidate details
            candidate_query = """
                MATCH (c:CandidateAttackPattern {candidate_id: $candidate_id})
                RETURN c.name as name, c.description as description
            """
            
            result = session.run(candidate_query, candidate_id=candidate_id)
            candidate = result.single()
            
            if not candidate:
                return []
            
            # Search for similar patterns by name/description overlap
            # In production, would use vector similarity
            similarity_query = """
                MATCH (c:CandidateAttackPattern {candidate_id: $candidate_id})
                MATCH (a:AttackPattern)
                WHERE (toLower(a.name) CONTAINS toLower($search_term) OR
                       toLower(a.description) CONTAINS toLower($search_term))
                RETURN a.stix_id as id,
                       a.name as name,
                       a.description as description,
                       a.external_id as external_id
                LIMIT 10
            """
            
            # Simple keyword search for now
            search_term = candidate["name"].split()[0] if candidate["name"] else ""
            
            similar_result = session.run(
                similarity_query,
                candidate_id=candidate_id,
                search_term=search_term
            )
            
            similar = []
            for record in similar_result:
                # Calculate simple similarity score
                name_match = search_term.lower() in record["name"].lower()
                desc_match = search_term.lower() in (record["description"] or "").lower()
                score = (1.0 if name_match else 0.5) * (1.0 if desc_match else 0.8)
                
                if score >= threshold:
                    similar.append({
                        "id": record["id"],
                        "name": record["name"],
                        "description": record["description"][:200] + "..." 
                                    if len(record["description"] or "") > 200 
                                    else record["description"],
                        "external_id": record["external_id"],
                        "similarity_score": round(score, 2)
                    })
            
            return sorted(similar, key=lambda x: x["similarity_score"], reverse=True)
    
    def close(self):
        """Close the Neo4j connection."""
        if self.driver:
            self.driver.close()