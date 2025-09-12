"""Batch Neo4j query helpers for optimizing database operations."""

import logging
from typing import Dict, Any, List, Optional, Tuple, Set
from functools import lru_cache
import json

logger = logging.getLogger(__name__)


class BatchNeo4jHelper:
    """Helper class for batch Neo4j operations to reduce N+1 queries."""
    
    def __init__(self, driver):
        """
        Initialize batch helper.
        
        Args:
            driver: Neo4j driver instance
        """
        self.driver = driver
        self._technique_cache = {}  # Cache for technique metadata
        self._tactic_cache = {}     # Cache for tactic mappings
    
    def batch_get_technique_tactics(
        self, 
        technique_ids: List[str]
    ) -> Dict[str, List[str]]:
        """
        Get tactics for multiple techniques in a single query.
        
        Args:
            technique_ids: List of technique STIX IDs
            
        Returns:
            Dict mapping technique_id to list of tactic shortnames
        """
        if not technique_ids:
            return {}
        
        # Check cache first
        uncached = []
        results = {}
        for tech_id in technique_ids:
            if tech_id in self._tactic_cache:
                results[tech_id] = self._tactic_cache[tech_id]
            else:
                uncached.append(tech_id)
        
        if not uncached:
            return results
        
        # Batch query for uncached techniques
        with self.driver.session() as session:
            query_result = session.run(
                """
                UNWIND $technique_ids AS tech_id
                MATCH (t:AttackPattern {stix_id: tech_id})
                OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
                WITH tech_id, collect(DISTINCT tac.shortname) AS tactics
                WHERE size(tactics) > 0
                RETURN tech_id, tactics
                """,
                technique_ids=uncached
            )
            
            for record in query_result:
                tech_id = record["tech_id"]
                tactics = record["tactics"]
                results[tech_id] = tactics
                self._tactic_cache[tech_id] = tactics  # Cache for future use
        
        # Add empty lists for techniques not found
        for tech_id in uncached:
            if tech_id not in results:
                results[tech_id] = []
                self._tactic_cache[tech_id] = []
        
        return results
    
    def batch_get_technique_metadata(
        self,
        technique_ids: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get metadata for multiple techniques in a single query.
        
        Args:
            technique_ids: List of technique STIX IDs or external IDs
            
        Returns:
            Dict mapping technique_id to metadata dict
        """
        if not technique_ids:
            return {}
        
        # Separate STIX IDs from external IDs
        stix_ids = [tid for tid in technique_ids if tid.startswith("attack-pattern--")]
        ext_ids = [tid for tid in technique_ids if not tid.startswith("attack-pattern--")]
        
        results = {}
        
        with self.driver.session() as session:
            # Query for STIX IDs
            if stix_ids:
                query_result = session.run(
                    """
                    UNWIND $stix_ids AS stix_id
                    MATCH (t:AttackPattern {stix_id: stix_id})
                    OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
                    RETURN stix_id AS tech_id, 
                           t.name AS name,
                           t.description AS description,
                           t.external_id AS external_id,
                           collect(DISTINCT tac.shortname) AS tactics
                    """,
                    stix_ids=stix_ids
                )
                
                for record in query_result:
                    results[record["tech_id"]] = {
                        "name": record["name"],
                        "description": record["description"],
                        "external_id": record["external_id"],
                        "tactics": record["tactics"]
                    }
            
            # Query for external IDs
            if ext_ids:
                query_result = session.run(
                    """
                    UNWIND $ext_ids AS ext_id
                    MATCH (t:AttackPattern)
                    WHERE t.external_id = ext_id OR ext_id IN t.external_ids
                    OPTIONAL MATCH (t)-[:HAS_TACTIC]->(tac:Tactic)
                    RETURN ext_id AS tech_id,
                           t.stix_id AS stix_id,
                           t.name AS name,
                           t.description AS description,
                           collect(DISTINCT tac.shortname) AS tactics
                    LIMIT 1
                    """,
                    ext_ids=ext_ids
                )
                
                for record in query_result:
                    results[record["tech_id"]] = {
                        "stix_id": record["stix_id"],
                        "name": record["name"],
                        "description": record["description"],
                        "tactics": record["tactics"]
                    }
        
        return results
    
    def batch_check_adjacencies(
        self,
        technique_pairs: List[Tuple[str, str]]
    ) -> Dict[Tuple[str, str], int]:
        """
        Check historical adjacencies for multiple technique pairs.
        
        Args:
            technique_pairs: List of (source_id, target_id) tuples
            
        Returns:
            Dict mapping (source_id, target_id) to adjacency count
        """
        if not technique_pairs:
            return {}
        
        # Prepare data for query
        pairs_data = [
            {"source": pair[0], "target": pair[1]} 
            for pair in technique_pairs
        ]
        
        results = {}
        
        with self.driver.session() as session:
            query_result = session.run(
                """
                UNWIND $pairs AS pair
                MATCH (t1:AttackPattern {stix_id: pair.source})
                MATCH (t2:AttackPattern {stix_id: pair.target})
                OPTIONAL MATCH (t1)-[n:NEXT]-(t2)
                RETURN pair.source AS source, 
                       pair.target AS target,
                       count(n) AS adjacency_count
                """,
                pairs_data=pairs_data
            )
            
            for record in query_result:
                key = (record["source"], record["target"])
                results[key] = record["adjacency_count"]
        
        # Add zero counts for pairs not found
        for pair in technique_pairs:
            if pair not in results:
                results[pair] = 0
        
        return results
    
    def batch_create_attack_actions(
        self,
        episode_id: str,
        actions: List[Dict[str, Any]]
    ) -> bool:
        """
        Create multiple AttackAction nodes in a single query.
        
        Args:
            episode_id: Episode ID to link actions to
            actions: List of action dictionaries
            
        Returns:
            Success boolean
        """
        if not actions:
            return True
        
        # Prepare action data
        action_data = []
        for action in actions:
            action_data.append({
                "action_id": action["action_id"],
                "attack_pattern_ref": action.get("attack_pattern_ref", action.get("technique_id", "unknown")),
                "confidence": action.get("confidence", 50.0),
                "order": action.get("order", 0),
                "description": action.get("description", ""),
                "evidence": json.dumps(action.get("evidence", [])),
                "rationale": action.get("reason", "")
            })
        
        try:
            with self.driver.session() as session:
                session.run(
                    """
                    MATCH (e:AttackEpisode {episode_id: $episode_id})
                    UNWIND $actions AS action
                    CREATE (a:AttackAction {
                        action_id: action.action_id,
                        attack_pattern_ref: action.attack_pattern_ref,
                        confidence: action.confidence,
                        order: action.order,
                        description: action.description,
                        evidence: action.evidence,
                        rationale: action.rationale,
                        timestamp: datetime()
                    })
                    CREATE (e)-[:CONTAINS {order: action.order}]->(a)
                    WITH a, action
                    MATCH (t:AttackPattern {stix_id: action.attack_pattern_ref})
                    CREATE (a)-[:OF_TECHNIQUE]->(t)
                    """,
                    episode_id=episode_id,
                    actions=action_data
                )
                
                logger.info(f"[BatchNeo4j] Created {len(actions)} AttackActions in single query")
                return True
                
        except Exception as e:
            logger.error(f"[BatchNeo4j] Failed to batch create actions: {e}")
            return False
    
    def batch_create_next_edges(
        self,
        edges: List[Dict[str, Any]]
    ) -> bool:
        """
        Create multiple NEXT edges in a single query.
        
        Args:
            edges: List of edge dictionaries with source, target, probability, rationale
            
        Returns:
            Success boolean
        """
        if not edges:
            return True
        
        # Prepare edge data
        edge_data = []
        for edge in edges:
            edge_data.append({
                "source": edge["source"],
                "target": edge["target"],
                "probability": edge.get("probability", 0.5),
                "rationale": edge.get("rationale", "sequential")
            })
        
        try:
            with self.driver.session() as session:
                session.run(
                    """
                    UNWIND $edges AS edge
                    MATCH (a1:AttackAction {action_id: edge.source})
                    MATCH (a2:AttackAction {action_id: edge.target})
                    CREATE (a1)-[:NEXT {
                        p: edge.probability, 
                        rationale: edge.rationale
                    }]->(a2)
                    """,
                    edges=edge_data
                )
                
                logger.info(f"[BatchNeo4j] Created {len(edges)} NEXT edges in single query")
                return True
                
        except Exception as e:
            logger.error(f"[BatchNeo4j] Failed to batch create edges: {e}")
            return False
    
    def batch_get_tactic_alignments(
        self,
        technique_pairs: List[Tuple[str, str]]
    ) -> Dict[Tuple[str, str], Dict[str, Any]]:
        """
        Get tactic alignment information for multiple technique pairs.
        
        Args:
            technique_pairs: List of (source_id, target_id) tuples
            
        Returns:
            Dict mapping pairs to tactic alignment info
        """
        if not technique_pairs:
            return {}
        
        # Prepare pairs for query
        pairs_data = [
            {"source": pair[0], "target": pair[1]} 
            for pair in technique_pairs
        ]
        
        results = {}
        
        with self.driver.session() as session:
            query_result = session.run(
                """
                UNWIND $pairs AS pair
                MATCH (t1:AttackPattern {stix_id: pair.source})
                MATCH (t2:AttackPattern {stix_id: pair.target})
                OPTIONAL MATCH (t1)-[:HAS_TACTIC]->(tac1:Tactic)
                OPTIONAL MATCH (t2)-[:HAS_TACTIC]->(tac2:Tactic)
                WITH pair.source AS source,
                     pair.target AS target,
                     collect(DISTINCT tac1.shortname) AS tactics1,
                     collect(DISTINCT tac2.shortname) AS tactics2
                RETURN source, target, tactics1, tactics2,
                       size([t IN tactics1 WHERE t IN tactics2]) > 0 AS same_tactic
                """,
                pairs_data=pairs_data
            )
            
            for record in query_result:
                key = (record["source"], record["target"])
                results[key] = {
                    "source_tactics": record["tactics1"],
                    "target_tactics": record["tactics2"],
                    "same_tactic": record["same_tactic"]
                }
        
        return results
    
    def clear_cache(self):
        """Clear all cached data."""
        self._technique_cache.clear()
        self._tactic_cache.clear()
        logger.info("[BatchNeo4j] Caches cleared")
    
    @lru_cache(maxsize=1000)
    def get_tactic_order(self, tactic: str) -> int:
        """
        Get numeric order for a tactic (cached).
        
        Args:
            tactic: Tactic shortname
            
        Returns:
            Numeric order (1-14) or 7 for unknown
        """
        tactic_order = {
            "reconnaissance": 1, "resource-development": 2,
            "initial-access": 3, "execution": 4,
            "persistence": 5, "privilege-escalation": 6,
            "defense-evasion": 7, "credential-access": 8,
            "discovery": 9, "lateral-movement": 10,
            "collection": 11, "command-and-control": 12,
            "exfiltration": 13, "impact": 14
        }
        return tactic_order.get(tactic, 7)