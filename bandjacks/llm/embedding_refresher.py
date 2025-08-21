"""Embedding refresh and cache management for active learning updates."""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
import json
import hashlib
from neo4j import GraphDatabase
import httpx

from ..config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class EmbeddingRefresher:
    """Manages embedding updates and cache invalidation after reviews/retraining."""
    
    def __init__(
        self,
        neo4j_uri: str,
        neo4j_user: str,
        neo4j_password: str,
        opensearch_url: str,
        batch_size: int = 100
    ):
        """
        Initialize embedding refresher.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            opensearch_url: OpenSearch URL
            batch_size: Batch size for updates
        """
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
        self.opensearch_url = opensearch_url
        self.batch_size = batch_size
        self._cache_invalidation_set: Set[str] = set()
    
    async def refresh_node_embeddings(
        self,
        refresh_id: str,
        node_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Refresh embeddings for nodes marked for refresh.
        
        Args:
            refresh_id: Refresh job ID
            node_types: Specific node types to refresh
            
        Returns:
            Refresh results
        """
        logger.info(f"Starting embedding refresh job {refresh_id}")
        
        # Default node types if not specified
        if not node_types:
            node_types = ["AttackPattern", "DetectionStrategy", "Analytic", "AttackEpisode"]
        
        total_refreshed = 0
        errors = []
        
        for node_type in node_types:
            try:
                count = await self._refresh_node_type(refresh_id, node_type)
                total_refreshed += count
                logger.info(f"Refreshed {count} embeddings for {node_type}")
            except Exception as e:
                logger.error(f"Failed to refresh {node_type}: {e}")
                errors.append({"node_type": node_type, "error": str(e)})
        
        # Invalidate caches
        await self._invalidate_caches()
        
        return {
            "refresh_id": refresh_id,
            "total_refreshed": total_refreshed,
            "node_types": node_types,
            "errors": errors,
            "cache_invalidated": len(self._cache_invalidation_set),
            "status": "completed" if not errors else "partial",
            "completed_at": datetime.utcnow().isoformat()
        }
    
    async def _refresh_node_type(self, refresh_id: str, node_type: str) -> int:
        """Refresh embeddings for a specific node type."""
        with self.driver.session() as session:
            # Get nodes needing refresh
            query = f"""
                MATCH (n:{node_type})
                WHERE n.needs_embedding_refresh = true
                    AND (n.refresh_id = $refresh_id OR n.refresh_id IS NULL)
                RETURN n.stix_id as id, n.name as name, n.description as description,
                       n.type as type, properties(n) as props
                LIMIT $batch_size
            """
            
            total_refreshed = 0
            
            while True:
                result = session.run(
                    query,
                    refresh_id=refresh_id,
                    batch_size=self.batch_size
                )
                
                nodes = list(result)
                if not nodes:
                    break
                
                # Generate new embeddings
                embeddings = await self._generate_embeddings(nodes)
                
                # Update OpenSearch
                await self._update_opensearch_embeddings(node_type, embeddings)
                
                # Mark nodes as refreshed
                update_query = f"""
                    UNWIND $node_ids as node_id
                    MATCH (n:{node_type})
                    WHERE n.stix_id = node_id
                    SET n.needs_embedding_refresh = false,
                        n.embedding_updated = datetime(),
                        n.last_refresh_id = $refresh_id
                """
                
                session.run(
                    update_query,
                    node_ids=[n["id"] for n in nodes],
                    refresh_id=refresh_id
                )
                
                # Add to cache invalidation set
                for node in nodes:
                    self._cache_invalidation_set.add(node["id"])
                
                total_refreshed += len(nodes)
            
            return total_refreshed
    
    async def _generate_embeddings(self, nodes: List[Dict]) -> List[Dict[str, Any]]:
        """Generate embeddings for nodes."""
        embeddings = []
        
        for node in nodes:
            # Create text for embedding
            text_parts = [
                node.get("name", ""),
                node.get("description", "")
            ]
            
            # Add relevant properties
            props = node.get("props", {})
            if "kill_chain_phases" in props:
                text_parts.append(f"Tactics: {props['kill_chain_phases']}")
            if "x_mitre_platforms" in props:
                text_parts.append(f"Platforms: {props['x_mitre_platforms']}")
            
            text = " ".join(filter(None, text_parts))
            
            # Generate embedding (placeholder - would use actual embedding model)
            embedding_vector = self._generate_embedding_vector(text)
            
            embeddings.append({
                "id": node["id"],
                "name": node.get("name"),
                "embedding": embedding_vector,
                "text": text,
                "updated_at": datetime.utcnow().isoformat()
            })
        
        return embeddings
    
    def _generate_embedding_vector(self, text: str) -> List[float]:
        """Generate embedding vector for text."""
        # Placeholder - would use actual embedding model
        # For now, generate deterministic fake embedding
        import hashlib
        import struct
        
        hash_obj = hashlib.sha256(text.encode())
        hash_bytes = hash_obj.digest()
        
        # Convert to 768-dim vector (typical for sentence transformers)
        vector = []
        for i in range(0, min(768 * 4, len(hash_bytes)), 4):
            if i + 4 <= len(hash_bytes):
                value = struct.unpack('>f', hash_bytes[i:i+4])[0]
            else:
                value = 0.0
            vector.append(value)
        
        # Pad to 768 dimensions
        while len(vector) < 768:
            vector.append(0.0)
        
        return vector[:768]
    
    async def _update_opensearch_embeddings(
        self,
        node_type: str,
        embeddings: List[Dict[str, Any]]
    ):
        """Update embeddings in OpenSearch."""
        # Determine index based on node type
        index_map = {
            "AttackPattern": "attack_nodes",
            "DetectionStrategy": "detection_strategies",
            "Analytic": "analytics",
            "AttackEpisode": "attack_flows"
        }
        
        index = index_map.get(node_type, "attack_nodes")
        
        async with httpx.AsyncClient() as client:
            for embedding in embeddings:
                try:
                    # Update document in OpenSearch
                    response = await client.post(
                        f"{self.opensearch_url}/{index}/_update/{embedding['id']}",
                        json={
                            "doc": {
                                "embedding": embedding["embedding"],
                                "name": embedding["name"],
                                "text": embedding["text"],
                                "embedding_updated": embedding["updated_at"]
                            },
                            "doc_as_upsert": True
                        },
                        headers={"Content-Type": "application/json"}
                    )
                    
                    if response.status_code >= 400:
                        logger.warning(f"Failed to update {embedding['id']}: {response.text}")
                        
                except Exception as e:
                    logger.error(f"Error updating embedding for {embedding['id']}: {e}")
    
    async def _invalidate_caches(self):
        """Invalidate caches for updated embeddings."""
        if not self._cache_invalidation_set:
            return
        
        logger.info(f"Invalidating cache for {len(self._cache_invalidation_set)} items")
        
        # Clear local cache entries
        self._cache_invalidation_set.clear()
        
        # Would also invalidate any external caches (Redis, etc.)
    
    async def refresh_after_review(
        self,
        review_decision: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Refresh embeddings after a review decision.
        
        Args:
            review_decision: Review decision details
            
        Returns:
            Refresh results
        """
        item_id = review_decision.get("item_id")
        item_type = review_decision.get("item_type")
        decision = review_decision.get("decision")
        
        if decision in ["accept", "edit"]:
            # Mark item for embedding refresh
            with self.driver.session() as session:
                query = """
                    MATCH (n)
                    WHERE n.stix_id = $item_id OR n.candidate_id = $item_id
                    SET n.needs_embedding_refresh = true,
                        n.review_updated = datetime()
                    RETURN n.stix_id as id
                """
                
                result = session.run(query, item_id=item_id)
                record = result.single()
                
                if record:
                    # Trigger immediate refresh for this item
                    refresh_id = f"review-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
                    return await self.refresh_node_embeddings(
                        refresh_id=refresh_id,
                        node_types=[item_type] if item_type else None
                    )
        
        return {"status": "no_refresh_needed", "decision": decision}
    
    async def refresh_after_retrain(
        self,
        retrain_job_id: str
    ) -> Dict[str, Any]:
        """
        Refresh embeddings after model retraining.
        
        Args:
            retrain_job_id: Retrain job ID
            
        Returns:
            Refresh results
        """
        with self.driver.session() as session:
            # Mark all items from retrain job for refresh
            query = """
                MATCH (r:RetrainJob {job_id: $job_id})
                MATCH (i:RetrainItem {retrain_job_id: $job_id})
                MATCH (n)
                WHERE n.stix_id = i.item_id OR n.candidate_id = i.item_id
                SET n.needs_embedding_refresh = true,
                    n.retrain_updated = datetime()
                WITH count(n) as marked_count
                RETURN marked_count
            """
            
            result = session.run(query, job_id=retrain_job_id)
            record = result.single()
            
            if record and record["marked_count"] > 0:
                # Trigger refresh for all marked items
                refresh_id = f"retrain-{retrain_job_id}"
                return await self.refresh_node_embeddings(refresh_id=refresh_id)
        
        return {"status": "no_items_to_refresh", "retrain_job_id": retrain_job_id}
    
    def close(self):
        """Close database connection."""
        if self.driver:
            self.driver.close()


# Singleton instance
_embedding_refresher = None


def get_embedding_refresher() -> EmbeddingRefresher:
    """Get or create embedding refresher singleton."""
    global _embedding_refresher
    if _embedding_refresher is None:
        _embedding_refresher = EmbeddingRefresher(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password,
            opensearch_url=settings.opensearch_url
        )
    return _embedding_refresher