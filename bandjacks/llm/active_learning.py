"""Active learning and uncertainty management for model improvement."""

import json
import logging
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from neo4j import GraphDatabase
import numpy as np
from .embedding_refresher import get_embedding_refresher
from ..services.cache_manager import invalidate_caches_for_item

logger = logging.getLogger(__name__)


class ActiveLearningManager:
    """Manages uncertainty queue and active learning workflows."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize active learning manager.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
    
    def add_to_uncertainty_queue(
        self,
        item_type: str,
        item_id: str,
        confidence: float,
        source_context: Dict[str, Any],
        proposed_value: Any,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Add an item to the uncertainty queue.
        
        Args:
            item_type: Type of item (flow_edge, mapping, extraction, detection)
            item_id: Unique identifier for the item
            confidence: Confidence score (0-1)
            source_context: Context about the source
            proposed_value: The proposed value/decision
            metadata: Additional metadata
            
        Returns:
            Queue item ID
        """
        with self.driver.session() as session:
            queue_id = f"queue-{hashlib.md5(f'{item_type}-{item_id}'.encode()).hexdigest()[:12]}"
            
            query = """
                MERGE (q:UncertaintyQueue {queue_id: $queue_id})
                SET q.item_type = $item_type,
                    q.item_id = $item_id,
                    q.confidence = $confidence,
                    q.source_context = $source_context,
                    q.proposed_value = $proposed_value,
                    q.metadata = $metadata,
                    q.created = coalesce(q.created, datetime()),
                    q.updated = datetime(),
                    q.status = 'pending',
                    q.priority = $priority
                RETURN q
            """
            
            # Calculate priority (lower confidence = higher priority)
            priority = (1 - confidence) * 100
            if confidence < 0.5:
                priority *= 2  # Double priority for very low confidence
            
            session.run(
                query,
                queue_id=queue_id,
                item_type=item_type,
                item_id=item_id,
                confidence=confidence,
                source_context=json.dumps(source_context),
                proposed_value=json.dumps(proposed_value) if not isinstance(proposed_value, str) else proposed_value,
                metadata=json.dumps(metadata) if metadata else None,
                priority=priority
            )
            
            logger.info(f"Added {item_type} to uncertainty queue with confidence {confidence:.2f}")
            return queue_id
    
    def get_items_for_review(
        self,
        item_type: Optional[str] = None,
        confidence_threshold: float = 0.7,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Get items from uncertainty queue that need review.
        
        Args:
            item_type: Filter by item type
            confidence_threshold: Maximum confidence to include
            limit: Maximum items to return
            
        Returns:
            List of items needing review
        """
        with self.driver.session() as session:
            type_filter = "AND q.item_type = $item_type" if item_type else ""
            
            query = f"""
                MATCH (q:UncertaintyQueue)
                WHERE q.status = 'pending' 
                    AND q.confidence < $threshold
                    {type_filter}
                RETURN q {{
                    .*,
                    age_hours: duration.inHours(q.created, datetime()).hours
                }}
                ORDER BY q.priority DESC, q.created
                LIMIT $limit
            """
            
            params = {
                "threshold": confidence_threshold,
                "limit": limit
            }
            if item_type:
                params["item_type"] = item_type
            
            result = session.run(query, **params)
            
            items = []
            for record in result:
                item = dict(record["q"])
                # Parse JSON fields
                if item.get("source_context"):
                    item["source_context"] = json.loads(item["source_context"])
                if item.get("proposed_value") and item["proposed_value"].startswith("{"):
                    try:
                        item["proposed_value"] = json.loads(item["proposed_value"])
                    except:
                        pass
                if item.get("metadata"):
                    item["metadata"] = json.loads(item["metadata"])
                items.append(item)
            
            return items
    
    def process_review_decision(
        self,
        queue_id: str,
        decision: str,
        reviewed_by: str,
        notes: Optional[str] = None,
        updated_value: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Process a review decision for a queued item.
        
        Args:
            queue_id: Queue item ID
            decision: Review decision (accept, edit, reject)
            reviewed_by: Reviewer identifier
            notes: Review notes
            updated_value: Updated value if edited
            
        Returns:
            Processing result
        """
        with self.driver.session() as session:
            # Update queue item
            update_query = """
                MATCH (q:UncertaintyQueue {queue_id: $queue_id})
                SET q.status = 'reviewed',
                    q.review_decision = $decision,
                    q.reviewed_by = $reviewed_by,
                    q.reviewed_at = datetime(),
                    q.review_notes = $notes,
                    q.updated_value = $updated_value
                RETURN q
            """
            
            result = session.run(
                update_query,
                queue_id=queue_id,
                decision=decision,
                reviewed_by=reviewed_by,
                notes=notes,
                updated_value=json.dumps(updated_value) if updated_value else None
            )
            
            record = result.single()
            if not record:
                raise ValueError(f"Queue item {queue_id} not found")
            
            item = dict(record["q"])
            
            # Trigger appropriate action based on item type and decision
            if item["item_type"] == "flow_edge" and decision in ["edit", "reject"]:
                self._mark_for_retrain("flow_edges", item["item_id"])
            elif item["item_type"] == "mapping" and decision in ["edit", "reject"]:
                self._mark_for_retrain("mappings", item["item_id"])
            
            # Invalidate caches and trigger embedding refresh if accepted or edited
            if decision in ["accept", "edit"]:
                invalidate_caches_for_item(item["item_id"])
                
                # Trigger embedding refresh asynchronously
                refresher = get_embedding_refresher()
                import asyncio
                asyncio.create_task(refresher.refresh_after_review({
                    "item_id": item["item_id"],
                    "item_type": item["item_type"],
                    "decision": decision
                }))
            
            return {
                "queue_id": queue_id,
                "processed": True,
                "decision": decision,
                "triggers_retrain": decision in ["edit", "reject"]
            }
    
    def _mark_for_retrain(self, category: str, item_id: str):
        """Mark an item for retraining."""
        with self.driver.session() as session:
            query = """
                MERGE (r:RetrainQueue {category: $category})
                SET r.updated = datetime()
                WITH r
                MERGE (r)-[:NEEDS_RETRAIN {item_id: $item_id}]->(i:RetrainItem {item_id: $item_id})
                SET i.added = datetime(),
                    i.category = $category
            """
            session.run(query, category=category, item_id=item_id)
    
    def get_retrain_items(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get items marked for retraining.
        
        Args:
            category: Filter by category
            
        Returns:
            List of items needing retrain
        """
        with self.driver.session() as session:
            category_filter = "WHERE i.category = $category" if category else ""
            
            query = f"""
                MATCH (i:RetrainItem)
                {category_filter}
                RETURN i {{.*}} as item
                ORDER BY i.added DESC
            """
            
            params = {}
            if category:
                params["category"] = category
            
            result = session.run(query, **params)
            return [dict(record["item"]) for record in result]
    
    def trigger_weekly_retrain(self) -> Dict[str, Any]:
        """
        Trigger weekly retrain process for all marked items.
        
        Returns:
            Retrain summary
        """
        logger.info("Starting weekly retrain process...")
        
        with self.driver.session() as session:
            # Get all items needing retrain
            items = self.get_retrain_items()
            
            # Group by category
            categories = {}
            for item in items:
                cat = item.get("category", "unknown")
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(item["item_id"])
            
            # Create retrain job
            job_id = f"retrain-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
            
            job_query = """
                CREATE (j:RetrainJob {
                    job_id: $job_id,
                    created: datetime(),
                    status: 'pending',
                    categories: $categories,
                    item_count: $item_count
                })
                RETURN j
            """
            
            session.run(
                job_query,
                job_id=job_id,
                categories=json.dumps(list(categories.keys())),
                item_count=len(items)
            )
            
            # Mark items as being retrained
            mark_query = """
                MATCH (i:RetrainItem)
                SET i.retrain_job_id = $job_id,
                    i.retrain_started = datetime()
            """
            session.run(mark_query, job_id=job_id)
            
            logger.info(f"Created retrain job {job_id} with {len(items)} items")
            
            return {
                "job_id": job_id,
                "categories": categories,
                "total_items": len(items),
                "status": "initiated"
            }
    
    def refresh_embeddings(self, node_types: List[str], limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Mark nodes for embedding refresh.
        
        Args:
            node_types: Types of nodes to refresh
            limit: Maximum nodes per type
            
        Returns:
            Refresh summary
        """
        with self.driver.session() as session:
            refresh_id = f"refresh-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
            total_marked = 0
            
            for node_type in node_types:
                # Map node type to label
                label_map = {
                    "attack_pattern": "AttackPattern",
                    "detection_strategy": "DetectionStrategy",
                    "analytic": "Analytic",
                    "flow": "AttackEpisode"
                }
                
                label = label_map.get(node_type, node_type)
                limit_clause = f"LIMIT {limit}" if limit else ""
                
                query = f"""
                    MATCH (n:{label})
                    WHERE n.embedding_updated IS NULL 
                        OR n.embedding_updated < datetime() - duration('P7D')
                    WITH n {limit_clause}
                    SET n.needs_embedding_refresh = true,
                        n.refresh_id = $refresh_id
                    RETURN count(n) as marked
                """
                
                result = session.run(query, refresh_id=refresh_id)
                count = result.single()["marked"]
                total_marked += count
                
                logger.info(f"Marked {count} {node_type} nodes for embedding refresh")
            
            return {
                "refresh_id": refresh_id,
                "node_types": node_types,
                "total_marked": total_marked,
                "status": "marked_for_refresh"
            }
    
    def get_queue_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the uncertainty queue.
        
        Returns:
            Queue statistics
        """
        with self.driver.session() as session:
            query = """
                MATCH (q:UncertaintyQueue)
                WITH q.status as status, q.item_type as item_type, count(q) as count
                RETURN status, item_type, count
                ORDER BY status, item_type
            """
            
            result = session.run(query)
            
            stats = {
                "by_status": {},
                "by_type": {},
                "total": 0
            }
            
            for record in result:
                status = record["status"]
                item_type = record["item_type"]
                count = record["count"]
                
                if status not in stats["by_status"]:
                    stats["by_status"][status] = 0
                stats["by_status"][status] += count
                
                if item_type not in stats["by_type"]:
                    stats["by_type"][item_type] = 0
                stats["by_type"][item_type] += count
                
                stats["total"] += count
            
            # Get confidence distribution for pending items
            confidence_query = """
                MATCH (q:UncertaintyQueue {status: 'pending'})
                RETURN 
                    avg(q.confidence) as avg_confidence,
                    min(q.confidence) as min_confidence,
                    max(q.confidence) as max_confidence,
                    stdev(q.confidence) as stdev_confidence
            """
            
            result = session.run(confidence_query).single()
            if result:
                stats["confidence_stats"] = {
                    "average": result["avg_confidence"],
                    "min": result["min_confidence"],
                    "max": result["max_confidence"],
                    "stdev": result["stdev_confidence"]
                }
            
            return stats
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()