"""Active Learning sampler job for identifying uncertain items."""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import random
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


class ALSampler:
    """Active Learning sampler to identify and enqueue uncertain items."""
    
    def __init__(
        self,
        neo4j_uri: str,
        neo4j_user: str,
        neo4j_password: str,
        sample_size: int = 20,
        confidence_threshold: float = 0.6
    ):
        """
        Initialize AL sampler.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            sample_size: Number of items to sample per run
            confidence_threshold: Max confidence for sampling
        """
        self.driver = GraphDatabase.driver(
            neo4j_uri,
            auth=(neo4j_user, neo4j_password)
        )
        self.sample_size = sample_size
        self.confidence_threshold = confidence_threshold
    
    async def run_sampling_job(self) -> Dict[str, Any]:
        """
        Run the sampling job to identify uncertain items.
        
        Returns:
            Job results with sampled items
        """
        logger.info("Starting AL sampling job")
        job_id = f"al-sample-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        
        sampled_items = []
        
        try:
            # Sample low-confidence flow edges
            flow_edges = await self._sample_flow_edges()
            sampled_items.extend(flow_edges)
            
            # Sample low-confidence mappings
            mappings = await self._sample_mappings()
            sampled_items.extend(mappings)
            
            # Sample low-confidence extractions
            extractions = await self._sample_extractions()
            sampled_items.extend(extractions)
            
            # Sample low-confidence detections
            detections = await self._sample_detections()
            sampled_items.extend(detections)
            
            # Sort by uncertainty score (inverse of confidence)
            sampled_items.sort(key=lambda x: x.get("uncertainty_score", 0), reverse=True)
            
            # Take top N items
            final_sample = sampled_items[:self.sample_size]
            
            # Enqueue sampled items
            enqueued_count = await self._enqueue_items(final_sample, job_id)
            
            # Create job record
            await self._create_job_record(job_id, final_sample, enqueued_count)
            
            # Trigger notifications if items were enqueued
            if enqueued_count > 0:
                await self._trigger_notifications(job_id, enqueued_count)
            
            logger.info(f"AL sampling job {job_id} completed: {enqueued_count} items enqueued")
            
            return {
                "job_id": job_id,
                "sampled_count": len(final_sample),
                "enqueued_count": enqueued_count,
                "status": "completed",
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"AL sampling job failed: {e}")
            return {
                "job_id": job_id,
                "status": "failed",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def _sample_flow_edges(self) -> List[Dict[str, Any]]:
        """Sample uncertain flow edges."""
        with self.driver.session() as session:
            query = """
                MATCH (a1:AttackAction)-[e:NEXT]->(a2:AttackAction)
                WHERE e.confidence < $threshold 
                    AND NOT e.reviewed
                    AND NOT EXISTS(e.in_queue)
                WITH e, a1, a2, 
                     (1 - e.confidence) as uncertainty,
                     rand() as random
                ORDER BY uncertainty DESC, random
                LIMIT $limit
                RETURN 
                    'flow_edge' as item_type,
                    coalesce(e.edge_id, elementId(e)) as item_id,
                    e.confidence as confidence,
                    uncertainty as uncertainty_score,
                    {
                        source: a1.name,
                        target: a2.name,
                        flow_id: e.flow_id,
                        probability: e.probability
                    } as context
            """
            
            result = session.run(
                query,
                threshold=self.confidence_threshold,
                limit=self.sample_size // 4  # Allocate 1/4 of sample to flow edges
            )
            
            return [dict(record) for record in result]
    
    async def _sample_mappings(self) -> List[Dict[str, Any]]:
        """Sample uncertain technique mappings."""
        with self.driver.session() as session:
            query = """
                MATCH (c:CandidateAttackPattern)
                WHERE c.confidence < $threshold 
                    AND c.status = 'pending'
                    AND NOT EXISTS(c.in_queue)
                WITH c,
                     (1 - c.confidence) as uncertainty,
                     rand() as random
                ORDER BY uncertainty DESC, random
                LIMIT $limit
                RETURN 
                    'mapping' as item_type,
                    c.candidate_id as item_id,
                    c.confidence as confidence,
                    uncertainty as uncertainty_score,
                    {
                        source_text: c.source_text,
                        technique_name: c.name,
                        technique_id: c.technique_id
                    } as context
            """
            
            result = session.run(
                query,
                threshold=self.confidence_threshold,
                limit=self.sample_size // 4
            )
            
            return [dict(record) for record in result]
    
    async def _sample_extractions(self) -> List[Dict[str, Any]]:
        """Sample uncertain extractions."""
        with self.driver.session() as session:
            query = """
                MATCH (e:Extraction)
                WHERE e.confidence < $threshold 
                    AND e.status = 'pending'
                    AND NOT EXISTS(e.in_queue)
                WITH e,
                     (1 - e.confidence) as uncertainty,
                     rand() as random
                ORDER BY uncertainty DESC, random
                LIMIT $limit
                RETURN 
                    'extraction' as item_type,
                    e.extraction_id as item_id,
                    e.confidence as confidence,
                    uncertainty as uncertainty_score,
                    {
                        source_doc: e.source_document,
                        entity_type: e.entity_type,
                        extracted_value: e.value
                    } as context
            """
            
            result = session.run(
                query,
                threshold=self.confidence_threshold,
                limit=self.sample_size // 4
            )
            
            return [dict(record) for record in result]
    
    async def _sample_detections(self) -> List[Dict[str, Any]]:
        """Sample uncertain detection mappings."""
        with self.driver.session() as session:
            query = """
                MATCH (ds:DetectionStrategy)-[d:DETECTS]->(ap:AttackPattern)
                WHERE d.confidence < $threshold 
                    AND NOT EXISTS(d.reviewed)
                    AND NOT EXISTS(d.in_queue)
                WITH d, ds, ap,
                     (1 - d.confidence) as uncertainty,
                     rand() as random
                ORDER BY uncertainty DESC, random
                LIMIT $limit
                RETURN 
                    'detection' as item_type,
                    coalesce(d.detection_id, elementId(d)) as item_id,
                    d.confidence as confidence,
                    uncertainty as uncertainty_score,
                    {
                        strategy_name: ds.name,
                        technique_id: ap.external_id,
                        technique_name: ap.name
                    } as context
            """
            
            result = session.run(
                query,
                threshold=self.confidence_threshold,
                limit=self.sample_size // 4
            )
            
            return [dict(record) for record in result]
    
    async def _enqueue_items(self, items: List[Dict[str, Any]], job_id: str) -> int:
        """Enqueue sampled items to uncertainty queue."""
        enqueued = 0
        
        with self.driver.session() as session:
            for item in items:
                # Check if already in queue
                check_query = """
                    MATCH (q:UncertaintyQueue {item_id: $item_id, item_type: $item_type})
                    WHERE q.status = 'pending'
                    RETURN count(q) as exists
                """
                
                result = session.run(
                    check_query,
                    item_id=item["item_id"],
                    item_type=item["item_type"]
                )
                
                if result.single()["exists"] == 0:
                    # Add to queue
                    enqueue_query = """
                        CREATE (q:UncertaintyQueue {
                            queue_id: $queue_id,
                            item_type: $item_type,
                            item_id: $item_id,
                            confidence: $confidence,
                            uncertainty_score: $uncertainty_score,
                            source_context: $context,
                            status: 'pending',
                            created: datetime(),
                            sampled_by: $job_id,
                            priority: $priority
                        })
                        WITH q
                        MATCH (n)
                        WHERE (n:AttackAction OR n:CandidateAttackPattern OR n:Extraction OR n:DetectionStrategy)
                            AND (n.action_id = $item_id OR n.candidate_id = $item_id 
                                OR n.extraction_id = $item_id OR n.stix_id = $item_id)
                        SET n.in_queue = true
                        RETURN q
                    """
                    
                    import json
                    import hashlib
                    
                    queue_id = f"queue-{hashlib.md5(f'{item["item_type"]}-{item["item_id"]}'.encode()).hexdigest()[:12]}"
                    
                    session.run(
                        enqueue_query,
                        queue_id=queue_id,
                        item_type=item["item_type"],
                        item_id=item["item_id"],
                        confidence=item["confidence"],
                        uncertainty_score=item["uncertainty_score"],
                        context=json.dumps(item["context"]),
                        job_id=job_id,
                        priority=item["uncertainty_score"] * 100
                    )
                    enqueued += 1
        
        return enqueued
    
    async def _create_job_record(self, job_id: str, sampled_items: List[Dict[str, Any]], enqueued_count: int):
        """Create a record of the sampling job."""
        with self.driver.session() as session:
            import json
            
            query = """
                CREATE (j:ALSamplingJob {
                    job_id: $job_id,
                    created: datetime(),
                    sampled_count: $sampled_count,
                    enqueued_count: $enqueued_count,
                    confidence_threshold: $threshold,
                    sample_size: $sample_size,
                    item_types: $item_types,
                    status: 'completed'
                })
                RETURN j
            """
            
            item_types = list(set(item["item_type"] for item in sampled_items))
            
            session.run(
                query,
                job_id=job_id,
                sampled_count=len(sampled_items),
                enqueued_count=enqueued_count,
                threshold=self.confidence_threshold,
                sample_size=self.sample_size,
                item_types=json.dumps(item_types)
            )
    
    async def _trigger_notifications(self, job_id: str, enqueued_count: int):
        """Trigger notifications for reviewers."""
        # This will be implemented by the notification service
        logger.info(f"Triggering notifications for job {job_id}: {enqueued_count} items need review")
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()


async def run_periodic_sampling(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    interval_hours: int = 1
):
    """
    Run AL sampling periodically.
    
    Args:
        neo4j_uri: Neo4j connection URI
        neo4j_user: Neo4j username
        neo4j_password: Neo4j password
        interval_hours: Hours between sampling runs
    """
    sampler = ALSampler(neo4j_uri, neo4j_user, neo4j_password)
    
    while True:
        try:
            result = await sampler.run_sampling_job()
            logger.info(f"Sampling job result: {result}")
        except Exception as e:
            logger.error(f"Sampling job error: {e}")
        
        # Wait for next run
        await asyncio.sleep(interval_hours * 3600)