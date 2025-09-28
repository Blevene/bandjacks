"""Neo4j-based caching system for judge verdicts."""

import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import asdict

from neo4j import GraphDatabase
from .judge_client import JudgeVerdict, VerdictType

logger = logging.getLogger(__name__)


class JudgeVerdictCache:
    """Neo4j-based cache for LLM judge verdicts with provenance."""
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize judge verdict cache.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username  
            neo4j_password: Neo4j password
        """
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self._ensure_constraints_and_indexes()
    
    def _ensure_constraints_and_indexes(self):
        """Create necessary constraints and indexes for judge verdict caching."""
        with self.driver.session() as session:
            # Constraint on judge verdict cache key (from_technique, to_technique, retrieval_hash)
            session.run("""
                CREATE CONSTRAINT judge_verdict_cache_key IF NOT EXISTS
                FOR (v:JudgeVerdict) REQUIRE (v.from_technique, v.to_technique, v.retrieval_hash) IS UNIQUE
            """)
            
            # Index on retrieval hash for fast lookups
            session.run("""
                CREATE INDEX judge_verdict_retrieval_hash IF NOT EXISTS
                FOR (v:JudgeVerdict) ON (v.retrieval_hash)
            """)
            
            # Index on judgment timestamp for cleanup operations
            session.run("""
                CREATE INDEX judge_verdict_timestamp IF NOT EXISTS
                FOR (v:JudgeVerdict) ON (v.judged_at)
            """)
            
            # Index on model name for analysis
            session.run("""
                CREATE INDEX judge_verdict_model IF NOT EXISTS
                FOR (v:JudgeVerdict) ON (v.model_name)
            """)
            
    def get_cached_verdict(
        self,
        from_technique: str,
        to_technique: str,
        retrieval_hash: str
    ) -> Optional[JudgeVerdict]:
        """
        Get cached verdict for a technique pair with specific evidence.
        
        Args:
            from_technique: Source technique ID
            to_technique: Target technique ID
            retrieval_hash: Hash of evidence pack used for judgment
            
        Returns:
            Cached verdict if available, None otherwise
        """
        with self.driver.session() as session:
            query = """
                MATCH (v:JudgeVerdict {
                    from_technique: $from_technique,
                    to_technique: $to_technique,
                    retrieval_hash: $retrieval_hash
                })
                RETURN v
                LIMIT 1
            """
            
            result = session.run(query, {
                "from_technique": from_technique,
                "to_technique": to_technique,
                "retrieval_hash": retrieval_hash
            })
            
            record = result.single()
            if record:
                verdict_data = dict(record["v"])
                verdict = self._neo4j_to_verdict(verdict_data)
                
                logger.debug(f"Cache hit: {from_technique}->{to_technique} ({retrieval_hash[:8]})")
                return verdict
                
        logger.debug(f"Cache miss: {from_technique}->{to_technique} ({retrieval_hash[:8]})")
        return None
    
    def cache_verdict(self, verdict: JudgeVerdict) -> bool:
        """
        Cache a judge verdict with provenance.
        
        Args:
            verdict: Judge verdict to cache
            
        Returns:
            True if successfully cached, False if already exists
        """
        with self.driver.session() as session:
            # Convert verdict to Neo4j properties
            verdict_props = self._verdict_to_neo4j(verdict)
            
            query = """
                MERGE (v:JudgeVerdict {
                    from_technique: $from_technique,
                    to_technique: $to_technique,
                    retrieval_hash: $retrieval_hash
                })
                ON CREATE SET 
                    v += $props,
                    v.created_at = datetime(),
                    v.access_count = 1
                ON MATCH SET
                    v.access_count = v.access_count + 1,
                    v.last_accessed = datetime()
                RETURN v.created_at IS NOT NULL as was_created
            """
            
            result = session.run(query, {
                "from_technique": verdict.from_technique,
                "to_technique": verdict.to_technique,
                "retrieval_hash": verdict.retrieval_hash,
                "props": verdict_props
            })
            
            record = result.single()
            was_created = record["was_created"] if record else False
            
            if was_created:
                logger.info(f"Cached verdict: {verdict.from_technique}->{verdict.to_technique}")
            else:
                logger.debug(f"Updated access count for cached verdict")
                
            return was_created
    
    def batch_cache_verdicts(self, verdicts: List[JudgeVerdict]) -> Dict[str, int]:
        """
        Cache multiple verdicts in batch.
        
        Args:
            verdicts: List of verdicts to cache
            
        Returns:
            Statistics about caching operation
        """
        cached_count = 0
        updated_count = 0
        
        with self.driver.session() as session:
            # Use transaction for batch operation
            def cache_batch(tx):
                nonlocal cached_count, updated_count
                
                for verdict in verdicts:
                    verdict_props = self._verdict_to_neo4j(verdict)
                    
                    query = """
                        MERGE (v:JudgeVerdict {
                            from_technique: $from_technique,
                            to_technique: $to_technique,
                            retrieval_hash: $retrieval_hash
                        })
                        ON CREATE SET 
                            v += $props,
                            v.created_at = datetime(),
                            v.access_count = 1
                        ON MATCH SET
                            v.access_count = v.access_count + 1,
                            v.last_accessed = datetime()
                        RETURN v.created_at IS NOT NULL as was_created
                    """
                    
                    result = tx.run(query, {
                        "from_technique": verdict.from_technique,
                        "to_technique": verdict.to_technique,
                        "retrieval_hash": verdict.retrieval_hash,
                        "props": verdict_props
                    })
                    
                    record = result.single()
                    if record and record["was_created"]:
                        cached_count += 1
                    else:
                        updated_count += 1
            
            session.execute_write(cache_batch)
        
        logger.info(f"Batch cached {cached_count} new verdicts, updated {updated_count} existing")
        
        return {
            "cached": cached_count,
            "updated": updated_count,
            "total": len(verdicts)
        }
    
    def get_cached_verdicts_for_pairs(
        self,
        pairs: List[Tuple[str, str]],
        retrieval_hashes: Dict[Tuple[str, str], str]
    ) -> Dict[Tuple[str, str], JudgeVerdict]:
        """
        Get cached verdicts for multiple pairs with their evidence hashes.
        
        Args:
            pairs: List of (from_technique, to_technique) pairs
            retrieval_hashes: Mapping of pairs to their evidence hashes
            
        Returns:
            Dictionary of pairs to their cached verdicts
        """
        cached_verdicts = {}
        
        with self.driver.session() as session:
            for from_tech, to_tech in pairs:
                pair_key = (from_tech, to_tech)
                
                if pair_key in retrieval_hashes:
                    retrieval_hash = retrieval_hashes[pair_key]
                    
                    cached_verdict = self.get_cached_verdict(
                        from_tech, to_tech, retrieval_hash
                    )
                    
                    if cached_verdict:
                        cached_verdicts[pair_key] = cached_verdict
        
        cache_hit_rate = len(cached_verdicts) / len(pairs) if pairs else 0
        logger.info(f"Cache hit rate: {cache_hit_rate:.2%} ({len(cached_verdicts)}/{len(pairs)})")
        
        return cached_verdicts
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """
        Get cache statistics and usage information.
        
        Returns:
            Cache statistics dictionary
        """
        with self.driver.session() as session:
            query = """
                MATCH (v:JudgeVerdict)
                RETURN 
                    count(v) as total_cached_verdicts,
                    avg(v.access_count) as avg_access_count,
                    max(v.access_count) as max_access_count,
                    count(DISTINCT v.model_name) as unique_models,
                    count(DISTINCT v.retrieval_hash) as unique_evidence_packs,
                    collect(DISTINCT v.verdict_type) as verdict_types
            """
            
            result = session.run(query)
            record = result.single()
            
            if not record:
                return {"total_cached_verdicts": 0}
            
            # Get verdict type distribution
            verdict_dist_query = """
                MATCH (v:JudgeVerdict)
                RETURN v.verdict_type as verdict_type, count(*) as count
                ORDER BY count DESC
            """
            
            verdict_dist_result = session.run(verdict_dist_query)
            verdict_distribution = {
                record["verdict_type"]: record["count"] 
                for record in verdict_dist_result
            }
            
            # Get model usage
            model_usage_query = """
                MATCH (v:JudgeVerdict)
                RETURN v.model_name as model, count(*) as count
                ORDER BY count DESC
            """
            
            model_usage_result = session.run(model_usage_query)
            model_usage = {
                record["model"]: record["count"]
                for record in model_usage_result
            }
            
            stats = {
                "total_cached_verdicts": record["total_cached_verdicts"],
                "avg_access_count": record["avg_access_count"],
                "max_access_count": record["max_access_count"],
                "unique_models": record["unique_models"],
                "unique_evidence_packs": record["unique_evidence_packs"],
                "verdict_types": record["verdict_types"],
                "verdict_distribution": verdict_distribution,
                "model_usage": model_usage
            }
            
            return stats
    
    def cleanup_old_verdicts(
        self,
        max_age_days: int = 30,
        keep_min_access_count: int = 2
    ) -> int:
        """
        Clean up old, rarely accessed verdicts to manage cache size.
        
        Args:
            max_age_days: Maximum age of verdicts to keep
            keep_min_access_count: Keep verdicts accessed at least this many times
            
        Returns:
            Number of verdicts deleted
        """
        cutoff_date = datetime.utcnow() - timedelta(days=max_age_days)
        
        with self.driver.session() as session:
            query = """
                MATCH (v:JudgeVerdict)
                WHERE v.created_at < datetime($cutoff_date)
                  AND v.access_count < $min_access_count
                DELETE v
                RETURN count(v) as deleted_count
            """
            
            result = session.run(query, {
                "cutoff_date": cutoff_date.isoformat(),
                "min_access_count": keep_min_access_count
            })
            
            record = result.single()
            deleted_count = record["deleted_count"] if record else 0
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old cached verdicts")
            
            return deleted_count
    
    def invalidate_verdicts_by_model(self, model_name: str) -> int:
        """
        Invalidate all cached verdicts from a specific model.
        
        Args:
            model_name: Name of model whose verdicts to invalidate
            
        Returns:
            Number of verdicts deleted
        """
        with self.driver.session() as session:
            query = """
                MATCH (v:JudgeVerdict {model_name: $model_name})
                DELETE v
                RETURN count(v) as deleted_count
            """
            
            result = session.run(query, {"model_name": model_name})
            record = result.single()
            deleted_count = record["deleted_count"] if record else 0
            
            if deleted_count > 0:
                logger.info(f"Invalidated {deleted_count} verdicts from model {model_name}")
                
            return deleted_count
    
    def _verdict_to_neo4j(self, verdict: JudgeVerdict) -> Dict[str, Any]:
        """Convert JudgeVerdict to Neo4j properties."""
        return {
            "from_technique": verdict.from_technique,
            "to_technique": verdict.to_technique,
            "verdict_type": verdict.verdict.value,
            "confidence": verdict.confidence,
            "evidence_ids": verdict.evidence_ids,
            "rationale_summary": verdict.rationale_summary,
            "model_name": verdict.model_name,
            "retrieval_hash": verdict.retrieval_hash,
            "judge_version": verdict.judge_version,
            "judged_at": verdict.judged_at.isoformat(),
            "cost_tokens": verdict.cost_tokens
        }
    
    def _neo4j_to_verdict(self, data: Dict[str, Any]) -> JudgeVerdict:
        """Convert Neo4j properties to JudgeVerdict."""
        return JudgeVerdict(
            from_technique=data["from_technique"],
            to_technique=data["to_technique"],
            verdict=VerdictType(data["verdict_type"]),
            confidence=data["confidence"],
            evidence_ids=data.get("evidence_ids", []),
            rationale_summary=data["rationale_summary"],
            model_name=data["model_name"],
            retrieval_hash=data["retrieval_hash"],
            judge_version=data.get("judge_version", "1.0"),
            judged_at=datetime.fromisoformat(data["judged_at"]) if isinstance(data["judged_at"], str) else data["judged_at"],
            cost_tokens=data.get("cost_tokens", 0)
        )
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()


def get_judge_cache(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str
) -> JudgeVerdictCache:
    """
    Convenience function to get judge verdict cache.
    
    Args:
        neo4j_uri: Neo4j connection URI
        neo4j_user: Neo4j username
        neo4j_password: Neo4j password
        
    Returns:
        Judge verdict cache instance
    """
    return JudgeVerdictCache(neo4j_uri, neo4j_user, neo4j_password)