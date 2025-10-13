# Vector Updates Strategy and Tracking Plan

## Overview

This document outlines the strategy for maintaining and updating vector embeddings in the Bandjacks knowledge graph. The system uses a hybrid approach combining immediate updates for critical vectors with scheduled batch regeneration for computationally intensive operations.

## Table of Contents

1. [Vector Types and Purpose](#vector-types-and-purpose)
2. [Update Strategy](#update-strategy)
3. [Implementation Plan](#implementation-plan)
4. [Tracking and Monitoring](#tracking-and-monitoring)
5. [Performance Considerations](#performance-considerations)
6. [Configuration](#configuration)
7. [Migration Plan](#migration-plan)

## Vector Types and Purpose

### 1. Report Vectors
- **Purpose**: Enable semantic search across threat intelligence reports
- **Dimensions**: 768 (using sentence-transformers)
- **Content**: Title + summary + key findings
- **Update Frequency**: Immediate on ingest/review

### 2. Entity Vectors
- **Purpose**: Find similar threat actors, malware, campaigns
- **Content**: Name + description + associated TTPs
- **Update Frequency**: Immediate for new entities, batch for relationship updates
- **Types**:
  - IntrusionSet (threat actors)
  - Software (malware/tools)
  - Campaign
  - Vulnerability

### 3. Technique Vectors
- **Purpose**: Semantic TTP search and similarity matching
- **Content**: Technique name + description + detection + mitigations
- **Update Frequency**: On ATT&CK update + batch for co-occurrence
- **Special Features**: Includes T-number for exact matching

### 4. Attack Flow Vectors
- **Purpose**: Find similar attack sequences
- **Content**: Concatenated technique sequence + temporal markers
- **Update Frequency**: Immediate on flow creation/update

### 5. Relationship Vectors
- **Purpose**: Graph traversal optimization and similarity
- **Content**: Source + edge type + target embeddings
- **Update Frequency**: Batch (daily)

### 6. Co-occurrence Vectors
- **Purpose**: Technique association patterns
- **Content**: Technique pairs with frequency weighting
- **Update Frequency**: Batch (daily/weekly)

## Update Strategy

### Hybrid Approach Decision Tree

```
Report Upserted
├── Count Changes
│   ├── ≤10 entities/techniques → Immediate Update
│   │   ├── Generate entity vectors
│   │   ├── Update report vector
│   │   └── Update flow vectors
│   └── >10 entities/techniques → Queue for Batch
│       ├── Add to Redis queue
│       ├── Update report vector only
│       └── Schedule batch if threshold met
└── Always Update
    ├── Report embedding (immediate)
    └── Track update metadata
```

### Update Priorities

| Priority | Vector Type | Update Trigger | Timing |
|----------|------------|----------------|---------|
| P0 | Report vectors | New report/review | Immediate |
| P0 | New entity vectors | Entity creation | Immediate |
| P1 | Flow vectors | Flow creation/edit | Immediate |
| P1 | Small entity updates | <10 changes | Immediate |
| P2 | Technique co-occurrence | Daily batch | 2 AM |
| P2 | Relationship vectors | Graph changes | Daily batch |
| P3 | Actor-TTP associations | New intelligence | Weekly |
| P3 | Full regeneration | Maintenance | Monthly |

## Implementation Plan

### Phase 1: Core Infrastructure (Week 1-2)

```python
# vector_update_manager.py

from enum import Enum
from typing import List, Dict, Optional
import asyncio
from datetime import datetime, timedelta

class UpdateStrategy(Enum):
    IMMEDIATE = "immediate"
    BATCH = "batch"
    HYBRID = "hybrid"

class VectorType(Enum):
    REPORT = "report"
    ENTITY = "entity"
    TECHNIQUE = "technique"
    FLOW = "flow"
    RELATIONSHIP = "relationship"
    COOCCURRENCE = "cooccurrence"

class VectorUpdateManager:
    """Manages vector update strategy and execution"""

    def __init__(
        self,
        strategy: UpdateStrategy = UpdateStrategy.HYBRID,
        immediate_threshold: int = 10,
        batch_threshold: int = 100
    ):
        self.strategy = strategy
        self.immediate_threshold = immediate_threshold
        self.batch_threshold = batch_threshold
        self.update_tracker = VectorUpdateTracker()
        self.queue_manager = VectorQueueManager()

    async def handle_report_upsert(
        self,
        report_id: str,
        entities_changed: List[Dict],
        techniques_changed: List[Dict],
        flows_changed: List[Dict]
    ) -> Dict:
        """Main entry point for vector updates after report upsert"""

        total_changes = len(entities_changed) + len(techniques_changed)
        update_result = {
            "immediate_updates": [],
            "queued_updates": [],
            "batch_triggered": False
        }

        # Always update report vector immediately
        await self.update_report_vector(report_id)
        update_result["immediate_updates"].append(f"report:{report_id}")

        # Decide strategy based on change volume
        if self.strategy == UpdateStrategy.IMMEDIATE:
            await self._immediate_update_all(
                entities_changed, techniques_changed, flows_changed
            )
            update_result["immediate_updates"].extend(
                [f"entity:{e['id']}" for e in entities_changed]
            )
        elif self.strategy == UpdateStrategy.BATCH:
            await self._queue_all_updates(
                report_id, entities_changed, techniques_changed, flows_changed
            )
            update_result["queued_updates"].append(f"batch:{report_id}")
        else:  # HYBRID
            if total_changes <= self.immediate_threshold:
                await self._immediate_update_all(
                    entities_changed, techniques_changed, flows_changed
                )
                update_result["immediate_updates"].extend(
                    [f"entity:{e['id']}" for e in entities_changed]
                )
            else:
                await self._queue_all_updates(
                    report_id, entities_changed, techniques_changed, flows_changed
                )
                update_result["queued_updates"].append(f"batch:{report_id}")

                # Check if batch should be triggered
                if await self.queue_manager.should_trigger_batch():
                    await self.trigger_batch_update()
                    update_result["batch_triggered"] = True

        # Track update completion
        await self.update_tracker.record_update_batch(update_result)

        return update_result
```

### Phase 2: Update Executors (Week 2-3)

```python
# vector_executors.py

class VectorUpdateExecutor:
    """Executes vector updates with parallelization"""

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.embedding_service = EmbeddingService()
        self.opensearch = OpenSearchClient()

    async def update_report_vector(self, report_id: str) -> bool:
        """Update single report vector"""
        try:
            # Fetch report content
            report = await fetch_report(report_id)

            # Generate embedding
            content = f"{report.title} {report.summary} {report.key_findings}"
            embedding = await self.embedding_service.generate_embedding(content)

            # Store in OpenSearch
            await self.opensearch.update_vector(
                index="reports",
                doc_id=report_id,
                vector=embedding,
                metadata={
                    "updated_at": datetime.utcnow().isoformat(),
                    "vector_version": "1.0"
                }
            )

            return True
        except Exception as e:
            logger.error(f"Failed to update report vector {report_id}: {e}")
            return False

    async def update_entity_vectors_batch(
        self,
        entities: List[Dict]
    ) -> Dict[str, bool]:
        """Update multiple entity vectors in parallel"""

        async def update_single_entity(entity: Dict) -> tuple:
            try:
                # Build entity content
                content = self._build_entity_content(entity)

                # Generate embedding
                embedding = await self.embedding_service.generate_embedding(
                    content
                )

                # Store in OpenSearch
                await self.opensearch.update_vector(
                    index="entities",
                    doc_id=entity["stix_id"],
                    vector=embedding,
                    metadata={
                        "entity_type": entity["type"],
                        "confidence": entity.get("confidence", 0),
                        "updated_at": datetime.utcnow().isoformat()
                    }
                )

                return (entity["stix_id"], True)
            except Exception as e:
                logger.error(f"Failed to update entity {entity['stix_id']}: {e}")
                return (entity["stix_id"], False)

        # Process in parallel with limited concurrency
        semaphore = asyncio.Semaphore(self.max_workers)

        async def bounded_update(entity):
            async with semaphore:
                return await update_single_entity(entity)

        results = await asyncio.gather(
            *[bounded_update(entity) for entity in entities]
        )

        return dict(results)

    def _build_entity_content(self, entity: Dict) -> str:
        """Build text content for entity embedding"""
        parts = [entity.get("name", "")]

        if desc := entity.get("description"):
            parts.append(desc)

        if aliases := entity.get("aliases"):
            parts.append(f"Also known as: {', '.join(aliases)}")

        if techniques := entity.get("techniques"):
            tech_names = [t["name"] for t in techniques[:10]]  # Top 10
            parts.append(f"Uses: {', '.join(tech_names)}")

        return " ".join(parts)
```

### Phase 3: Batch Processing System (Week 3-4)

```python
# batch_processor.py

class VectorBatchProcessor:
    """Handles scheduled batch vector updates"""

    def __init__(self):
        self.redis = RedisClient()
        self.executor = VectorUpdateExecutor()
        self.neo4j = Neo4jClient()

    async def process_batch_queue(self) -> Dict:
        """Process all queued vector updates"""

        start_time = datetime.utcnow()
        stats = {
            "processed": 0,
            "failed": 0,
            "duration_seconds": 0,
            "vector_types": {}
        }

        # Get all queued items
        queue_items = await self.redis.get_all_queue_items(
            "vector_update_queue"
        )

        # Group by vector type for efficient processing
        grouped = self._group_by_type(queue_items)

        # Process each type
        for vector_type, items in grouped.items():
            processor = self._get_processor(vector_type)
            results = await processor(items)

            stats["vector_types"][vector_type] = {
                "total": len(items),
                "success": sum(1 for r in results.values() if r),
                "failed": sum(1 for r in results.values() if not r)
            }

            stats["processed"] += sum(1 for r in results.values() if r)
            stats["failed"] += sum(1 for r in results.values() if not r)

        # Clear processed items from queue
        await self.redis.clear_queue("vector_update_queue")

        stats["duration_seconds"] = (
            datetime.utcnow() - start_time
        ).total_seconds()

        # Log batch completion
        await self._log_batch_completion(stats)

        return stats

    async def regenerate_cooccurrence_vectors(self) -> Dict:
        """Regenerate technique co-occurrence vectors"""

        logger.info("Starting co-occurrence vector regeneration")

        # Query Neo4j for co-occurrence patterns
        query = """
        MATCH (r:Report)-[:EXTRACTED_TECHNIQUE]->(t1:AttackPattern)
        MATCH (r)-[:EXTRACTED_TECHNIQUE]->(t2:AttackPattern)
        WHERE t1.stix_id < t2.stix_id
        RETURN t1.stix_id as tech1, t2.stix_id as tech2,
               count(r) as cooccurrence_count
        ORDER BY cooccurrence_count DESC
        """

        cooccurrences = await self.neo4j.query(query)

        # Generate vectors for high-frequency pairs
        vectors_generated = 0
        for row in cooccurrences:
            if row["cooccurrence_count"] >= 5:  # Min threshold
                vector = await self._generate_cooccurrence_vector(
                    row["tech1"], row["tech2"], row["cooccurrence_count"]
                )

                await self.opensearch.index_cooccurrence_vector(
                    tech1=row["tech1"],
                    tech2=row["tech2"],
                    vector=vector,
                    count=row["cooccurrence_count"]
                )

                vectors_generated += 1

        logger.info(f"Generated {vectors_generated} co-occurrence vectors")

        return {"vectors_generated": vectors_generated}
```

### Phase 4: Tracking and Monitoring (Week 4)

```python
# vector_tracking.py

class VectorUpdateTracker:
    """Track vector freshness and update history"""

    def __init__(self):
        self.redis = RedisClient()
        self.metrics = MetricsClient()

    async def record_update(
        self,
        vector_type: VectorType,
        entity_id: str,
        success: bool = True,
        duration_ms: Optional[int] = None
    ):
        """Record single vector update"""

        key = f"vector:update:{vector_type.value}:{entity_id}"

        update_record = {
            "timestamp": datetime.utcnow().isoformat(),
            "success": success,
            "duration_ms": duration_ms
        }

        # Store in Redis with TTL
        await self.redis.set(
            key,
            json.dumps(update_record),
            ex=86400 * 30  # 30 days retention
        )

        # Update metrics
        self.metrics.increment(
            f"vector_updates_{vector_type.value}",
            tags={"success": str(success)}
        )

        if duration_ms:
            self.metrics.histogram(
                f"vector_update_duration_ms",
                duration_ms,
                tags={"type": vector_type.value}
            )

    async def get_staleness_report(self) -> Dict:
        """Generate report on vector staleness"""

        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "vector_types": {}
        }

        for vector_type in VectorType:
            pattern = f"vector:update:{vector_type.value}:*"
            keys = await self.redis.scan_keys(pattern)

            stale_count = 0
            fresh_count = 0
            total_count = len(keys)

            for key in keys:
                update_data = await self.redis.get(key)
                if update_data:
                    update = json.loads(update_data)
                    update_time = datetime.fromisoformat(update["timestamp"])
                    age = datetime.utcnow() - update_time

                    if age > timedelta(days=7):
                        stale_count += 1
                    else:
                        fresh_count += 1

            report["vector_types"][vector_type.value] = {
                "total": total_count,
                "fresh": fresh_count,
                "stale": stale_count,
                "staleness_percentage": (
                    (stale_count / total_count * 100) if total_count > 0 else 0
                )
            }

        return report

    async def needs_update(
        self,
        vector_type: VectorType,
        entity_id: str,
        max_age_hours: int = 24
    ) -> bool:
        """Check if specific vector needs updating"""

        key = f"vector:update:{vector_type.value}:{entity_id}"
        update_data = await self.redis.get(key)

        if not update_data:
            return True  # No record, needs update

        update = json.loads(update_data)
        update_time = datetime.fromisoformat(update["timestamp"])
        age = datetime.utcnow() - update_time

        return age > timedelta(hours=max_age_hours)
```

## Tracking and Monitoring

### Key Metrics

1. **Update Latency**
   - P50/P95/P99 latencies per vector type
   - Queue depth and processing time
   - Batch processing duration

2. **Vector Freshness**
   - Percentage of vectors updated in last 24h/7d/30d
   - Oldest vector age by type
   - Update failure rate

3. **System Performance**
   - Embedding generation rate (vectors/second)
   - OpenSearch indexing throughput
   - Memory usage during batch processing

### Dashboard Queries

```python
# Example dashboard queries

# Vector freshness by type
GET /metrics/vector_freshness
{
  "aggregations": {
    "by_type": {
      "terms": {
        "field": "vector_type"
      },
      "aggs": {
        "age_buckets": {
          "range": {
            "field": "age_hours",
            "ranges": [
              {"to": 24, "key": "fresh"},
              {"from": 24, "to": 168, "key": "recent"},
              {"from": 168, "key": "stale"}
            ]
          }
        }
      }
    }
  }
}

# Update performance trends
GET /metrics/vector_updates/_search
{
  "aggregations": {
    "updates_over_time": {
      "date_histogram": {
        "field": "timestamp",
        "interval": "1h"
      },
      "aggs": {
        "avg_duration": {
          "avg": {"field": "duration_ms"}
        },
        "success_rate": {
          "terms": {"field": "success"}
        }
      }
    }
  }
}
```

### Alert Rules

```yaml
# alerts.yaml

alerts:
  - name: vector_staleness_high
    condition: staleness_percentage > 20
    severity: warning
    message: "More than 20% of vectors are stale"

  - name: batch_processing_failed
    condition: batch_success_rate < 95
    severity: critical
    message: "Batch vector processing failure rate exceeded"

  - name: update_queue_backlog
    condition: queue_depth > 1000
    severity: warning
    message: "Vector update queue backlog growing"

  - name: embedding_service_slow
    condition: p95_latency > 1000ms
    severity: warning
    message: "Embedding generation P95 latency exceeds 1s"
```

## Performance Considerations

### Optimization Strategies

1. **Batch Size Tuning**
   ```python
   OPTIMAL_BATCH_SIZES = {
       VectorType.ENTITY: 100,
       VectorType.TECHNIQUE: 200,
       VectorType.FLOW: 50,
       VectorType.RELATIONSHIP: 500
   }
   ```

2. **Caching Strategy**
   - Cache frequently accessed vectors in Redis
   - Use TTL based on vector type and access patterns
   - Implement cache warming after batch updates

3. **Parallel Processing**
   - Use asyncio for I/O-bound operations
   - Implement semaphores to limit concurrent requests
   - Distribute batch processing across workers

4. **Resource Management**
   ```python
   # Resource limits
   MAX_CONCURRENT_EMBEDDINGS = 10
   MAX_OPENSEARCH_BULK_SIZE = 500
   MAX_MEMORY_PER_BATCH_GB = 4
   ```

### Benchmarks

| Operation | Target Latency | Current | Notes |
|-----------|---------------|---------|-------|
| Single entity vector | <500ms | - | Including embedding generation |
| Report vector update | <1s | - | Full content processing |
| Batch (100 entities) | <30s | - | Parallel processing |
| Co-occurrence regeneration | <5min | - | Full graph analysis |
| Flow vector update | <2s | - | Sequence processing |

## Configuration

### Environment Variables

```bash
# Vector update configuration
VECTOR_UPDATE_STRATEGY="hybrid"              # immediate, batch, or hybrid
VECTOR_IMMEDIATE_THRESHOLD=10                # Max items for immediate update
VECTOR_BATCH_QUEUE_THRESHOLD=100            # Trigger batch processing
VECTOR_BATCH_SCHEDULE="0 2 * * *"           # Cron expression for batch
VECTOR_MAX_PARALLEL_WORKERS=4               # Parallel processing limit

# Embedding service
EMBEDDING_MODEL="all-MiniLM-L6-v2"          # Sentence transformer model
EMBEDDING_BATCH_SIZE=32                     # Batch size for encoding
EMBEDDING_CACHE_ENABLED=true                # Cache embeddings
EMBEDDING_CACHE_TTL=3600                    # Cache TTL in seconds

# OpenSearch settings
OPENSEARCH_VECTOR_INDEX_SHARDS=2            # Number of shards
OPENSEARCH_VECTOR_INDEX_REPLICAS=1          # Number of replicas
OPENSEARCH_BULK_SIZE=100                    # Bulk indexing size
OPENSEARCH_BULK_TIMEOUT=30                  # Bulk timeout in seconds

# Monitoring
VECTOR_METRICS_ENABLED=true                 # Enable metrics collection
VECTOR_METRICS_INTERVAL=60                  # Metrics collection interval
VECTOR_ALERT_EMAIL="ops@example.com"        # Alert notification email
```

### Configuration File

```yaml
# vector_config.yaml

vector_updates:
  strategy: hybrid

  immediate:
    threshold: 10
    timeout_ms: 5000
    retry_attempts: 3

  batch:
    queue_name: "vector_update_queue"
    trigger_threshold: 100
    schedule:
      daily: "02:00"
      weekly: "sunday 03:00"
    max_batch_size: 1000

  vector_types:
    report:
      priority: 0
      update_mode: immediate
      cache_ttl: 3600

    entity:
      priority: 1
      update_mode: hybrid
      immediate_threshold: 5
      cache_ttl: 7200

    technique:
      priority: 2
      update_mode: batch
      regeneration_schedule: "daily"
      cache_ttl: 86400

    flow:
      priority: 1
      update_mode: immediate
      cache_ttl: 3600

    relationship:
      priority: 3
      update_mode: batch
      regeneration_schedule: "daily"
      cache_ttl: 86400

    cooccurrence:
      priority: 3
      update_mode: batch
      regeneration_schedule: "weekly"
      min_frequency: 5
      cache_ttl: 604800
```

## Migration Plan

### Phase 1: Initial Vector Generation

```bash
# Generate initial vectors for existing data
python -m bandjacks.vectors.initialize_all

# Verify vector coverage
python -m bandjacks.vectors.verify_coverage

# Run benchmark tests
python -m bandjacks.vectors.benchmark
```

### Phase 2: Enable Hybrid Updates

1. Deploy vector update manager
2. Configure immediate update threshold
3. Set up batch processing schedule
4. Enable monitoring and alerts

### Phase 3: Optimization

1. Analyze update patterns
2. Tune batch sizes and thresholds
3. Implement caching strategy
4. Optimize parallel processing

### Migration Checklist

- [ ] Deploy vector update infrastructure
- [ ] Generate initial vectors for all entities
- [ ] Configure update strategies per vector type
- [ ] Set up batch processing schedules
- [ ] Enable monitoring and dashboards
- [ ] Configure alerts
- [ ] Test failover and recovery
- [ ] Document operational procedures
- [ ] Train team on vector management
- [ ] Establish SLAs for vector freshness

## Operational Procedures

### Manual Vector Regeneration

```bash
# Regenerate all vectors for a specific type
python -m bandjacks.vectors.regenerate --type=entity

# Regenerate vectors for specific report
python -m bandjacks.vectors.regenerate --report-id=report--uuid

# Force immediate processing of queue
python -m bandjacks.vectors.process_queue --force
```

### Troubleshooting

```bash
# Check vector staleness
python -m bandjacks.vectors.check_staleness

# Verify vector integrity
python -m bandjacks.vectors.verify --entity-id=entity--uuid

# Clear stuck queue items
python -m bandjacks.vectors.clear_stuck_queue

# Reindex vectors in OpenSearch
python -m bandjacks.vectors.reindex --index=entities
```

### Recovery Procedures

1. **Embedding Service Failure**
   - Switch to backup embedding service
   - Queue updates for retry
   - Alert on-call team

2. **OpenSearch Indexing Failure**
   - Retry with exponential backoff
   - Store vectors in backup storage
   - Trigger manual reindexing

3. **Batch Processing Failure**
   - Log failed items for investigation
   - Retry individual items
   - Skip and continue if necessary

## Future Enhancements

### Short Term (Q1)
- [ ] Implement vector versioning
- [ ] Add support for multiple embedding models
- [ ] Optimize batch processing performance
- [ ] Add vector quality metrics

### Medium Term (Q2)
- [ ] Machine learning for update priority
- [ ] Predictive cache warming
- [ ] Dynamic threshold adjustment
- [ ] A/B testing for embedding models

### Long Term (Q3-Q4)
- [ ] Distributed vector processing
- [ ] Real-time vector streaming
- [ ] Graph embedding techniques
- [ ] Custom embedding models

## Appendix

### Vector Schemas

```json
// Report Vector Schema
{
  "report_id": "report--uuid",
  "vector": [0.1, 0.2, ...],  // 768 dimensions
  "metadata": {
    "title": "Report Title",
    "created": "2024-01-01T00:00:00Z",
    "updated": "2024-01-02T00:00:00Z",
    "vector_version": "1.0",
    "model": "all-MiniLM-L6-v2"
  }
}

// Entity Vector Schema
{
  "entity_id": "entity--uuid",
  "entity_type": "intrusion-set",
  "vector": [0.1, 0.2, ...],
  "metadata": {
    "name": "APT28",
    "confidence": 95,
    "techniques_count": 45,
    "reports_count": 12,
    "updated": "2024-01-02T00:00:00Z"
  }
}

// Co-occurrence Vector Schema
{
  "pair_id": "tech1--uuid:tech2--uuid",
  "vector": [0.1, 0.2, ...],
  "metadata": {
    "tech1": "T1566.001",
    "tech2": "T1055",
    "cooccurrence_count": 15,
    "confidence": 0.85,
    "updated": "2024-01-02T00:00:00Z"
  }
}
```

### API Endpoints

```yaml
# Vector management endpoints
POST   /v1/vectors/update           # Trigger immediate update
POST   /v1/vectors/batch            # Trigger batch processing
GET    /v1/vectors/status           # Get update status
GET    /v1/vectors/staleness        # Get staleness report
DELETE /v1/vectors/cache            # Clear vector cache
POST   /v1/vectors/regenerate       # Force regeneration
GET    /v1/vectors/metrics          # Get vector metrics
```

## References

- [Sentence Transformers Documentation](https://www.sbert.net/)
- [OpenSearch KNN Plugin](https://opensearch.org/docs/latest/search-plugins/knn/)
- [Vector Database Benchmarks](https://github.com/erikbern/ann-benchmarks)
- [Embedding Best Practices](https://www.pinecone.io/learn/vector-embeddings/)