"""Vector Update Manager for handling knowledge graph embedding updates."""

import asyncio
import json
import logging
import time
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

import redis
from redis.exceptions import RedisError

from bandjacks.services.api.settings import settings

logger = logging.getLogger(__name__)


class UpdatePriority(Enum):
    """Priority levels for vector updates."""
    IMMEDIATE = "immediate"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


class UpdateAction(Enum):
    """Types of update actions."""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    REGENERATE = "regenerate"


@dataclass
class VectorUpdateRequest:
    """Represents a vector update request."""
    entity_id: str
    entity_type: str
    action: UpdateAction
    priority: UpdatePriority = UpdatePriority.NORMAL
    data: Optional[Dict[str, Any]] = None
    source: Optional[str] = None  # e.g., "unified_review", "report_ingestion"
    timestamp: float = field(default_factory=time.time)
    retry_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Redis storage."""
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "action": self.action.value,
            "priority": self.priority.value,
            "data": self.data,
            "source": self.source,
            "timestamp": self.timestamp,
            "retry_count": self.retry_count
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VectorUpdateRequest":
        """Create from dictionary retrieved from Redis."""
        return cls(
            entity_id=data["entity_id"],
            entity_type=data["entity_type"],
            action=UpdateAction(data["action"]),
            priority=UpdatePriority(data.get("priority", "normal")),
            data=data.get("data"),
            source=data.get("source"),
            timestamp=data.get("timestamp", time.time()),
            retry_count=data.get("retry_count", 0)
        )


@dataclass
class UpdateMetrics:
    """Metrics for vector update operations."""
    total_requests: int = 0
    immediate_updates: int = 0
    batch_updates: int = 0
    successful_updates: int = 0
    failed_updates: int = 0
    retry_count: int = 0
    avg_latency_ms: float = 0.0
    last_batch_time: Optional[float] = None
    queue_depth: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "total_requests": self.total_requests,
            "immediate_updates": self.immediate_updates,
            "batch_updates": self.batch_updates,
            "successful_updates": self.successful_updates,
            "failed_updates": self.failed_updates,
            "retry_count": self.retry_count,
            "avg_latency_ms": self.avg_latency_ms,
            "last_batch_time": self.last_batch_time,
            "queue_depth": self.queue_depth,
            "timestamp": time.time()
        }


class VectorUpdateManager:
    """
    Manages vector embedding updates for the knowledge graph.

    Implements a hybrid approach with immediate updates for small changes
    and batch processing for larger volumes.
    """

    def __init__(self, redis_client: Optional[redis.Redis] = None):
        """
        Initialize the VectorUpdateManager.

        Args:
            redis_client: Optional Redis client for queue management
        """
        self.enabled = settings.vector_update_enabled
        self.immediate_threshold = settings.vector_update_immediate_threshold
        self.batch_interval = settings.vector_update_batch_interval
        self.max_batch_size = settings.vector_update_max_batch_size
        self.parallelization = settings.vector_update_parallelization
        self.queue_name = settings.vector_update_redis_queue
        self.priority_entities = set(settings.vector_update_priority_entities.split(","))

        # Initialize Redis client
        if redis_client:
            self.redis_client = redis_client
        else:
            try:
                self.redis_client = redis.Redis(
                    host=settings.redis_host,
                    port=settings.redis_port,
                    db=settings.redis_db,
                    password=settings.redis_password,
                    decode_responses=False,
                    socket_connect_timeout=2,
                    socket_timeout=2,
                )
                self.redis_client.ping()
                logger.info(f"Vector update manager connected to Redis: {settings.redis_host}:{settings.redis_port}")
            except (RedisError, ConnectionError) as e:
                logger.warning(f"Redis not available for vector updates: {e}")
                self.redis_client = None

        # Metrics tracking
        self.metrics = UpdateMetrics()
        self._latency_samples: List[float] = []
        self._max_latency_samples = 100

        # Batch processing state
        self._batch_task: Optional[asyncio.Task] = None
        self._shutdown = False

        # Executors registry (will be populated by executor classes)
        self._executors: Dict[str, Any] = {}

        logger.info(f"VectorUpdateManager initialized (enabled={self.enabled})")

    async def submit_update(
        self,
        entity_id: str,
        entity_type: str,
        action: UpdateAction = UpdateAction.UPDATE,
        data: Optional[Dict[str, Any]] = None,
        source: Optional[str] = None
    ) -> bool:
        """
        Submit a vector update request.

        Args:
            entity_id: ID of the entity to update
            entity_type: Type of entity (e.g., "AttackPattern", "IntrusionSet")
            action: Type of update action
            data: Optional data for the update
            source: Source of the update request

        Returns:
            True if submitted successfully
        """
        if not self.enabled:
            logger.debug("Vector updates disabled, skipping")
            return False

        # Determine priority
        priority = self._determine_priority(entity_type)

        # Create update request
        request = VectorUpdateRequest(
            entity_id=entity_id,
            entity_type=entity_type,
            action=action,
            priority=priority,
            data=data,
            source=source
        )

        # Update metrics
        self.metrics.total_requests += 1

        # Apply hybrid decision logic
        if await self._should_update_immediately(request):
            return await self._process_immediately(request)
        else:
            return await self._queue_for_batch(request)

    async def submit_batch(
        self,
        updates: List[Tuple[str, str, UpdateAction]],
        source: Optional[str] = None
    ) -> int:
        """
        Submit multiple vector update requests.

        Args:
            updates: List of (entity_id, entity_type, action) tuples
            source: Source of the update requests

        Returns:
            Number of successfully submitted updates
        """
        if not self.enabled:
            return 0

        submitted = 0
        for entity_id, entity_type, action in updates:
            if await self.submit_update(entity_id, entity_type, action, source=source):
                submitted += 1

        return submitted

    def _determine_priority(self, entity_type: str) -> UpdatePriority:
        """
        Determine the priority of an update based on entity type.

        Args:
            entity_type: Type of entity

        Returns:
            Update priority
        """
        if entity_type in self.priority_entities:
            return UpdatePriority.HIGH
        return UpdatePriority.NORMAL

    async def _should_update_immediately(self, request: VectorUpdateRequest) -> bool:
        """
        Determine if an update should be processed immediately.

        Args:
            request: Update request

        Returns:
            True if should process immediately
        """
        # Always process immediate priority
        if request.priority == UpdatePriority.IMMEDIATE:
            return True

        # Check queue depth
        queue_depth = await self._get_queue_depth()

        # Process immediately if under threshold
        if queue_depth < self.immediate_threshold:
            return True

        # Process high priority items immediately if not too many
        if request.priority == UpdatePriority.HIGH and queue_depth < self.immediate_threshold * 2:
            return True

        return False

    async def _process_immediately(self, request: VectorUpdateRequest) -> bool:
        """
        Process an update request immediately.

        Args:
            request: Update request

        Returns:
            True if processed successfully
        """
        start_time = time.time()

        try:
            # Get appropriate executor
            executor = self._get_executor(request.entity_type)
            if not executor:
                logger.warning(f"No executor found for entity type: {request.entity_type}")
                return False

            # Execute update
            success = await executor.execute(request)

            # Update metrics
            latency_ms = (time.time() - start_time) * 1000
            self._update_latency_metrics(latency_ms)

            if success:
                self.metrics.immediate_updates += 1
                self.metrics.successful_updates += 1
                logger.debug(f"Immediate update completed for {request.entity_type}:{request.entity_id}")
            else:
                self.metrics.failed_updates += 1
                logger.warning(f"Immediate update failed for {request.entity_type}:{request.entity_id}")

            return success

        except Exception as e:
            logger.error(f"Error processing immediate update: {e}")
            self.metrics.failed_updates += 1
            return False

    async def _queue_for_batch(self, request: VectorUpdateRequest) -> bool:
        """
        Queue an update request for batch processing.

        Args:
            request: Update request

        Returns:
            True if queued successfully
        """
        if not self.redis_client:
            logger.warning("Redis not available, falling back to immediate processing")
            return await self._process_immediately(request)

        try:
            # Add to queue
            queue_key = f"{self.queue_name}:{request.priority.value}"
            self.redis_client.rpush(
                queue_key,
                json.dumps(request.to_dict())
            )

            self.metrics.batch_updates += 1
            logger.debug(f"Queued update for batch processing: {request.entity_type}:{request.entity_id}")
            return True

        except RedisError as e:
            logger.error(f"Failed to queue update: {e}")
            # Fall back to immediate processing
            return await self._process_immediately(request)

    async def _get_queue_depth(self) -> int:
        """
        Get the current depth of the update queue.

        Returns:
            Total number of items in queue
        """
        if not self.redis_client:
            return 0

        try:
            total = 0
            for priority in UpdatePriority:
                queue_key = f"{self.queue_name}:{priority.value}"
                total += self.redis_client.llen(queue_key)

            self.metrics.queue_depth = total
            return total

        except RedisError:
            return 0

    async def process_batch(self) -> int:
        """
        Process a batch of queued updates.

        Returns:
            Number of updates processed
        """
        if not self.redis_client:
            return 0

        processed = 0
        batch: List[VectorUpdateRequest] = []

        try:
            # Collect batch from queues (priority order)
            for priority in [UpdatePriority.IMMEDIATE, UpdatePriority.HIGH,
                            UpdatePriority.NORMAL, UpdatePriority.LOW]:
                queue_key = f"{self.queue_name}:{priority.value}"

                while len(batch) < self.max_batch_size:
                    item = self.redis_client.lpop(queue_key)
                    if not item:
                        break

                    try:
                        data = json.loads(item)
                        request = VectorUpdateRequest.from_dict(data)
                        batch.append(request)
                    except (json.JSONDecodeError, KeyError) as e:
                        logger.error(f"Invalid queue item: {e}")
                        continue

                if len(batch) >= self.max_batch_size:
                    break

            if not batch:
                return 0

            # Group by entity type for efficient processing
            by_type: Dict[str, List[VectorUpdateRequest]] = {}
            for request in batch:
                if request.entity_type not in by_type:
                    by_type[request.entity_type] = []
                by_type[request.entity_type].append(request)

            # Process each type group in parallel
            tasks = []
            for entity_type, requests in by_type.items():
                executor = self._get_executor(entity_type)
                if executor:
                    # Split into chunks for parallelization
                    chunk_size = max(1, len(requests) // self.parallelization)
                    for i in range(0, len(requests), chunk_size):
                        chunk = requests[i:i + chunk_size]
                        tasks.append(self._process_batch_chunk(executor, chunk))

            # Execute all tasks
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, int):
                        processed += result
                    elif isinstance(result, Exception):
                        logger.error(f"Batch chunk processing error: {result}")

            # Update metrics
            self.metrics.last_batch_time = time.time()
            self.metrics.successful_updates += processed

            logger.info(f"Batch processing completed: {processed}/{len(batch)} updates")
            return processed

        except Exception as e:
            logger.error(f"Batch processing error: {e}")
            return processed

    async def _process_batch_chunk(self, executor: Any, requests: List[VectorUpdateRequest]) -> int:
        """
        Process a chunk of requests with a single executor.

        Args:
            executor: Executor to use
            requests: List of requests to process

        Returns:
            Number of successful updates
        """
        successful = 0

        for request in requests:
            try:
                if await executor.execute(request):
                    successful += 1
                else:
                    # Handle retry logic
                    if request.retry_count < settings.vector_update_retry_attempts:
                        request.retry_count += 1
                        await self._queue_for_batch(request)
                        self.metrics.retry_count += 1
                    else:
                        self.metrics.failed_updates += 1

            except Exception as e:
                logger.error(f"Error processing request {request.entity_id}: {e}")
                self.metrics.failed_updates += 1

        return successful

    def _get_executor(self, entity_type: str) -> Optional[Any]:
        """
        Get the appropriate executor for an entity type.

        Args:
            entity_type: Type of entity

        Returns:
            Executor instance or None
        """
        return self._executors.get(entity_type)

    def register_executor(self, entity_type: str, executor: Any) -> None:
        """
        Register an executor for an entity type.

        Args:
            entity_type: Type of entity
            executor: Executor instance
        """
        self._executors[entity_type] = executor
        logger.info(f"Registered executor for {entity_type}")

    def _update_latency_metrics(self, latency_ms: float) -> None:
        """
        Update latency metrics.

        Args:
            latency_ms: Latency in milliseconds
        """
        self._latency_samples.append(latency_ms)
        if len(self._latency_samples) > self._max_latency_samples:
            self._latency_samples.pop(0)

        if self._latency_samples:
            self.metrics.avg_latency_ms = sum(self._latency_samples) / len(self._latency_samples)

    async def start_batch_processor(self) -> None:
        """Start the background batch processing task."""
        if self._batch_task is None or self._batch_task.done():
            self._batch_task = asyncio.create_task(self._batch_processor_loop())
            logger.info("Started batch processor task")

    async def stop_batch_processor(self) -> None:
        """Stop the background batch processing task."""
        self._shutdown = True
        if self._batch_task and not self._batch_task.done():
            self._batch_task.cancel()
            try:
                await self._batch_task
            except asyncio.CancelledError:
                pass
            logger.info("Stopped batch processor task")

    async def _batch_processor_loop(self) -> None:
        """Background loop for batch processing."""
        logger.info(f"Batch processor started (interval={self.batch_interval}s)")

        while not self._shutdown:
            try:
                # Wait for batch interval
                await asyncio.sleep(self.batch_interval)

                # Check queue depth
                queue_depth = await self._get_queue_depth()
                if queue_depth > 0:
                    logger.info(f"Processing batch with {queue_depth} items in queue")
                    await self.process_batch()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in batch processor loop: {e}")
                await asyncio.sleep(60)  # Wait before retrying

    def get_metrics(self) -> Dict[str, Any]:
        """
        Get current metrics.

        Returns:
            Dictionary of metrics
        """
        return self.metrics.to_dict()

    async def get_status(self) -> Dict[str, Any]:
        """
        Get current status of the vector update system.

        Returns:
            Status dictionary
        """
        queue_depth = await self._get_queue_depth()

        return {
            "enabled": self.enabled,
            "queue_depth": queue_depth,
            "batch_processor_running": self._batch_task and not self._batch_task.done(),
            "executors_registered": list(self._executors.keys()),
            "metrics": self.get_metrics(),
            "config": {
                "immediate_threshold": self.immediate_threshold,
                "batch_interval": self.batch_interval,
                "max_batch_size": self.max_batch_size,
                "parallelization": self.parallelization,
                "priority_entities": list(self.priority_entities)
            }
        }


# Global instance (singleton)
_global_manager: Optional[VectorUpdateManager] = None


def get_vector_update_manager() -> VectorUpdateManager:
    """
    Get the global VectorUpdateManager instance.

    Returns:
        The global VectorUpdateManager instance
    """
    global _global_manager

    if _global_manager is None:
        _global_manager = VectorUpdateManager()

    return _global_manager