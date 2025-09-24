"""Redis-based job store with atomic operations and distributed locking."""

import json
import os
import time
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging
import redis
from redis.lock import Lock

logger = logging.getLogger(__name__)


class RedisJobStore:
    """Redis-based job store with atomic claiming and distributed locking.
    
    This store provides:
    - Atomic job claiming to prevent duplicate processing
    - Worker heartbeats to detect failures
    - Automatic recovery of abandoned jobs
    - Quality-based result merging for duplicate processing
    """
    
    # Key prefixes for Redis organization
    JOB_PREFIX = "job:"
    QUEUE_KEY = "job:queue"
    PROCESSING_SET = "job:processing"
    COMPLETED_SET = "job:completed"
    LOCK_PREFIX = "lock:job:"
    HEARTBEAT_PREFIX = "heartbeat:"
    WORKER_PREFIX = "worker:"
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        lock_timeout: int = 600,  # 10 minutes
        heartbeat_ttl: int = 60,  # 1 minute
        decode_responses: bool = False
    ):
        """Initialize Redis connection and settings.
        
        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password (if required)
            lock_timeout: Maximum time a job can be locked (seconds)
            heartbeat_ttl: TTL for worker heartbeats (seconds)
            decode_responses: Whether to decode responses as strings
        """
        self.redis = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password,
            decode_responses=decode_responses
        )
        self.lock_timeout = lock_timeout
        self.heartbeat_ttl = heartbeat_ttl
        
        # Generate unique worker ID for this process
        self.worker_id = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
        logger.info(f"RedisJobStore initialized with worker_id: {self.worker_id}")
        
        # Test connection
        try:
            self.redis.ping()
            logger.info("Redis connection successful")
        except redis.ConnectionError as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    def create_job(
        self,
        job_id: str,
        file_path: str,
        file_name: str,
        file_ext: str,
        file_size: int,
        config: Dict[str, Any],
        file_content: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Create a new job and add to queue.
        
        Args:
            job_id: Unique job identifier
            file_path: Path to the saved file
            file_name: Original filename
            file_ext: File extension
            file_size: Size of the file in bytes
            config: Processing configuration
            file_content: Optional file content to store in Redis
            
        Returns:
            The created job data
        """
        # Store file content in Redis if provided
        if file_content:
            content_key = f"job:content:{job_id}"
            self.redis.set(content_key, file_content, ex=3600)  # Expire after 1 hour
            logger.info(f"Stored file content in Redis for job {job_id} ({len(file_content)} bytes)")
            # Use Redis key instead of file path
            file_path = f"redis://{content_key}"
        
        job_data = {
            "job_id": job_id,
            "status": "queued",
            "progress": 0,
            "message": "Job queued for processing",
            "created_at": datetime.utcnow().isoformat(),
            "file_path": file_path,
            "file_name": file_name,
            "file_ext": file_ext,
            "file_size": file_size,
            "config": config,
            "result": None,
            "error": None,
            "started_at": None,
            "completed_at": None,
            "worker_id": None,
            "claimed_at": None,
            "retry_count": 0
        }
        
        # Store job data
        job_key = f"{self.JOB_PREFIX}{job_id}"
        self.redis.set(job_key, json.dumps(job_data))
        
        # Add to queue
        self.redis.rpush(self.QUEUE_KEY, job_id)
        
        logger.info(f"Created job {job_id}")
        return job_data
    
    def claim_and_get_next_job(self, worker_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Atomically claim the next available job.
        
        This method uses Redis atomic operations to ensure only one worker
        can claim a job. It also checks for abandoned jobs to reclaim.
        
        Args:
            worker_id: Worker identifier (uses self.worker_id if not provided)
            
        Returns:
            Job data if claimed successfully, None if no jobs available
        """
        worker_id = worker_id or self.worker_id
        
        # First, try to reclaim abandoned jobs
        self._reclaim_abandoned_jobs()
        
        # Use Redis transaction to atomically claim a job
        pipeline = self.redis.pipeline()
        
        # Pop from queue
        pipeline.lpop(self.QUEUE_KEY)
        result = pipeline.execute()
        
        job_id = result[0]
        if not job_id:
            return None
        
        # Handle bytes if not decoded
        if isinstance(job_id, bytes):
            job_id = job_id.decode('utf-8')
        
        # Try to acquire lock on this job
        lock_key = f"{self.LOCK_PREFIX}{job_id}"
        lock = Lock(self.redis, lock_key, timeout=self.lock_timeout, thread_local=False)
        
        if not lock.acquire(blocking=False):
            # Another worker got the lock, re-queue the job
            self.redis.rpush(self.QUEUE_KEY, job_id)
            logger.debug(f"Failed to acquire lock for job {job_id}")
            return None
        
        try:
            # Get job data
            job_key = f"{self.JOB_PREFIX}{job_id}"
            job_data = self.redis.get(job_key)
            
            if not job_data:
                logger.warning(f"Job {job_id} not found after claiming")
                return None
            
            # Parse job data
            if isinstance(job_data, bytes):
                job_data = job_data.decode('utf-8')
            job = json.loads(job_data)
            
            # Check if job is already completed
            if job.get("status") == "completed":
                logger.warning(f"✅ Job {job_id} is already completed, skipping claim")
                # Release lock and don't process
                lock.release()
                # Clean up if it's in processing set
                self.redis.srem(self.PROCESSING_SET, job_id)
                # Try next job
                return self.claim_and_get_next_job(worker_id)
            
            # Check if job is failed (might want to skip these too)
            if job.get("status") == "failed":
                logger.warning(f"Job {job_id} is failed, skipping")
                lock.release()
                # Try next job
                return self.claim_and_get_next_job(worker_id)
            
            # Check if job is in retry state (waiting to retry)
            if job.get("status") == "retrying":
                # Check if it's owned by current worker
                if job.get("worker_id") == worker_id:
                    logger.info(f"⚡ Job {job_id} is owned by this worker and in retry state - reclaiming for retry")
                    # This worker owns it - allow reclaim for retry
                else:
                    logger.info(f"⏳ Job {job_id} is in retry state by worker {job.get('worker_id')}, skipping")
                    lock.release()
                    # Put it back in queue for later
                    self.redis.rpush(self.QUEUE_KEY, job_id)
                    # Try next job
                    return self.claim_and_get_next_job(worker_id)
            
            # Update job with claim information
            job.update({
                "status": "processing",
                "worker_id": worker_id,
                "claimed_at": datetime.utcnow().isoformat(),
                "started_at": datetime.utcnow().isoformat(),
                "message": f"Processing by worker {worker_id}"
            })
            
            # Save updated job
            self.redis.set(job_key, json.dumps(job))
            
            # Add to processing set
            self.redis.sadd(self.PROCESSING_SET, job_id)
            
            # Set initial heartbeat
            self._update_heartbeat(job_id, worker_id)
            
            logger.info(f"Worker {worker_id} claimed job {job_id}")
            return job
            
        except Exception as e:
            # Release lock on error
            lock.release()
            # Re-queue the job
            self.redis.rpush(self.QUEUE_KEY, job_id)
            logger.error(f"Error claiming job {job_id}: {e}")
            return None
    
    def update_heartbeat(self, job_id: str, worker_id: Optional[str] = None) -> bool:
        """Update worker heartbeat for a job.
        
        Args:
            job_id: Job identifier
            worker_id: Worker identifier (uses self.worker_id if not provided)
            
        Returns:
            True if heartbeat updated, False if job not owned by worker
        """
        worker_id = worker_id or self.worker_id
        return self._update_heartbeat(job_id, worker_id)
    
    def _update_heartbeat(self, job_id: str, worker_id: str) -> bool:
        """Internal method to update heartbeat."""
        heartbeat_key = f"{self.HEARTBEAT_PREFIX}{job_id}"
        heartbeat_data = {
            "worker_id": worker_id,
            "timestamp": time.time(),
            "job_id": job_id
        }
        
        # Set heartbeat with TTL
        self.redis.setex(
            heartbeat_key,
            self.heartbeat_ttl,
            json.dumps(heartbeat_data)
        )
        
        # Also update job's last_heartbeat field
        job_key = f"{self.JOB_PREFIX}{job_id}"
        job_data = self.redis.get(job_key)
        
        if job_data:
            if isinstance(job_data, bytes):
                job_data = job_data.decode('utf-8')
            job = json.loads(job_data)
            
            # Verify ownership
            if job.get("worker_id") != worker_id:
                logger.warning(f"Worker {worker_id} doesn't own job {job_id}")
                return False
            
            job["last_heartbeat"] = datetime.utcnow().isoformat()
            self.redis.set(job_key, json.dumps(job))
            return True
        
        return False
    
    def complete_job(
        self,
        job_id: str,
        result: Dict[str, Any],
        worker_id: Optional[str] = None
    ) -> bool:
        """Mark a job as completed.
        
        Args:
            job_id: Job identifier
            result: Job result data
            worker_id: Worker identifier (uses self.worker_id if not provided)
            
        Returns:
            True if job completed successfully, False otherwise
        """
        worker_id = worker_id or self.worker_id
        
        # Get job data
        job_key = f"{self.JOB_PREFIX}{job_id}"
        job_data = self.redis.get(job_key)
        
        if not job_data:
            logger.warning(f"Job {job_id} not found")
            return False
        
        if isinstance(job_data, bytes):
            job_data = job_data.decode('utf-8')
        job = json.loads(job_data)
        
        # Check if already completed
        if job.get("status") == "completed":
            logger.warning(f"⚠️ Job {job_id} already completed - handling duplicate completion from worker {worker_id}")
            return self._handle_duplicate_result(job_id, job, result, worker_id)

        # Log ownership but don't block completion to avoid stuck jobs
        expected_worker = job.get("worker_id")
        if expected_worker != worker_id:
            logger.warning(f"⚠️ Worker mismatch for job {job_id}: expected {expected_worker}, got {worker_id} - allowing completion anyway")
            # Don't return False - allow the completion to proceed to avoid stuck jobs
        
        # Update job with result
        job.update({
            "status": "completed",
            "result": result,
            "completed_at": datetime.utcnow().isoformat(),
            "message": "Processing completed successfully",
            "progress": 100
        })
        
        # Save updated job
        self.redis.set(job_key, json.dumps(job))

        # Publish update to subscribers
        self.publish_update(job_id, job)

        # Move from processing to completed set (ensure atomic operation)
        pipe = self.redis.pipeline()
        pipe.srem(self.PROCESSING_SET, job_id)
        pipe.sadd(self.COMPLETED_SET, job_id)
        pipe.execute()

        # Release lock
        lock_key = f"{self.LOCK_PREFIX}{job_id}"
        lock = Lock(self.redis, lock_key, timeout=self.lock_timeout, thread_local=False)
        try:
            lock.release()
        except:
            pass  # Lock may have expired

        # Remove heartbeat
        heartbeat_key = f"{self.HEARTBEAT_PREFIX}{job_id}"
        self.redis.delete(heartbeat_key)

        techniques_count = result.get('techniques_count', 0)
        logger.info(f"✅ Job {job_id} SUCCESSFULLY COMPLETED by worker {worker_id} with {techniques_count} techniques")
        logger.info(f"✅ Job {job_id} removed from processing set and added to completed set")
        return True
    
    def fail_job(
        self,
        job_id: str,
        error: str,
        worker_id: Optional[str] = None
    ) -> bool:
        """Mark a job as failed.
        
        Args:
            job_id: Job identifier
            error: Error message
            worker_id: Worker identifier (uses self.worker_id if not provided)
            
        Returns:
            True if job marked as failed, False otherwise
        """
        worker_id = worker_id or self.worker_id
        
        # Get job data
        job_key = f"{self.JOB_PREFIX}{job_id}"
        job_data = self.redis.get(job_key)
        
        if not job_data:
            logger.warning(f"Job {job_id} not found")
            return False
        
        if isinstance(job_data, bytes):
            job_data = job_data.decode('utf-8')
        job = json.loads(job_data)
        
        # Update job with error
        job.update({
            "status": "failed",
            "error": error,
            "completed_at": datetime.utcnow().isoformat(),
            "message": f"Processing failed: {error[:200]}"
        })
        
        # Save updated job
        self.redis.set(job_key, json.dumps(job))

        # Publish update to subscribers
        self.publish_update(job_id, job)

        # Move from processing to completed set (ensure atomic operation)
        pipe = self.redis.pipeline()
        pipe.srem(self.PROCESSING_SET, job_id)
        pipe.sadd(self.COMPLETED_SET, job_id)
        pipe.execute()
        
        # Release lock
        lock_key = f"{self.LOCK_PREFIX}{job_id}"
        lock = Lock(self.redis, lock_key, timeout=self.lock_timeout, thread_local=False)
        try:
            lock.release()
        except:
            pass  # Lock may have expired
        
        # Remove heartbeat
        heartbeat_key = f"{self.HEARTBEAT_PREFIX}{job_id}"
        self.redis.delete(heartbeat_key)
        
        logger.info(f"Job {job_id} failed by worker {worker_id}: {error[:100]}")
        return True
    
    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job data by ID.
        
        Args:
            job_id: Job identifier
            
        Returns:
            Job data dictionary or None if not found
        """
        job_key = f"{self.JOB_PREFIX}{job_id}"
        job_data = self.redis.get(job_key)
        
        if not job_data:
            return None
        
        if isinstance(job_data, bytes):
            job_data = job_data.decode('utf-8')
        
        return json.loads(job_data)
    
    def update(self, job_id: str, updates: Dict[str, Any]) -> bool:
        """Update job fields and publish update event.

        Args:
            job_id: Job identifier
            updates: Dictionary of fields to update

        Returns:
            True if updated, False if job not found
        """
        job = self.get(job_id)
        if not job:
            return False

        job.update(updates)
        job_key = f"{self.JOB_PREFIX}{job_id}"
        self.redis.set(job_key, json.dumps(job))

        # Publish update to Redis pub/sub channel
        self.publish_update(job_id, job)

        return True

    def publish_update(self, job_id: str, job_data: Dict[str, Any]) -> None:
        """Publish job update to Redis pub/sub channel.

        Args:
            job_id: Job identifier
            job_data: Complete job data to publish
        """
        try:
            channel = f"job:updates:{job_id}"
            message = json.dumps(job_data)
            self.redis.publish(channel, message)
            logger.debug(f"Published update for job {job_id} to channel {channel}")
        except Exception as e:
            # Don't fail if pub/sub fails - it's optional
            logger.warning(f"Failed to publish job update: {e}")
    
    def _reclaim_abandoned_jobs(self) -> int:
        """Reclaim jobs abandoned by dead workers.
        
        Returns:
            Number of jobs reclaimed
        """
        reclaimed = 0
        
        # Get all processing jobs
        processing_jobs = self.redis.smembers(self.PROCESSING_SET)
        
        for job_id in processing_jobs:
            if isinstance(job_id, bytes):
                job_id = job_id.decode('utf-8')
            
            # Check heartbeat
            heartbeat_key = f"{self.HEARTBEAT_PREFIX}{job_id}"
            heartbeat_data = self.redis.get(heartbeat_key)
            
            if not heartbeat_data:
                # No heartbeat, check if job is old enough to reclaim
                job = self.get(job_id)
                if job:
                    status = job.get("status")
                    
                    # If job is completed, clean it from processing set and ensure it's in completed set
                    if status == "completed":
                        logger.warning(f"Found completed job {job_id} in processing set, cleaning up")
                        pipe = self.redis.pipeline()
                        pipe.srem(self.PROCESSING_SET, job_id)
                        pipe.sadd(self.COMPLETED_SET, job_id)
                        pipe.execute()
                        # Release any stale locks and heartbeats
                        lock_key = f"{self.LOCK_PREFIX}{job_id}"
                        heartbeat_key = f"{self.HEARTBEAT_PREFIX}{job_id}"
                        self.redis.delete(lock_key)
                        self.redis.delete(heartbeat_key)
                        continue
                    
                    # Only reclaim if job is actually processing (not retrying or completed)
                    if status == "processing":
                        claimed_at = job.get("claimed_at")
                        if claimed_at:
                            claimed_time = datetime.fromisoformat(claimed_at)
                            elapsed = (datetime.utcnow() - claimed_time).total_seconds()
                            
                            # Reclaim if older than heartbeat TTL * 3 (more tolerance)
                            if elapsed > self.heartbeat_ttl * 3:
                                logger.info(f"Reclaiming abandoned job {job_id} (elapsed: {elapsed}s)")
                                
                                # Reset job status
                                job.update({
                                    "status": "queued",
                                    "worker_id": None,
                                    "claimed_at": None,
                                    "message": "Job reclaimed after worker failure"
                                })
                                
                                # Save and re-queue
                                job_key = f"{self.JOB_PREFIX}{job_id}"
                                self.redis.set(job_key, json.dumps(job))
                                self.redis.srem(self.PROCESSING_SET, job_id)
                                self.redis.rpush(self.QUEUE_KEY, job_id)
                                
                                # Release any locks
                                lock_key = f"{self.LOCK_PREFIX}{job_id}"
                                self.redis.delete(lock_key)
                                
                                reclaimed += 1
        
        if reclaimed > 0:
            logger.info(f"Reclaimed {reclaimed} abandoned jobs")
        
        return reclaimed
    
    def _handle_duplicate_result(
        self,
        job_id: str,
        existing_job: Dict[str, Any],
        new_result: Dict[str, Any],
        worker_id: str
    ) -> bool:
        """Handle duplicate job completion intelligently.
        
        Compares quality metrics and keeps the better result.
        
        Args:
            job_id: Job identifier
            existing_job: Existing completed job data
            new_result: New result from duplicate processing
            worker_id: Worker that produced new result
            
        Returns:
            True if handled successfully
        """
        existing_result = existing_job.get("result", {})
        
        # Compare quality metrics
        existing_techniques = existing_result.get("techniques_count", 0)
        new_techniques = new_result.get("techniques_count", 0)
        
        logger.warning(
            f"Duplicate completion for job {job_id}: "
            f"existing={existing_techniques} techniques, "
            f"new={new_techniques} techniques from worker {worker_id}"
        )
        
        # Keep the better result
        if new_techniques > existing_techniques:
            logger.info(f"📈 Updating job {job_id} with better result from worker {worker_id} ({new_techniques} > {existing_techniques} techniques)")

            existing_job.update({
                "result": new_result,
                "duplicate_count": existing_job.get("duplicate_count", 1) + 1,
                "last_updated_by": worker_id,
                "last_updated_at": datetime.utcnow().isoformat()
            })

            job_key = f"{self.JOB_PREFIX}{job_id}"
            self.redis.set(job_key, json.dumps(existing_job))
        else:
            logger.info(f"📉 Keeping existing result for job {job_id} ({existing_techniques} >= {new_techniques} techniques)")

        # CRITICAL: ALWAYS ensure job is removed from processing set and added to completed set
        # This handles the case where a job was completed but not properly cleaned up
        logger.info(f"🧹 Cleaning up job {job_id} - ensuring it's in completed set and removed from processing")
        pipe = self.redis.pipeline()
        pipe.srem(self.PROCESSING_SET, job_id)
        pipe.sadd(self.COMPLETED_SET, job_id)
        pipe.execute()

        # Clean up any stale locks and heartbeats (force cleanup even if they don't exist)
        lock_key = f"{self.LOCK_PREFIX}{job_id}"
        heartbeat_key = f"{self.HEARTBEAT_PREFIX}{job_id}"
        self.redis.delete(lock_key, heartbeat_key)  # Delete both in one call

        logger.info(f"✅ Job {job_id} fully cleaned up - locks and heartbeats removed")
        return True
    
    def get_queue_length(self) -> int:
        """Get number of jobs in queue.
        
        Returns:
            Number of queued jobs
        """
        return self.redis.llen(self.QUEUE_KEY)
    
    def get_processing_count(self) -> int:
        """Get number of jobs being processed.
        
        Returns:
            Number of jobs currently being processed
        """
        return self.redis.scard(self.PROCESSING_SET)
    
    def get_completed_count(self) -> int:
        """Get number of completed jobs.
        
        Returns:
            Number of completed jobs
        """
        return self.redis.scard(self.COMPLETED_SET)
    
    def cleanup_old_jobs(self, hours: int = 24) -> int:
        """Clean up old completed jobs.
        
        Args:
            hours: Remove jobs older than this many hours
            
        Returns:
            Number of jobs cleaned up
        """
        cutoff = datetime.utcnow().timestamp() - (hours * 3600)
        cleaned = 0
        
        # Get all completed jobs
        completed_jobs = self.redis.smembers(self.COMPLETED_SET)
        
        for job_id in completed_jobs:
            if isinstance(job_id, bytes):
                job_id = job_id.decode('utf-8')
            
            job = self.get(job_id)
            if job and job.get("completed_at"):
                completed_time = datetime.fromisoformat(job["completed_at"])
                if completed_time.timestamp() < cutoff:
                    # Delete job
                    job_key = f"{self.JOB_PREFIX}{job_id}"
                    self.redis.delete(job_key)
                    self.redis.srem(self.COMPLETED_SET, job_id)
                    cleaned += 1
        
        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} old jobs")
        
        return cleaned


# Global singleton instance
_redis_job_store: Optional[RedisJobStore] = None


def get_redis_job_store() -> RedisJobStore:
    """Get the global Redis job store instance.
    
    Returns:
        The singleton RedisJobStore instance
    """
    global _redis_job_store
    if _redis_job_store is None:
        from bandjacks.services.api.settings import settings
        _redis_job_store = RedisJobStore(
            host=settings.redis_host,
            port=settings.redis_port,
            db=settings.redis_db,
            password=settings.redis_password if settings.redis_password else None,
            lock_timeout=settings.redis_lock_timeout,
            heartbeat_ttl=settings.job_heartbeat_ttl
        )
    return _redis_job_store