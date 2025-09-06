#!/usr/bin/env python
"""Test script for Redis-based atomic job claiming."""

import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor
import time

# Add parent directory to path
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from bandjacks.services.api.redis_job_store import RedisJobStore


def create_test_job(store: RedisJobStore, job_num: int):
    """Create a test job."""
    job_id = f"test-job-{job_num}-{uuid.uuid4().hex[:8]}"
    job_data = store.create_job(
        job_id=job_id,
        file_path=f"/tmp/test-{job_num}.pdf",
        file_name=f"test-{job_num}.pdf",
        file_ext=".pdf",
        file_size=1024 * job_num,
        config={"test": True}
    )
    print(f"Created job: {job_id}")
    return job_id


def worker_process(worker_id: str, num_jobs: int = 3):
    """Simulate a worker claiming and processing jobs."""
    store = RedisJobStore()
    store.worker_id = worker_id
    
    claimed_jobs = []
    
    for _ in range(num_jobs):
        job = store.claim_and_get_next_job()
        if job:
            job_id = job['job_id']
            print(f"Worker {worker_id} claimed job {job_id}")
            claimed_jobs.append(job_id)
            
            # Simulate processing
            time.sleep(0.5)
            
            # Complete the job
            store.complete_job(job_id, {
                "techniques_count": 10,
                "processed_by": worker_id
            })
            print(f"Worker {worker_id} completed job {job_id}")
        else:
            print(f"Worker {worker_id} found no jobs to claim")
            time.sleep(0.1)
    
    return claimed_jobs


def main():
    """Run the test."""
    print("="*60)
    print("Testing Redis-based Atomic Job Claiming")
    print("="*60)
    
    # Initialize store and clean up any old test jobs
    store = RedisJobStore()
    
    # Create test jobs
    num_jobs = 10
    job_ids = []
    print(f"\n1. Creating {num_jobs} test jobs...")
    for i in range(num_jobs):
        job_id = create_test_job(store, i)
        job_ids.append(job_id)
    
    print(f"\nQueue length: {store.get_queue_length()}")
    
    # Simulate multiple workers claiming jobs concurrently
    print(f"\n2. Starting 4 workers to process {num_jobs} jobs...")
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for i in range(4):
            worker_id = f"worker-{i}"
            future = executor.submit(worker_process, worker_id, num_jobs // 2)
            futures.append(future)
        
        # Collect results
        all_claimed = []
        for future in futures:
            claimed = future.result()
            all_claimed.extend(claimed)
    
    # Check results
    print(f"\n3. Results:")
    print(f"   Jobs created: {len(job_ids)}")
    print(f"   Jobs claimed: {len(all_claimed)}")
    print(f"   Unique jobs: {len(set(all_claimed))}")
    print(f"   Queue remaining: {store.get_queue_length()}")
    print(f"   Completed: {store.get_completed_count()}")
    
    # Check for duplicates
    if len(all_claimed) != len(set(all_claimed)):
        print("\n❌ ERROR: Duplicate job processing detected!")
        duplicates = [job for job in all_claimed if all_claimed.count(job) > 1]
        print(f"   Duplicate jobs: {set(duplicates)}")
    else:
        print("\n✅ SUCCESS: No duplicate processing - atomic claiming works!")
    
    # Check all jobs were processed
    unclaimed = set(job_ids) - set(all_claimed)
    if unclaimed:
        print(f"\n⚠️ WARNING: Some jobs were not claimed: {unclaimed}")
    
    # Clean up test jobs
    print("\n4. Cleaning up test jobs...")
    for job_id in job_ids:
        job_key = f"job:{job_id}"
        store.redis.delete(job_key)
    store.redis.delete("job:queue")
    store.redis.delete("job:processing")
    store.redis.delete("job:completed")
    
    print("\n" + "="*60)
    print("Test completed!")
    print("="*60)


if __name__ == "__main__":
    main()