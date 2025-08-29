"""Persistent job store for async operations."""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class FileJobStore:
    """File-based persistent job store for async operations.
    
    This store persists jobs to disk to handle multiple worker processes
    and server restarts. Each job is stored as a separate JSON file.
    """
    
    def __init__(self, storage_dir: str = "/tmp/bandjacks_jobs"):
        """Initialize the file-based job store.
        
        Args:
            storage_dir: Directory to store job files
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Clean up old completed jobs on startup (older than 1 hour)
        self._cleanup_old_jobs(hours=1)
    
    def _job_file(self, job_id: str) -> Path:
        """Get the file path for a job."""
        return self.storage_dir / f"{job_id}.json"
    
    def set(self, job_id: str, job_data: Dict[str, Any]) -> None:
        """Store or update a job.
        
        Args:
            job_id: Unique job identifier
            job_data: Job data dictionary
        """
        try:
            job_file = self._job_file(job_id)
            with open(job_file, 'w') as f:
                json.dump(job_data, f, indent=2, default=str)
            logger.debug(f"Stored job {job_id} to {job_file}")
        except Exception as e:
            logger.error(f"Failed to store job {job_id}: {e}")
            raise
    
    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a job by ID.
        
        Args:
            job_id: Unique job identifier
            
        Returns:
            Job data dictionary or None if not found
        """
        try:
            job_file = self._job_file(job_id)
            if job_file.exists():
                with open(job_file, 'r') as f:
                    return json.load(f)
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve job {job_id}: {e}")
            return None
    
    def update(self, job_id: str, updates: Dict[str, Any]) -> None:
        """Update specific fields of a job.
        
        Args:
            job_id: Unique job identifier
            updates: Dictionary of fields to update
        """
        job_data = self.get(job_id)
        if job_data:
            job_data.update(updates)
            self.set(job_id, job_data)
        else:
            logger.warning(f"Job {job_id} not found for update")
    
    def delete(self, job_id: str) -> bool:
        """Delete a job.
        
        Args:
            job_id: Unique job identifier
            
        Returns:
            True if deleted, False if not found
        """
        try:
            job_file = self._job_file(job_id)
            if job_file.exists():
                job_file.unlink()
                logger.debug(f"Deleted job {job_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete job {job_id}: {e}")
            return False
    
    def list_all(self) -> Dict[str, Dict[str, Any]]:
        """List all jobs.
        
        Returns:
            Dictionary of job_id -> job_data
        """
        jobs = {}
        try:
            for job_file in self.storage_dir.glob("*.json"):
                job_id = job_file.stem
                try:
                    with open(job_file, 'r') as f:
                        jobs[job_id] = json.load(f)
                except Exception as e:
                    logger.warning(f"Failed to load job {job_id}: {e}")
                    continue
        except Exception as e:
            logger.error(f"Failed to list jobs: {e}")
        return jobs
    
    def exists(self, job_id: str) -> bool:
        """Check if a job exists.
        
        Args:
            job_id: Unique job identifier
            
        Returns:
            True if job exists, False otherwise
        """
        return self._job_file(job_id).exists()
    
    def get_queued_jobs(self) -> list:
        """Get all jobs with status 'queued'.
        
        Returns:
            List of job IDs that are queued for processing
        """
        queued = []
        try:
            for job_file in self.storage_dir.glob("*.json"):
                job_id = job_file.stem
                try:
                    with open(job_file, 'r') as f:
                        job_data = json.load(f)
                        if job_data.get("status") == "queued":
                            queued.append(job_id)
                except Exception as e:
                    logger.warning(f"Failed to check job {job_id}: {e}")
                    continue
        except Exception as e:
            logger.error(f"Failed to get queued jobs: {e}")
        
        # Sort by created_at to process oldest first
        return queued
    
    def create_job(
        self, 
        job_id: str,
        file_path: str,
        file_name: str,
        file_ext: str,
        file_size: int,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a new job record.
        
        Args:
            job_id: Unique job identifier
            file_path: Path to the saved file
            file_name: Original filename
            file_ext: File extension
            file_size: Size of the file in bytes
            config: Processing configuration
            
        Returns:
            The created job data
        """
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
            "completed_at": None
        }
        
        self.set(job_id, job_data)
        return job_data
    
    def _cleanup_old_jobs(self, hours: int = 24) -> None:
        """Clean up old completed or failed jobs.
        
        Args:
            hours: Remove jobs older than this many hours
        """
        try:
            cutoff = datetime.utcnow().timestamp() - (hours * 3600)
            cleaned = 0
            
            for job_file in self.storage_dir.glob("*.json"):
                try:
                    # Check file modification time
                    if job_file.stat().st_mtime < cutoff:
                        with open(job_file, 'r') as f:
                            job_data = json.load(f)
                        
                        # Only delete completed or failed jobs
                        if job_data.get('status') in ['completed', 'failed']:
                            job_file.unlink()
                            cleaned += 1
                except Exception as e:
                    logger.warning(f"Failed to clean up job file {job_file}: {e}")
                    continue
            
            if cleaned > 0:
                logger.info(f"Cleaned up {cleaned} old job files")
                
        except Exception as e:
            logger.warning(f"Failed to cleanup old jobs: {e}")


# Global singleton instance
_job_store: Optional[FileJobStore] = None


def get_job_store() -> FileJobStore:
    """Get the global job store instance.
    
    Returns:
        The singleton FileJobStore instance
    """
    global _job_store
    if _job_store is None:
        _job_store = FileJobStore()
    return _job_store