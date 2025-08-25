"""Async report ingestion endpoints for handling long-running extractions."""

import asyncio
import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from uuid import uuid4
from fastapi import APIRouter, HTTPException, BackgroundTasks, UploadFile, File, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import httpx

from bandjacks.services.api.routes.reports import (
    ReportSDO,
    # ExtractionConfig,  # TODO: Fix this import
    create_stix_bundle,
    evaluate_campaign_rubric,
    extract_text_from_pdf
)

# Temporary ExtractionConfig definition
class ExtractionConfig(BaseModel):
    """Configuration for extraction process."""
    chunk_size: int = Field(default=3000, description="Size of text chunks")
    chunk_overlap: int = Field(default=200, description="Overlap between chunks")
    max_chunks: int = Field(default=50, description="Maximum number of chunks to process")
from bandjacks.llm.chunked_extractor import extract_chunked
from bandjacks.llm.tracker import ExtractionTracker
from bandjacks.llm.bundle_validator import validate_bundle_for_upsert
from bandjacks.store.report_store import ReportStore
from bandjacks.services.api.settings import settings


router = APIRouter(prefix="/reports", tags=["reports_async"])


# In-memory job store (in production, use Redis or database)
JOB_STORE: Dict[str, Dict[str, Any]] = {}


class AsyncIngestRequest(BaseModel):
    """Request for async report ingestion."""
    inline_text: Optional[str] = Field(None, description="Inline text content")
    file_url: Optional[str] = Field(None, description="URL to download file from")
    report_sdo: Optional[ReportSDO] = Field(None, description="Optional Report SDO")
    config: ExtractionConfig = Field(default_factory=ExtractionConfig)
    webhook_url: Optional[str] = Field(None, description="Webhook to call on completion")


class JobResponse(BaseModel):
    """Response with job information."""
    job_id: str
    status: str
    message: str
    status_url: str
    

class JobStatus(BaseModel):
    """Job status information."""
    job_id: str
    status: str  # pending, processing, completed, failed
    progress: int  # 0-100
    message: str
    started_at: Optional[str]
    completed_at: Optional[str]
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


async def process_report_async(
    job_id: str,
    text_content: str,
    report_sdo: ReportSDO,
    config: Dict[str, Any],
    webhook_url: Optional[str] = None
):
    """
    Background task to process report extraction.
    
    Args:
        job_id: Unique job identifier
        text_content: Report text to process
        report_sdo: Report SDO metadata
        config: Extraction configuration
        webhook_url: Optional webhook for completion notification
    """
    # Update job status
    JOB_STORE[job_id]["status"] = "processing"
    JOB_STORE[job_id]["started_at"] = datetime.utcnow().isoformat()
    JOB_STORE[job_id]["message"] = "Extracting techniques from report..."
    
    try:
        # Use chunked extraction for all async processing
        extraction_results = extract_chunked(
            text=text_content,
            config=config,
            chunk_size=3000,
            overlap=200,
            max_chunks=15,  # Allow more chunks for async
            parallel=True
        )
        
        JOB_STORE[job_id]["progress"] = 60
        JOB_STORE[job_id]["message"] = "Evaluating campaign rubric..."
        
        # Evaluate campaign rubric
        claims = extraction_results.get("claims", [])
        rubric, rubric_evidence = evaluate_campaign_rubric(
            claims, 
            config.get("force_provisional_campaign", False)
        )
        
        JOB_STORE[job_id]["progress"] = 80
        JOB_STORE[job_id]["message"] = "Creating STIX bundle..."
        
        # Create STIX bundle
        bundle = create_stix_bundle(
            report_sdo,
            extraction_results,
            rubric,
            rubric_evidence
        )
        
        # Validate bundle
        is_valid, validation_errors = validate_bundle_for_upsert(bundle)
        if not is_valid:
            raise ValueError(f"Invalid STIX bundle: {'; '.join(validation_errors)}")
        
        JOB_STORE[job_id]["progress"] = 90
        JOB_STORE[job_id]["message"] = "Upserting to graph..."
        
        # Upsert to graph
        report_store = ReportStore(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        upsert_result = report_store.upsert_bundle(bundle)
        report_store.close()
        
        # Prepare result
        result = {
            "report_id": bundle["objects"][0]["id"],
            "techniques_count": len(extraction_results.get("techniques", {})),
            "claims_count": len(claims),
            "campaign_created": rubric.created_campaign,
            "bundle_size": len(bundle.get("objects", [])),
            "extraction_metrics": extraction_results.get("metrics", {}),
            "upsert_result": upsert_result
        }
        
        # Update job as completed
        JOB_STORE[job_id].update({
            "status": "completed",
            "progress": 100,
            "message": "Report processing completed successfully",
            "completed_at": datetime.utcnow().isoformat(),
            "result": result
        })
        
        # Call webhook if provided
        if webhook_url:
            await notify_webhook(webhook_url, job_id, "completed", result)
        
    except Exception as e:
        # Update job as failed
        JOB_STORE[job_id].update({
            "status": "failed",
            "message": "Report processing failed",
            "completed_at": datetime.utcnow().isoformat(),
            "error": str(e)
        })
        
        # Call webhook if provided
        if webhook_url:
            await notify_webhook(webhook_url, job_id, "failed", {"error": str(e)})


async def notify_webhook(webhook_url: str, job_id: str, status: str, data: Dict[str, Any]):
    """Send webhook notification."""
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                webhook_url,
                json={
                    "job_id": job_id,
                    "status": status,
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": data
                },
                timeout=10
            )
    except Exception as e:
        print(f"[WARNING] Webhook notification failed: {e}")


@router.post(
    "/ingest_async",
    response_model=JobResponse,
    operation_id="ingestReportAsync",
    summary="Async Report Ingestion",
    description="""
    Start async report ingestion job. Returns immediately with job ID.
    Use the status endpoint to check progress and retrieve results.
    """
)
async def ingest_report_async(
    background_tasks: BackgroundTasks,
    request: AsyncIngestRequest
):
    """Start async report ingestion."""
    
    # Generate job ID
    job_id = f"job-{uuid4()}"
    
    # Initialize job in store
    JOB_STORE[job_id] = {
        "job_id": job_id,
        "status": "pending",
        "progress": 0,
        "message": "Job queued for processing",
        "created_at": datetime.utcnow().isoformat(),
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None
    }
    
    # Get text content
    if request.inline_text:
        text_content = request.inline_text
    elif request.file_url:
        # TODO: Implement file download
        raise HTTPException(status_code=501, detail="File URL extraction not yet implemented")
    else:
        raise HTTPException(status_code=400, detail="Either inline_text or file_url must be provided")
    
    # Create or use provided Report SDO
    if not request.report_sdo:
        request.report_sdo = ReportSDO(
            name="Extracted Report",
            description="Auto-generated report from async extraction",
            published=datetime.utcnow().isoformat()
        )
    
    # Add background task
    background_tasks.add_task(
        process_report_async,
        job_id,
        text_content,
        request.report_sdo,
        request.config.dict(),
        request.webhook_url
    )
    
    return JobResponse(
        job_id=job_id,
        status="pending",
        message="Report ingestion job started",
        status_url=f"/v1/reports/jobs/{job_id}/status"
    )


@router.post(
    "/ingest_file_async",
    response_model=JobResponse,
    operation_id="ingestFileAsync",
    summary="Async File Ingestion",
    description="Upload a PDF file for async processing"
)
async def ingest_file_async(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    config: str = Form('{}'),
    webhook_url: Optional[str] = Form(None)
):
    """Upload and process a file asynchronously."""
    
    # Validate file type
    if not file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=400, detail="Only PDF files are supported")
    
    # Generate job ID
    job_id = f"job-{uuid4()}"
    
    # Initialize job in store
    JOB_STORE[job_id] = {
        "job_id": job_id,
        "status": "pending",
        "progress": 0,
        "message": "Processing uploaded file",
        "created_at": datetime.utcnow().isoformat(),
        "file_name": file.filename,
        "started_at": None,
        "completed_at": None,
        "result": None,
        "error": None
    }
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
        content = await file.read()
        tmp_file.write(content)
        temp_path = tmp_file.name
    
    # Extract text from PDF
    try:
        text_content = extract_text_from_pdf(temp_path)
        Path(temp_path).unlink()  # Clean up temp file
    except Exception as e:
        Path(temp_path).unlink()  # Clean up temp file
        JOB_STORE[job_id]["status"] = "failed"
        JOB_STORE[job_id]["error"] = f"PDF extraction failed: {e}"
        raise HTTPException(status_code=400, detail=f"Failed to extract text from PDF: {e}")
    
    # Parse config
    try:
        config_dict = json.loads(config) if config else {}
    except json.JSONDecodeError:
        config_dict = {}
    
    extraction_config = ExtractionConfig(**config_dict)
    
    # Create Report SDO
    report_sdo = ReportSDO(
        name=file.filename,
        description=f"Extracted from {file.filename}",
        published=datetime.utcnow().isoformat()
    )
    
    # Add background task
    background_tasks.add_task(
        process_report_async,
        job_id,
        text_content,
        report_sdo,
        extraction_config.dict(),
        webhook_url
    )
    
    return JobResponse(
        job_id=job_id,
        status="pending",
        message=f"File {file.filename} queued for processing",
        status_url=f"/v1/reports/jobs/{job_id}/status"
    )


@router.get(
    "/jobs/{job_id}/status",
    response_model=JobStatus,
    operation_id="getJobStatus",
    summary="Get Job Status",
    description="Check the status of an async ingestion job"
)
async def get_job_status(job_id: str):
    """Get status of an async job."""
    
    if job_id not in JOB_STORE:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    
    return JobStatus(**JOB_STORE[job_id])


@router.get(
    "/jobs",
    operation_id="listJobs",
    summary="List Jobs",
    description="List all async ingestion jobs"
)
async def list_jobs():
    """List all jobs with their current status."""
    
    jobs = []
    for job_id, job_data in JOB_STORE.items():
        jobs.append({
            "job_id": job_id,
            "status": job_data["status"],
            "progress": job_data.get("progress", 0),
            "created_at": job_data.get("created_at"),
            "file_name": job_data.get("file_name")
        })
    
    return {
        "total": len(jobs),
        "jobs": sorted(jobs, key=lambda x: x["created_at"], reverse=True)
    }


@router.delete(
    "/jobs/{job_id}",
    operation_id="deleteJob",
    summary="Delete Job",
    description="Delete a completed or failed job from the store"
)
async def delete_job(job_id: str):
    """Delete a job from the store."""
    
    if job_id not in JOB_STORE:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    
    job = JOB_STORE[job_id]
    
    # Only allow deletion of completed or failed jobs
    if job["status"] not in ["completed", "failed"]:
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot delete job in {job['status']} status"
        )
    
    del JOB_STORE[job_id]
    
    return {"message": f"Job {job_id} deleted"}