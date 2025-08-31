"""Consolidated report management endpoints.

This module combines all report-related functionality:
- Ingestion (sync/async)
- Retrieval and search
- Review workflow
- Attribution management
- Flow generation
- Job management
"""

import os
import uuid
import json
import asyncio
import logging
import tempfile
import shutil
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import httpx

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form, Query, status
from opensearchpy import OpenSearch
from pydantic import BaseModel, Field
from neo4j import Session

from bandjacks.services.api.deps import get_neo4j_session, get_opensearch_client
from bandjacks.services.api.settings import settings
from bandjacks.services.api.job_store import get_job_store
from bandjacks.store.report_store import ReportStore
from bandjacks.store.campaign_store import CampaignStore
from bandjacks.store.opensearch_report_store import OpenSearchReportStore
# Legacy import removed - using extraction_pipeline instead
from bandjacks.llm.flow_builder import FlowBuilder

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])

# Job store is now handled by FileJobStore for persistence across workers


# ============================================================================
# SCHEMA DEFINITIONS
# ============================================================================

class IngestRequest(BaseModel):
    """Request for report ingestion."""
    text: Optional[str] = Field(None, description="Text content to ingest")
    url: Optional[str] = Field(None, description="URL to fetch and ingest")
    name: Optional[str] = Field(None, description="Report name")
    use_batch_mapper: bool = Field(True, description="Use batch mapper for extraction")
    skip_verification: bool = Field(False, description="Skip verification")
    webhook_url: Optional[str] = Field(None, description="Webhook URL for async notifications")


class IngestResponse(BaseModel):
    """Response from report ingestion."""
    report_id: str = Field(..., description="Generated report ID")
    provisional: bool = Field(..., description="Whether report is provisional")
    rubric: Any = Field(..., description="Quality rubric")
    rubric_evidence: Dict[str, Any] = Field(..., description="Evidence for rubric")
    entities: Dict[str, Any] = Field(..., description="Extracted entities")
    trace_id: str = Field(..., description="Trace ID for debugging")
    extraction_metrics: Dict[str, Any] = Field(..., description="Extraction metrics")


class ReportGetResponse(BaseModel):
    """Report retrieval response."""
    report_id: str
    name: str
    description: str
    created: str
    modified: str
    status: str
    extraction: Optional[Dict[str, Any]] = None
    review: Optional[Dict[str, Any]] = None
    attribution: Optional[Dict[str, Any]] = None


class CampaignMergeRequest(BaseModel):
    """Request to merge reports into a campaign."""
    report_ids: List[str] = Field(..., description="Report IDs to merge")
    campaign_name: str = Field(..., description="Campaign name")
    campaign_description: Optional[str] = Field(None, description="Campaign description")
    confidence_threshold: float = Field(0.7, description="Confidence threshold")


class ReviewSubmission(BaseModel):
    """Review submission for a report."""
    reviewer_id: str = Field(..., description="Reviewer ID")
    technique_actions: List[Dict[str, Any]] = Field(..., description="Review actions for techniques")
    notes: Optional[str] = Field(None, description="Review notes")


class ApprovalRequest(BaseModel):
    """Report approval request."""
    reviewer_id: str = Field(..., description="Reviewer ID")
    upsert_to_graph: bool = Field(False, description="Upsert to Neo4j")
    generate_flow: bool = Field(False, description="Generate attack flow")


class JobStatusResponse(BaseModel):
    """Job status response."""
    job_id: str
    status: str
    progress: int
    message: str
    created_at: str
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None


class JobListResponse(BaseModel):
    """Job list response."""
    jobs: List[Dict[str, Any]]
    total: int


class AttributionRequest(BaseModel):
    """Attribution update request."""
    intrusion_sets: List[str] = Field(..., description="Intrusion set IDs")
    malware: List[str] = Field(..., description="Malware IDs")
    confidence: float = Field(..., description="Attribution confidence")
    notes: Optional[str] = Field(None, description="Attribution notes")


class ReportListItem(BaseModel):
    """Report list item."""
    report_id: str
    name: str
    description: str
    created: Optional[str] = None
    modified: Optional[str] = None
    status: str
    extraction_status: Optional[str] = None
    techniques_count: int = 0
    claims_count: int = 0
    confidence_avg: float = 0.0
    has_campaign: bool = False
    has_flow: bool = False
    reviewed_at: Optional[str] = None
    approved_at: Optional[str] = None


class ReportsListResponse(BaseModel):
    """Reports list response."""
    reports: List[ReportListItem]
    total: int
    limit: int
    offset: int


# ============================================================================
# SECTION 1: INGESTION ENDPOINTS (SYNC & ASYNC)
# ============================================================================

@router.post(
    "/ingest",
    response_model=IngestResponse,
    operation_id="ingestReport",
    summary="Ingest Report",
    description="Ingest a threat intelligence report from text or URL (synchronous)."
)
async def ingest_report(request: IngestRequest):
    """Synchronous report ingestion from text or URL."""
    
    trace_id = str(uuid.uuid4())[:8]
    
    try:
        # Get text content
        if request.text:
            text_content = request.text
            source_info = {"type": "inline"}
        elif request.url:
            # URL ingestion not currently supported
            raise HTTPException(status_code=400, detail="URL ingestion not currently implemented")
        else:
            raise HTTPException(status_code=400, detail="Either text or url must be provided")
        
        # Check content size and redirect to async if too large
        if len(text_content) > 5000:
            return HTTPException(
                status_code=400,
                detail="Content too large for synchronous processing. Use /ingest_async endpoint."
            )
        
        # Extract techniques using unified pipeline
        from bandjacks.llm.extraction_pipeline import run_extraction_pipeline
        config = {
            "use_batch_mapper": request.use_batch_mapper,
            "use_batch_retriever": True,  # Always use batch retriever for performance
            "skip_verification": request.skip_verification,
            "max_spans": 20,
            "disable_discovery": False,
            "disable_targeted_extraction": True
        }
        
        # Run extraction pipeline
        pipeline_results = run_extraction_pipeline(
            report_text=text_content,
            config=config,
            source_id=f"report--{uuid.uuid4()}"
        )
        
        # Extract results in expected format
        extraction_results = {
            "techniques": pipeline_results.get("techniques", {}),
            "techniques_count": pipeline_results.get("techniques_count", pipeline_results.get("technique_count", 0)),
            "claims": pipeline_results.get("claims", []),
            "entities": pipeline_results.get("entities", {}),
            "metrics": pipeline_results.get("metrics", {})
        }
        
        # Create report SDO
        report_name = request.name or f"Report {datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        report_sdo = {
            "type": "report",
            "id": f"report--{uuid.uuid4()}",
            "name": report_name,
            "description": text_content[:500],
            "published": datetime.utcnow().isoformat() + "Z",
            "object_refs": []
        }
        
        # Evaluate rubric
        rubric = evaluate_rubric(extraction_results)
        rubric_evidence = generate_rubric_evidence(extraction_results, rubric)
        
        # Create bundle
        bundle = create_stix_bundle(report_sdo, extraction_results, rubric, rubric_evidence)
        
        # Save to OpenSearch
        os_client = get_opensearch_client()
        os_store = OpenSearchReportStore(os_client)
        
        os_store.save_report(
            report_id=report_sdo["id"],
            job_id=trace_id,
            report_data=report_sdo,
            extraction_result={
                "techniques_count": extraction_results.get("techniques_count", 0),
                "claims_count": len(extraction_results.get("claims", [])),
                "bundle_preview": bundle,
                "extraction_claims": extraction_results.get("claims", []),
                "entities": extraction_results.get("entities", {})
            },
            source_info=source_info,
            raw_text=text_content,
            text_chunks=create_text_chunks(text_content)
        )
        
        return IngestResponse(
            report_id=report_sdo["id"],
            provisional=rubric.criteria_met < 2,
            rubric={"criteria_met": rubric.criteria_met},
            rubric_evidence=rubric_evidence,
            entities=extraction_results.get("entities", {}),
            trace_id=trace_id,
            extraction_metrics=extraction_results.get("metrics", {})
        )
        
    except Exception as e:
        logger.error(f"Report ingestion failed ({trace_id}): {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/ingest/upload",
    response_model=IngestResponse,
    operation_id="ingestReportUpload",
    summary="Ingest Report from File",
    description="Upload a PDF/TXT/MD file for extraction (synchronous)."
)
async def ingest_report_upload(
    file: UploadFile = File(...),
    use_batch_mapper: bool = Form(True),
    skip_verification: bool = Form(False)
):
    """Synchronous report ingestion from file upload."""
    
    # Validate file type
    allowed_types = {".pdf", ".txt", ".md", ".markdown"}
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file_ext}"
        )
    
    # Process file
    content = await file.read()
    
    if file_ext == ".pdf":
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        try:
            text_content = load_pdf_text(tmp_path)
        finally:
            os.unlink(tmp_path)
    else:
        text_content = content.decode("utf-8", errors="ignore")
    
    # Check size and redirect if needed
    if len(text_content) > 5000:
        raise HTTPException(
            status_code=400,
            detail="File too large for synchronous processing. Use /ingest_file_async endpoint."
        )
    
    # Use the main ingest function
    request = IngestRequest(
        text=text_content,
        name=file.filename,
        use_batch_mapper=use_batch_mapper,
        skip_verification=skip_verification
    )
    
    return await ingest_report(request)


@router.post(
    "/ingest_async",
    response_model=JobStatusResponse,
    summary="Ingest Report Async",
    description="Ingest a report asynchronously from text or URL."
)
async def ingest_report_async(request: IngestRequest):
    """Asynchronous report ingestion from text or URL.
    
    This endpoint:
    1. Saves text content to a temp file
    2. Creates a job record in the job store
    3. Returns immediately with job ID
    4. The JobProcessor picks up and processes the job asynchronously
    """
    
    job_id = f"job-{uuid.uuid4().hex[:8]}"
    
    # Get text content
    if request.text:
        text_content = request.text
        source_type = "inline"
    elif request.url:
        # URL ingestion not currently supported
        raise HTTPException(status_code=400, detail="URL ingestion not currently implemented")
    else:
        raise HTTPException(status_code=400, detail="Either text or url required")
    
    # Create temp file for text content
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, f"{job_id}.txt")
    
    try:
        # Save text to file
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write(text_content)
        
        file_size = os.path.getsize(temp_path)
        
    except Exception as e:
        logger.error(f"Failed to save text content: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save content: {str(e)}"
        )
    
    # Create job in the persistent job store (queued status)
    job_store = get_job_store()
    job_data = job_store.create_job(
        job_id=job_id,
        file_path=temp_path,
        file_name=request.name or "inline_text",
        file_ext=".txt",
        file_size=file_size,
        config={
            "use_batch_mapper": request.use_batch_mapper,
            "skip_verification": request.skip_verification,
            "auto_generate_flow": True,
            "webhook_url": request.webhook_url
        }
    )
    
    # FileJobStore is already updated above
    
    return JobStatusResponse(
        job_id=job_id,
        status="queued",
        progress=0,
        message="Content queued for processing",
        created_at=job_data["created_at"]
    )


@router.post(
    "/ingest_file_async",
    response_model=JobStatusResponse,
    summary="Ingest File Async",
    description="Upload and process a file asynchronously."
)
async def ingest_file_async(
    file: UploadFile = File(...),
    use_batch_mapper: bool = Form(True),
    skip_verification: bool = Form(False),
    auto_generate_flow: bool = Form(True),
    webhook_url: Optional[str] = Form(None)
):
    """Asynchronous file upload and processing using queue-based job processor.
    
    This endpoint:
    1. Saves the uploaded file to disk (blocking)
    2. Creates a job record in the job store
    3. Returns immediately with job ID
    4. The JobProcessor picks up and processes the job asynchronously
    """
    
    # Validate file type
    allowed_types = {".pdf", ".txt", ".md", ".markdown"}
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file_ext}"
        )
    
    job_id = f"job-{uuid.uuid4().hex[:8]}"
    
    # Create temp file path
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, f"{job_id}{file_ext}")
    
    # Save file to disk (blocking but fast)
    try:
        # Use shutil to copy efficiently without loading entire file into memory
        with open(temp_path, 'wb') as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        file_size = os.path.getsize(temp_path)
        
    except Exception as e:
        logger.error(f"Failed to save uploaded file: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save file: {str(e)}"
        )
    
    # Create job in the persistent job store (queued status)
    job_store = get_job_store()
    job_data = job_store.create_job(
        job_id=job_id,
        file_path=temp_path,
        file_name=file.filename,
        file_ext=file_ext,
        file_size=file_size,
        config={
            "use_batch_mapper": use_batch_mapper,
            "skip_verification": skip_verification,
            "auto_generate_flow": auto_generate_flow,
            "webhook_url": webhook_url
        }
    )
    
    # FileJobStore is already updated above
    
    # Return immediately - job will be processed by JobProcessor
    return JobStatusResponse(
        job_id=job_id,
        status="queued",
        progress=0,
        message="File uploaded successfully, queued for processing",
        created_at=job_data["created_at"],
        file_name=file.filename,
        file_size=file_size
    )


# ============================================================================
# SECTION 2: RETRIEVAL ENDPOINTS
# ============================================================================

@router.get(
    "/{report_id}",
    response_model=ReportGetResponse,
    summary="Get Report",
    description="Retrieve a report by ID from OpenSearch or Neo4j."
)
async def get_report(
    report_id: str,
    os_client: OpenSearch = Depends(get_opensearch_client),
    neo4j_session: Session = Depends(get_neo4j_session)
):
    """Get a report by ID."""
    
    # First check OpenSearch
    os_store = OpenSearchReportStore(os_client)
    report = os_store.get_report(report_id)
    
    if report:
        return report
    
    # Not in OpenSearch, check Neo4j
    query = """
        MATCH (r:Report {stix_id: $report_id})
        RETURN r
    """
    result = neo4j_session.run(query, report_id=report_id)
    record = result.single()
    
    if record:
        return dict(record["r"])
    
    raise HTTPException(status_code=404, detail=f"Report {report_id} not found")


@router.get(
    "/",
    response_model=ReportsListResponse,
    summary="List Reports",
    description="List all reports with filtering and search."
)
async def list_reports(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None),
    has_campaign: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: str = Query("ingested_at"),
    sort_order: str = Query("desc"),
    os_client: OpenSearch = Depends(get_opensearch_client)
):
    """List all reports with optional filtering."""
    
    os_store = OpenSearchReportStore(os_client)
    
    result = os_store.list_reports(
        limit=limit,
        offset=offset,
        status=status,
        has_campaign=has_campaign,
        search_query=search,
        sort_by=sort_by,
        sort_order=sort_order
    )
    
    # Transform to response model
    report_items = []
    for report in result["reports"]:
        extraction = report.get("extraction", {})
        review_info = report.get("review", {})
        
        report_items.append(ReportListItem(
            report_id=report["report_id"],
            name=report.get("name"),
            description=report.get("description", "")[:200],
            created=report.get("created"),
            modified=report.get("modified"),
            status=report.get("status"),
            extraction_status=report.get("extraction_status"),
            techniques_count=extraction.get("techniques_count", 0),
            claims_count=extraction.get("claims_count", 0),
            confidence_avg=extraction.get("confidence_avg", 0),
            has_campaign=bool(report.get("campaign")),
            has_flow=bool(extraction.get("flow")),
            reviewed_at=review_info.get("reviewed_at"),
            approved_at=report.get("approval", {}).get("approved_at")
        ))
    
    return ReportsListResponse(
        reports=report_items,
        total=result["total"],
        limit=limit,
        offset=offset
    )


@router.get(
    "/stats",
    summary="Get Statistics",
    description="Get aggregate statistics about reports."
)
async def get_report_statistics(
    os_client: OpenSearch = Depends(get_opensearch_client)
):
    """Get report statistics."""
    
    os_store = OpenSearchReportStore(os_client)
    return os_store.get_statistics()


# ============================================================================
# SECTION 3: JOB MANAGEMENT
# ============================================================================

@router.get(
    "/jobs/{job_id}/status",
    response_model=JobStatusResponse,
    summary="Get Job Status",
    description="Get status of an async processing job."
)
async def get_job_status(job_id: str):
    """Get job status from persistent store or in-memory cache."""
    
    # First check persistent store
    job_store = get_job_store()
    job = job_store.get(job_id)
    
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    
    return JobStatusResponse(
        job_id=job_id,
        status=job["status"],
        progress=job.get("progress", 0),
        message=job.get("message", ""),
        created_at=job["created_at"],
        completed_at=job.get("completed_at"),
        result=job.get("result"),
        error=job.get("error"),
        file_name=job.get("file_name"),
        file_size=job.get("file_size")
    )


@router.get(
    "/jobs",
    response_model=JobListResponse,
    summary="List Jobs",
    description="List all async processing jobs."
)
async def list_jobs():
    """List all jobs."""
    
    try:
        # Use FileJobStore instead of in-memory store
        job_store = get_job_store()
        all_jobs = job_store.list_all()
        
        jobs = []
        for job_id, job_data in all_jobs.items():
            jobs.append({
                "job_id": job_id,
                "status": job_data["status"],
                "created_at": job_data["created_at"],
                "progress": job_data.get("progress", 0)
            })
        
        # Sort by created_at descending
        jobs.sort(key=lambda x: x["created_at"], reverse=True)
        
        return JobListResponse(
            jobs=jobs,
            total=len(jobs)
        )
    except Exception as e:
        logger.error(f"Error in list_jobs: {e}", exc_info=True)
        raise


@router.delete(
    "/jobs/{job_id}",
    summary="Delete Job",
    description="Delete a completed job from the store."
)
async def delete_job(job_id: str):
    """Delete a job."""
    
    # Use FileJobStore instead of in-memory store
    job_store = get_job_store()
    job = job_store.get(job_id)
    
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    
    if job["status"] in ["pending", "processing"]:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete active job"
        )
    
    # Delete from FileJobStore
    job_store.delete(job_id)
    
    return {"message": f"Job {job_id} deleted"}


# ============================================================================
# SECTION 4: REVIEW WORKFLOW
# ============================================================================

@router.get(
    "/{report_id}/review",
    summary="Get Review Status",
    description="Get review status and decisions for a report."
)
async def get_review_status(
    report_id: str,
    os_client: OpenSearch = Depends(get_opensearch_client)
):
    """Get review status for a report."""
    
    os_store = OpenSearchReportStore(os_client)
    report = os_store.get_report(report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    
    extraction = report.get("extraction", {})
    review_info = report.get("review", {})
    
    return {
        "report_id": report_id,
        "status": report.get("status"),
        "techniques_count": extraction.get("techniques_count", 0),
        "review": review_info,
        "bundle_preview": extraction.get("bundle", {})
    }


@router.post(
    "/{report_id}/review",
    summary="Submit Review",
    description="Submit technique review decisions."
)
async def submit_review(
    report_id: str,
    review: ReviewSubmission,
    os_client: OpenSearch = Depends(get_opensearch_client)
):
    """Submit review for a report."""
    
    os_store = OpenSearchReportStore(os_client)
    report = os_store.get_report(report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    
    # Update review in OpenSearch
    os_store.update_review(
        report_id=report_id,
        reviewer_id=review.reviewer_id,
        technique_actions=review.technique_actions,
        notes=review.notes
    )
    
    return {
        "message": "Review submitted successfully",
        "report_id": report_id,
        "techniques_reviewed": len(review.technique_actions)
    }


@router.post(
    "/{report_id}/approve",
    summary="Approve Report",
    description="Approve report and optionally upsert to graph."
)
async def approve_report(
    report_id: str,
    request: ApprovalRequest,
    os_client: OpenSearch = Depends(get_opensearch_client)
):
    """Approve and finalize the report review."""
    
    os_store = OpenSearchReportStore(os_client)
    report = os_store.get_report(report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    
    if report.get("status") != "reviewed":
        raise HTTPException(
            status_code=400,
            detail="Report must be reviewed before approval"
        )
    
    # Get review data
    extraction = report.get("extraction", {})
    review_info = report.get("review", {})
    bundle_preview = extraction.get("bundle", {})
    
    # Filter approved techniques
    decisions = review_info.get("decisions", {})
    approved_ids = set([tid for tid, action in decisions.items() if action.get("action") == "approve"])
    
    # Build approved bundle
    approved_bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": []
    }
    
    # Add report and approved objects
    if bundle_preview.get("objects"):
        # Add report
        approved_bundle["objects"].append(bundle_preview["objects"][0])
        
        # Add approved techniques
        for obj in bundle_preview["objects"][1:]:
            if obj.get("id") in approved_ids:
                # Apply edits if needed
                if decisions.get(obj["id"], {}).get("action") == "edit":
                    edited_data = decisions[obj["id"]].get("edited_data", {})
                    obj.update(edited_data)
                approved_bundle["objects"].append(obj)
    
    # Update status
    os_store.approve_report(
        report_id=report_id,
        approver_id=request.reviewer_id,
        upserted=False
    )
    
    result = {
        "report_id": report_id,
        "status": "approved",
        "approved_techniques": len(approved_ids),
        "bundle_size": len(approved_bundle["objects"])
    }
    
    # Upsert to Neo4j if requested
    if request.upsert_to_graph and approved_bundle["objects"]:
        try:
            # Upsert to graph
            report_store = ReportStore(
                neo4j_uri=settings.neo4j_uri,
                neo4j_user=settings.neo4j_user,
                neo4j_password=settings.neo4j_password
            )
            try:
                upsert_result = report_store.upsert_bundle(approved_bundle)
                result["upserted"] = True
                result["upsert_result"] = upsert_result
                
                # Update OpenSearch
                os_store.approve_report(
                    report_id=report_id,
                    approver_id=request.reviewer_id,
                    upserted=True
                )
                
                # Generate flow if requested
                if request.generate_flow:
                    try:
                        flow_builder = FlowBuilder(
                            neo4j_uri=settings.neo4j_uri,
                            neo4j_user=settings.neo4j_user,
                            neo4j_password=settings.neo4j_password,
                            opensearch_client=os_client
                        )
                        
                        # Filter extraction for approved techniques
                        flow_extraction = extraction.copy()
                        flow_extraction["claims"] = [
                            claim for claim in extraction.get("claims", [])
                            if claim.get("technique_id") in approved_ids
                        ]
                        
                        # Build flow
                        flow_data = flow_builder.build_from_extraction(
                            extraction_data=flow_extraction,
                            source_id=report_id,
                            use_stored_text=True
                        )
                        
                        if flow_data:
                            flow_builder.persist_to_neo4j(flow_data)
                            result["flow_generated"] = True
                            result["flow_id"] = flow_data.get("episode_id")
                            
                            # Update OpenSearch
                            os_store.update_report_flow(
                                report_id=report_id,
                                flow_id=flow_data.get("episode_id"),
                                flow_data=flow_data
                            )
                        
                        flow_builder.close()
                        
                    except Exception as e:
                        logger.error(f"Failed to generate flow: {e}")
                        result["flow_error"] = str(e)
                        
            finally:
                report_store.close()
                
        except Exception as e:
            logger.error(f"Failed to upsert: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    return result


@router.get(
    "/{report_id}/review/claims",
    summary="Get Extraction Claims",
    description="Get detailed extraction claims for review."
)
async def get_extraction_claims(
    report_id: str,
    os_client: OpenSearch = Depends(get_opensearch_client)
):
    """Get extraction claims for a report."""
    
    os_store = OpenSearchReportStore(os_client)
    report = os_store.get_report(report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    
    extraction = report.get("extraction", {})
    claims = extraction.get("claims", [])
    
    # Add review status to claims
    review_info = report.get("review", {})
    decisions = review_info.get("decisions", {})
    
    for claim in claims:
        technique_id = claim.get("technique_id")
        if technique_id and technique_id in decisions:
            claim["review_action"] = decisions[technique_id].get("action")
            claim["review_notes"] = decisions[technique_id].get("notes")
    
    return {
        "report_id": report_id,
        "total_claims": len(claims),
        "claims": claims,
        "review_status": report.get("status", "pending_review")
    }


# ============================================================================
# SECTION 5: ATTRIBUTION & FLOW
# ============================================================================

@router.get(
    "/{report_id}/attribution",
    summary="Get Attribution Suggestions",
    description="Get suggested threat actors for a report."
)
async def get_attribution_suggestions(
    report_id: str,
    os_client: OpenSearch = Depends(get_opensearch_client),
    neo4j_session: Session = Depends(get_neo4j_session)
):
    """Get attribution suggestions based on techniques."""
    
    os_store = OpenSearchReportStore(os_client)
    report = os_store.get_report(report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    
    # Get techniques from report
    extraction = report.get("extraction", {})
    techniques = extraction.get("techniques", [])
    
    if not techniques:
        return {"suggestions": [], "message": "No techniques to analyze"}
    
    # Query Neo4j for groups using these techniques
    query = """
        MATCH (g:IntrusionSet)-[:USES]->(t:AttackPattern)
        WHERE t.stix_id IN $techniques
        WITH g, COUNT(DISTINCT t) as technique_overlap
        RETURN g.stix_id as group_id,
               g.name as group_name,
               technique_overlap,
               COLLECT(DISTINCT t.name) as matching_techniques
        ORDER BY technique_overlap DESC
        LIMIT 10
    """
    
    result = neo4j_session.run(query, techniques=techniques)
    
    suggestions = []
    for record in result:
        confidence = min(95, record["technique_overlap"] * 15)
        suggestions.append({
            "intrusion_set_id": record["group_id"],
            "name": record["group_name"],
            "technique_overlap": record["technique_overlap"],
            "confidence": confidence,
            "matching_techniques": record["matching_techniques"][:5]
        })
    
    return {
        "report_id": report_id,
        "suggestions": suggestions,
        "total_techniques": len(techniques)
    }


@router.post(
    "/{report_id}/attribution",
    summary="Update Attribution",
    description="Update threat actor attribution for a report."
)
async def update_attribution(
    report_id: str,
    attribution: AttributionRequest,
    os_client: OpenSearch = Depends(get_opensearch_client)
):
    """Update attribution for a report."""
    
    os_store = OpenSearchReportStore(os_client)
    report = os_store.get_report(report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    
    try:
        os_store.update_attribution(
            report_id=report_id,
            intrusion_sets=attribution.intrusion_sets,
            malware=attribution.malware,
            confidence=attribution.confidence,
            notes=attribution.notes
        )
        
        return {
            "message": "Attribution updated successfully",
            "report_id": report_id,
            "intrusion_sets": len(attribution.intrusion_sets),
            "malware": len(attribution.malware)
        }
    except Exception as e:
        logger.error(f"Failed to update attribution: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/{report_id}/generate-flow",
    summary="Generate Attack Flow",
    description="Generate an attack flow from extracted techniques."
)
async def generate_flow_for_report(
    report_id: str,
    os_client: OpenSearch = Depends(get_opensearch_client)
):
    """Generate attack flow from extraction results."""
    
    os_store = OpenSearchReportStore(os_client)
    report = os_store.get_report(report_id)
    
    if not report:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    
    extraction = report.get("extraction", {})
    
    # Check if flow already exists
    if extraction.get("flow"):
        return {
            "message": "Flow already exists",
            "flow": extraction["flow"]
        }
    
    # Generate flow
    try:
        flow_builder = FlowBuilder(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password,
            opensearch_client=os_client
        )
        
        # Build extraction data
        # Convert claims to techniques dict
        techniques = {}
        for claim in extraction.get("claims", []):
            techniques[claim["technique_id"]] = {
                "technique_id": claim["technique_id"],
                "technique_name": claim["technique_name"],
                "confidence": claim["confidence"],
                "evidence": claim["evidence"]
            }
        
        extraction_data = {
            "extraction_claims": extraction.get("claims", []),
            "techniques": techniques,
            "chunks": [{
                "claims": extraction.get("claims", []),
                "entities": {
                    "threat_actors": extraction.get("threat_actors", []),
                    "malware": extraction.get("malware", []),
                    "tools": extraction.get("tools", [])
                }
            }]
        }
        
        # Generate flow using stored text
        flow_result = flow_builder.build_from_extraction(
            extraction_data=extraction_data,
            source_id=report_id,
            use_stored_text=True
        )
        
        if flow_result:
            # Convert to simpler format
            flow_data = {
                "flow_name": flow_result.get("name"),
                "flow_type": "llm_synthesized" if flow_result.get("llm_synthesized") else "deterministic",
                "confidence": "high" if flow_result.get("llm_synthesized") else "medium",
                "steps": [
                    {
                        "order": action["order"],
                        "entity": {
                            "label": action.get("name"),
                            "id": action.get("attack_pattern_ref")
                        },
                        "description": action.get("description"),
                        "reason": action.get("reason", "")
                    }
                    for action in flow_result.get("actions", [])
                ],
                "notes": f"Generated with {len(flow_result.get('actions', []))} steps"
            }
            
            # Update report
            extraction["flow"] = flow_data
            update_body = {
                "doc": {
                    "extraction": extraction,
                    "modified": datetime.utcnow().isoformat()
                }
            }
            os_store.client.update(
                index=os_store.index_name,
                id=report_id,
                body=update_body
            )
            
            flow_builder.close()
            
            return {
                "message": "Attack flow generated successfully",
                "flow": flow_data,
                "steps_count": len(flow_data.get("steps", []))
            }
        else:
            return {
                "message": "No attack flow could be generated",
                "flow": None
            }
            
    except Exception as e:
        logger.error(f"Failed to generate flow: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/attribution/search",
    summary="Search Attribution Candidates",
    description="Search for threat actors by name or alias."
)
async def search_attribution_candidates(
    query: str = Query(..., min_length=2),
    neo4j_session: Session = Depends(get_neo4j_session)
):
    """Search for threat actors and malware."""
    
    # Search intrusion sets
    intrusion_query = """
        MATCH (g:IntrusionSet)
        WHERE toLower(g.name) CONTAINS toLower($query)
           OR ANY(alias IN g.aliases WHERE toLower(alias) CONTAINS toLower($query))
        RETURN g.stix_id as id,
               g.name as name,
               g.aliases as aliases,
               'intrusion-set' as type
        LIMIT 10
    """
    
    # Search malware
    malware_query = """
        MATCH (m:Software)
        WHERE toLower(m.name) CONTAINS toLower($query)
           OR ANY(alias IN m.aliases WHERE toLower(alias) CONTAINS toLower($query))
        RETURN m.stix_id as id,
               m.name as name,
               m.aliases as aliases,
               CASE WHEN m.is_malware THEN 'malware' ELSE 'tool' END as type
        LIMIT 10
    """
    
    results = []
    
    # Get intrusion sets
    for record in neo4j_session.run(intrusion_query, query=query):
        results.append(dict(record))
    
    # Get malware/tools
    for record in neo4j_session.run(malware_query, query=query):
        results.append(dict(record))
    
    return {
        "query": query,
        "results": results,
        "total": len(results)
    }


# ============================================================================
# SECTION 6: CAMPAIGNS
# ============================================================================

@router.post(
    "/campaigns/merge",
    response_model=Dict[str, Any],
    summary="Merge Campaigns",
    description="Merge multiple reports into a campaign."
)
async def merge_campaigns(request: CampaignMergeRequest):
    """Merge multiple reports into a single campaign."""
    
    campaign_store = CampaignStore(
        neo4j_uri=settings.neo4j_uri,
        neo4j_user=settings.neo4j_user,
        neo4j_password=settings.neo4j_password
    )
    
    try:
        result = campaign_store.merge_reports_to_campaign(
            report_ids=request.report_ids,
            campaign_name=request.campaign_name,
            campaign_description=request.campaign_description,
            confidence_threshold=request.confidence_threshold
        )
        
        return result
    finally:
        campaign_store.close()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def load_pdf_text(pdf_path: str) -> str:
    """Extract text from PDF file."""
    try:
        import pdfplumber
        text_parts = []
        with pdfplumber.open(pdf_path) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    text_parts.append(text)
        return "\n\n".join(text_parts)
    except ImportError:
        # Fallback to PyPDF2 if pdfplumber not available
        import PyPDF2
        text_parts = []
        with open(pdf_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)
            for page in pdf_reader.pages:
                text = page.extract_text()
                if text:
                    text_parts.append(text)
        return "\n".join(text_parts)


def evaluate_rubric(extraction_results: Dict[str, Any]) -> Any:
    """Evaluate extraction quality rubric."""
    class Rubric:
        def __init__(self):
            self.criteria_met = 2 if extraction_results.get("techniques_count", 0) > 0 else 0
    return Rubric()


def generate_rubric_evidence(extraction_results: Dict[str, Any], rubric: Any) -> Dict[str, Any]:
    """Generate evidence for rubric evaluation."""
    return {
        "techniques_found": extraction_results.get("techniques_count", 0),
        "confidence": "high" if rubric.criteria_met >= 2 else "low"
    }


def create_text_chunks(text: str, chunk_size: int = 3000, overlap: int = 200) -> List[Dict[str, Any]]:
    """Create overlapping text chunks for storage."""
    chunks = []
    for i in range(0, len(text), chunk_size - overlap):
        chunk_text = text[i:i + chunk_size]
        chunks.append({
            "chunk_id": len(chunks),
            "text": chunk_text,
            "start_idx": i,
            "end_idx": min(i + chunk_size, len(text))
        })
    return chunks


def create_stix_bundle(
    report_sdo: Dict[str, Any],
    extraction_results: Dict[str, Any],
    rubric: Any,
    rubric_evidence: Dict[str, Any]
) -> Dict[str, Any]:
    """Create STIX bundle from extraction results."""
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [report_sdo]
    }
    
    # Track entity STIX IDs for relationships
    entity_stix_ids = {}
    campaign_id = None
    
    # Add extracted techniques
    for technique_id, technique_data in extraction_results.get("techniques", {}).items():
        technique_obj = {
            "type": "attack-pattern",
            "id": technique_id,
            "name": technique_data.get("name", "Unknown"),
            "x_bj_confidence": technique_data.get("confidence", 50.0)
        }
        bundle["objects"].append(technique_obj)
        report_sdo["object_refs"].append(technique_id)
    
    # Add extracted entities
    entities = extraction_results.get("entities", {})
    
    # Add malware entities
    for malware in entities.get("malware", []):
        if isinstance(malware, dict):
            malware_id = f"malware--{uuid.uuid4()}"
            malware_obj = {
                "type": "malware",
                "id": malware_id,
                "spec_version": "2.1",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": malware.get("name", "Unknown Malware"),
                "description": malware.get("description", ""),
                "is_family": False,
                "x_bj_confidence": malware.get("confidence", 50.0),
                "x_bj_evidence": malware.get("evidence", [])
            }
            if malware.get("aliases"):
                malware_obj["aliases"] = malware.get("aliases")
            
            bundle["objects"].append(malware_obj)
            report_sdo["object_refs"].append(malware_id)
            entity_stix_ids[malware.get("name")] = malware_id
    
    # Add tool/software entities
    for software in entities.get("software", []):
        if isinstance(software, dict):
            tool_id = f"tool--{uuid.uuid4()}"
            tool_obj = {
                "type": "tool",
                "id": tool_id,
                "spec_version": "2.1",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": software.get("name", "Unknown Tool"),
                "description": software.get("description", ""),
                "x_bj_confidence": software.get("confidence", 50.0),
                "x_bj_evidence": software.get("evidence", [])
            }
            if software.get("aliases"):
                tool_obj["aliases"] = software.get("aliases")
            
            bundle["objects"].append(tool_obj)
            report_sdo["object_refs"].append(tool_id)
            entity_stix_ids[software.get("name")] = tool_id
    
    # Add threat actor entities
    for threat_actor in entities.get("threat_actors", []):
        if isinstance(threat_actor, dict):
            intrusion_set_id = f"intrusion-set--{uuid.uuid4()}"
            intrusion_set_obj = {
                "type": "intrusion-set",
                "id": intrusion_set_id,
                "spec_version": "2.1",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": threat_actor.get("name", "Unknown Threat Actor"),
                "description": threat_actor.get("description", ""),
                "x_bj_confidence": threat_actor.get("confidence", 50.0),
                "x_bj_evidence": threat_actor.get("evidence", [])
            }
            if threat_actor.get("aliases"):
                intrusion_set_obj["aliases"] = threat_actor.get("aliases")
            
            bundle["objects"].append(intrusion_set_obj)
            report_sdo["object_refs"].append(intrusion_set_id)
            entity_stix_ids[threat_actor.get("name")] = intrusion_set_id
    
    # Add campaign entities
    for campaign in entities.get("campaigns", []):
        if isinstance(campaign, dict):
            campaign_id = f"campaign--{uuid.uuid4()}"
            campaign_obj = {
                "type": "campaign",
                "id": campaign_id,
                "spec_version": "2.1",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "name": campaign.get("name", "Unknown Campaign"),
                "description": campaign.get("description", ""),
                "x_bj_status": "provisional",
                "x_bj_confidence": campaign.get("confidence", 50.0),
                "x_bj_evidence": campaign.get("evidence", [])
            }
            if campaign.get("first_seen"):
                campaign_obj["first_seen"] = campaign.get("first_seen")
            if campaign.get("last_seen"):
                campaign_obj["last_seen"] = campaign.get("last_seen")
            
            bundle["objects"].append(campaign_obj)
            report_sdo["object_refs"].append(campaign_id)
            entity_stix_ids[campaign.get("name")] = campaign_id
    
    # Create relationships between entities and techniques
    # This is a simplified approach - in production you'd want more sophisticated linking
    if campaign_id:
        # Link campaign to all techniques
        for technique_id in extraction_results.get("techniques", {}).keys():
            relationship_obj = {
                "type": "relationship",
                "id": f"relationship--{uuid.uuid4()}",
                "spec_version": "2.1",
                "created": datetime.utcnow().isoformat() + "Z",
                "modified": datetime.utcnow().isoformat() + "Z",
                "relationship_type": "uses",
                "source_ref": campaign_id,
                "target_ref": technique_id
            }
            bundle["objects"].append(relationship_obj)
        
        # Link campaign to malware/tools
        for malware in entities.get("malware", []):
            if isinstance(malware, dict) and malware.get("name") in entity_stix_ids:
                relationship_obj = {
                    "type": "relationship",
                    "id": f"relationship--{uuid.uuid4()}",
                    "spec_version": "2.1",
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "relationship_type": "uses",
                    "source_ref": campaign_id,
                    "target_ref": entity_stix_ids[malware.get("name")]
                }
                bundle["objects"].append(relationship_obj)
    
    return bundle


def validate_bundle_for_upsert(bundle: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate bundle before upserting."""
    errors = []
    
    if not bundle.get("objects"):
        errors.append("Bundle has no objects")
    
    # Check for report object
    has_report = any(obj.get("type") == "report" for obj in bundle.get("objects", []))
    if not has_report:
        errors.append("Bundle missing report object")
    
    return len(errors) == 0, errors
