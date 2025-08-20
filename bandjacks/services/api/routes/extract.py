"""API endpoints for CTI extraction - redirects to extract_runs for async processing."""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
import hashlib
from datetime import datetime

from bandjacks.services.api.routes.extract_runs import (
    StartRunRequest,
    start_run
)

router = APIRouter(prefix="/extract", tags=["extraction"])


class ExtractionRequest(BaseModel):
    """Request for report extraction (legacy compatibility)."""
    source_url: Optional[str] = Field(None, description="URL of source document")
    source_type: str = Field("report", description="Type of source (report, blog, pdf, etc)")
    content: str = Field(..., description="Text content to extract from")
    title: Optional[str] = Field(None, description="Optional title for the report")
    method: str = Field("agentic_v2", description="Extraction method (only agentic_v2 supported)")
    confidence_threshold: float = Field(50.0, description="Minimum confidence for extraction")
    auto_ingest: bool = Field(False, description="Automatically ingest to graph if True")


class ExtractionResponse(BaseModel):
    """Response from extraction."""
    extraction_id: str
    message: str = "Extraction started. Use /v1/extract/runs/{run_id}/status to check progress"


@router.post(
    "/report", 
    response_model=ExtractionResponse,
    operation_id="extractTechniquesFromReport",
    summary="Extract Techniques from Report (Legacy)",
    description="""
    Extract ATT&CK techniques from a threat intelligence report.
    
    **DEPRECATED**: This endpoint is maintained for backward compatibility.
    Use /v1/extract/runs instead for the high-performance async pipeline.
    
    This endpoint now redirects to the async extraction pipeline and returns
    immediately with a run_id for status checking.
    """,
    deprecated=True
)
async def extract_from_report(request: ExtractionRequest) -> ExtractionResponse:
    """
    Extract techniques from a report using the async pipeline.
    
    This is a compatibility wrapper that redirects to the modern extract_runs endpoint.
    """
    
    # Validate method - only agentic_v2 is supported now
    if request.method != "agentic_v2":
        raise HTTPException(
            status_code=400,
            detail=f"Method '{request.method}' is no longer supported. Only 'agentic_v2' is available."
        )
    
    # Create request for the new endpoint
    run_request = StartRunRequest(
        method="agentic_v2",
        content=request.content,
        title=request.title or f"Report from {request.source_type}",
        source_type=request.source_type,
        config={
            "confidence_threshold": request.confidence_threshold,
            "source_url": request.source_url,
            "auto_ingest": request.auto_ingest,
            # Use async pipeline by default
            "use_async": True,
            "cache_llm_responses": True
        }
    )
    
    # Start the extraction run
    response = await start_run(run_request)
    
    return ExtractionResponse(
        extraction_id=response.run_id,
        message=f"Extraction started. Check status at /v1/extract/runs/{response.run_id}/status"
    )


@router.get(
    "/provenance/{source_id}",
    operation_id="getExtractionProvenance",
    summary="Get Extraction Provenance",
    description="Get provenance information for an extracted source document.",
    response_model=Dict[str, Any]
)
async def get_provenance(source_id: str) -> Dict[str, Any]:
    """
    Get extraction provenance for a source document.
    
    This endpoint is maintained for compatibility but may be deprecated
    in favor of the metrics provided by extract_runs.
    """
    
    # Generate mock provenance for now
    # In production, this would query the provenance tracking system
    return {
        "source_id": source_id,
        "source_metadata": {
            "filename": "document",
            "hash": hashlib.sha256(source_id.encode()).hexdigest(),
            "extracted_at": datetime.utcnow().isoformat() + "Z"
        },
        "extraction_metadata": {
            "method": "agentic_v2_async",
            "model": "gemini-2.5-flash",
            "pipeline": "async",
            "confidence_threshold": 50.0
        },
        "message": "Use /v1/extract/runs/{run_id}/result for detailed extraction metrics"
    }