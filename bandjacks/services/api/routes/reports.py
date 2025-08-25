"""Report ingestion API endpoints with agentic_v2_optimized integration."""

import logging
import hashlib
import json
from typing import Dict, Any, List, Optional, Tuple, Literal
from datetime import datetime
from uuid import uuid4
import asyncio
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile, File, Form, BackgroundTasks
from pydantic import BaseModel, Field
import pdfplumber
from neo4j import GraphDatabase

from bandjacks.llm.agentic_v2_optimized import run_agentic_v2_optimized
from bandjacks.llm.chunked_extractor import extract_chunked
from bandjacks.llm.tracker import ExtractionTracker
from bandjacks.llm.bundle_validator import validate_bundle_for_upsert
from bandjacks.store.report_store import ReportStore
from bandjacks.store.campaign_store import CampaignStore
from bandjacks.services.api.settings import settings
from bandjacks.services.api.deps import get_neo4j_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reports", tags=["reports"])


class ReportSDO(BaseModel):
    """STIX Report object."""
    type: Literal["report"] = "report"
    spec_version: Literal["2.1"] = "2.1"
    id: Optional[str] = Field(None, description="STIX ID (auto-generated if not provided)")
    name: str = Field(..., description="Report name/title")
    description: Optional[str] = Field(None, description="Report description")
    published: Optional[str] = Field(None, description="Publication date (ISO 8601)")
    created: Optional[str] = Field(None, description="Creation timestamp (ISO 8601)")
    modified: Optional[str] = Field(None, description="Last modified timestamp (ISO 8601)")
    object_refs: List[str] = Field(default_factory=list, description="Referenced STIX objects")
    external_references: List[Dict[str, Any]] = Field(default_factory=list)
    object_marking_refs: List[str] = Field(default_factory=list)
    x_bj_provenance: Optional[Dict[str, Any]] = Field(None, description="Bandjacks provenance")


class IngestConfig(BaseModel):
    """Configuration for report ingestion."""
    use_batch_mapper: bool = Field(True, description="Use optimized batch mapper")
    skip_verification: bool = Field(False, description="Skip evidence verification for speed")
    force_provisional_campaign: bool = Field(False, description="Force campaign creation even if rubric not met")
    disable_targeted_extraction: bool = Field(True, description="Skip second pass extraction")
    max_spans: int = Field(10, description="Maximum spans to process")
    confidence_threshold: float = Field(50.0, description="Minimum confidence for extraction")
    auto_generate_flow: bool = Field(True, description="Auto-generate Attack Flow if techniques found")


class IngestRequest(BaseModel):
    """Request for report ingestion."""
    report_sdo: Optional[ReportSDO] = Field(None, description="STIX Report object")
    file_url: Optional[str] = Field(None, description="URL to file for extraction")
    inline_text: Optional[str] = Field(None, description="Inline text content")
    config: IngestConfig = Field(default_factory=IngestConfig)


class RubricEvidence(BaseModel):
    """Evidence details for rubric evaluation."""
    time_bounds_detected: List[Dict[str, Any]] = Field(default_factory=list, description="Time bounds found")
    distinct_techniques: List[str] = Field(default_factory=list, description="Unique techniques identified")
    intrusion_sets: List[Dict[str, Any]] = Field(default_factory=list, description="Intrusion sets with confidence")
    sequence_cues: List[str] = Field(default_factory=list, description="Sequential indicators found")
    confidence_scores: Dict[str, float] = Field(default_factory=dict, description="Entity confidence scores")


class RubricDecision(BaseModel):
    """Campaign creation rubric evaluation."""
    time_bounded: bool = Field(False, description="Has first_seen/last_seen")
    operational_scope: bool = Field(False, description="Multiple techniques detected")
    attribution_present: bool = Field(False, description="IntrusionSet identified")
    multi_step_activity: bool = Field(False, description="Sequenced activity detected")
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    criteria_met: int = Field(0, description="Number of criteria met")
    created_campaign: bool = Field(False, description="Whether campaign was created")
    reason: Optional[str] = None


class IngestResponse(BaseModel):
    """Response from report ingestion."""
    report_id: str
    campaign_id: Optional[str] = None
    flow_id: Optional[str] = None
    provisional: bool = False
    rubric: RubricDecision
    rubric_evidence: RubricEvidence
    object_refs: List[str]
    entities: Dict[str, List[str]]
    rejected: List[Dict[str, str]]
    warnings: List[str]
    trace_id: str
    extraction_metrics: Dict[str, Any]


def extract_text_from_pdf(file_path: str) -> str:
    """Extract text from PDF file."""
    try:
        text_parts = []
        with pdfplumber.open(file_path) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    text_parts.append(text)
        return "\n\n".join(text_parts)
    except Exception as e:
        logger.error(f"Failed to extract PDF text: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to extract PDF text: {str(e)}")


def evaluate_campaign_rubric(
    claims: List[Dict[str, Any]], 
    force_provisional: bool = False
) -> Tuple[RubricDecision, RubricEvidence]:
    """
    Evaluate whether to create a campaign based on extraction results.
    
    Criteria (need ≥2 for campaign):
    1. Time-bounded: first_seen/last_seen present
    2. Operational scope: Multiple techniques
    3. Attribution: IntrusionSet identified
    4. Multi-step: Sequence detected
    """
    decision = RubricDecision()
    evidence = RubricEvidence()
    
    # Check for time bounds
    timestamps = []
    for claim in claims:
        if claim.get("first_seen") or claim.get("last_seen"):
            time_bound = {
                "text": claim.get("text", ""),
                "first_seen": claim.get("first_seen"),
                "last_seen": claim.get("last_seen")
            }
            evidence.time_bounds_detected.append(time_bound)
            if claim.get("first_seen"):
                timestamps.append(claim["first_seen"])
            if claim.get("last_seen"):
                timestamps.append(claim["last_seen"])
    
    if timestamps:
        decision.time_bounded = True
        decision.first_seen = min(timestamps)
        decision.last_seen = max(timestamps)
    
    # Check operational scope (multiple techniques)
    techniques = {c.get("technique_id") for c in claims if c.get("technique_id")}
    evidence.distinct_techniques = list(techniques)
    if len(techniques) >= 2:
        decision.operational_scope = True
    
    # Check attribution
    for claim in claims:
        if claim.get("intrusion_set"):
            evidence.intrusion_sets.append({
                "name": claim["intrusion_set"],
                "confidence": claim.get("confidence", 0.5),
                "evidence": claim.get("evidence", {})
            })
            evidence.confidence_scores[claim["intrusion_set"]] = claim.get("confidence", 0.5)
    
    if evidence.intrusion_sets:
        decision.attribution_present = True
    
    # Check for multi-step activity (sequence indicators)
    sequence_indicators = ["then", "followed by", "next", "after", "subsequently", "before", "during", "while"]
    full_text = " ".join(c.get("text", "") for c in claims).lower()
    for indicator in sequence_indicators:
        if indicator in full_text:
            evidence.sequence_cues.append(indicator)
    
    if evidence.sequence_cues:
        decision.multi_step_activity = True
    
    # Count criteria met
    criteria = [
        decision.time_bounded,
        decision.operational_scope,
        decision.attribution_present,
        decision.multi_step_activity
    ]
    decision.criteria_met = sum(criteria)
    
    # Decision: create campaign if ≥2 criteria OR forced
    if decision.criteria_met >= 2 or force_provisional:
        decision.created_campaign = True
        if force_provisional and decision.criteria_met < 2:
            decision.reason = f"Provisional campaign (forced): {decision.criteria_met}/4 criteria met"
        else:
            decision.reason = f"Campaign created: {decision.criteria_met}/4 criteria met"
    else:
        decision.created_campaign = False
        decision.reason = f"Campaign not created: only {decision.criteria_met}/4 criteria met"
    
    return decision, evidence


def create_stix_bundle(
    report: ReportSDO,
    extraction_results: Dict[str, Any],
    rubric: RubricDecision,
    rubric_evidence: RubricEvidence,
    campaign_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create STIX bundle with proper relationships per relationships_annotation.md.
    Report uses object_refs[] to reference objects, not 'describes' relationships.
    """
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid4()}",
        "objects": []
    }
    
    # Will track all referenced object IDs for Report.object_refs[]
    referenced_ids = []
    
    # Add Report SDO (will be updated with object_refs at the end)
    report_dict = report.dict(exclude_none=True)
    if not report_dict.get("id"):
        report_dict["id"] = f"report--{uuid4()}"
    
    # Ensure required STIX timestamps are present
    now_iso = datetime.utcnow().isoformat() + "Z"
    if not report_dict.get("created"):
        report_dict["created"] = now_iso
    if not report_dict.get("modified"):
        report_dict["modified"] = now_iso
    
    # Add provenance
    report_dict["x_bj_provenance"] = {
        "extraction_method": "agentic_v2_optimized",
        "extracted_at": datetime.utcnow().isoformat(),
        "rubric_evaluation": rubric.dict(),
        "rubric_evidence": rubric_evidence.dict()
    }
    
    report_id = report_dict["id"]
    
    # Extract entities from claims
    techniques = []
    intrusion_sets = []
    software = []
    relationships = []
    
    for claim in extraction_results.get("claims", []):
        # Add AttackPattern
        if claim.get("technique_id"):
            technique = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": f"attack-pattern--{uuid4()}",
                "name": claim.get("technique_name", claim["technique_id"]),
                "created": now_iso,
                "modified": now_iso,
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": claim["technique_id"],
                    "url": f"https://attack.mitre.org/techniques/{claim['technique_id'].replace('.', '/')}/"
                }],
                "x_bj_provenance": {
                    "evidence": claim.get("evidence", {}),
                    "confidence": claim.get("confidence", 0.5)
                }
            }
            techniques.append(technique)
            bundle["objects"].append(technique)
            referenced_ids.append(technique["id"])  # Add to Report's object_refs
        
        # Add IntrusionSet if present
        if claim.get("intrusion_set"):
            intrusion_set = {
                "type": "intrusion-set",
                "spec_version": "2.1",
                "id": f"intrusion-set--{uuid4()}",
                "name": claim["intrusion_set"],
                "x_bj_provenance": {
                    "evidence": claim.get("evidence", {}),
                    "confidence": claim.get("confidence", 0.5)
                }
            }
            intrusion_sets.append(intrusion_set)
            bundle["objects"].append(intrusion_set)
            referenced_ids.append(intrusion_set["id"])  # Add to Report's object_refs
    
    # Create Campaign if rubric met
    if rubric.created_campaign:
        campaign = {
            "type": "campaign",
            "spec_version": "2.1",
            "id": campaign_id or f"campaign--{uuid4()}",
            "name": f"Campaign from {report.name}",
            "description": f"Campaign extracted from report: {report.name}",
            "created": now_iso,
            "modified": now_iso
        }
        
        if rubric.first_seen:
            campaign["first_seen"] = rubric.first_seen
        if rubric.last_seen:
            campaign["last_seen"] = rubric.last_seen
        
        # Mark as provisional if forced
        if rubric.criteria_met < 2:
            campaign["x_bj_status"] = "provisional"
        
        bundle["objects"].append(campaign)
        referenced_ids.append(campaign["id"])  # Add to Report's object_refs
        
        # Create ATTRIBUTED_TO relationships
        for intrusion_set in intrusion_sets:
            relationships.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid4()}",
                "relationship_type": "attributed-to",
                "source_ref": campaign["id"],
                "target_ref": intrusion_set["id"],
                "created": now_iso,
                "modified": now_iso
            })
        
        # Create USES relationships for techniques
        for technique in techniques:
            relationships.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid4()}",
                "relationship_type": "uses",
                "source_ref": campaign["id"],
                "target_ref": technique["id"],
                "created": now_iso,
                "modified": now_iso
            })
    
    # Add all relationships to bundle
    bundle["objects"].extend(relationships)
    
    # Set Report's object_refs to all referenced objects (not including relationships)
    report_dict["object_refs"] = referenced_ids
    
    # Add the Report to the bundle (with object_refs populated)
    bundle["objects"].insert(0, report_dict)
    
    return bundle


@router.post(
    "/ingest",
    response_model=IngestResponse,
    operation_id="ingestReport",
    summary="Ingest Report with Extraction",
    description="""
    Ingest a threat intelligence report, extract entities using agentic_v2_optimized,
    apply campaign creation rubric, and create STIX objects with proper relationships.
    
    The extraction pipeline will:
    1. Extract text from PDF/document if needed
    2. Run agentic_v2_optimized for technique extraction
    3. Apply campaign creation rubric (≥2 criteria needed)
    4. Create STIX bundle with relationships per spec
    5. Validate and upsert to graph
    """
)
async def ingest_report(request: IngestRequest):
    """Ingest report with full extraction pipeline."""
    
    trace_id = f"trace-{uuid4()}"
    logger.info(f"Starting report ingestion: {trace_id}")
    
    try:
        # Get text content
        if request.inline_text:
            text_content = request.inline_text
        elif request.file_url:
            # TODO: Implement file download and extraction
            raise HTTPException(status_code=501, detail="File URL extraction not yet implemented")
        else:
            raise HTTPException(status_code=400, detail="Either inline_text or file_url must be provided")
        
        # Create or use provided Report SDO
        if not request.report_sdo:
            request.report_sdo = ReportSDO(
                name="Extracted Report",
                description="Auto-generated report from extraction",
                published=datetime.utcnow().isoformat()
            )
        
        # Run extraction with chunked extractor for large documents
        tracker = ExtractionTracker()
        config = request.config.dict()
        
        logger.info(f"Running extraction on text ({len(text_content)} chars)")
        
        # Use chunked extraction for large documents
        if len(text_content) > 5000:  # Threshold for chunked processing
            logger.info("Using chunked extraction for large document")
            extraction_results = extract_chunked(
                text=text_content,
                config=config,
                chunk_size=3000,
                overlap=200,
                max_chunks=10,
                parallel=True
            )
        else:
            # Use regular extraction for small documents
            extraction_results = run_agentic_v2_optimized(
                report_text=text_content,
                config=config,
                tracker=tracker
            )
        
        logger.info(f"Extraction complete: {len(extraction_results.get('claims', []))} claims found")
        
        # Evaluate campaign rubric
        claims = extraction_results.get("claims", [])
        logger.info(f"Extraction returned: {json.dumps(extraction_results, default=str)[:500]}")
        rubric, rubric_evidence = evaluate_campaign_rubric(claims, request.config.force_provisional_campaign)
        
        # Create STIX bundle
        bundle = create_stix_bundle(
            request.report_sdo,
            extraction_results,
            rubric,
            rubric_evidence
        )
        
        logger.info(f"Bundle created with {len(bundle.get('objects', []))} objects")
        if bundle.get('objects'):
            report_obj = bundle['objects'][0]
            logger.info(f"Report object_refs: {len(report_obj.get('object_refs', []))} items")
        
        # Validate bundle
        is_valid, validation_errors = validate_bundle_for_upsert(bundle)
        if not is_valid:
            logger.error(f"Bundle validation failed: {validation_errors}")
            raise HTTPException(status_code=400, detail=f"Invalid STIX bundle: {'; '.join(validation_errors)}")
        
        # Upsert to graph
        report_store = ReportStore(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        upsert_result = report_store.upsert_bundle(bundle)
        report_store.close()
        
        # Prepare response
        report_id = bundle["objects"][0]["id"]
        campaign_id = None
        flow_id = None
        
        # Find campaign if created
        for obj in bundle["objects"]:
            if obj["type"] == "campaign":
                campaign_id = obj["id"]
                break
        
        # Extract entity lists
        entities = {
            "describes": [],
            "intrusion_sets": [],
            "software": [],
            "attack_patterns": []
        }
        
        for obj in bundle["objects"]:
            if obj["type"] == "attack-pattern":
                entities["attack_patterns"].append(obj["id"])
                entities["describes"].append(obj["id"])
            elif obj["type"] == "intrusion-set":
                entities["intrusion_sets"].append(obj["id"])
                entities["describes"].append(obj["id"])
            elif obj["type"] in ["tool", "malware"]:
                entities["software"].append(obj["id"])
                entities["describes"].append(obj["id"])
        
        # Get extraction metrics
        metrics = tracker.snapshot()
        metrics["duration_ms"] = metrics.get("total_time", 0) * 1000
        metrics["spans_found"] = len(extraction_results.get("spans", []))
        metrics["techniques_extracted"] = len(entities["attack_patterns"])
        metrics["confidence_avg"] = sum(c.get("confidence", 0) for c in claims) / max(1, len(claims))
        
        # Get object_refs from the report in the bundle
        report_obj = bundle["objects"][0]
        object_refs = report_obj.get("object_refs", [])
        
        return IngestResponse(
            report_id=report_id,
            campaign_id=campaign_id,
            flow_id=flow_id,
            provisional=rubric.criteria_met < 2 and rubric.created_campaign,
            rubric=rubric,
            rubric_evidence=rubric_evidence,
            object_refs=object_refs,
            entities=entities,
            rejected=upsert_result.get("rejected", []),
            warnings=upsert_result.get("warnings", []),
            trace_id=trace_id,
            extraction_metrics=metrics
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report ingestion failed ({trace_id}): {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")


@router.post(
    "/ingest/upload",
    response_model=IngestResponse,
    operation_id="ingestReportUpload",
    summary="Ingest Report from File Upload",
    description="Upload a PDF/TXT/MD file for extraction and ingestion."
)
async def ingest_report_upload(
    file: UploadFile = File(...),
    use_batch_mapper: bool = Form(True),
    skip_verification: bool = Form(False),
    force_provisional_campaign: bool = Form(False)
):
    """Handle file upload for report ingestion."""
    
    # Validate file type
    allowed_types = {".pdf", ".txt", ".md", ".markdown"}
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {file_ext}. Allowed: {', '.join(allowed_types)}"
        )
    
    try:
        # Save uploaded file temporarily
        temp_path = f"/tmp/upload_{uuid4()}{file_ext}"
        with open(temp_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        # Extract text based on file type
        if file_ext == ".pdf":
            text_content = extract_text_from_pdf(temp_path)
        else:
            text_content = content.decode("utf-8")
        
        # Clean up temp file
        Path(temp_path).unlink(missing_ok=True)
        
        # Create ingestion request
        request = IngestRequest(
            report_sdo=ReportSDO(
                name=file.filename,
                description=f"Uploaded report: {file.filename}",
                published=datetime.utcnow().isoformat()
            ),
            inline_text=text_content,
            config=IngestConfig(
                use_batch_mapper=use_batch_mapper,
                skip_verification=skip_verification,
                force_provisional_campaign=force_provisional_campaign
            )
        )
        
        # Process ingestion
        return await ingest_report(request)
        
    except Exception as e:
        logger.error(f"File upload ingestion failed: {e}")
        raise HTTPException(status_code=500, detail=f"Upload processing failed: {str(e)}")


@router.get(
    "/{report_id}",
    operation_id="getReport",
    summary="Get Report Details",
    description="Get report with linked entities and campaign decision."
)
async def get_report(report_id: str):
    """Get report details with relationships."""
    
    try:
        report_store = ReportStore(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        report = report_store.get_report_with_relationships(report_id)
        report_store.close()
        
        if not report:
            raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
        
        return report
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get report: {str(e)}")


@router.post(
    "/campaigns/merge",
    operation_id="mergeCampaigns",
    summary="Merge Provisional Campaigns",
    description="Merge multiple provisional campaigns into a confirmed campaign."
)
async def merge_campaigns(
    from_ids: List[str],
    into_id: Optional[str] = None
):
    """Merge provisional campaigns."""
    
    try:
        campaign_store = CampaignStore(
            neo4j_uri=settings.neo4j_uri,
            neo4j_user=settings.neo4j_user,
            neo4j_password=settings.neo4j_password
        )
        
        result = campaign_store.merge_campaigns(
            from_ids=from_ids,
            into_id=into_id or f"campaign--{uuid4()}"
        )
        
        campaign_store.close()
        
        return result
        
    except Exception as e:
        logger.error(f"Campaign merge failed: {e}")
        raise HTTPException(status_code=500, detail=f"Merge failed: {str(e)}")