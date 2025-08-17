"""LLM extraction API routes."""

from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from bandjacks.llm.extractor import extract_with_llm
from bandjacks.llm.stix_converter import llm_to_stix_bundle, apply_safeguards, validate_stix_ids
from bandjacks.services.api.settings import settings
from neo4j import GraphDatabase


router = APIRouter(tags=["llm"])


class LLMExtractRequest(BaseModel):
    """Request for LLM extraction."""
    source_id: str
    source_type: str = Field(..., pattern="^(pdf|html|md|json|csv)$")
    content_url: Optional[str] = None
    inline_text: Optional[str] = None
    max_candidates: int = Field(5, ge=1, le=20)
    chunking: Dict[str, Any] = Field(default={"target_chars": 1200, "overlap": 150})


class LLMExtractResponse(BaseModel):
    """Response from LLM extraction."""
    extraction_id: str
    chunks: list
    metadata: Dict[str, Any]


def check_stix_id_exists(stix_id: str) -> bool:
    """
    Check if a STIX ID exists in our knowledge base.
    
    Args:
        stix_id: STIX ID to validate
        
    Returns:
        True if ID exists in Neo4j
    """
    driver = GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password)
    )
    
    try:
        with driver.session() as session:
            result = session.run(
                "MATCH (n {stix_id: $stix_id}) RETURN count(n) as count",
                stix_id=stix_id
            )
            count = result.single()["count"]
            return count > 0
    finally:
        driver.close()


@router.post("/llm/extract", response_model=LLMExtractResponse)
async def extract_with_llm_endpoint(request: LLMExtractRequest, dry_run: bool = Query(False)):
    """
    Extract TTP claims from document using LLM with tool grounding.
    
    This endpoint uses an LLM to analyze the document and extract:
    - ATT&CK technique mappings with confidence scores
    - Evidence spans showing where claims are supported
    - Threat actor and malware identifications
    - Relationships between entities
    
    All mappings are grounded through tool calls to the Bandjacks KB.
    """
    try:
        if dry_run:
            # Return mock response for testing
            return LLMExtractResponse(
                extraction_id="dry-run-001",
                chunks=[
                    {
                        "chunk_id": f"{request.source_id}#c0",
                        "claims": [
                            {
                                "type": "activity",
                                "span": {"text": "mock extraction"},
                                "mappings": [
                                    {
                                        "stix_id": "attack-pattern--test",
                                        "confidence": 75,
                                        "rationale": "Dry run test"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                metadata={
                    "llm_model": "dry-run",
                    "prompt_version": "1.0.0",
                    "total_tool_calls": 0,
                    "extraction_time_ms": 0
                }
            )
        
        # Perform real LLM extraction
        result = extract_with_llm(
            source_id=request.source_id,
            source_type=request.source_type,
            content_url=request.content_url,
            inline_text=request.inline_text,
            max_candidates=request.max_candidates,
            chunking_params=request.chunking
        )
        
        # Generate extraction ID
        import uuid
        extraction_id = f"llm-ext-{uuid.uuid4().hex[:8]}"
        
        return LLMExtractResponse(
            extraction_id=extraction_id,
            chunks=result.get("chunks", []),
            metadata=result.get("metadata", {})
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM extraction failed: {str(e)}")


@router.post("/llm/to-stix")
async def convert_to_stix(
    extraction: Dict[str, Any],
    validate_ids: bool = Query(True),
    apply_guards: bool = Query(True)
):
    """
    Convert LLM extraction output to STIX bundle.
    
    This endpoint:
    - Converts LLM claims to STIX objects
    - Validates all STIX IDs against the KB
    - Applies safeguards to cap confidence
    - Removes any hallucinated/invalid IDs
    """
    try:
        # Convert to STIX
        bundle = llm_to_stix_bundle(
            extraction,
            kb_validator=check_stix_id_exists if validate_ids else None
        )
        
        # Apply safeguards
        if apply_guards:
            bundle = apply_safeguards(bundle, max_confidence=85)
        
        # Validate IDs
        if validate_ids:
            bundle = validate_stix_ids(bundle, check_stix_id_exists)
        
        return bundle
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"STIX conversion failed: {str(e)}")