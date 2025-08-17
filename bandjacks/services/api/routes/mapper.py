"""Mapper API routes for document analysis and TTP extraction."""

import httpx
import uuid
from fastapi import APIRouter, HTTPException
from bandjacks.services.api.schemas import ProposeRequest, ProposalResponse, ProposalStats
from bandjacks.services.api.settings import settings
from bandjacks.loaders.parse_text import extract_text
from bandjacks.loaders.chunker import split_into_chunks
from bandjacks.loaders.propose import propose_bundle
from bandjacks.llm.stix_converter import merge_with_vector_results

router = APIRouter(tags=["mapper"])


@router.post("/mapper/propose", response_model=ProposalResponse)
async def propose_mapping(request: ProposeRequest):
    """
    Analyze document and propose ATT&CK mappings.
    
    Takes a document (via URL or inline text), extracts text,
    chunks it, and proposes ATT&CK techniques, groups, software,
    and relationships based on the content.
    """
    try:
        # Extract text from document
        extracted = extract_text(
            source_type=request.source_type,
            content_url=request.content_url,
            inline_text=request.inline_text
        )
        
        # Chunk the text
        chunks = split_into_chunks(
            text=extracted["text"],
            source_id=request.source_id,
            target_chars=request.chunking.target_chars,
            overlap=request.chunking.overlap,
            metadata=extracted.get("metadata")
        )
        
        if not chunks:
            return ProposalResponse(
                proposal_id="empty",
                bundle={"type": "bundle", "objects": []},
                stats=ProposalStats(chunks=0, candidates_total=0)
            )
        
        # Generate proposal based on engine
        if request.engine == "vector":
            # Original vector-only approach
            result = propose_bundle(
                chunks=chunks,
                max_candidates=request.max_candidates,
                os_url=settings.opensearch_url,
                os_index=settings.os_index_nodes
            )
            
        elif request.engine == "llm":
            # LLM-based extraction
            result = await _propose_with_llm(
                request=request,
                chunks=chunks
            )
            
        elif request.engine == "hybrid":
            # Both vector and LLM, then merge
            vector_result = propose_bundle(
                chunks=chunks,
                max_candidates=request.max_candidates,
                os_url=settings.opensearch_url,
                os_index=settings.os_index_nodes
            )
            
            llm_result = await _propose_with_llm(
                request=request,
                chunks=chunks
            )
            
            # Merge results
            merged_bundle = merge_with_vector_results(
                llm_bundle=llm_result["bundle"],
                vector_bundle=vector_result["bundle"]
            )
            
            # Combine stats
            result = {
                "proposal_id": f"hybrid-{uuid.uuid4().hex[:8]}",
                "bundle": merged_bundle,
                "stats": {
                    "chunks": len(chunks),
                    "candidates_total": len(merged_bundle.get("objects", [])),
                    "techniques_found": sum(1 for o in merged_bundle.get("objects", []) if o.get("type") == "attack-pattern"),
                    "groups_found": sum(1 for o in merged_bundle.get("objects", []) if o.get("type") == "intrusion-set"),
                    "software_found": sum(1 for o in merged_bundle.get("objects", []) if o.get("type") in ["malware", "tool"]),
                    "relationships_proposed": sum(1 for o in merged_bundle.get("objects", []) if o.get("type") == "relationship")
                }
            }
        else:
            raise ValueError(f"Unknown engine: {request.engine}")
        
        # Convert stats dict to ProposalStats model
        stats = ProposalStats(**result["stats"])
        
        return ProposalResponse(
            proposal_id=result["proposal_id"],
            bundle=result["bundle"],
            stats=stats
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Proposal generation failed: {str(e)}")


async def _propose_with_llm(request: ProposeRequest, chunks: list) -> dict:
    """Helper to call LLM extraction and convert to proposal format."""
    # Call LLM extraction endpoint
    async with httpx.AsyncClient() as client:
        llm_response = await client.post(
            f"http://localhost:8000/v1/llm/extract",
            json={
                "source_id": request.source_id,
                "source_type": request.source_type,
                "content_url": request.content_url,
                "inline_text": request.inline_text,
                "max_candidates": request.max_candidates,
                "chunking": {"target_chars": request.chunking.target_chars, "overlap": request.chunking.overlap}
            },
            timeout=60.0
        )
        llm_response.raise_for_status()
        extraction = llm_response.json()
    
    # Convert to STIX bundle
    async with httpx.AsyncClient() as client:
        stix_response = await client.post(
            f"http://localhost:8000/v1/llm/to-stix",
            json=extraction,
            params={"validate_ids": True, "apply_guards": True},
            timeout=30.0
        )
        stix_response.raise_for_status()
        bundle = stix_response.json()
    
    # Format as proposal result
    return {
        "proposal_id": extraction.get("extraction_id", f"llm-{uuid.uuid4().hex[:8]}"),
        "bundle": bundle,
        "stats": {
            "chunks": len(chunks),
            "candidates_total": len(bundle.get("objects", [])),
            "techniques_found": sum(1 for o in bundle.get("objects", []) if o.get("type") == "attack-pattern"),
            "groups_found": sum(1 for o in bundle.get("objects", []) if o.get("type") == "intrusion-set"),
            "software_found": sum(1 for o in bundle.get("objects", []) if o.get("type") in ["malware", "tool"]),
            "relationships_proposed": sum(1 for o in bundle.get("objects", []) if o.get("type") == "relationship")
        }
    }