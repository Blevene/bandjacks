"""Mapper API routes for document analysis and TTP extraction."""

from fastapi import APIRouter, HTTPException
from bandjacks.services.api.schemas import ProposeRequest, ProposalResponse, ProposalStats
from bandjacks.services.api.settings import settings
from bandjacks.loaders.parse_text import extract_text
from bandjacks.loaders.chunker import split_into_chunks
from bandjacks.loaders.propose import propose_bundle

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
        
        # Generate proposal
        result = propose_bundle(
            chunks=chunks,
            max_candidates=request.max_candidates,
            os_url=settings.opensearch_url,
            os_index=settings.os_index_nodes
        )
        
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