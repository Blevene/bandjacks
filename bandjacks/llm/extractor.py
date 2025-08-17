"""LLM-based extraction pipeline for threat intelligence text."""

import time
import json
from typing import List, Dict, Any, Optional
from bandjacks.llm.client import execute_tool_loop, validate_json_response
from bandjacks.llm.tools import get_tool_definitions, get_tool_functions
from bandjacks.llm.prompts import get_messages_for_chunk, PROMPT_VERSION
from bandjacks.llm.schemas import LLM_OUTPUT_SCHEMA, LLM_EXTRACTION_SCHEMA
from bandjacks.loaders.parse_text import extract_text
from bandjacks.loaders.chunker import split_into_chunks


class LLMExtractor:
    """Extract TTP claims from text using LLM with tool grounding."""
    
    def __init__(self, model: str = None):
        """
        Initialize the extractor.
        
        Args:
            model: Optional model override
        """
        self.model = model or "gpt-4o-mini"
        self.tools = get_tool_definitions()
        self.tool_functions = get_tool_functions()
        self.total_tool_calls = 0
    
    def extract_chunk(self, chunk_id: str, text: str) -> Dict[str, Any]:
        """
        Extract claims from a single text chunk.
        
        Args:
            chunk_id: Identifier for the chunk
            text: Text content to analyze
            
        Returns:
            Extracted claims matching LLM_OUTPUT_SCHEMA
        """
        # Get messages for this chunk
        messages = get_messages_for_chunk(chunk_id, text)
        
        # Execute tool loop to get LLM response
        try:
            response = execute_tool_loop(
                messages=messages,
                tools=self.tools,
                tool_functions=self.tool_functions,
                max_iterations=10
            )
            
            # Validate and parse JSON response
            result = validate_json_response(response, LLM_OUTPUT_SCHEMA)
            
            # Ensure chunk_id matches
            if result.get("chunk_id") != chunk_id:
                result["chunk_id"] = chunk_id
            
            return result
            
        except Exception as e:
            # Return minimal valid response on error
            return {
                "chunk_id": chunk_id,
                "claims": [],
                "error": str(e)
            }
    
    def extract_document(
        self,
        source_id: str,
        source_type: str,
        content_url: Optional[str] = None,
        inline_text: Optional[str] = None,
        chunking_params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Extract claims from an entire document.
        
        Args:
            source_id: Document identifier
            source_type: Type of document (pdf, html, md, json, csv)
            content_url: URL to fetch content from
            inline_text: Direct text content
            chunking_params: Parameters for text chunking
            
        Returns:
            Aggregated extraction matching LLM_EXTRACTION_SCHEMA
        """
        start_time = time.time()
        
        # Extract text from document
        extracted = extract_text(
            source_type=source_type,
            content_url=content_url,
            inline_text=inline_text
        )
        
        # Chunk the text
        chunk_params = chunking_params or {"target_chars": 1200, "overlap": 150}
        chunks = split_into_chunks(
            text=extracted["text"],
            source_id=source_id,
            target_chars=chunk_params.get("target_chars", 1200),
            overlap=chunk_params.get("overlap", 150),
            metadata=extracted.get("metadata")
        )
        
        # Extract from each chunk
        chunk_results = []
        for chunk in chunks:
            chunk_result = self.extract_chunk(
                chunk_id=chunk["id"],
                text=chunk["text"]
            )
            chunk_results.append(chunk_result)
        
        # Calculate execution time
        extraction_time_ms = int((time.time() - start_time) * 1000)
        
        # Build response
        return {
            "chunks": chunk_results,
            "metadata": {
                "llm_model": self.model,
                "prompt_version": PROMPT_VERSION,
                "total_tool_calls": self.total_tool_calls,
                "extraction_time_ms": extraction_time_ms
            }
        }


def extract_with_llm(
    source_id: str,
    source_type: str,
    content_url: Optional[str] = None,
    inline_text: Optional[str] = None,
    max_candidates: int = 5,
    chunking_params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Main entry point for LLM extraction.
    
    Args:
        source_id: Document identifier
        source_type: Document type
        content_url: URL to fetch from
        inline_text: Direct text
        max_candidates: Maximum candidates per claim
        chunking_params: Chunking parameters
        
    Returns:
        LLM extraction results
    """
    extractor = LLMExtractor()
    return extractor.extract_document(
        source_id=source_id,
        source_type=source_type,
        content_url=content_url,
        inline_text=inline_text,
        chunking_params=chunking_params
    )