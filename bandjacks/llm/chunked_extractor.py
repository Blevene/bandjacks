"""Chunked document extraction for handling large PDFs efficiently."""

import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import concurrent.futures
from bandjacks.llm.agentic_v2_optimized import run_agentic_v2_optimized
from bandjacks.llm.tracker import ExtractionTracker


@dataclass
class DocumentChunk:
    """Represents a chunk of document text with metadata."""
    text: str
    start_idx: int
    end_idx: int
    chunk_id: int
    overlap_start: int = 0  # Characters overlapping with previous chunk
    overlap_end: int = 0    # Characters overlapping with next chunk


class ChunkedExtractor:
    """Extract techniques from large documents by processing chunks."""
    
    def __init__(
        self,
        chunk_size: int = 3000,
        overlap: int = 200,
        max_chunks: int = 10,
        parallel_workers: int = 3
    ):
        """
        Initialize chunked extractor.
        
        Args:
            chunk_size: Target size for each chunk in characters
            overlap: Number of characters to overlap between chunks
            max_chunks: Maximum number of chunks to process
            parallel_workers: Number of parallel workers for chunk processing
        """
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.max_chunks = max_chunks
        self.parallel_workers = parallel_workers
    
    def create_chunks(self, text: str) -> List[DocumentChunk]:
        """
        Split document into overlapping chunks.
        
        Args:
            text: Full document text
            
        Returns:
            List of document chunks
        """
        chunks = []
        text_len = len(text)
        
        # If text is small enough, return single chunk
        if text_len <= self.chunk_size:
            return [DocumentChunk(
                text=text,
                start_idx=0,
                end_idx=text_len,
                chunk_id=0
            )]
        
        # Find sentence boundaries for cleaner splits
        sentence_pattern = re.compile(r'[.!?]\s+')
        
        current_pos = 0
        chunk_id = 0
        
        while current_pos < text_len and chunk_id < self.max_chunks:
            # Calculate chunk boundaries
            chunk_start = max(0, current_pos - self.overlap if chunk_id > 0 else 0)
            chunk_end = min(text_len, current_pos + self.chunk_size)
            
            # Try to end at sentence boundary
            if chunk_end < text_len:
                # Look for sentence end near chunk_end
                search_start = max(chunk_end - 100, current_pos)
                match = None
                for m in sentence_pattern.finditer(text, search_start, chunk_end + 100):
                    if m.end() <= chunk_end + 100:
                        match = m
                
                if match:
                    chunk_end = match.end()
            
            # Extract chunk text
            chunk_text = text[chunk_start:chunk_end]
            
            # Calculate overlaps
            overlap_start = current_pos - chunk_start if chunk_id > 0 else 0
            overlap_end = 0
            if chunk_id < self.max_chunks - 1 and chunk_end < text_len:
                next_start = chunk_end - self.overlap
                overlap_end = chunk_end - next_start
            
            chunks.append(DocumentChunk(
                text=chunk_text,
                start_idx=chunk_start,
                end_idx=chunk_end,
                chunk_id=chunk_id,
                overlap_start=overlap_start,
                overlap_end=overlap_end
            ))
            
            # Move to next chunk position
            current_pos = chunk_end - self.overlap
            chunk_id += 1
            
            # Stop if we've covered enough of the document
            if chunk_end >= text_len:
                break
        
        return chunks
    
    def process_chunk(
        self,
        chunk: DocumentChunk,
        config: Dict[str, Any],
        tracker: Optional[ExtractionTracker] = None
    ) -> Dict[str, Any]:
        """
        Process a single chunk of text.
        
        Args:
            chunk: Document chunk to process
            config: Extraction configuration
            tracker: Optional extraction tracker
            
        Returns:
            Extraction results for the chunk
        """
        # Create chunk-specific config with aggressive optimization
        chunk_config = config.copy()
        chunk_config.update({
            "use_batch_mapper": True,
            "disable_discovery": True,
            "disable_targeted_extraction": True,
            "skip_verification": True,
            "max_spans": 5,  # Limit spans per chunk
            "span_score_threshold": 0.85,  # Higher threshold for chunks
            "max_tool_iterations": 2,  # Reduce iterations
        })
        
        # Add chunk context to help with deduplication
        chunk_text = chunk.text
        if chunk.overlap_start > 0:
            chunk_text = f"[...continued from previous section...]\n{chunk_text}"
        if chunk.overlap_end > 0:
            chunk_text = f"{chunk_text}\n[...continues in next section...]"
        
        # Run extraction on chunk
        try:
            result = run_agentic_v2_optimized(
                report_text=chunk_text,
                config=chunk_config,
                tracker=tracker
            )
            result["chunk_id"] = chunk.chunk_id
            result["chunk_boundaries"] = (chunk.start_idx, chunk.end_idx)
            return result
        except Exception as e:
            print(f"[ERROR] Chunk {chunk.chunk_id} extraction failed: {e}")
            return {
                "chunk_id": chunk.chunk_id,
                "chunk_boundaries": (chunk.start_idx, chunk.end_idx),
                "claims": [],
                "error": str(e)
            }
    
    def merge_results(self, chunk_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Merge results from multiple chunks, deduplicating techniques.
        
        Args:
            chunk_results: List of extraction results from chunks
            
        Returns:
            Merged extraction results
        """
        merged = {
            "claims": [],
            "techniques": {},
            "chunks_processed": len(chunk_results),
            "metrics": {}
        }
        
        # Track seen techniques to avoid duplicates
        seen_techniques = {}
        all_claims = []
        
        for result in chunk_results:
            chunk_id = result.get("chunk_id", -1)
            
            # Process claims from this chunk
            for claim in result.get("claims", []):
                tech_id = claim.get("technique_id", "")
                if not tech_id:
                    continue
                
                # Check if we've seen this technique
                if tech_id in seen_techniques:
                    # Merge evidence if confidence is high enough
                    existing = seen_techniques[tech_id]
                    if claim.get("confidence", 0) >= existing.get("confidence", 0) - 10:
                        # Add new evidence to existing technique
                        existing_evidence = existing.get("evidence", {})
                        new_evidence = claim.get("evidence", {})
                        
                        # Merge quotes (avoid duplicates)
                        existing_quotes = set(existing_evidence.get("quotes", []))
                        new_quotes = new_evidence.get("quotes", [])
                        for quote in new_quotes:
                            if not any(quote in eq or eq in quote for eq in existing_quotes):
                                existing_quotes.add(quote)
                        
                        existing_evidence["quotes"] = list(existing_quotes)[:5]  # Limit to 5 quotes
                        
                        # Update confidence to max
                        existing["confidence"] = max(
                            existing.get("confidence", 0),
                            claim.get("confidence", 0)
                        )
                else:
                    # New technique
                    claim["source_chunk"] = chunk_id
                    seen_techniques[tech_id] = claim
                    all_claims.append(claim)
        
        # Convert to final format
        merged["claims"] = list(seen_techniques.values())
        
        # Build techniques dict for compatibility
        for claim in merged["claims"]:
            tech_id = claim.get("technique_id", "")
            if tech_id:
                merged["techniques"][tech_id] = {
                    "name": claim.get("technique_name", tech_id),
                    "confidence": claim.get("confidence", 50),
                    "evidence": claim.get("evidence", {}).get("quotes", []),
                    "line_refs": claim.get("evidence", {}).get("line_refs", [])
                }
        
        # Aggregate metrics
        total_time = sum(r.get("metrics", {}).get("dur_sec", 0) for r in chunk_results)
        merged["metrics"]["total_chunks"] = len(chunk_results)
        merged["metrics"]["total_time_sec"] = total_time
        merged["metrics"]["techniques_found"] = len(merged["techniques"])
        
        return merged
    
    def extract(
        self,
        text: str,
        config: Dict[str, Any],
        parallel: bool = True
    ) -> Dict[str, Any]:
        """
        Extract techniques from document using chunked processing.
        
        Args:
            text: Full document text
            config: Extraction configuration
            parallel: Whether to process chunks in parallel
            
        Returns:
            Extraction results with merged techniques
        """
        # Create chunks
        chunks = self.create_chunks(text)
        print(f"[INFO] Created {len(chunks)} chunks from {len(text)} chars")
        
        # Process chunks
        chunk_results = []
        
        if parallel and len(chunks) > 1:
            # Process chunks in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallel_workers) as executor:
                # Create individual trackers for each chunk
                futures = []
                for chunk in chunks:
                    tracker = ExtractionTracker()
                    future = executor.submit(self.process_chunk, chunk, config, tracker)
                    futures.append((future, chunk.chunk_id))
                
                # Collect results as they complete
                for future, chunk_id in futures:
                    try:
                        result = future.result(timeout=60)  # 1 minute timeout per chunk
                        chunk_results.append(result)
                        print(f"[INFO] Chunk {chunk_id} complete: {len(result.get('claims', []))} claims")
                    except Exception as e:
                        print(f"[ERROR] Chunk {chunk_id} failed: {e}")
                        chunk_results.append({
                            "chunk_id": chunk_id,
                            "claims": [],
                            "error": str(e)
                        })
        else:
            # Process chunks sequentially
            for chunk in chunks:
                tracker = ExtractionTracker()
                result = self.process_chunk(chunk, config, tracker)
                chunk_results.append(result)
                print(f"[INFO] Chunk {chunk.chunk_id} complete: {len(result.get('claims', []))} claims")
        
        # Merge results
        merged = self.merge_results(chunk_results)
        print(f"[INFO] Extraction complete: {len(merged['techniques'])} unique techniques from {len(chunks)} chunks")
        
        return merged


def extract_chunked(
    text: str,
    config: Dict[str, Any],
    chunk_size: int = 3000,
    overlap: int = 200,
    max_chunks: int = 10,
    parallel: bool = True
) -> Dict[str, Any]:
    """
    Convenience function for chunked extraction.
    
    Args:
        text: Document text to extract from
        config: Extraction configuration
        chunk_size: Size of each chunk
        overlap: Overlap between chunks
        max_chunks: Maximum chunks to process
        parallel: Whether to process in parallel
        
    Returns:
        Merged extraction results
    """
    extractor = ChunkedExtractor(
        chunk_size=chunk_size,
        overlap=overlap,
        max_chunks=max_chunks,
        parallel_workers=3
    )
    
    return extractor.extract(text, config, parallel=parallel)