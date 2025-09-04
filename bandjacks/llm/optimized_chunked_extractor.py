"""Optimized chunked document extraction with smart span detection."""

import re
import logging
import time
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass
import concurrent.futures

from bandjacks.llm.chunked_extractor import ChunkedExtractor, DocumentChunk
from bandjacks.llm.extraction_pipeline import run_extraction_pipeline
from bandjacks.llm.agents_v2 import SpanFinderAgent
from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.entity_utils import consolidate_entities

logger = logging.getLogger(__name__)


@dataclass
class DetectedSpan:
    """Represents a detected span with position information."""
    text: str
    start_pos: int
    end_pos: int
    line_refs: List[int]
    score: float
    tactics: List[str]
    type: str = "sentence_based"


class OptimizedChunkedExtractor(ChunkedExtractor):
    """
    Optimized chunked extractor with smart span detection.
    
    Key optimization: Detect spans ONCE globally or with sliding windows,
    then map them to chunks instead of detecting spans in each chunk separately.
    """
    
    def __init__(
        self,
        chunk_size: int = 4000,
        overlap: int = 150,
        max_chunks: int = 8,
        parallel_workers: int = 1,
        window_size: int = 30000,  # ~8K tokens for span detection
        window_overlap: int = 5000  # ~1.5K tokens overlap
    ):
        """
        Initialize optimized chunked extractor.
        
        Args:
            chunk_size: Target size for each chunk in characters
            overlap: Number of characters to overlap between chunks
            max_chunks: Maximum number of chunks to process
            parallel_workers: Number of parallel workers for chunk processing
            window_size: Size of sliding window for span detection (large docs)
            window_overlap: Overlap between detection windows
        """
        super().__init__(chunk_size, overlap, max_chunks, parallel_workers)
        self.window_size = window_size
        self.window_overlap = window_overlap
        
    def detect_spans_global(self, text: str, config: Dict[str, Any]) -> List[DetectedSpan]:
        """
        Detect all spans in document globally (for small documents).
        
        Args:
            text: Full document text
            config: Extraction configuration
            
        Returns:
            List of detected spans with position information
        """
        logger.info("Using global span detection for small document")
        
        # Create memory with full text
        mem = WorkingMemory()
        mem.document_text = text
        mem.line_index = text.splitlines()
        
        # Run span finder on entire document
        span_finder = SpanFinderAgent()
        span_finder.run(mem, config)
        
        # Convert to DetectedSpan objects with position tracking
        detected_spans = []
        current_pos = 0
        
        for span in mem.spans:
            # Find position of span text in document
            span_text = span.get("text", "")
            if not span_text:
                continue
                
            # Try to find exact position (may be approximate for sentence-based spans)
            pos = text.find(span_text, current_pos)
            if pos == -1:
                # Try from beginning if not found from current position
                pos = text.find(span_text)
            
            if pos != -1:
                detected = DetectedSpan(
                    text=span_text,
                    start_pos=pos,
                    end_pos=pos + len(span_text),
                    line_refs=span.get("line_refs", []),
                    score=span.get("score", 0.5),
                    tactics=span.get("tactics", []),
                    type=span.get("type", "sentence_based")
                )
                detected_spans.append(detected)
                current_pos = pos + len(span_text)
        
        logger.info(f"Global detection found {len(detected_spans)} spans")
        return detected_spans
    
    def detect_spans_windowed(self, text: str, config: Dict[str, Any]) -> List[DetectedSpan]:
        """
        Detect spans using sliding windows for large documents.
        
        Args:
            text: Full document text
            config: Extraction configuration
            
        Returns:
            List of detected spans with position information
        """
        text_length = len(text)
        logger.info(f"Using windowed span detection for large document ({text_length} chars)")
        
        all_spans = []
        seen_spans: Set[Tuple[int, int, str]] = set()
        
        # Process document in overlapping windows
        window_count = 0
        for window_start in range(0, text_length, self.window_size - self.window_overlap):
            window_end = min(window_start + self.window_size, text_length)
            window_text = text[window_start:window_end]
            
            if len(window_text.strip()) < 100:  # Skip nearly empty windows
                continue
            
            window_count += 1
            logger.debug(f"Processing detection window {window_count}: chars {window_start}-{window_end}")
            
            # Create memory for this window
            mem = WorkingMemory()
            mem.document_text = window_text
            mem.line_index = window_text.splitlines()
            
            # Detect spans in this window
            span_finder = SpanFinderAgent()
            span_finder.run(mem, config)
            
            # Convert to DetectedSpan with adjusted positions
            for span in mem.spans:
                span_text = span.get("text", "")
                if not span_text:
                    continue
                
                # Find position within window
                window_pos = window_text.find(span_text)
                if window_pos == -1:
                    continue
                
                # Adjust to document position
                doc_start = window_start + window_pos
                doc_end = doc_start + len(span_text)
                
                # Create deduplication key (position + first 50 chars)
                span_key = (doc_start, doc_end, span_text[:50])
                
                if span_key not in seen_spans:
                    detected = DetectedSpan(
                        text=span_text,
                        start_pos=doc_start,
                        end_pos=doc_end,
                        line_refs=span.get("line_refs", []),
                        score=span.get("score", 0.5),
                        tactics=span.get("tactics", []),
                        type=span.get("type", "sentence_based")
                    )
                    all_spans.append(detected)
                    seen_spans.add(span_key)
            
            # Stop if we've reached the end
            if window_end >= text_length:
                break
        
        # Sort spans by position for better chunk mapping
        all_spans.sort(key=lambda x: x.start_pos)
        
        logger.info(f"Windowed detection found {len(all_spans)} unique spans from {window_count} windows")
        return all_spans
    
    def redistribute_spans_evenly(
        self,
        all_spans: List[DetectedSpan],
        chunks: List[DocumentChunk],
        config: Dict[str, Any]
    ) -> Dict[int, List[Dict[str, Any]]]:
        """
        Redistribute spans evenly across chunks for balanced processing.
        
        Instead of mapping spans based on text position (which can be uneven),
        distribute spans round-robin style across chunks for even workload.
        
        Args:
            all_spans: All detected spans from document
            chunks: Document chunks
            config: Configuration
            
        Returns:
            Dictionary mapping chunk_id to list of spans
        """
        max_spans_per_chunk = config.get("max_spans_per_chunk", 25)
        
        # First, map spans to their natural chunks
        natural_mapping = {}
        for chunk in chunks:
            mapped_spans = self.map_spans_to_chunk(all_spans, chunk)
            natural_mapping[chunk.chunk_id] = mapped_spans
            
        # Check if redistribution is needed
        max_natural = max(len(spans) for spans in natural_mapping.values()) if natural_mapping else 0
        total_spans = len(all_spans)
        
        # Only redistribute if severely unbalanced (2x threshold) or forced
        force_redistribution = config.get("force_redistribution", False)
        severely_unbalanced = max_natural > max_spans_per_chunk * 2
        
        if not force_redistribution and max_natural <= max_spans_per_chunk:
            # Natural distribution is fine
            for chunk_id, spans in natural_mapping.items():
                logger.debug(f"Chunk {chunk_id}: {len(spans)} spans (natural distribution)")
            return natural_mapping
        
        if not force_redistribution and not severely_unbalanced:
            # Moderately unbalanced but acceptable - keep natural distribution
            logger.info(f"Keeping natural distribution (max {max_natural} spans, threshold {max_spans_per_chunk})")
            for chunk_id, spans in natural_mapping.items():
                logger.debug(f"Chunk {chunk_id}: {len(spans)} spans (natural)")
            return natural_mapping
        
        # Need to redistribute - use sequential blocks to preserve context
        logger.info(f"Redistributing {total_spans} spans for balance (max natural: {max_natural} spans)")
        
        # Calculate spans per chunk for even distribution
        spans_per_chunk = (total_spans + len(chunks) - 1) // len(chunks)
        
        # Distribute spans in sequential blocks (preserves document flow)
        redistributed = {chunk.chunk_id: [] for chunk in chunks}
        
        for i, span in enumerate(all_spans):
            # Sequential block assignment (not round-robin)
            chunk_idx = min(i // spans_per_chunk, len(chunks) - 1)
            chunk_id = chunks[chunk_idx].chunk_id
            
            # Convert DetectedSpan to dict format
            span_dict = {
                "text": span.text,
                "line_refs": span.line_refs,
                "score": span.score,
                "tactics": span.tactics,
                "type": span.type,
                "doc_position": (span.start_pos, span.end_pos)
            }
            redistributed[chunk_id].append(span_dict)
        
        # Log the redistribution
        for chunk_id, spans in redistributed.items():
            logger.debug(f"Chunk {chunk_id}: {len(spans)} spans (redistributed)")
        
        return redistributed
    
    def map_spans_to_chunk(self, all_spans: List[DetectedSpan], chunk: DocumentChunk) -> List[Dict[str, Any]]:
        """
        Map pre-detected spans to a specific chunk.
        
        Args:
            all_spans: All detected spans from document
            chunk: Document chunk to map spans to
            
        Returns:
            List of spans that belong to this chunk
        """
        chunk_spans = []
        
        for span in all_spans:
            # Check if span overlaps with chunk
            # A span belongs to a chunk if any part of it falls within the chunk boundaries
            span_overlaps = (
                # Span starts within chunk
                (chunk.start_idx <= span.start_pos < chunk.end_idx) or
                # Span ends within chunk  
                (chunk.start_idx < span.end_pos <= chunk.end_idx) or
                # Span completely contains chunk
                (span.start_pos <= chunk.start_idx and span.end_pos >= chunk.end_idx)
            )
            
            if span_overlaps:
                # Convert back to original span format for compatibility
                chunk_span = {
                    "text": span.text,
                    "line_refs": span.line_refs,
                    "score": span.score,
                    "tactics": span.tactics,
                    "type": span.type,
                    "doc_position": (span.start_pos, span.end_pos)  # Keep position for deduplication
                }
                chunk_spans.append(chunk_span)
        
        return chunk_spans
    
    def process_chunk_with_spans(
        self,
        chunk: DocumentChunk,
        pre_detected_spans: List[Dict[str, Any]],
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process a chunk with pre-detected spans.
        
        Args:
            chunk: Document chunk to process
            pre_detected_spans: Spans already detected for this chunk
            config: Extraction configuration
            
        Returns:
            Extraction results for the chunk
        """
        # Skip span detection - use pre-detected spans
        chunk_config = config.copy()
        chunk_config["skip_span_detection"] = True  # Signal to skip SpanFinderAgent
        
        # Create a modified pipeline that uses pre-detected spans
        # We'll need to inject spans directly into the memory
        from bandjacks.llm.memory import WorkingMemory
        mem = WorkingMemory()
        mem.document_text = chunk.text
        mem.line_index = chunk.text.splitlines()
        mem.spans = pre_detected_spans  # Inject pre-detected spans
        
        # Now run the rest of the pipeline (mapping, consolidation, etc.)
        # We need a modified extraction that can accept pre-populated memory
        try:
            # Run extraction with injected spans (no special import needed)
            result = self._run_extraction_with_injected_spans(
                chunk_text=chunk.text,
                pre_detected_spans=pre_detected_spans,
                config=chunk_config
            )
            
            result["chunk_id"] = chunk.chunk_id
            result["chunk_boundaries"] = (chunk.start_idx, chunk.end_idx)
            
            claims_count = len(result.get("claims", []))
            logger.info(f"Chunk {chunk.chunk_id} processed {len(pre_detected_spans)} pre-detected spans → {claims_count} claims")
            
            return result
            
        except Exception as e:
            logger.error(f"Chunk {chunk.chunk_id} processing failed: {e}", exc_info=True)
            return {
                "chunk_id": chunk.chunk_id,
                "chunk_boundaries": (chunk.start_idx, chunk.end_idx),
                "claims": [],
                "techniques": {},
                "entities": {},
                "error": str(e),
                "failed": True
            }
    
    def _run_extraction_with_injected_spans(
        self,
        chunk_text: str,
        pre_detected_spans: List[Dict[str, Any]],
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Run extraction pipeline with pre-detected spans injected.
        
        This is a workaround to inject spans into the extraction pipeline
        without modifying the core pipeline code.
        """
        # Import here to avoid circular imports
        from bandjacks.llm.mapper_optimized import BatchMapperAgent
        from bandjacks.llm.agents_v2 import MapperAgent, ConsolidatorAgent
        from bandjacks.llm.entity_extractor import EntityExtractionAgent
        from bandjacks.llm.memory import WorkingMemory
        
        # Create memory with injected spans
        mem = WorkingMemory()
        mem.document_text = chunk_text
        mem.line_index = chunk_text.splitlines()
        mem.spans = pre_detected_spans
        
        # Run mapper on pre-detected spans
        if pre_detected_spans:
            if config.get("use_batch_mapper", True):
                mapper = BatchMapperAgent()
                mapper.run(mem, config)
            else:
                mapper = MapperAgent()
                mapper.run(mem, config)
        
        # Run consolidator
        consolidator = ConsolidatorAgent()
        consolidator.run(mem, config)
        
        # Run entity extraction if enabled
        entities = {}
        if not config.get("disable_entity_extraction", False):
            try:
                entity_agent = EntityExtractionAgent()
                entity_agent.run(mem, config)
                if hasattr(mem, 'entities') and mem.entities:
                    entities = mem.entities
            except Exception as e:
                logger.warning(f"Entity extraction failed: {e}")
                entities = {"entities": [], "extraction_status": "failed"}
        
        # Build result - use claims directly since consolidator may not set consolidated_claims
        claims_to_use = []
        if hasattr(mem, 'consolidated_claims') and mem.consolidated_claims:
            claims_to_use = mem.consolidated_claims
        elif hasattr(mem, 'claims') and mem.claims:
            claims_to_use = mem.claims
            logger.debug(f"Using mem.claims ({len(claims_to_use)} claims) as consolidated_claims not found")
        
        result = {
            "claims": claims_to_use,
            "techniques": {},
            "entities": entities
        }
        
        # Convert claims to techniques dict
        for claim in result["claims"]:
            tech_id = claim.get("technique_id") or claim.get("external_id", "")
            if tech_id:
                result["techniques"][tech_id] = {
                    "name": claim.get("technique_name") or claim.get("name", tech_id),
                    "confidence": claim.get("confidence", 50),
                    "evidence": claim.get("evidence", {})
                }
        
        return result
    
    def extract(
        self,
        text: str,
        config: Dict[str, Any],
        parallel: bool = True,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Extract techniques using optimized chunked processing.
        
        Args:
            text: Full document text
            config: Extraction configuration
            parallel: Whether to process chunks in parallel
            progress_callback: Optional callback for progress updates
            
        Returns:
            Extraction results with merged techniques
        """
        text_length = len(text)
        
        # Step 1: Adaptive span detection based on document size
        if text_length < self.window_size:
            # Small document: use global span detection
            logger.info(f"Document size {text_length} chars < {self.window_size}, using global span detection")
            all_spans = self.detect_spans_global(text, config)
        else:
            # Large document: use windowed span detection
            logger.info(f"Document size {text_length} chars >= {self.window_size}, using windowed span detection")
            all_spans = self.detect_spans_windowed(text, config)
        
        logger.info(f"Total spans detected: {len(all_spans)}")
        
        # Update progress if callback provided
        if progress_callback:
            progress_callback(20, f"Detected {len(all_spans)} spans")
        
        # Step 2: Create chunks for processing
        chunks = self.create_chunks(text)
        logger.info(f"Created {len(chunks)} chunks for processing")
        
        # Step 3: Redistribute spans evenly across chunks
        chunk_spans_map = self.redistribute_spans_evenly(all_spans, chunks, config)
        
        # Update progress
        if progress_callback:
            progress_callback(30, f"Mapped spans to {len(chunks)} chunks")
        
        # Step 4: Process chunks with their pre-detected spans
        chunk_results = []
        
        if parallel and len(chunks) > 1 and self.parallel_workers > 1:
            # Parallel processing
            logger.info(f"Processing {len(chunks)} chunks in parallel with {self.parallel_workers} workers")
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallel_workers) as executor:
                futures = []
                for chunk in chunks:
                    chunk_spans = chunk_spans_map[chunk.chunk_id]
                    future = executor.submit(
                        self.process_chunk_with_spans,
                        chunk,
                        chunk_spans,
                        config
                    )
                    futures.append((future, chunk.chunk_id))
                
                # Collect results
                completed = 0
                chunk_results = [None] * len(chunks)
                
                for idx, (future, chunk_id) in enumerate(futures):
                    try:
                        result = future.result(timeout=60)
                        chunk_results[idx] = result
                        completed += 1
                        
                        if progress_callback:
                            progress_pct = 30 + int((completed / len(chunks)) * 40)  # 30-70%
                            progress_callback(progress_pct, f"Processed chunk {completed}/{len(chunks)}")
                        
                        logger.info(f"Chunk {chunk_id} complete: {len(result.get('claims', []))} claims")
                        
                    except Exception as e:
                        logger.error(f"Chunk {chunk_id} failed: {e}")
                        chunk_results[idx] = {
                            "chunk_id": chunk_id,
                            "claims": [],
                            "techniques": {},
                            "entities": {},
                            "error": str(e),
                            "failed": True
                        }
                        completed += 1
                
                # Filter out None values
                chunk_results = [r for r in chunk_results if r is not None]
                
        else:
            # Sequential processing
            logger.info(f"Processing {len(chunks)} chunks sequentially")
            for i, chunk in enumerate(chunks):
                chunk_spans = chunk_spans_map[chunk.chunk_id]
                result = self.process_chunk_with_spans(chunk, chunk_spans, config)
                chunk_results.append(result)
                
                if progress_callback:
                    progress_pct = 30 + int(((i + 1) / len(chunks)) * 40)  # 30-70%
                    progress_callback(progress_pct, f"Processed chunk {i + 1}/{len(chunks)}")
                
                logger.info(f"Chunk {chunk.chunk_id} complete: {len(result.get('claims', []))} claims")
        
        # Step 5: Merge results
        merged = self.merge_results(chunk_results)
        
        # Add optimization metadata
        merged["optimization_metadata"] = {
            "method": "global" if text_length < self.window_size else "windowed",
            "total_spans_detected": len(all_spans),
            "chunks_processed": len(chunks),
            "spans_per_chunk": [len(chunk_spans_map[c.chunk_id]) for c in chunks]
        }
        
        logger.info(f"Optimized extraction complete: {len(merged['techniques'])} techniques from {len(all_spans)} pre-detected spans")
        
        if progress_callback:
            progress_callback(75, f"Consolidating {len(merged['techniques'])} techniques")
        
        return merged