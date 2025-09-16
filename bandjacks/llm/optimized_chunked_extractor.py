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
from bandjacks.llm.accumulator import ThreadSafeAccumulator
from bandjacks.llm.token_utils import TokenEstimator

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
        window_overlap: int = 5000,  # ~1.5K tokens overlap
        enable_dynamic_chunking: bool = True,  # Enable dynamic chunk sizing
        min_chunk_size: int = 1000,  # Minimum chunk size
        max_chunk_size: int = 8000   # Maximum chunk size
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
            enable_dynamic_chunking: Enable token-aware dynamic chunk sizing
            min_chunk_size: Minimum chunk size in characters
            max_chunk_size: Maximum chunk size in characters
        """
        super().__init__(chunk_size, overlap, max_chunks, parallel_workers)
        self.window_size = window_size
        self.window_overlap = window_overlap
        self.enable_dynamic_chunking = enable_dynamic_chunking
        self.min_chunk_size = min_chunk_size
        self.max_chunk_size = max_chunk_size
        
        # Initialize token estimator if dynamic chunking enabled
        if self.enable_dynamic_chunking:
            self.token_estimator = TokenEstimator()
            logger.info("Dynamic chunk sizing enabled with token estimation")
    
    def create_chunks(self, text: str) -> List[DocumentChunk]:
        """
        Create chunks with dynamic sizing based on token estimates.
        
        Overrides parent method to add token-aware chunking.
        
        Args:
            text: Document text to chunk
            
        Returns:
            List of DocumentChunk objects
        """
        if not self.enable_dynamic_chunking:
            # Use parent's standard chunking
            return super().create_chunks(text)
        
        logger.info("Creating chunks with dynamic sizing based on token estimates")
        
        # Estimate content density
        density = self.token_estimator.estimate_content_density(text)
        logger.info(f"Content density estimate: {density:.2f}")
        
        # Calculate safe chunk size for this content
        safe_chunk_size = self.token_estimator.calculate_safe_chunk_size(
            content_density=density,
            target_operation='span_finder'  # Most token-sensitive operation
        )
        
        # Apply hard caps based on density
        if density > 2.0:
            safe_chunk_size = min(safe_chunk_size, 2000)  # Very dense content
            logger.info(f"Very dense content (density={density:.2f}), capping chunk size at 2000 chars")
        elif density > 1.5:
            safe_chunk_size = min(safe_chunk_size, 3000)  # Dense content
            logger.info(f"Dense content (density={density:.2f}), capping chunk size at 3000 chars")
        
        # Clamp to configured limits
        safe_chunk_size = max(self.min_chunk_size, min(safe_chunk_size, self.max_chunk_size))
        logger.info(f"Adjusted chunk size from {self.chunk_size} to {safe_chunk_size} chars")
        
        # Create chunks with adjusted size
        chunks = []
        text_length = len(text)
        chunk_id = 0
        position = 0
        
        while position < text_length and chunk_id < self.max_chunks:
            # Determine chunk end position
            end_position = min(position + safe_chunk_size, text_length)
            
            # Extract chunk text
            chunk_text = text[position:end_position]
            
            # Check if chunk is still too large in tokens
            estimated_tokens = self.token_estimator.estimate_tokens(chunk_text)
            
            # More aggressive limits for dense content
            max_tokens = 2000 if density > 1.5 else 3000
            
            if estimated_tokens > max_tokens:
                # Reduce chunk size further
                reduction_factor = max_tokens / estimated_tokens
                new_size = int(len(chunk_text) * reduction_factor * 0.7)  # 70% for extra safety
                end_position = min(position + new_size, text_length)
                chunk_text = text[position:end_position]
                logger.warning(f"Chunk {chunk_id} has {estimated_tokens} tokens, reduced to {len(chunk_text)} chars")
            
            # Create chunk object
            chunk = DocumentChunk(
                chunk_id=chunk_id,
                text=chunk_text,
                start_idx=position,
                end_idx=end_position
            )
            
            # Store metadata for logging (not part of DocumentChunk)
            estimated_tokens = self.token_estimator.estimate_tokens(chunk_text)
            chunks.append(chunk)
            
            logger.debug(f"Chunk {chunk_id}: {len(chunk_text)} chars, "
                        f"~{estimated_tokens} tokens")
            
            # Move position with overlap
            position = end_position - self.overlap if end_position < text_length else text_length
            chunk_id += 1
        
        logger.info(f"Created {len(chunks)} dynamically sized chunks")
        return chunks
        
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
    
    def batch_retrieve_candidates(
        self,
        all_spans: List[DetectedSpan],
        config: Dict[str, Any]
    ) -> Dict[int, List[Dict[str, Any]]]:
        """
        Batch retrieve candidates for all spans at once.
        
        This performs a single batch vector search for all spans instead of
        searching per chunk, reducing OpenSearch queries by 60-70%.
        
        Args:
            all_spans: All detected spans from the document
            config: Configuration with retrieval parameters
            
        Returns:
            Dictionary mapping span index to list of candidates
        """
        from bandjacks.llm.memory import WorkingMemory
        from bandjacks.llm.batch_retriever import BatchRetrieverAgent
        
        # Create a temporary memory object with all spans
        mem = WorkingMemory()
        mem.spans = []
        
        # Convert DetectedSpan objects to dict format for BatchRetrieverAgent
        for span in all_spans:
            span_dict = {
                "text": span.text,
                "line_refs": span.line_refs,
                "score": span.score,
                "tactics": span.tactics,
                "type": span.type
            }
            mem.spans.append(span_dict)
        
        # Run batch retrieval
        retriever = BatchRetrieverAgent()
        retriever.run(mem, config)
        
        # Extract candidates from memory
        candidates_map = {}
        if hasattr(mem, 'candidates'):
            candidates_map = mem.candidates
            
        logger.info(f"Batch retrieved candidates for {len(candidates_map)} spans")
        return candidates_map
    
    def _extract_chunk_candidates(
        self,
        chunk_spans: List[Dict[str, Any]],
        candidates_map: Dict[int, List[Dict[str, Any]]],
        all_spans: List[DetectedSpan]
    ) -> Dict[int, List[Dict[str, Any]]]:
        """
        Extract candidates for spans in a specific chunk.
        
        Maps the global span indices to chunk-local indices.
        
        Args:
            chunk_spans: Spans assigned to this chunk
            candidates_map: Global candidates map (span_idx -> candidates)
            all_spans: All spans from the document
            
        Returns:
            Dictionary mapping chunk-local span indices to candidates
        """
        chunk_candidates = {}
        
        # Find the global index for each chunk span
        for local_idx, chunk_span in enumerate(chunk_spans):
            # Match by text and position to find global index
            for global_idx, global_span in enumerate(all_spans):
                if (global_span.text == chunk_span["text"] and 
                    hasattr(global_span, 'start_pos') and 
                    chunk_span.get("doc_position") == (global_span.start_pos, global_span.end_pos)):
                    # Found matching global span
                    if global_idx in candidates_map:
                        chunk_candidates[local_idx] = candidates_map[global_idx]
                    break
        
        return chunk_candidates
    
    def process_chunk_with_spans(
        self,
        chunk: DocumentChunk,
        pre_detected_spans: List[Dict[str, Any]],
        config: Dict[str, Any],
        pre_retrieved_candidates: Optional[Dict[int, List[Dict[str, Any]]]] = None,
        accumulator: Optional[ThreadSafeAccumulator] = None
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
        
        # Add context hints from accumulator if available
        if accumulator and config.get("context_hints_enabled", True):
            context_hints = accumulator.get_context_hints()
            if context_hints["hint_count"] > 0:
                chunk_config["context_hints"] = context_hints
                logger.debug(
                    f"Chunk {chunk.chunk_id}: Using {context_hints['hint_count']} context hints "
                    f"from {context_hints['total_found']} discovered techniques"
                )
        
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
            # Run extraction with injected spans and candidates
            result = self._run_extraction_with_injected_spans(
                chunk_text=chunk.text,
                pre_detected_spans=pre_detected_spans,
                config=chunk_config,
                pre_retrieved_candidates=pre_retrieved_candidates
            )
            
            result["chunk_id"] = chunk.chunk_id
            result["chunk_boundaries"] = (chunk.start_idx, chunk.end_idx)
            
            claims_count = len(result.get("claims", []))
            logger.info(f"Chunk {chunk.chunk_id} processed {len(pre_detected_spans)} pre-detected spans → {claims_count} claims")
            
            # Update accumulator with discovered techniques and entities
            if accumulator:
                # Add techniques
                for claim in result.get("claims", []):
                    tech_id = claim.get("technique_id") or claim.get("external_id", "")
                    if tech_id:
                        accumulator.add_technique(
                            technique_id=tech_id,
                            name=claim.get("technique_name") or claim.get("name", tech_id),
                            confidence=claim.get("confidence", 50),
                            evidence=claim.get("evidence", {}).get("sentences", []),
                            chunk_id=chunk.chunk_id
                        )
                
                # Add entities if available
                entities = result.get("entities", {})
                if entities and entities.get("entities"):
                    for entity in entities["entities"]:
                        # Extract evidence from mentions
                        evidence_quotes = []
                        if entity.get("mentions"):
                            for mention in entity["mentions"]:
                                if mention.get("quote"):
                                    evidence_quotes.append(mention["quote"])
                        
                        # Generate entity ID if not present
                        entity_type = entity.get("type", "unknown")
                        entity_name = entity.get("name", "")
                        entity_id = f"{entity_type}_{entity_name.lower().replace(' ', '_')}"
                        
                        accumulator.add_entity(
                            entity_id=entity_id,
                            name=entity_name,
                            entity_type=entity_type,
                            confidence=entity.get("confidence", 75),
                            evidence=evidence_quotes,
                            chunk_id=chunk.chunk_id
                        )
                
                accumulator.mark_chunk_complete(chunk.chunk_id)
            
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
        config: Dict[str, Any],
        pre_retrieved_candidates: Optional[Dict[int, List[Dict[str, Any]]]] = None
    ) -> Dict[str, Any]:
        """
        Run extraction pipeline with pre-detected spans and candidates injected.
        
        This is a workaround to inject spans and candidates into the extraction pipeline
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
        
        # Inject pre-retrieved candidates if provided
        if pre_retrieved_candidates:
            mem.candidates = pre_retrieved_candidates
            logger.debug(f"Injected {len(pre_retrieved_candidates)} pre-retrieved candidate sets")
        
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
                # Configure entity extraction to use claims
                entity_config = config.copy()
                entity_config["use_entity_claims"] = True
                
                # Get chunk_id from config if available
                chunk_id = config.get("chunk_id", 0)
                entity_config["chunk_id"] = chunk_id
                
                # Use batch entity extractor for better performance
                if config.get("use_batch_entity_extraction", True):
                    from bandjacks.llm.entity_batch_extractor import BatchEntityExtractor
                    logger.info("Using BatchEntityExtractor for optimized entity extraction")
                    batch_extractor = BatchEntityExtractor()
                    result = batch_extractor.extract(chunk_text, entity_config)
                    
                    # Check if batch extractor returned claims or entities
                    if result.get("entity_claims"):
                        # Batch extractor generated claims directly
                        mem.entity_claims = result["entity_claims"]
                        logger.info(f"BatchEntityExtractor generated {len(result['entity_claims'])} entity claims")
                    elif result.get("entities"):
                        # Batch extractor returned entities - convert to claims if needed
                        if entity_config.get("use_entity_claims"):
                            entity_agent = EntityExtractionAgent()
                            mem.entity_claims = entity_agent._entities_to_claims(
                                result["entities"], 
                                chunk_text, 
                                chunk_id=chunk_id
                            )
                        else:
                            # Store entities directly
                            mem.entities = result
                else:
                    # Fallback to original entity extraction with claims
                    logger.info("Using standard EntityExtractionAgent with claims")
                    entity_agent = EntityExtractionAgent()
                    entity_agent.run(mem, entity_config)
                
                # Run entity consolidator if we have claims
                if hasattr(mem, 'entity_claims') and mem.entity_claims:
                    from bandjacks.llm.entity_consolidator import EntityConsolidatorAgent
                    logger.info(f"Consolidating {len(mem.entity_claims)} entity claims")
                    entity_consolidator = EntityConsolidatorAgent()
                    entity_consolidator.run(mem, config)
                    
                    if hasattr(mem, 'entities') and mem.entities:
                        entities = mem.entities
                    else:
                        entities = {"entities": [], "extraction_status": "no_entities"}
                else:
                    # If no claims were generated but we have entities, use them
                    if hasattr(mem, 'entities') and mem.entities:
                        entities = mem.entities
                    else:
                        entities = {"entities": [], "extraction_status": "no_claims"}
                        
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
        
        # Step 2: Batch retrieve candidates for all spans (NEW)
        candidates_map = {}
        if len(all_spans) > 0 and not config.get("skip_vector_search", False):
            logger.info(f"Batch retrieving candidates for {len(all_spans)} spans")
            candidates_map = self.batch_retrieve_candidates(all_spans, config)
            logger.info(f"Retrieved candidates for {len(candidates_map)} spans")
            
            if progress_callback:
                progress_callback(25, f"Retrieved candidates for {len(all_spans)} spans")
        
        # Step 3: Create chunks for processing
        chunks = self.create_chunks(text)
        logger.info(f"Created {len(chunks)} chunks for processing")
        
        # Step 4: Redistribute spans evenly across chunks
        chunk_spans_map = self.redistribute_spans_evenly(all_spans, chunks, config)
        
        # Update progress
        if progress_callback:
            progress_callback(30, f"Mapped spans to {len(chunks)} chunks")
        
        # Step 4.5: Initialize accumulator if progressive mode is enabled
        accumulator = None
        if config.get("progressive_mode", "async") != "disabled":
            accumulator = ThreadSafeAccumulator(
                early_termination_threshold=config.get("early_termination_threshold"),
                max_context_hints=config.get("max_context_hints"),
                confidence_boost=config.get("confidence_boost"),
                min_techniques_for_termination=config.get("min_techniques_for_termination"),
                enable_early_termination=config.get("enable_early_termination")
            )
            logger.info(f"Progressive context accumulation enabled (mode: {config.get('progressive_mode', 'async')})") 
        
        # Step 5: Process chunks with their pre-detected spans
        chunk_results = []
        
        if parallel and len(chunks) > 1 and self.parallel_workers > 1:
            # Parallel processing
            logger.info(f"Processing {len(chunks)} chunks in parallel with {self.parallel_workers} workers")
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallel_workers) as executor:
                futures = []
                for chunk in chunks:
                    chunk_spans = chunk_spans_map[chunk.chunk_id]
                    # Pass candidates for this chunk's spans
                    chunk_candidates = self._extract_chunk_candidates(
                        chunk_spans, candidates_map, all_spans
                    )
                    future = executor.submit(
                        self.process_chunk_with_spans,
                        chunk,
                        chunk_spans,
                        config,
                        chunk_candidates,
                        accumulator
                    )
                    futures.append((future, chunk.chunk_id))
                
                # Collect results
                completed = 0
                chunk_results = [None] * len(chunks)
                
                for idx, (future, chunk_id) in enumerate(futures):
                    try:
                        # Increased timeout for semantic deduplication operations
                        chunk_timeout = int(os.getenv("CHUNK_PROCESSING_TIMEOUT", "180"))
                        result = future.result(timeout=chunk_timeout)
                        chunk_results[idx] = result
                        completed += 1
                        
                        if progress_callback:
                            progress_pct = 30 + int((completed / len(chunks)) * 40)  # 30-70%
                            progress_callback(progress_pct, f"Processed chunk {completed}/{len(chunks)}")
                        
                        logger.info(f"Chunk {chunk_id} complete: {len(result.get('claims', []))} claims")
                        
                        # Check for early termination
                        if accumulator and accumulator.should_stop_processing():
                            logger.info(f"Early termination triggered after chunk {chunk_id}")
                            # Cancel remaining futures
                            for remaining_future, _ in futures[idx+1:]:
                                remaining_future.cancel()
                        
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
                # Pass candidates for this chunk's spans
                chunk_candidates = self._extract_chunk_candidates(
                    chunk_spans, candidates_map, all_spans
                )
                result = self.process_chunk_with_spans(chunk, chunk_spans, config, chunk_candidates, accumulator)
                chunk_results.append(result)
                
                # Check for early termination
                if accumulator and accumulator.should_stop_processing():
                    logger.info(f"Early termination triggered after chunk {chunk.chunk_id}")
                    break
                
                if progress_callback:
                    progress_pct = 30 + int(((i + 1) / len(chunks)) * 40)  # 30-70%
                    progress_callback(progress_pct, f"Processed chunk {i + 1}/{len(chunks)}")
                
                logger.info(f"Chunk {chunk.chunk_id} complete: {len(result.get('claims', []))} claims")
        
        # Step 6: Merge results (with accumulated techniques if available)
        merged = self.merge_results(chunk_results)
        
        # Add accumulated techniques and entities if using progressive mode
        if accumulator:
            accumulated_techniques = accumulator.get_accumulated_techniques()
            accumulated_entities = accumulator.get_accumulated_entities()
            stats = accumulator.get_statistics()
            
            # Merge accumulated techniques with higher confidence
            for tech_id, tech_data in accumulated_techniques.items():
                if tech_id in merged["techniques"]:
                    # Update with accumulated confidence and evidence
                    merged["techniques"][tech_id]["confidence"] = tech_data["confidence"]
                    merged["techniques"][tech_id]["evidence"] = tech_data["evidence"]
                else:
                    # Add new technique from accumulator
                    merged["techniques"][tech_id] = tech_data
            
            # Merge accumulated entities with higher confidence
            if "entities" not in merged:
                merged["entities"] = {"entities": [], "extraction_status": "success"}
            
            # Convert accumulated entities to standard format
            entity_dict = {}
            for entity_id, entity_data in accumulated_entities.items():
                entity_dict[entity_id] = {
                    "name": entity_data["name"],
                    "type": entity_data["type"],
                    "confidence": entity_data["confidence"],
                    "mentions": [
                        {
                            "quote": quote,
                            "line_refs": [],  # Would need to be tracked separately
                            "context": "accumulated"
                        }
                        for quote in entity_data.get("evidence", [])[:3]  # Top 3 evidence pieces
                    ]
                }
            
            # Merge with existing entities
            existing_entities = {f"{e['type']}_{e['name'].lower().replace(' ', '_')}": e 
                               for e in merged["entities"].get("entities", [])}
            
            for entity_id, entity_data in entity_dict.items():
                if entity_id in existing_entities:
                    # Update confidence if higher
                    if entity_data["confidence"] > existing_entities[entity_id].get("confidence", 0):
                        existing_entities[entity_id]["confidence"] = entity_data["confidence"]
                    # Merge mentions
                    existing_mentions = existing_entities[entity_id].get("mentions", [])
                    for new_mention in entity_data.get("mentions", []):
                        # Check if this quote already exists
                        if not any(m.get("quote") == new_mention.get("quote") for m in existing_mentions):
                            existing_mentions.append(new_mention)
                else:
                    # Add new entity
                    merged["entities"]["entities"].append(entity_data)
            
            # Add accumulator statistics
            merged["accumulator_stats"] = stats
        
        # Add optimization metadata
        merged["optimization_metadata"] = {
            "method": "global" if text_length < self.window_size else "windowed",
            "total_spans_detected": len(all_spans),
            "chunks_processed": len(chunk_results),  # Actual processed (may be less due to early termination)
            "spans_per_chunk": [len(chunk_spans_map[c.chunk_id]) for c in chunks],
            "progressive_mode": config.get("progressive_mode", "async"),
            "early_terminated": accumulator.should_stop_processing() if accumulator else False
        }
        
        # Log technique preservation for debugging Task 1.7
        if merged["techniques"]:
            technique_ids = sorted(merged["techniques"].keys())
            parent_count = sum(1 for tid in technique_ids if "." not in tid)
            sub_count = sum(1 for tid in technique_ids if "." in tid)
            
            # Log parent/subtechnique relationships
            parents_with_subs = {}
            for tid in technique_ids:
                if "." in tid:
                    parent = tid.split(".")[0]
                    if parent not in parents_with_subs:
                        parents_with_subs[parent] = []
                    parents_with_subs[parent].append(tid)
            
            logger.info(f"Optimized extraction complete: {len(technique_ids)} techniques "
                       f"({parent_count} parent, {sub_count} subtechniques) from {len(all_spans)} pre-detected spans")
            
            for parent, subs in parents_with_subs.items():
                if parent in technique_ids:
                    logger.debug(f"  {parent} (parent) with subtechniques: {', '.join(subs)}")
                else:
                    logger.debug(f"  Subtechniques only (no parent): {', '.join(subs)}")
        else:
            logger.info(f"Optimized extraction complete: 0 techniques from {len(all_spans)} pre-detected spans")
        
        if progress_callback:
            progress_callback(75, f"Consolidating {len(merged['techniques'])} techniques")
        
        return merged