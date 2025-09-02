"""Chunked document extraction for handling large PDFs efficiently."""

import re
import logging
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import concurrent.futures
from bandjacks.llm.extraction_pipeline import run_extraction_pipeline
from bandjacks.llm.tracker import ExtractionTracker
from bandjacks.llm.entity_utils import consolidate_entities
# Removed hardcoded threat actor and malware extraction - handled by proper entity recognition

logger = logging.getLogger(__name__)


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
        chunk_size: int = 4000,
        overlap: int = 150,
        max_chunks: int = 8,
        parallel_workers: int = 1
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
            
            chunk = DocumentChunk(
                text=chunk_text,
                start_idx=chunk_start,
                end_idx=chunk_end,
                chunk_id=chunk_id,
                overlap_start=overlap_start,
                overlap_end=overlap_end
            )
            chunks.append(chunk)
            logger.debug(f"Created chunk {chunk_id}: chars={len(chunk_text)}, boundaries=({chunk_start}, {chunk_end}), preview={chunk_text[:100]}...")
            
            # Move to next chunk position
            current_pos = chunk_end - self.overlap
            chunk_id += 1
            
            # Stop if we've covered enough of the document
            if chunk_end >= text_len:
                break
        
        return chunks
    
    def process_chunk_with_retry(
        self,
        chunk: DocumentChunk,
        config: Dict[str, Any],
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """
        Process a chunk with retry logic.
        
        Args:
            chunk: Document chunk to process
            config: Extraction configuration
            max_retries: Maximum number of retry attempts
            
        Returns:
            Extraction results for the chunk
        """
        last_error = None
        
        for attempt in range(max_retries):
            try:
                tracker = ExtractionTracker()
                result = self.process_chunk(chunk, config, tracker)
                
                # If we got results, return them (check for key existence, not truthiness)
                if "claims" in result or "techniques" in result:
                    return result
                    
                # If empty but no error, might be legitimately empty
                if not result.get("failed"):
                    return result
                    
                # Otherwise, retry
                last_error = result.get("error", "Unknown error")
                
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Chunk {chunk.chunk_id} attempt {attempt + 1} failed: {e}")
            
            # Wait before retry with exponential backoff
            if attempt < max_retries - 1:
                wait_time = (2 ** attempt) * 2  # 2, 4, 8 seconds
                logger.info(f"Retrying chunk {chunk.chunk_id} in {wait_time}s...")
                time.sleep(wait_time)
        
        # All retries failed
        logger.error(f"Chunk {chunk.chunk_id} failed after {max_retries} attempts: {last_error}")
        return {
            "chunk_id": chunk.chunk_id,
            "chunk_boundaries": (chunk.start_idx, chunk.end_idx),
            "claims": [],
            "techniques": {},
            "entities": {},  # Empty entities for failed chunks
            "error": f"Failed after {max_retries} attempts: {last_error}",
            "failed": True
        }
    
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
        # Create chunk-specific config
        chunk_config = config.copy()
        
        # Adjust spans per chunk based on text richness
        spans_for_chunk = config.get("max_spans", 8)  # Reduced default
        
        chunk_config.update({
            "use_batch_mapper": True,  # Always use batch for efficiency
            "use_batch_retriever": True,
            "disable_discovery": True,  # Disable discovery to reduce LLM calls
            "disable_targeted_extraction": True,
            "skip_verification": True,  # Skip verification for speed
            "max_spans": spans_for_chunk,
            "span_score_threshold": 0.9,  # Higher threshold for better quality
            "confidence_threshold": 60,  # Higher confidence threshold
            "max_tool_iterations": 1,  # Single iteration only
            "batch_size": 3,  # Smaller batches for reliability
            "max_batch_spans": 15,  # Limit total spans in batch mode
        })
        
        # Add chunk context to help with deduplication
        chunk_text = chunk.text
        if chunk.overlap_start > 0:
            chunk_text = f"[...continued from previous section...]\n{chunk_text}"
        if chunk.overlap_end > 0:
            chunk_text = f"{chunk_text}\n[...continues in next section...]"
        
        # Run extraction on chunk
        try:
            result = run_extraction_pipeline(
                report_text=chunk_text,
                config=chunk_config
            )
            
            # Ensure result has required fields
            if not isinstance(result, dict):
                result = {"claims": []}
            
            result["chunk_id"] = chunk.chunk_id
            result["chunk_boundaries"] = (chunk.start_idx, chunk.end_idx)
            
            # Log successful extraction
            claims_count = len(result.get("claims", []))
            if claims_count > 0:
                logger.info(f"Chunk {chunk.chunk_id} extracted {claims_count} claims successfully")
            else:
                logger.warning(f"Chunk {chunk.chunk_id} completed but found no claims")
                
            return result
            
        except Exception as e:
            logger.error(f"Chunk {chunk.chunk_id} extraction failed: {e}", exc_info=True)
            # Return empty result but continue processing other chunks
            return {
                "chunk_id": chunk.chunk_id,
                "chunk_boundaries": (chunk.start_idx, chunk.end_idx),
                "claims": [],
                "techniques": {},
                "entities": {},  # Empty entities for failed chunks
                "error": str(e),
                "failed": True
            }
    
    def merge_entity_evidence(self, entity_instances: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Merge evidence from multiple entity mentions, including aliases.
        
        Args:
            entity_instances: List of entity instances to merge
            
        Returns:
            Merged entity with consolidated evidence
        """
        if not entity_instances:
            return None
            
        # Determine the primary name (prefer non-alias names)
        primary_name = entity_instances[0]["name"]
        aliases = set()
        
        for instance in entity_instances:
            # Check if this instance has an original_name (indicating it was mapped as alias)
            original_name = instance.get("original_name", instance["name"])
            if original_name != primary_name:
                aliases.add(original_name)
            
            # Also check for non-alias mentions to find the best primary name
            for mention in instance.get("mentions", []):
                if mention.get("context") != "alias":
                    primary_name = instance["name"]
                    break
        
        # Start with merged entity
        merged = {
            "name": primary_name,
            "type": entity_instances[0]["type"],
            "confidence": max(e.get("confidence", 50) for e in entity_instances),
            "mentions": [],
            "chunks_found": [],
            "aliases": list(aliases) if aliases else None
        }
        
        # Combine all unique mentions
        seen_quotes = set()
        for instance in entity_instances:
            # Track which chunk this came from
            chunk_id = instance.get("chunk_id", -1)
            if chunk_id not in merged["chunks_found"]:
                merged["chunks_found"].append(chunk_id)
            
            # Add mentions from this instance
            for mention in instance.get("mentions", []):
                # Use first 100 chars of quote as dedup key
                quote_key = mention.get("quote", "")[:100]
                if quote_key and quote_key not in seen_quotes:
                    merged["mentions"].append(mention)
                    seen_quotes.add(quote_key)
        
        # Boost confidence based on multiple mentions
        mention_boost = min(20, len(merged["mentions"]) * 5)
        merged["confidence"] = min(100, merged["confidence"] + mention_boost)
        
        # Also boost if found in multiple chunks
        chunk_boost = min(10, len(merged["chunks_found"]) * 3)
        merged["confidence"] = min(100, merged["confidence"] + chunk_boost)
        
        # Clean up - remove aliases field if empty
        if not merged.get("aliases"):
            merged.pop("aliases", None)
        
        return merged
    
    def merge_results(self, chunk_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Merge results from multiple chunks, deduplicating techniques and consolidating entity evidence.
        
        Args:
            chunk_results: List of extraction results from chunks
            
        Returns:
            Merged extraction results
        """
        merged = {
            "claims": [],
            "techniques": {},
            "chunks_processed": len(chunk_results),
            "metrics": {},
            "entities": {
                "entities": [],
                "extraction_status": "not_attempted"
            }
        }
        
        # Track seen techniques to avoid duplicates
        seen_techniques = {}
        all_claims = []
        
        # Early termination threshold
        MAX_TECHNIQUES = 60  # Reasonable upper limit
        
        for result in chunk_results:
            chunk_id = result.get("chunk_id", -1)
            
            # Process claims from this chunk
            for claim in result.get("claims", []):
                # Handle both field names for compatibility
                tech_id = claim.get("technique_id") or claim.get("external_id", "")
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
                    
                    # Check if we've found enough techniques
                    if len(seen_techniques) >= MAX_TECHNIQUES:
                        logger.info(f"Found {len(seen_techniques)} techniques, stopping merge early")
                        break
        
        # Convert to final format
        merged["claims"] = list(seen_techniques.values())
        
        # Build techniques dict for compatibility
        for claim in merged["claims"]:
            # Handle both field names
            tech_id = claim.get("technique_id") or claim.get("external_id", "")
            if tech_id:
                merged["techniques"][tech_id] = {
                    "name": claim.get("technique_name") or claim.get("name", tech_id),
                    "confidence": claim.get("confidence", 50),
                    "evidence": claim.get("evidence", {}).get("quotes", claim.get("quotes", [])),
                    "line_refs": claim.get("evidence", {}).get("line_refs", claim.get("line_refs", []))
                }
        
        # Merge entities from all chunks with evidence consolidation
        # Group entities by (name.lower(), type) for merging
        entity_groups = {}  # Key: (name_lower, type) -> Value: list of entity instances
        alias_map = {}  # Track known aliases: alias_name -> primary_name
        
        for idx, result in enumerate(chunk_results):
            chunk_id = result.get("chunk_id", idx)
            chunk_entities = result.get("entities", {})
            
            # Handle new format from extraction pipeline
            if isinstance(chunk_entities, dict) and "entities" in chunk_entities:
                # New format with list of entities
                for entity in chunk_entities.get("entities", []):
                    if isinstance(entity, dict):
                        entity_name = entity.get("name", "").strip()
                        entity_type = entity.get("type", "")
                        
                        if entity_name:
                            # Check if this is a known alias
                            canonical_name = alias_map.get(entity_name.lower(), entity_name)
                            
                            # Check mentions for alias context  
                            for mention in entity.get("mentions", []):
                                if mention.get("context") == "alias":
                                    # This entity is an alias - try to find the primary entity
                                    quote = mention.get("quote", "")
                                    # Look for patterns like "X, also known as Y" or "X (aka Y)"
                                    if "also known as" in quote.lower() or "aka" in quote.lower():
                                        # Try to extract the primary name
                                        for existing_key, _ in entity_groups.items():
                                            existing_name = existing_key[0]
                                            if existing_name in quote.lower() and existing_name != entity_name.lower():
                                                # Found the primary entity
                                                alias_map[entity_name.lower()] = existing_name
                                                canonical_name = existing_name
                                                logger.debug(f"Identified {entity_name} as alias of {existing_name}")
                                                break
                            
                            # Create grouping key using canonical name
                            key = (canonical_name.lower(), entity_type)
                            
                            # Add chunk_id to entity for tracking
                            entity["chunk_id"] = chunk_id
                            # Store original name for consolidation
                            entity["original_name"] = entity_name
                            
                            if key not in entity_groups:
                                entity_groups[key] = []
                            entity_groups[key].append(entity)
                            
                            logger.debug(f"Chunk {chunk_id}: Found entity {entity_name} ({entity_type}) with {len(entity.get('mentions', []))} mentions")
        
        # Merge entities with evidence consolidation
        all_entities = []
        for (name_lower, entity_type), entity_instances in entity_groups.items():
            if len(entity_instances) == 1:
                # Single instance, no merging needed
                entity = entity_instances[0]
                # Remove chunk_id from final output
                entity.pop("chunk_id", None)
                all_entities.append(entity)
            else:
                # Multiple instances - merge with evidence consolidation
                logger.debug(f"Merging {len(entity_instances)} instances of entity: {entity_instances[0]['name']} ({entity_type})")
                merged_entity = self.merge_entity_evidence(entity_instances)
                
                if merged_entity:
                    # Log consolidation results
                    logger.info(f"Consolidated entity '{merged_entity['name']}': "
                              f"{len(merged_entity['mentions'])} mentions from {len(merged_entity['chunks_found'])} chunks, "
                              f"confidence: {merged_entity['confidence']}%")
                    
                    # Remove internal tracking fields
                    merged_entity.pop("chunks_found", None)
                    all_entities.append(merged_entity)
        
        # Sort entities by confidence (highest first)
        all_entities.sort(key=lambda e: e.get("confidence", 0), reverse=True)
        
        # Use the new format for merged entities
        merged["entities"] = {
            "entities": all_entities,
            "extraction_status": "completed" if all_entities else "no_entities_found"
        }
        
        # Log entity extraction results
        if all_entities:
            unique_count = len(all_entities)
            total_mentions = sum(len(e.get("mentions", [])) for e in all_entities)
            logger.info(f"Entity consolidation complete: {unique_count} unique entities with {total_mentions} total mentions")
            for entity in all_entities[:3]:  # Log top 3 entities by confidence
                logger.info(f"  - {entity.get('name')} ({entity.get('type')}): "
                          f"confidence={entity.get('confidence')}%, mentions={len(entity.get('mentions', []))}")
        
        # Aggregate metrics
        total_time = sum(r.get("metrics", {}).get("dur_sec", 0) for r in chunk_results)
        successful_chunks = sum(1 for r in chunk_results if not r.get("failed", False))
        failed_chunks = sum(1 for r in chunk_results if r.get("failed", False))
        
        merged["metrics"]["total_chunks"] = len(chunk_results)
        merged["metrics"]["successful_chunks"] = successful_chunks
        merged["metrics"]["failed_chunks"] = failed_chunks
        merged["metrics"]["total_time_sec"] = total_time
        merged["metrics"]["techniques_found"] = len(merged["techniques"])
        merged["metrics"]["total_claims"] = len(merged["claims"])
        
        # Log summary
        logger.info(f"Merge complete: {len(merged['techniques'])} techniques from {successful_chunks}/{len(chunk_results)} successful chunks")
        if failed_chunks > 0:
            logger.warning(f"{failed_chunks} chunks failed during processing")
        
        return merged
    
    def extract(
        self,
        text: str,
        config: Dict[str, Any],
        parallel: bool = True,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Extract techniques from document using chunked processing.
        
        Args:
            text: Full document text
            config: Extraction configuration
            parallel: Whether to process chunks in parallel
            progress_callback: Optional callback for progress updates
            
        Returns:
            Extraction results with merged techniques
        """
        # Create chunks
        chunks = self.create_chunks(text)
        spans_per_chunk = config.get("max_spans", 10)
        total_potential_spans = len(chunks) * spans_per_chunk
        
        logger.info(f"Created {len(chunks)} chunks from {len(text)} chars")
        logger.info(f"Processing with {spans_per_chunk} spans per chunk (up to {total_potential_spans} total spans)")
        
        # Process chunks
        chunk_results = []
        
        if parallel and len(chunks) > 1 and self.parallel_workers > 1:
            # Process chunks in parallel
            logger.info(f"Processing {len(chunks)} chunks in parallel with {self.parallel_workers} workers")
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallel_workers) as executor:
                # Create individual trackers for each chunk
                futures = []
                for chunk in chunks:
                    # Use retry version for better resilience
                    future = executor.submit(self.process_chunk_with_retry, chunk, config)
                    futures.append((future, chunk.chunk_id))
                
                # Collect results as they complete
                completed = 0
                chunk_results = [None] * len(chunks)  # Preserve order
                
                # Create mapping of future to chunk info
                future_to_info = {future: (chunk_id, idx) 
                                 for idx, (future, chunk_id) in enumerate(futures)}
                
                # Use as_completed for better async handling
                for future in concurrent.futures.as_completed(future_to_info, timeout=300):
                    chunk_id, idx = future_to_info[future]
                    try:
                        result = future.result()  # No timeout here, as_completed handles it
                        chunk_results[idx] = result
                        completed += 1
                        
                        # Log and update progress
                        logger.info(f"Chunk {chunk_id} complete: {len(result.get('claims', []))} claims, {len(result.get('techniques', {}))} techniques")
                        if progress_callback:
                            progress_pct = 35 + int((completed / len(chunks)) * 30)
                            progress_callback(progress_pct, f"Processed chunk {completed}/{len(chunks)}")
                            
                    except Exception as e:
                        logger.error(f"Chunk {chunk_id} failed: {type(e).__name__}: {str(e) or 'No error message'}")
                        chunk_results[idx] = {
                            "chunk_id": chunk_id,
                            "claims": [],
                            "techniques": {},
                            "entities": {},
                            "error": f"{type(e).__name__}: {str(e)}",
                            "failed": True
                        }
                        completed += 1
                        if progress_callback:
                            progress_pct = 35 + int((completed / len(chunks)) * 30)
                            progress_callback(progress_pct, f"Chunk {completed}/{len(chunks)} (failed)")
                
                # Filter out None values in case of catastrophic failure
                chunk_results = [r for r in chunk_results if r is not None]
        else:
            # Process chunks sequentially
            reason = "single chunk" if len(chunks) == 1 else f"single worker (parallel_workers={self.parallel_workers})"
            logger.info(f"Processing {len(chunks)} chunks sequentially ({reason})")
            for i, chunk in enumerate(chunks):
                # Use retry version for better resilience
                result = self.process_chunk_with_retry(chunk, config)
                chunk_results.append(result)
                
                # Update progress
                if progress_callback:
                    progress_pct = 35 + int(((i + 1) / len(chunks)) * 30)  # 35-65% for extraction
                    progress_callback(progress_pct, f"Processed chunk {i + 1}/{len(chunks)}")
                
                logger.info(f"Chunk {chunk.chunk_id} complete: {len(result.get('claims', []))} claims")
        
        # Merge results
        merged = self.merge_results(chunk_results)
        logger.info(f"Extraction complete: {len(merged['techniques'])} unique techniques from {len(chunks)} chunks")
        
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