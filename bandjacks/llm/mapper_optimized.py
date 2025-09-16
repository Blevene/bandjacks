"""Optimized batch mapper for faster extraction."""

import json
import re
import logging
import os
from typing import Any, Dict, List
from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.client import LLMClient
from bandjacks.llm.tools import list_subtechniques, resolve_technique_by_external_id
from bandjacks.services.technique_cache import technique_cache
from bandjacks.llm.json_utils import parse_json_with_fallback, validate_and_ensure_claims
from bandjacks.llm.token_utils import TokenEstimator

logger = logging.getLogger(__name__)


# cleanup_json moved to json_utils.py for shared use


class BatchMapperAgent:
    """Batch process spans in smaller groups to prevent LLM timeouts."""
    
    def __init__(self):
        """Initialize the batch mapper with token estimator."""
        self.token_estimator = TokenEstimator()
    
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        # Check for valid memory object
        if not mem or not hasattr(mem, 'spans'):
            logger.error("Invalid WorkingMemory object provided to BatchMapperAgent")
            return
            
        # Safe length check
        try:
            span_count = len(mem.spans) if mem.spans else 0
        except (TypeError, AttributeError):
            logger.error("Unable to get span count from WorkingMemory")
            return
            
        initial_claims = len(mem.claims) if hasattr(mem, 'claims') else 0
        logger.debug(f"BatchMapperAgent called with {span_count} spans, {initial_claims} existing claims")
        
        if span_count == 0:
            return
        
        # Use dynamic batch sizing if enabled
        enable_dynamic_batching = config.get("enable_dynamic_batching", 
                                            os.getenv("ENABLE_DYNAMIC_BATCHING", "true").lower() == "true")
        
        if enable_dynamic_batching:
            default_batch_size = self._calculate_dynamic_batch_size(mem.spans, config)
        else:
            # Legacy batch size calculation
            if span_count <= 15:
                default_batch_size = min(15, span_count)
            elif span_count <= 30:
                default_batch_size = 15
            elif span_count <= 60:
                default_batch_size = 20
            else:
                default_batch_size = 25
        
        # Override with config if provided - use mapper_batch_size key for clarity
        batch_size = config.get("mapper_batch_size", config.get("batch_size", default_batch_size))
        
        # Apply maximum batch size limit from environment
        max_batch_size = int(os.getenv("MAX_MAPPER_BATCH_SIZE", "30"))
        if batch_size > max_batch_size:
            logger.info(f"Capping batch size from {batch_size} to max {max_batch_size}")
            batch_size = max_batch_size
        
        # No more fallback to sequential - always use batching
        logger.info(f"Processing {span_count} spans with batch size {batch_size}")
        
        # Process spans in batches
        logger.info(f"Processing {span_count} spans in batches of {batch_size}")
        total_added_claims = 0
        
        # Split spans into batches
        for batch_start in range(0, span_count, batch_size):
            batch_end = min(batch_start + batch_size, span_count)
            batch_spans = list(range(batch_start, batch_end))
            
            logger.debug(f"Processing batch: spans {batch_start}-{batch_end-1} ({len(batch_spans)} spans)")
            
            # Prepare batch data
            spans_data = []
            for i in batch_spans:
                span = mem.spans[i]
                cands = mem.candidates.get(i, [])
                
                # Get evidence lines
                line_refs = span.get("line_refs", [])
                evidence_lines = []
                for ref in line_refs:
                    if 1 <= ref <= len(mem.line_index):
                        evidence_lines.append(f"Line {ref}: {mem.line_index[ref-1]}")
                
                spans_data.append({
                    "span_id": i,
                    "text": span["text"][:500],  # Limit length
                    "line_refs": line_refs,
                    "evidence_lines": evidence_lines[:3],  # Limit evidence to 3 lines
                    "candidates": [
                        {"external_id": c["external_id"], "name": c.get("name", ""), "score": c.get("score", 0)} 
                        for c in cands[:5]  # Limit candidates
                    ]
                })
            
            # Process this batch
            batch_claims = self._process_batch(spans_data, mem, config)
            total_added_claims += batch_claims
            
            logger.debug(f"Batch {batch_start}-{batch_end-1} completed: {batch_claims} claims added")
        
        logger.info(f"BatchMapperAgent: Added {total_added_claims} total claims (now {len(mem.claims)} claims)")
        
        # Validate that we have claims if techniques were found
        validate_and_ensure_claims(mem, "BatchMapperAgent")
    
    def _process_batch(self, spans_data: List[Dict], mem: WorkingMemory, config: Dict[str, Any]) -> int:
        """Process a single batch of spans."""
        # Create batch prompt with JSON requirement
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity analyst. Extract ATT&CK technique IDs from text spans.\n\n"
                    "Output a JSON object with a 'techniques' array:\n"
                    "{\"techniques\":[{\"span\":0,\"tid\":\"T1055\",\"conf\":80}]}\n\n"
                    "Rules:\n"
                    "- span: span index (0-based)\n"
                    "- tid: technique ID (e.g., T1055, T1566.001)\n"
                    "- conf: confidence score (0-100)\n"
                    "- Extract ALL techniques you find\n"
                    "- Include explicit IDs and behaviors that match techniques\n"
                    "- Output ONLY valid JSON, nothing else"
                )
            },
            {
                "role": "user",
                "content": f"Process these {len(spans_data)} spans:\n\n" + json.dumps(spans_data, indent=2)
            }
        ]
        
        # JSON schema for technique extraction
        technique_schema = {
            "type": "object",
            "properties": {
                "techniques": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "span": {
                                "type": "integer",
                                "description": "Span index (0-based)"
                            },
                            "tid": {
                                "type": "string",
                                "description": "Technique ID (e.g., T1566.001)"
                            },
                            "conf": {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": 100,
                                "description": "Confidence score"
                            }
                        },
                        "required": ["span", "tid", "conf"],
                        "additionalProperties": False
                    }
                }
            },
            "required": ["techniques"],
            "additionalProperties": False
        }
        
        # Single LLM call for this batch with structured output
        logger.info(f"BatchMapper LLM request: batch of {len(spans_data)} spans")
        client = LLMClient()
        try:
            # Call LLM with proper response format
            response = client.call(
                messages,
                response_format={
                    "type": "json_schema",
                    "json_schema": technique_schema
                },
                max_tokens=4000  # Conservative limit to prevent truncation issues
            )
            content = response.get("content", "")
            
            # Log response
            logger.info(f"BatchMapper LLM response: {len(content)} chars")
            logger.debug(f"BatchMapper raw response preview: {content[:500]}...")
            
            if not content:
                logger.error("Empty response from LLM for batch technique extraction")
                return 0
            
            # Parse the simplified JSON array
            try:
                # Store original content for fallback
                original_content = content
                
                # Strip markdown wrapper if present
                if '```' in content:
                    if '```json' in content:
                        content = content.split('```json')[1].split('```')[0].strip()
                    elif content.strip().startswith('```'):
                        content = content.split('```')[1].split('```')[0].strip()
                    logger.debug(f"Stripped markdown wrapper, new length: {len(content)}")
                
                # Parse the structured response - expects {"techniques": [...]}
                parsed = json.loads(content)
                if isinstance(parsed, dict) and "techniques" in parsed:
                    results = parsed["techniques"]
                else:
                    # Fallback for unexpected structure
                    logger.warning(f"Unexpected response structure: {type(parsed)}")
                    results = []
                
                if not isinstance(results, list):
                    logger.error(f"Expected list, got {type(results)}")
                    results = []
                    
                logger.info(f"Successfully parsed {len(results)} technique extractions")
                
            except json.JSONDecodeError as e:
                logger.error(f"JSON parse error in technique extraction: {e}")
                logger.debug(f"Failed content preview: {content[:200] if content else 'Empty'}")
                
                # Try fallback parsing with original content
                parsed = parse_json_with_fallback(
                    original_content,  # Use original content, not modified
                    expected_structure=[],
                    max_retries=2
                )
                results = parsed if isinstance(parsed, list) else []
            
            # Process simplified results
            added_claims = 0
            
            if isinstance(results, list):
                logger.debug(f"Processing {len(results)} technique items from LLM")
                
                for item in results:
                    if not isinstance(item, dict):
                        logger.warning(f"Skipping non-dict item: {type(item)}")
                        continue
                    
                    # Extract from simplified format
                    span_id = item.get("span", -1)
                    technique_id = item.get("tid", "")
                    confidence = item.get("conf", 50)
                    
                    if not technique_id:
                        logger.debug(f"Skipping item without technique ID: {item}")
                        continue
                    
                    if span_id < 0 or span_id >= len(mem.spans):
                        logger.warning(f"Invalid span ID {span_id} for technique {technique_id}")
                        continue
                    
                    # Get span text and line refs for evidence
                    span_data = mem.spans[span_id]
                    span_text = span_data.get("text", "")[:500]
                    line_refs = span_data.get("line_refs", [])
                    
                    # Create simplified claim
                    claim = {
                        "external_id": technique_id,
                        "name": "",  # Will be enriched from candidates or lookup
                        "quotes": [span_text] if span_text else [],
                        "line_refs": line_refs,
                        "confidence": confidence,
                        "span_idx": span_id,
                        "evidence_score": confidence,
                        "source": "batch_mapper"
                    }
                    
                    # Try to enrich with candidate metadata if available
                    technique_name = ""
                    for cand in mem.candidates.get(span_id, []):
                        if cand.get("external_id") == technique_id:
                            technique_name = cand.get("name", "")
                            claim["technique_meta"] = {
                                "name": cand.get("name", ""),
                                "description": cand.get("description", ""),
                                "tactic": cand.get("tactic", ""),
                                "platforms": cand.get("platforms", []),
                                "subtechnique_of": cand.get("subtechnique_of"),
                            }
                            break
                    
                    # If name not found in candidates, try to look it up from cache
                    if not technique_name:
                        # First try the fast cache lookup
                        tech_meta = technique_cache.get(technique_id)
                        if tech_meta:
                            technique_name = tech_meta.get("name", "")
                            # Also populate technique_meta if not already set
                            if "technique_meta" not in claim:
                                claim["technique_meta"] = {
                                    "name": tech_meta.get("name", ""),
                                    "description": tech_meta.get("description", ""),
                                    "tactic": tech_meta.get("tactic", ""),
                                    "platforms": tech_meta.get("platforms", []),
                                    "subtechnique_of": tech_meta.get("subtechnique_of"),
                                }
                        else:
                            # Fallback to direct lookup if not in cache (shouldn't happen normally)
                            try:
                                tech_meta = resolve_technique_by_external_id(technique_id)
                                if tech_meta and tech_meta.get("name"):
                                    technique_name = tech_meta["name"]
                                    # Also populate technique_meta if not already set
                                    if "technique_meta" not in claim:
                                        claim["technique_meta"] = {
                                            "name": tech_meta.get("name", ""),
                                            "description": tech_meta.get("description", ""),
                                            "tactic": tech_meta.get("tactic", ""),
                                            "platforms": tech_meta.get("platforms", []),
                                            "subtechnique_of": tech_meta.get("subtechnique_of"),
                                        }
                            except Exception as e:
                                logger.debug(f"Failed to resolve technique {technique_id}: {e}")
                    
                    # Set the name (fallback to technique_id if name not found)
                    claim["name"] = technique_name if technique_name else technique_id
                    
                    mem.claims.append(claim)
                    added_claims += 1
                    
                    logger.debug(f"Added claim: span={span_id}, technique={technique_id}, conf={confidence}")
            else:
                logger.warning(f"Results is not a list after parsing: {type(results)}")
            
            logger.info(f"BatchMapperAgent: Batch added {added_claims} claims")
            return added_claims
                        
        except Exception as e:
            logger.error(f"Batch processing failed: {e}")
            logger.debug(f"Error details: {str(e)}", exc_info=True)
            return 0
    
    def _calculate_dynamic_batch_size(self, spans: List[Dict], config: Dict[str, Any]) -> int:
        """
        Calculate optimal batch size based on token estimates.
        
        Args:
            spans: List of span dictionaries
            config: Configuration dictionary
            
        Returns:
            Optimal batch size
        """
        if not spans:
            return 1
        
        # Sample more spans for better estimation
        sample_size = min(10, len(spans))
        sample_spans = spans[:sample_size]
        
        total_tokens = 0
        max_span_tokens = 0
        
        for span in sample_spans:
            # Estimate tokens for span text
            span_text = span.get("text", "")
            span_tokens = self.token_estimator.estimate_tokens(span_text)
            
            # Track maximum span size
            max_span_tokens = max(max_span_tokens, span_tokens)
            
            # Add overhead for structure, candidates, evidence lines
            overhead = 150  # Increased overhead for JSON structure, candidates, etc.
            total_tokens += span_tokens + overhead
        
        # Calculate average tokens per span
        avg_tokens_per_span = total_tokens / sample_size if sample_size > 0 else 300
        
        # Detect if content is dense based on average tokens
        is_dense = avg_tokens_per_span > 400 or max_span_tokens > 600
        
        # Get token limit for batch mapper operation (use dense limits if needed)
        if is_dense:
            token_limit = 1200  # Very conservative for dense content to prevent truncation
            logger.info(f"Dense spans detected (avg: {avg_tokens_per_span:.0f}, max: {max_span_tokens})")
        else:
            token_limit = self.token_estimator.limits.get('batch_mapper', 2000)  # Reduced from 2500
        
        # Calculate optimal batch size with better safety margin
        # Use 50% margin for dense content, 60% for normal
        safety_factor = 0.5 if is_dense else 0.6
        safe_token_limit = int(token_limit * safety_factor)
        
        # Calculate batch size
        if avg_tokens_per_span > 0:
            optimal_batch_size = max(1, int(safe_token_limit / avg_tokens_per_span))
        else:
            optimal_batch_size = 10
        
        # Apply more conservative bounds
        # Smaller batches for dense content
        if is_dense:
            min_batch = 3   # Allow smaller batches for very large spans
            max_batch = 10  # Much smaller max for dense content
        else:
            min_batch = 5
            max_batch = 15  # Reduced from 30
        
        # Override with environment variable if set
        min_batch = int(os.getenv("MIN_BATCH_SIZE", str(min_batch)))
        max_batch = int(os.getenv("MAX_MAPPER_BATCH_SIZE", str(max_batch)))
        
        optimal_batch_size = max(min_batch, min(optimal_batch_size, max_batch))
        
        logger.info(f"Dynamic batch sizing: avg {avg_tokens_per_span:.0f} tokens/span, "
                   f"max {max_span_tokens} tokens, optimal batch size: {optimal_batch_size}")
        
        return optimal_batch_size
    
