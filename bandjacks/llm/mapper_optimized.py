"""Optimized batch mapper for faster extraction."""

import json
import re
import logging
from typing import Any, Dict, List
from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.client import LLMClient
from bandjacks.llm.tools import list_subtechniques

logger = logging.getLogger(__name__)


def cleanup_json(json_str: str) -> str:
    """Clean up common JSON formatting errors from LLM responses."""
    # Remove extra quotes after closing braces/brackets
    json_str = re.sub(r'\}"\s*,', '},', json_str)
    json_str = re.sub(r'\]"\s*,', '],', json_str)
    json_str = re.sub(r'\}"\s*\]', '}]', json_str)
    json_str = re.sub(r'\}"\s*\}', '}}', json_str)
    
    # Remove trailing commas before closing braces/brackets
    json_str = re.sub(r',\s*\}', '}', json_str)
    json_str = re.sub(r',\s*\]', ']', json_str)
    
    # Fix missing commas between objects (careful pattern)
    json_str = re.sub(r'\}\s*\{', '},{', json_str)
    json_str = re.sub(r'\]\s*\[', '],[', json_str)
    
    return json_str


class BatchMapperAgent:
    """Batch process spans in smaller groups to prevent LLM timeouts."""
    
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
            
        # Dynamic configuration
        max_batch_spans = config.get("max_batch_spans", 20)  # Total spans to process in batch mode
        batch_size = config.get("batch_size", 5)  # Spans per LLM call (default 5 to prevent timeouts)
        
        # Skip if too many spans (fallback to sequential)
        if span_count > max_batch_spans:
            logger.debug(f"Too many spans ({span_count} > {max_batch_spans}), falling back to sequential")
            return self._run_sequential(mem, config)
        
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
    
    def _process_batch(self, spans_data: List[Dict], mem: WorkingMemory, config: Dict[str, Any]) -> int:
        """Process a single batch of spans."""
        # Create batch prompt with JSON requirement
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a cybersecurity analyst that outputs JSON. "
                    "Analyze multiple text spans and extract ALL ATT&CK techniques mentioned or implied.\n\n"
                    "For EACH span, extract ALL techniques that are:\n"
                    "1. Explicitly mentioned by ID (e.g., T1055, T1566.001)\n"
                    "2. Described by behavior matching a technique\n"
                    "3. Present in the candidate list and relevant\n\n"
                    "You must output a JSON array with MULTIPLE techniques per span if applicable:\n"
                    "[{\"span_id\":int, \"techniques\":[{\"external_id\":str,\"name\":str,\"evidence\":{\"quotes\":[str],\"line_refs\":[int]},\"confidence\":int}]}]\n\n"
                    "Extract every valid technique. Include explicit IDs even if not in candidates. Output ONLY valid JSON."
                )
            },
            {
                "role": "user",
                "content": f"Process these {len(spans_data)} spans:\n\n" + json.dumps(spans_data, indent=2)
            }
        ]
        
        # Single LLM call for this batch with structured output
        logger.debug(f"  Calling LLM with batch of {len(spans_data)} spans")
        client = LLMClient()
        try:
            # Use response_format to enforce JSON output, reasonable tokens for 5 spans
            response = client.call(
                messages,
                response_format={"type": "json_object"},
                max_tokens=16000  # Doubled limit to prevent truncation
            )
            content = response.get("content", "")
            logger.debug(f"  LLM response received, length: {len(content)}")
            
            # With structured output, we should get valid JSON directly
            content = content.strip()
            if not content:
                logger.warning("Empty response from LLM for batch")
                return 0
            
            try:
                # Direct JSON parsing - no need for markdown extraction
                results = json.loads(content)
            except json.JSONDecodeError as e:
                logger.warning(f"Initial JSON parse failed: {e}")
                logger.debug(f"Attempting to clean up malformed JSON...")
                
                # Try cleaning up common JSON errors
                cleaned_content = cleanup_json(content)
                try:
                    results = json.loads(cleaned_content)
                    logger.info("Successfully parsed JSON after cleanup")
                except json.JSONDecodeError as e2:
                    logger.error(f"Failed to parse JSON even after cleanup: {e2}")
                    logger.debug(f"Original response: {content[:500]}")
                    logger.debug(f"Cleaned response: {cleaned_content[:500]}")
                    return 0
            
            # Process results
            added_claims = 0
            if isinstance(results, list):
                logger.debug(f"Processing {len(results)} results from LLM")
                for result in results:
                    span_id = result.get("span_id")
                    if span_id is None or span_id >= len(mem.spans):
                        continue
                    
                    # Handle new format with multiple techniques per span
                    techniques = result.get("techniques", [])
                    
                    # Fallback to old format if needed
                    if not techniques and result.get("technique"):
                        techniques = [{
                            "external_id": result["technique"].get("external_id"),
                            "name": result["technique"].get("name"),
                            "evidence": result.get("evidence", {}),
                            "confidence": result.get("confidence", 60)
                        }]
                    
                    for tech in techniques:
                        if not tech.get("external_id"):
                            continue
                            
                        evidence = tech.get("evidence", {})
                        
                        # Validate evidence before adding claim
                        quotes = evidence.get("quotes", [])
                        line_refs = evidence.get("line_refs", [])
                        if not quotes:
                            logger.debug(f"  Skipping {tech.get('external_id')}: no quotes")
                            continue
                        if not line_refs:
                            logger.debug(f"  Warning: {tech.get('external_id')} has no line_refs, using span refs")
                            line_refs = mem.spans[span_id].get("line_refs", [])
                        
                        # Check for sub-technique preference
                        choice_id = tech.get("external_id", "")
                        if choice_id and "." not in choice_id:
                            subs = list_subtechniques(choice_id)
                            if isinstance(subs, list) and subs:
                                for s in subs:
                                    nm = (s.get("name", "") or "").lower()
                                    if nm and any(nm in (q or "").lower() for q in evidence.get("quotes", [])):
                                        tech["external_id"] = s.get("external_id", choice_id)
                                        tech["name"] = s.get("name", tech.get("name", ""))
                                        break
                        
                        # Handle confidence conversion (might be string like "high" or number)
                        confidence = tech.get("confidence", 60)
                        if isinstance(confidence, str):
                            confidence_map = {
                                "very high": 95, "veryhigh": 95,
                                "high": 85,
                                "medium": 60, "moderate": 60,
                                "low": 40,
                                "very low": 20, "verylow": 20
                            }
                            confidence = confidence_map.get(confidence.lower(), 60)
                        else:
                            try:
                                confidence = int(confidence)
                            except (ValueError, TypeError):
                                confidence = 60
                        
                        mem.claims.append({
                            "span_idx": span_id,
                            "external_id": tech["external_id"],
                            "name": tech.get("name", ""),
                            "quotes": quotes,
                            "line_refs": line_refs,
                            "confidence": confidence,
                            "source": "batch_mapper"
                        })
                        added_claims += 1
                        logger.debug(f"  Added claim: {tech['external_id']} with {len(quotes)} quotes")
            
            return added_claims
                        
        except Exception as e:
            logger.error(f"Batch processing failed: {e}")
            logger.debug(f"Error details: {str(e)}", exc_info=True)
            return 0
    
    def _run_sequential(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        """Fallback to sequential processing if batch fails."""
        from bandjacks.llm.agents_v2 import MapperAgent
        MapperAgent().run(mem, config)