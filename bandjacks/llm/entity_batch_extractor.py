"""Batch entity extractor with progressive windowing and context carry-forward."""

import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from bandjacks.llm.client import LLMClient
from bandjacks.llm.entity_ignorelist import get_entity_ignorelist
from bandjacks.llm.evidence_utils import calculate_line_refs, extract_sentence_evidence
from bandjacks.llm.json_utils import parse_json_with_fallback

logger = logging.getLogger(__name__)


class BatchEntityExtractor:
    """Progressive entity extraction with batching and context carry-forward."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the batch entity extractor.
        
        Args:
            config: Optional configuration dictionary
        """
        config = config or {}
        self.client = LLMClient()
        self.ignorelist = get_entity_ignorelist()
        
        # Configuration parameters (with environment variable overrides)
        import os
        self.single_pass_limit = config.get("single_pass_limit",
                                           int(os.getenv("ENTITY_SINGLE_PASS_LIMIT", "15000")))
        self.window_size = config.get("window_size",
                                     int(os.getenv("ENTITY_WINDOW_SIZE", "15000")))
        self.overlap_size = config.get("overlap_size",
                                      int(os.getenv("ENTITY_OVERLAP_SIZE", "2000")))
        self.max_windows_per_batch = config.get("max_windows_per_batch",
                                               int(os.getenv("ENTITY_MAX_WINDOWS_PER_BATCH", "1")))
        
        logger.info(f"BatchEntityExtractor initialized: single_pass={self.single_pass_limit}, "
                   f"window={self.window_size}, overlap={self.overlap_size}")
    
    def extract(self, text: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Main extraction entry point with intelligent batching.
        
        Args:
            text: Document text to extract entities from
            config: Optional extraction configuration
            
        Returns:
            Dictionary with extracted entities or entity claims
        """
        config = config or {}
        text_length = len(text)
        use_entity_claims = config.get("use_entity_claims", False)
        
        logger.info(f"Starting entity extraction for document of {text_length} characters (claims={use_entity_claims})")
        
        try:
            if text_length <= self.single_pass_limit:
                # Small documents: single LLM call
                logger.info("Using single-pass extraction for small document")
                entities = self._extract_single_pass(text, config)
            else:
                # Large documents: progressive windowed extraction
                logger.info("Using progressive windowed extraction for large document")
                entities = self._extract_progressive(text, config)
            
            # Apply ignorelist filtering
            filtered_entities = self._filter_entities(entities)
            
            # If using entity claims, convert entities to claims
            if use_entity_claims:
                entity_list = filtered_entities.get("entities", [])
                chunk_id = config.get("chunk_id", 0)
                
                logger.info(f"Converting {len(entity_list)} entities to claims")
                entity_claims = self._entities_to_claims(entity_list, text, chunk_id)
                
                # Return claims instead of entities
                return {
                    "entity_claims": entity_claims,
                    "extraction_status": "claims_generated",
                    "extraction_method": "single_pass" if text_length <= self.single_pass_limit else "progressive",
                    "claims_count": len(entity_claims)
                }
            else:
                # Add extraction metadata for direct entities
                filtered_entities["extraction_status"] = "success"
                filtered_entities["extraction_method"] = "single_pass" if text_length <= self.single_pass_limit else "progressive"
                
                return filtered_entities
            
        except Exception as e:
            logger.error(f"Entity extraction failed: {e}")
            return {
                "entities": [],
                "extraction_status": "failed",
                "error": str(e)
            }
    
    def _extract_single_pass(self, text: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Extract entities in a single LLM call.
        
        Args:
            text: Document text
            config: Extraction configuration
            
        Returns:
            Extracted entities dictionary
        """
        messages = self._build_extraction_messages(text, context=None, is_continuation=False)
        
        try:
            response = self.client.call(
                messages=messages,
                max_tokens=8000,
                response_format={
                    "type": "json_schema",
                    "json_schema": self._get_entity_schema()
                }
            )
            
            content = response.get("content", "")
            if not content:
                logger.warning("Empty response from LLM for single-pass extraction")
                return {"entities": []}
            
            # Parse response
            result = self._parse_entity_response(content)
            
            # Add line references to entities
            for entity in result.get("entities", []):
                self._add_line_references(entity, text)
            
            logger.info(f"Single-pass extraction found {len(result.get('entities', []))} entities")
            return result
            
        except Exception as e:
            logger.error(f"Single-pass extraction failed: {e}")
            return {"entities": []}
    
    def _extract_progressive(self, text: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Progressive windowed extraction with batching.
        
        Args:
            text: Document text
            config: Extraction configuration
            
        Returns:
            Extracted entities dictionary
        """
        windows = self._create_sliding_windows(text)
        logger.info(f"Created {len(windows)} windows for progressive extraction")
        
        all_entities = []
        accumulated_context = {}
        
        # Process windows in batches
        for batch_start in range(0, len(windows), self.max_windows_per_batch):
            batch_end = min(batch_start + self.max_windows_per_batch, len(windows))
            batch_windows = windows[batch_start:batch_end]
            
            logger.info(f"Processing window batch {batch_start}-{batch_end-1} ({len(batch_windows)} windows)")
            
            # Build prompts for all windows in this batch
            window_data = []
            for i, window in enumerate(batch_windows):
                global_idx = batch_start + i
                window_prompt = {
                    "window_id": global_idx,
                    "text": window["text"],
                    "start": window["start"],
                    "end": window["end"],
                    "context": accumulated_context.copy() if global_idx > 0 else None,
                    "is_continuation": global_idx > 0
                }
                window_data.append(window_prompt)
            
            # Batch extract all windows in one LLM call
            batch_entities = self._batch_extract_windows(window_data, text)
            
            # Update accumulated context from first window if needed
            if batch_start == 0 and batch_entities:
                accumulated_context = self._extract_primary_entities(batch_entities)
            
            # Add to all entities
            all_entities.extend(batch_entities)
        
        # Progressive merge with coreference resolution
        merged_entities = self._progressive_merge(all_entities)
        
        logger.info(f"Progressive extraction found {len(merged_entities.get('entities', []))} unique entities")
        return merged_entities
    
    def _create_sliding_windows(self, text: str) -> List[Dict[str, Any]]:
        """Create overlapping windows for text processing.
        
        Args:
            text: Document text
            
        Returns:
            List of window dictionaries with text and position info
        """
        windows = []
        text_length = len(text)
        
        start = 0
        while start < text_length:
            end = min(start + self.window_size, text_length)
            
            # Try to find a good boundary (paragraph or sentence)
            if end < text_length:
                boundary_end = self._find_good_boundary(text, end, start)
                if boundary_end:
                    end = boundary_end
            
            windows.append({
                "text": text[start:end],
                "start": start,
                "end": end
            })
            
            # Move to next window with overlap
            start = end - self.overlap_size
            
            # Avoid tiny final windows
            if text_length - start < self.overlap_size and start < text_length:
                # Extend the last window to include remaining text
                windows[-1]["text"] = text[windows[-1]["start"]:]
                windows[-1]["end"] = text_length
                break
        
        return windows
    
    def _find_good_boundary(self, text: str, target_pos: int, min_pos: int) -> Optional[int]:
        """Find a good boundary (paragraph or sentence) near the target position.
        
        Args:
            text: Full text
            target_pos: Target boundary position
            min_pos: Minimum allowed position
            
        Returns:
            Better boundary position or None
        """
        # Look for paragraph break first
        search_window = 500
        search_start = max(min_pos, target_pos - search_window)
        search_text = text[search_start:target_pos + search_window]
        
        # Find last paragraph break before target
        para_pos = search_text.rfind('\n\n', 0, target_pos - search_start)
        if para_pos > 0:
            return search_start + para_pos + 2
        
        # Find last sentence boundary before target
        import re
        sentence_pattern = re.compile(r'[.!?]\s+[A-Z]')
        matches = list(sentence_pattern.finditer(search_text))
        
        for match in reversed(matches):
            if search_start + match.end() <= target_pos:
                return search_start + match.end()
        
        return None
    
    def _batch_extract_windows(self, window_data: List[Dict[str, Any]], full_text: str) -> List[Dict[str, Any]]:
        """Extract entities from multiple windows in a single LLM call.
        
        Args:
            window_data: List of window dictionaries with text and context
            full_text: Full document text for line reference calculation
            
        Returns:
            List of entity dictionaries
        """
        # Build a single prompt for all windows
        system_prompt = self._get_batch_system_prompt()
        user_prompt = self._build_batch_user_prompt(window_data)
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
        
        try:
            response = self.client.call(
                messages=messages,
                max_tokens=8000,  # Increased to prevent truncation
                response_format={
                    "type": "json_schema",
                    "json_schema": self._get_batch_schema()
                }
            )
            
            content = response.get("content", "")
            if not content:
                logger.warning("Empty response from LLM for batch extraction")
                return []
            
            # Parse batch response
            result = self._parse_batch_response(content, window_data, full_text)
            return result
            
        except Exception as e:
            logger.error(f"Batch extraction failed: {e}")
            return []
    
    def _build_extraction_messages(self, text: str, context: Optional[Dict], is_continuation: bool) -> List[Dict]:
        """Build messages for entity extraction.
        
        Args:
            text: Text to extract from
            context: Optional context from previous windows
            is_continuation: Whether this is a continuation of previous text
            
        Returns:
            List of messages for LLM
        """
        system_prompt = """You are an expert cyber threat intelligence analyst specializing in entity extraction.

Extract ALL named entities from threat intelligence reports.

Entity types:
- group: Threat actors, APT groups (e.g., APT29, Lazarus Group)
- malware: Malicious software (e.g., SUNBURST, Emotet, TrickBot)
- tool: Legitimate software used by attackers (e.g., PowerShell, Mimikatz)
- target: Victim organizations or sectors
- campaign: Named operations or attacks

Return a JSON object with an "entities" array containing entity objects with name, type, confidence, evidence, and context fields."""
        
        user_prompt = f"""Extract all cyber threat entities from this {'continuation of a ' if is_continuation else ''}report.

{f"Context from earlier sections: {json.dumps(context)}" if context else ""}

TEXT:
{text}

Extract EVERY named entity with evidence."""
        
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    
    def _get_batch_system_prompt(self) -> str:
        """Get system prompt for batch extraction."""
        return """You are an expert cyber threat intelligence analyst specializing in entity extraction.

You will be given multiple text windows from the same document. Extract ALL named entities from each window.

Entity types:
- group: Threat actors, APT groups
- malware: Malicious software
- tool: Legitimate software used by attackers
- target: Victim organizations or sectors
- campaign: Named operations or attacks

For each window, track:
1. New entities found
2. References to entities from previous windows
3. Coreferences (e.g., "the group" referring to APT29)

Return a JSON object with a "windows" array, where each window contains its extracted entities."""
    
    def _build_batch_user_prompt(self, window_data: List[Dict[str, Any]]) -> str:
        """Build user prompt for batch extraction."""
        prompt_parts = ["Process these text windows from a threat intelligence report:\n"]
        
        for window in window_data:
            prompt_parts.append(f"\n--- WINDOW {window['window_id']} ---")
            if window.get('context'):
                prompt_parts.append(f"Context: {json.dumps(window['context'])}")
            prompt_parts.append(f"Text ({window['start']}-{window['end']} chars):")
            prompt_parts.append(window['text'][:5000])  # Limit text per window
            prompt_parts.append("---\n")
        
        prompt_parts.append("\nExtract ALL entities from each window, maintaining consistency across windows.")
        return "\n".join(prompt_parts)
    
    def _get_entity_schema(self) -> Dict[str, Any]:
        """Get JSON schema for entity extraction."""
        return {
            "type": "object",
            "properties": {
                "entities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "type": {"type": "string", "enum": ["group", "malware", "tool", "target", "campaign"]},
                            "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                            "evidence": {"type": "string"},
                            "context": {"type": "string"}
                        },
                        "required": ["name", "type", "confidence"],
                        "additionalProperties": False
                    }
                }
            },
            "required": ["entities"],
            "additionalProperties": False
        }
    
    def _get_batch_schema(self) -> Dict[str, Any]:
        """Get JSON schema for batch extraction."""
        return {
            "type": "object",
            "properties": {
                "windows": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "window_id": {"type": "integer"},
                            "entities": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "type": {"type": "string"},
                                        "confidence": {"type": "integer"},
                                        "evidence": {"type": "string"},
                                        "context": {"type": "string"}
                                    },
                                    "required": ["name", "type"],
                                    "additionalProperties": False
                                }
                            }
                        },
                        "required": ["window_id", "entities"],
                        "additionalProperties": False
                    }
                }
            },
            "required": ["windows"],
            "additionalProperties": False
        }
    
    def _parse_entity_response(self, content: str) -> Dict[str, Any]:
        """Parse entity extraction response."""
        try:
            # Try direct JSON parse
            if '```json' in content:
                content = content.split('```json')[1].split('```')[0].strip()
            elif '```' in content:
                content = content.split('```')[1].split('```')[0].strip()
            
            result = json.loads(content)
            return result
        except json.JSONDecodeError:
            # Fallback parsing
            result = parse_json_with_fallback(
                content,
                expected_structure={"entities": []},
                max_retries=2
            )
            return result
    
    def _parse_batch_response(self, content: str, window_data: List[Dict], full_text: str) -> List[Dict[str, Any]]:
        """Parse batch extraction response."""
        try:
            result = self._parse_entity_response(content)
            
            all_entities = []
            
            # Extract entities from each window
            for window_result in result.get("windows", []):
                window_id = window_result.get("window_id", 0)
                window_info = window_data[window_id] if window_id < len(window_data) else None
                
                for entity in window_result.get("entities", []):
                    # Add position information
                    if window_info:
                        entity["window_start"] = window_info["start"]
                        entity["window_end"] = window_info["end"]
                    
                    # Calculate line references
                    self._add_line_references(entity, full_text)
                    
                    all_entities.append(entity)
            
            return all_entities
            
        except Exception as e:
            logger.error(f"Failed to parse batch response: {e}")
            return []
    
    def _add_line_references(self, entity: Dict[str, Any], text: str):
        """Add line references and enhance evidence to full sentences."""
        if not entity.get("evidence"):
            return
        
        evidence = entity["evidence"]
        evidence_pos = text.find(evidence)
        
        if evidence_pos < 0:
            # Try case-insensitive search
            evidence_pos = text.lower().find(evidence.lower())
        
        if evidence_pos >= 0:
            # Extract full sentences around the evidence
            sentence_evidence = extract_sentence_evidence(
                text,
                evidence_pos,
                context_sentences=1  # Get 1 sentence before and after
            )
            
            # Update entity with enhanced evidence
            if sentence_evidence.get("quote"):
                entity["evidence"] = sentence_evidence["quote"]
                entity["line_refs"] = sentence_evidence.get("line_refs", [])
            else:
                # Fallback to original line refs if sentence extraction fails
                line_refs = calculate_line_refs(
                    text,
                    evidence_pos,
                    evidence_pos + len(evidence)
                )
                entity["line_refs"] = line_refs
    
    def _extract_primary_entities(self, entities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract primary entities for context."""
        context = {
            "primary_threat_actor": None,
            "primary_malware": None,
            "seen_entities": []
        }
        
        # Find highest confidence entities of each type
        for entity in entities:
            entity_type = entity.get("type")
            entity_name = entity.get("name")
            confidence = entity.get("confidence", 0)
            
            if entity_type == "group" and confidence > 80:
                if not context["primary_threat_actor"] or confidence > context["primary_threat_actor"][1]:
                    context["primary_threat_actor"] = (entity_name, confidence)
            
            elif entity_type == "malware" and confidence > 80:
                if not context["primary_malware"] or confidence > context["primary_malware"][1]:
                    context["primary_malware"] = (entity_name, confidence)
            
            context["seen_entities"].append(entity_name)
        
        # Simplify context
        if context["primary_threat_actor"]:
            context["primary_threat_actor"] = context["primary_threat_actor"][0]
        if context["primary_malware"]:
            context["primary_malware"] = context["primary_malware"][0]
        
        # Limit seen entities
        context["seen_entities"] = list(set(context["seen_entities"]))[:20]
        
        return context
    
    def _progressive_merge(self, all_entities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Progressively merge entities with coreference resolution."""
        # Group entities by name and type
        entity_groups = {}
        
        for entity in all_entities:
            name = entity.get("name", "").lower().strip()
            entity_type = entity.get("type", "")
            
            if not name:
                continue
            
            key = (name, entity_type)
            
            if key not in entity_groups:
                entity_groups[key] = {
                    "name": entity.get("name"),  # Keep original casing
                    "type": entity_type,
                    "confidence": entity.get("confidence", 50),
                    "mentions": []
                }
            
            # Add mention
            mention = {
                "quote": entity.get("evidence", ""),
                "line_refs": entity.get("line_refs", []),
                "context": entity.get("context", "primary_mention")
            }
            
            if mention["quote"]:
                entity_groups[key]["mentions"].append(mention)
            
            # Update max confidence
            entity_groups[key]["confidence"] = max(
                entity_groups[key]["confidence"],
                entity.get("confidence", 50)
            )
        
        # Convert to list and boost confidence for multiple mentions
        merged_entities = []
        for entity_data in entity_groups.values():
            # Boost confidence based on mentions
            mention_boost = min(20, len(entity_data["mentions"]) * 5)
            entity_data["confidence"] = min(100, entity_data["confidence"] + mention_boost)
            merged_entities.append(entity_data)
        
        return {"entities": merged_entities}
    
    def _filter_entities(self, entities: Dict[str, Any]) -> Dict[str, Any]:
        """Apply ignorelist filtering to entities."""
        if not entities.get("entities"):
            return entities
        
        filtered = self.ignorelist.filter_entities(entities["entities"])
        
        logger.info(f"Filtered {len(entities['entities']) - len(filtered)} entities using ignorelist")
        
        return {"entities": filtered}
    
    def _entities_to_claims(self, entities: List[Dict[str, Any]], doc_text: str, chunk_id: int = 0) -> List[Dict[str, Any]]:
        """
        Convert extracted entities to entity claims with full sentence evidence.
        
        Args:
            entities: List of extracted entities
            doc_text: Full document text for line reference calculation
            chunk_id: ID of the chunk these entities came from
            
        Returns:
            List of entity claims with sentence-based evidence
        """
        claims = []
        
        for entity in entities:
            if not isinstance(entity, dict):
                continue
                
            entity_name = entity.get("name", "")
            entity_type = entity.get("type", "")
            
            if not entity_name or not entity_type:
                continue
            
            # Generate entity ID from type and normalized name
            entity_id = f"{entity_type}_{entity_name.lower().replace(' ', '_').replace('-', '_')}"
            
            # Get original evidence quote from LLM or entity name
            original_evidence = entity.get("evidence", "") or entity_name
            
            # Extract full sentence evidence
            enhanced_quotes = []
            line_refs = []
            
            # Find the position of the evidence in the document
            evidence_pos = doc_text.find(original_evidence)
            
            if evidence_pos < 0 and original_evidence:
                # Try case-insensitive search
                lower_text = doc_text.lower()
                lower_evidence = original_evidence.lower()
                evidence_pos = lower_text.find(lower_evidence)
            
            # If we still can't find the evidence, try the entity name
            if evidence_pos < 0:
                name_pos = doc_text.find(entity_name)
                if name_pos < 0:
                    # Try case-insensitive
                    name_pos = doc_text.lower().find(entity_name.lower())
                if name_pos >= 0:
                    evidence_pos = name_pos
                    original_evidence = entity_name
            
            if evidence_pos >= 0:
                # Extract full sentences around the evidence
                sentence_evidence = extract_sentence_evidence(
                    doc_text,
                    evidence_pos,
                    context_sentences=1  # Get 1 sentence before and after
                )
                
                if sentence_evidence.get("quote"):
                    enhanced_quotes.append(sentence_evidence["quote"])
                    line_refs = sentence_evidence.get("line_refs", [])
                else:
                    # Fallback to original if sentence extraction fails
                    enhanced_quotes.append(original_evidence)
                    line_refs = calculate_line_refs(
                        doc_text,
                        evidence_pos,
                        evidence_pos + len(original_evidence)
                    )
            else:
                # If we can't find any evidence, use what we have
                if original_evidence:
                    enhanced_quotes.append(original_evidence)
                # Try to get line refs from existing entity if available
                if entity.get("line_refs"):
                    line_refs = entity["line_refs"]
            
            # Create the claim
            claim = {
                "entity_id": entity_id,
                "name": entity_name,
                "entity_type": entity_type,
                "quotes": enhanced_quotes,
                "line_refs": line_refs,
                "confidence": entity.get("confidence", 75),
                "chunk_id": chunk_id,
                "context": entity.get("context", "primary_mention")
            }
            
            claims.append(claim)
            
        return claims