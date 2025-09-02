"""Entity extraction using LLM with structured prompts."""

import json
import logging
import re
from typing import Dict, Any, List, Optional
from bandjacks.llm.client import LLMClient
from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.json_utils import parse_json_with_fallback
from bandjacks.llm.evidence_utils import extract_sentence_evidence, calculate_line_refs

logger = logging.getLogger(__name__)


ENTITY_EXTRACTION_SYSTEM_PROMPT = """
You are an expert cyber threat intelligence analyst specializing in entity extraction.

Your task is to identify and extract ALL named entities from threat intelligence reports.

Entity types to extract:
- group: Threat actor groups, APT groups, intrusion sets (e.g., APT29, Lazarus Group, Cozy Bear, FIN7)
- malware: Malicious software created for harmful purposes:
  * Viruses, trojans, backdoors, ransomware, stealers, rootkits, spyware
  * Examples: SUNBURST, Emotet, DarkCloud Stealer, TrickBot, Maze ransomware, Cobalt Strike beacon
- tool: Legitimate software abused or used by attackers:
  * System administration tools, penetration testing tools, living-off-the-land binaries
  * Examples: PowerShell, PsExec, Mimikatz, WMI, cmd.exe, rundll32.exe, certutil.exe
- target: Targeted organizations, sectors, or entities (e.g., SolarWinds, Microsoft, healthcare sector)
- campaign: Named operations or attack campaigns (e.g., Operation Aurora, SolarWinds supply chain attack)

CRITICAL: Distinguish between malware and tool:
- MALWARE: Software designed to be malicious (custom trojans, ransomware, backdoors, etc.)
- TOOL: Legitimate software misused by attackers (system utilities, admin tools, etc.)

Key extraction rules:
1. Extract EVERY unique named entity you find
2. Correctly classify software as "malware" or "tool" based on its intended purpose
3. Include all aliases and alternate names as separate entities
4. Look everywhere: title, summary, body text, conclusions
5. Common patterns to look for:
   - Group indicators: APT, FIN, UNC, DEV, TAG, TA, G followed by numbers
   - Malware indicators: custom names, names ending in "bot", "RAT", "stealer", "ransomware", "backdoor"
   - Tool indicators: known software names (PowerShell, PsExec, etc.), system utilities
   - Target indicators: company names, sectors, industries mentioned as victims
   - Campaign indicators: "Operation", "Campaign", named attacks

OUTPUT FORMAT - Return ONLY valid JSON:
{
  "entities": [
    {
      "name": "APT29",
      "type": "group",
      "confidence": 95,
      "evidence": "APT29, also known as Cozy Bear, conducted a sophisticated campaign",
      "context": "primary_mention"
    },
    {
      "name": "Cozy Bear",
      "type": "group", 
      "confidence": 95,
      "evidence": "APT29, also known as Cozy Bear, conducted a sophisticated campaign",
      "context": "alias"
    },
    {
      "name": "SUNBURST",
      "type": "malware",
      "confidence": 100,
      "evidence": "The threat actors deployed a custom backdoor called SUNBURST",
      "context": "primary_mention"
    }
  ]
}

For each entity provide:
- name: The entity name
- type: group/malware/tool/target/campaign
- confidence: 0-100 score
- evidence: The sentence or phrase containing the entity
- context: primary_mention/alias/coreference
"""


USER_PROMPT_TEMPLATE = """
Extract all cyber threat entities from this report.

Find ALL:
- Groups: threat actors, APT groups, intrusion sets (APT29, Lazarus, Cozy Bear)
- Malware: malicious software designed for harmful purposes (SUNBURST, Emotet, TrickBot, ransomware)
- Tools: legitimate software abused by attackers (PowerShell, PsExec, Mimikatz, cmd.exe)
- Targets: victim organizations, sectors, or entities
- Campaigns: named operations or attack campaigns

IMPORTANT: Distinguish between malware and tools:
- Use "malware" for malicious software created to harm (trojans, backdoors, ransomware, etc.)
- Use "tool" for legitimate software misused in attacks (system utilities, admin tools, etc.)

TEXT TO ANALYZE:
{document_text}

Extract EVERY named entity with evidence. For each entity, include:
1. The exact quote/sentence where it appears
2. Your confidence score (0-100)
3. The context (primary_mention, alias, or coreference)

Be aggressive and comprehensive - include everything that could be an entity."""


class EntityExtractionAgent:
    """Extract cyber threat entities using LLM with structured prompts."""
    
    def __init__(self):
        """Initialize the entity extraction agent."""
        self.client = LLMClient()
        self.chunk_size = 4000  # Size of each chunk for processing
        self.chunk_overlap = 500  # Overlap between chunks to avoid missing entities at boundaries
        
        # JSON schema for structured entity extraction
        # JSON schema for entity extraction - LiteLLM format
        # Based on error, LiteLLM expects the schema directly without wrapper
        self.entity_schema = {
            "type": "object",
            "properties": {
                "entities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                                "description": "The entity name"
                            },
                            "type": {
                                "type": "string",
                                "enum": ["group", "malware", "tool", "target", "campaign"],
                                "description": "The entity type"
                            },
                            "confidence": {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": 100,
                                "description": "Confidence score 0-100"
                            },
                            "evidence": {
                                "type": "string",
                                "description": "The sentence or phrase containing the entity"
                            },
                            "context": {
                                "type": "string",
                                "enum": ["primary_mention", "alias", "coreference"],
                                "description": "The context of this mention"
                            }
                        },
                        "required": ["name", "type", "confidence", "evidence", "context"],
                        "additionalProperties": False
                    }
                }
            },
            "required": ["entities"],
            "additionalProperties": False
        }
    
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        """
        Extract entities from entire document using chunked processing.
        
        Args:
            mem: Working memory containing document text
            config: Configuration options
        """
        logger.info("Starting chunked entity extraction with LLM")
        
        doc_text = mem.document_text
        doc_length = len(doc_text)
        
        # Determine if we need chunking
        use_chunking = doc_length > self.chunk_size or config.get("force_chunking", False)
        
        try:
            if use_chunking:
                # Create chunks for processing
                chunks = self._create_chunks(doc_text)
                logger.info(f"Processing {len(chunks)} chunks for entity extraction (doc length: {doc_length})")
                
                # Extract entities from each chunk
                chunk_entities = []
                for i, chunk in enumerate(chunks):
                    logger.debug(f"Extracting entities from chunk {i+1}/{len(chunks)} ({len(chunk)} chars)")
                    entities = self._extract_from_chunk(chunk)
                    # Enhance each entity with line references
                    for entity in entities:
                        self._enhance_entity_with_line_refs(entity, doc_text)
                    chunk_entities.append(entities)
                    logger.debug(f"Found {len(entities)} entities in chunk {i+1}")
                
                # Merge and deduplicate entities from all chunks
                merged_entities = self._merge_entities(chunk_entities)
                logger.info(f"Extracted {len(merged_entities)} unique entities from {len(chunks)} chunks")
                
                entities = {
                    "entities": merged_entities,
                    "extraction_status": "success",
                    "chunks_processed": len(chunks)
                }
                
            else:
                # For smaller documents, process in one go
                logger.info(f"Processing document in single pass ({doc_length} chars)")
                
                user_prompt = USER_PROMPT_TEMPLATE.format(document_text=doc_text)
                
                messages = [
                    {"role": "system", "content": ENTITY_EXTRACTION_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt}
                ]
                
                # Try with structured output first, fall back to plain if needed
                try:
                    response = self.client.call(
                        messages=messages,
                        max_tokens=8000,  # Increased to 8000 to handle large entity lists
                        response_format={
                            "type": "json_schema",
                            "json_schema": self.entity_schema
                        }
                    )
                    content = response.get("content", "")
                except Exception as e:
                    logger.warning(f"Structured output failed: {e}, retrying without schema")
                    # Retry without strict schema but with explicit JSON instruction
                    messages_with_json = [
                        {"role": "system", "content": ENTITY_EXTRACTION_SYSTEM_PROMPT + "\n\nIMPORTANT: Return ONLY valid JSON, no markdown."},
                        {"role": "user", "content": user_prompt}
                    ]
                    response = self.client.call(
                        messages=messages_with_json,
                        max_tokens=8000  # Increased to 8000 to handle large entity lists
                    )
                    content = response.get("content", "")
                
                if not content:
                    # Try one more time with simplified prompt
                    logger.warning("Empty response, retrying with simplified prompt")
                    simple_prompt = f"""Extract entities from this text. Return JSON with format:
{{"entities": [{{"name": "entity_name", "type": "group/malware/tool/target/campaign", "confidence": 90, "evidence": "quote from text", "context": "primary_mention"}}]}}

Text: {doc_text[:2000]}"""
                    
                    response = self.client.call(
                        messages=[
                            {"role": "system", "content": "Extract entities and return JSON"},
                            {"role": "user", "content": simple_prompt}
                        ],
                        max_tokens=8000  # Increased to 8000
                    )
                    content = response.get("content", "")
                
                if not content:
                    error_msg = "Empty response from LLM for entity extraction after retries"
                    logger.error(error_msg)
                    mem.entities = {"entities": [], "extraction_status": "failed", "error": error_msg}
                    mem.extraction_errors = getattr(mem, 'extraction_errors', [])
                    mem.extraction_errors.append({"stage": "entity_extraction", "error": error_msg})
                    return
                
                # Parse JSON response
                try:
                    # Try to extract JSON from potential markdown wrapper
                    if '```json' in content:
                        content = content.split('```json')[1].split('```')[0].strip()
                    elif '```' in content:
                        content = content.split('```')[1].split('```')[0].strip()
                    
                    entities = json.loads(content)
                    
                    # Validate structure
                    if not isinstance(entities, dict) or "entities" not in entities:
                        raise ValueError(f"Invalid structure: expected dict with 'entities' key")
                    
                    if not isinstance(entities["entities"], list):
                        raise ValueError(f"Invalid entities field: expected list")
                    
                    # Enhance entities with line references
                    for entity in entities["entities"]:
                        self._enhance_entity_with_line_refs(entity, doc_text)
                    
                    # Convert to new format with mentions
                    enhanced_entities = []
                    for entity in entities["entities"]:
                        enhanced = {
                            "name": entity.get("name", ""),
                            "type": entity.get("type", ""),
                            "confidence": entity.get("confidence", 75),
                            "mentions": [{
                                "quote": entity.get("evidence", ""),
                                "line_refs": entity.get("line_refs", []),
                                "context": entity.get("context", "primary_mention")
                            }] if entity.get("evidence") else []
                        }
                        enhanced_entities.append(enhanced)
                    
                    entities["entities"] = enhanced_entities
                    # Add extraction status
                    entities["extraction_status"] = "success"
                    
                except json.JSONDecodeError as e:
                    error_msg = f"JSON parse error in entity extraction: {e}"
                    logger.error(error_msg)
                    
                    # Try fallback parsing
                    entities = parse_json_with_fallback(
                        content,
                        expected_structure={"entities": []},
                        max_retries=2
                    )
                    entities["extraction_status"] = "partial"
                    entities["error"] = error_msg
                
                except ValueError as e:
                    error_msg = f"Invalid entity structure: {e}"
                    logger.error(error_msg)
                    entities = {"entities": [], "extraction_status": "failed", "error": error_msg}
            
            # Store in working memory - entities now contains structured format
            mem.entities = entities
            
            # Log entity breakdown
            entity_count = len(entities.get("entities", []))
            logger.info(f"Entity extraction complete: {entity_count} entities extracted")
                
        except Exception as e:
            error_msg = f"Entity extraction failed with exception: {e}"
            logger.error(error_msg, exc_info=True)
            
            # Set failure state
            mem.entities = {"entities": [], "extraction_status": "failed", "error": str(e)}
            
            # Track error for reporting
            mem.extraction_errors = getattr(mem, 'extraction_errors', [])
            mem.extraction_errors.append({"stage": "entity_extraction", "error": str(e)})
    
    def _create_chunks(self, text: str, chunk_size: int = None, overlap: int = None) -> List[str]:
        """
        Create overlapping chunks from text.
        
        Args:
            text: Full document text
            chunk_size: Size of each chunk (default: self.chunk_size)
            overlap: Overlap between chunks (default: self.chunk_overlap)
            
        Returns:
            List of text chunks
        """
        if chunk_size is None:
            chunk_size = self.chunk_size
        if overlap is None:
            overlap = self.chunk_overlap
            
        chunks = []
        start = 0
        text_length = len(text)
        
        while start < text_length:
            end = min(start + chunk_size, text_length)
            chunk = text[start:end]
            chunks.append(chunk)
            
            # Move start position forward, accounting for overlap
            start += chunk_size - overlap
            
            # Avoid tiny final chunks
            if text_length - start < overlap and start < text_length:
                # Append remaining text to last chunk
                chunks[-1] = text[start - (chunk_size - overlap):]
                break
                
        return chunks
    
    def _enhance_entity_with_line_refs(self, entity: Dict[str, Any], text: str) -> Dict[str, Any]:
        """
        Enhance an entity with line references based on evidence.
        
        Args:
            entity: Entity dict with evidence field
            text: Full document text
            
        Returns:
            Enhanced entity with line_refs
        """
        if not entity.get("evidence"):
            return entity
            
        # Find the evidence in the text
        evidence = entity["evidence"]
        evidence_pos = text.find(evidence)
        
        if evidence_pos >= 0:
            # Calculate line references for the evidence
            line_refs = calculate_line_refs(
                text, 
                evidence_pos, 
                evidence_pos + len(evidence)
            )
            entity["line_refs"] = line_refs
        else:
            # Try case-insensitive search
            lower_text = text.lower()
            lower_evidence = evidence.lower()
            evidence_pos = lower_text.find(lower_evidence)
            if evidence_pos >= 0:
                line_refs = calculate_line_refs(
                    text,
                    evidence_pos,
                    evidence_pos + len(evidence)
                )
                entity["line_refs"] = line_refs
            else:
                entity["line_refs"] = []
                
        return entity
    
    def _merge_entities(self, entity_lists: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Merge and deduplicate entities from multiple chunks, combining evidence.
        
        Args:
            entity_lists: List of entity lists from different chunks
            
        Returns:
            Merged and deduplicated entity list with combined evidence
        """
        # Group entities by (name, type)
        entity_groups = {}
        
        for entities in entity_lists:
            for entity in entities:
                if isinstance(entity, dict):
                    name = entity.get("name", "")
                    entity_type = entity.get("type", "")
                    
                    if not name:
                        continue
                    
                    # Create key for grouping
                    key = (name.lower().strip(), entity_type)
                    
                    if key not in entity_groups:
                        entity_groups[key] = {
                            "name": name,  # Keep original casing
                            "type": entity_type,
                            "confidence": entity.get("confidence", 50),
                            "mentions": []
                        }
                    
                    # Add this mention
                    mention = {
                        "quote": entity.get("evidence", ""),
                        "line_refs": entity.get("line_refs", []),
                        "context": entity.get("context", "unknown"),
                        "confidence": entity.get("confidence", 50)
                    }
                    
                    # Only add if we have evidence
                    if mention["quote"]:
                        # Check if this exact quote already exists
                        existing_quotes = [m["quote"] for m in entity_groups[key]["mentions"]]
                        if mention["quote"] not in existing_quotes:
                            entity_groups[key]["mentions"].append(mention)
                    
                    # Update max confidence
                    entity_groups[key]["confidence"] = max(
                        entity_groups[key]["confidence"],
                        entity.get("confidence", 50)
                    )
        
        # Convert back to list and boost confidence for multiple mentions
        merged_entities = []
        for entity_data in entity_groups.values():
            # Boost confidence based on number of mentions
            mention_boost = min(20, len(entity_data["mentions"]) * 5)
            entity_data["confidence"] = min(100, entity_data["confidence"] + mention_boost)
            
            merged_entities.append(entity_data)
        
        return merged_entities
    
    def _extract_from_chunk(self, text_chunk: str) -> List[Dict[str, Any]]:
        """
        Extract entities from a single text chunk.
        
        Args:
            text_chunk: Portion of document text
            
        Returns:
            List of extracted entities
        """
        user_prompt = USER_PROMPT_TEMPLATE.format(document_text=text_chunk)
        
        messages = [
            {"role": "system", "content": ENTITY_EXTRACTION_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ]
        
        try:
            # Try with schema first, fall back if needed
            try:
                response = self.client.call(
                    messages=messages,
                    max_tokens=8000,  # Increased to 8000 to handle large entity lists
                    response_format={
                        "type": "json_schema",
                        "json_schema": self.entity_schema
                    }
                )
            except Exception as e:
                logger.warning(f"Chunk extraction with schema failed: {e}, retrying without schema")
                # Add explicit instruction to return valid JSON
                messages_with_json = [
                    {"role": "system", "content": ENTITY_EXTRACTION_SYSTEM_PROMPT + "\n\nIMPORTANT: Return ONLY valid JSON, no markdown."},
                    {"role": "user", "content": user_prompt}
                ]
                response = self.client.call(
                    messages=messages_with_json,
                    max_tokens=8000  # Increased to 8000 to handle large entity lists
                )
            
            content = response.get("content", "")
            
            if not content:
                return []
            
            # Parse JSON response
            try:
                result = json.loads(content)
                if isinstance(result, dict) and "entities" in result:
                    return result["entities"]
                return []
                
            except json.JSONDecodeError:
                # Try to extract JSON from the response
                import re
                json_match = re.search(r'\{.*\}', content, re.DOTALL)
                if json_match:
                    try:
                        result = json.loads(json_match.group(0))
                        if isinstance(result, dict) and "entities" in result:
                            return result["entities"]
                    except:
                        pass
                return []
                
        except Exception as e:
            logger.error(f"Error extracting entities from chunk: {e}")
            return []
    
    def _empty_entities(self) -> Dict[str, Any]:
        """Return empty entities structure."""
        return {
            "entities": [],
            "extraction_status": "not_attempted"
        }
    
    def extract_from_text(self, text: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Standalone method to extract entities from text.
        
        Args:
            text: Document text to analyze
            config: Optional configuration
            
        Returns:
            Extracted entities dictionary
        """
        # Create temporary working memory
        mem = WorkingMemory(document_text=text)
        
        # Run extraction
        self.run(mem, config or {})
        
        return mem.entities