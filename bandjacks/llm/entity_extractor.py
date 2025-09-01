"""Entity extraction using LLM with structured prompts."""

import json
import logging
import re
from typing import Dict, Any, List, Optional
from bandjacks.llm.client import LLMClient
from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.json_utils import parse_json_with_fallback

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
    {"name": "APT29", "type": "group"},
    {"name": "Cozy Bear", "type": "group"},
    {"name": "SUNBURST", "type": "malware"},
    {"name": "PowerShell", "type": "tool"},
    {"name": "SolarWinds", "type": "target"}
  ]
}
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

Extract EVERY named entity. Be aggressive and comprehensive - include everything that could be an entity."""


class EntityExtractionAgent:
    """Extract cyber threat entities using LLM with structured prompts."""
    
    def __init__(self):
        """Initialize the entity extraction agent."""
        self.client = LLMClient()
        self.chunk_size = 4000  # Size of each chunk for processing
        self.chunk_overlap = 500  # Overlap between chunks to avoid missing entities at boundaries
    
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
                
                # Call LLM
                response = self.client.call(
                    messages=messages,
                    max_tokens=2000
                )
                
                content = response.get("content", "")
                
                if not content:
                    error_msg = "Empty response from LLM for entity extraction"
                    logger.error(error_msg)
                    mem.entities = {"entities": [], "extraction_status": "failed", "error": error_msg}
                    mem.extraction_errors = getattr(mem, 'extraction_errors', [])
                    mem.extraction_errors.append({"stage": "entity_extraction", "error": error_msg})
                    return
                
                # Parse JSON response
                try:
                    entities = json.loads(content)
                    
                    # Validate structure
                    if not isinstance(entities, dict) or "entities" not in entities:
                        raise ValueError(f"Invalid structure: expected dict with 'entities' key")
                    
                    if not isinstance(entities["entities"], list):
                        raise ValueError(f"Invalid entities field: expected list")
                    
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
    
    def _merge_entities(self, entity_lists: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Merge and deduplicate entities from multiple chunks.
        
        Args:
            entity_lists: List of entity lists from different chunks
            
        Returns:
            Merged and deduplicated entity list
        """
        # Collect all entities
        all_entities = []
        for entities in entity_lists:
            all_entities.extend(entities)
        
        # Deduplicate by (normalized_name, type) tuple
        seen = set()
        unique_entities = []
        
        for entity in all_entities:
            if isinstance(entity, dict):
                name = entity.get("name", "")
                entity_type = entity.get("type", "")
                
                # Normalize name for deduplication (lowercase, strip spaces)
                normalized = (name.lower().strip(), entity_type)
                
                if normalized not in seen and name:
                    seen.add(normalized)
                    unique_entities.append(entity)
        
        return unique_entities
    
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
            response = self.client.call(
                messages=messages,
                max_tokens=2000
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