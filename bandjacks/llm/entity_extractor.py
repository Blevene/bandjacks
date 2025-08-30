"""Entity extraction using LLM with structured prompts."""

import json
import logging
from typing import Dict, Any, List, Optional
from bandjacks.llm.client import LLMClient
from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.json_utils import parse_json_with_fallback

logger = logging.getLogger(__name__)


ENTITY_EXTRACTION_SYSTEM_PROMPT = """
You are a cyber threat intelligence analyst. Extract entity names from the text.

Entity types:
- malware: Malicious software (trojans, ransomware, stealers, etc.)
- tool: Legitimate tools used in attacks (PowerShell, Mimikatz, etc.)  
- actor: Threat actors or groups (APT28, Lazarus, etc.)
- campaign: Named operations (SolarWinds, NotPetya, etc.)

OUTPUT ONLY THIS JSON FORMAT:
{
  "entities": [
    {"name": "entity name", "type": "malware|tool|actor|campaign"}
  ]
}

Guidelines:
- Extract ALL entity names you find
- The document title often contains the main threat
- Just output names and types, nothing else
- Keep the JSON structure simple and flat

Output ONLY valid JSON, no additional text.
"""


USER_PROMPT_TEMPLATE = """
You are an expert CTI information extractor.

TASK: From the given cyber threat report text, extract entities of types:
- malware, tool, intrusion-set (threat actor), campaign
- plus the primary threat from title/filename as type "title-primary"

Follow these rules:
- Extract only explicitly referenced threats/actors/campaigns/tools.
- Avoid generic platforms/vendors unless clearly used offensively.
- Canonicalize to normalized_name; merge duplicates and collect aliases.
- Provide evidence_snippet and exact character offsets for each source occurrence.
- Include confidence (0.0–1.0) with a brief rationale in notes (optional).

TITLE/FILENAME HANDLING:
- Derive a single "title-primary" if possible from the title/filename.
- Strip dates/version markers and generic words (report, analysis, blog).
- If multiple candidates, choose the most specific named threat/campaign.

ALIASES:
- Capture aka/also-known-as/tracked-as/formerly/MITRE/GPT/UNC/DEV/TAG labels as aliases.

DISAMBIGUATION:
- Prefer canonical family/group names; keep stylized casing in `name`.
- If ambiguous, include with lower confidence and note the reason.

If no entities are found, return [].

TEXT:
{document_text}

Return only the JSON array.
"""


class EntityExtractionAgent:
    """Extract cyber threat entities using LLM with structured prompts."""
    
    def __init__(self):
        """Initialize the entity extraction agent."""
        self.client = LLMClient()
    
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        """
        Extract entities from document text using LLM.
        
        Args:
            mem: Working memory containing document text
            config: Configuration options
        """
        logger.info("Starting entity extraction with LLM")
        
        # Use first 3000 chars for entity extraction to reduce token usage
        doc_text = mem.document_text[:3000] if len(mem.document_text) > 3000 else mem.document_text
        
        user_prompt = USER_PROMPT_TEMPLATE.format(document_text=doc_text)
        
        messages = [
            {"role": "system", "content": ENTITY_EXTRACTION_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ]
        
        try:
            # Log request details
            logger.info(f"Entity extraction LLM request: {len(doc_text)} chars")
            logger.debug(f"Entity extraction prompt preview: {user_prompt[:200]}...")
            
            # Call LLM - temporarily without response_format to debug
            response = self.client.call(
                messages=messages,
                # response_format={"type": "json_object"},  # TEMPORARILY DISABLED FOR DEBUGGING
                max_tokens=2000  # Reduced - simple list doesn't need many tokens
            )
            
            content = response.get("content", "")
            
            # Log response details
            logger.info(f"Entity extraction LLM response: {len(content)} chars")
            logger.debug(f"Entity extraction raw response: {content[:500]}...")
            
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
                    raise ValueError(f"Invalid structure: expected dict with 'entities' key, got {type(entities)}")
                
                if not isinstance(entities["entities"], list):
                    raise ValueError(f"Invalid entities field: expected list, got {type(entities['entities'])}")
                
                # Log success
                entity_count = len(entities.get("entities", []))
                logger.info(f"Successfully extracted {entity_count} entities")
                
                # Add extraction status
                entities["extraction_status"] = "success"
                
            except json.JSONDecodeError as e:
                error_msg = f"JSON parse error in entity extraction: {e}"
                logger.error(error_msg)
                logger.debug(f"Failed to parse: {content}")
                
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
            
            # Store in working memory
            mem.entities = entities
            
            # Extract entity names for backward compatibility
            entity_names_by_type = {"malware": [], "tool": [], "actor": [], "campaign": []}
            
            for entity in entities.get("entities", []):
                if isinstance(entity, dict):
                    name = entity.get("name", "")
                    entity_type = entity.get("type", "")
                    
                    if name and entity_type:
                        if entity_type == "malware":
                            entity_names_by_type["malware"].append(name)
                        elif entity_type == "tool":
                            entity_names_by_type["tool"].append(name)
                        elif entity_type == "actor":
                            entity_names_by_type["actor"].append(name)
                        elif entity_type == "campaign":
                            entity_names_by_type["campaign"].append(name)
            
            # Set backward compatibility attributes
            mem.malware = entity_names_by_type["malware"]
            mem.software = entity_names_by_type["tool"]  # Map tool -> software
            mem.threat_actors = entity_names_by_type["actor"]
            mem.campaigns = entity_names_by_type["campaign"]
            
            # Log entity breakdown
            logger.info(f"Entity breakdown: {len(mem.malware)} malware, {len(mem.software)} tools, "
                       f"{len(mem.threat_actors)} actors, {len(mem.campaigns)} campaigns")
                
        except Exception as e:
            error_msg = f"Entity extraction failed with exception: {e}"
            logger.error(error_msg, exc_info=True)
            
            # Set failure state
            mem.entities = {"entities": [], "extraction_status": "failed", "error": str(e)}
            
            # Track error for reporting
            mem.extraction_errors = getattr(mem, 'extraction_errors', [])
            mem.extraction_errors.append({"stage": "entity_extraction", "error": str(e)})
            
            # Set empty lists for compatibility
            mem.malware = []
            mem.software = []
            mem.threat_actors = []
            mem.campaigns = []
    
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