"""JSON utility functions for robust LLM response handling."""

import json
import re
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def cleanup_json(json_str: str) -> str:
    """
    Clean up common JSON formatting errors from LLM responses.
    
    Handles:
    - Extra quotes after closing braces/brackets
    - Trailing commas
    - Missing commas between objects
    - Truncated JSON (attempts to close)
    """
    if not json_str:
        return "{}"
    
    # Remove extra quotes after closing braces/brackets
    json_str = re.sub(r'\}"\s*,', '},', json_str)
    json_str = re.sub(r'\]"\s*,', '],', json_str)
    json_str = re.sub(r'\}"\s*\]', '}]', json_str)
    json_str = re.sub(r'\}"\s*\}', '}}', json_str)
    
    # Remove trailing commas before closing braces/brackets
    json_str = re.sub(r',\s*\}', '}', json_str)
    json_str = re.sub(r',\s*\]', ']', json_str)
    
    # Fix missing commas between objects
    json_str = re.sub(r'\}\s*\{', '},{', json_str)
    json_str = re.sub(r'\]\s*\[', '],[', json_str)
    
    # Handle truncated JSON - count brackets and try to close
    open_braces = json_str.count('{') - json_str.count('}')
    open_brackets = json_str.count('[') - json_str.count(']')
    
    # Add missing closing characters
    if open_brackets > 0:
        json_str += ']' * open_brackets
    if open_braces > 0:
        json_str += '}' * open_braces
    
    # Handle incomplete strings (add closing quote if needed)
    # This is more complex but helps with truncated responses
    in_string = False
    escape_next = False
    for i, char in enumerate(json_str):
        if escape_next:
            escape_next = False
            continue
        if char == '\\':
            escape_next = True
            continue
        if char == '"':
            in_string = not in_string
    
    if in_string:
        json_str += '"'
    
    return json_str


def parse_json_with_fallback(
    content: str,
    expected_structure: Optional[Dict[str, Any]] = None,
    max_retries: int = 3
) -> Dict[str, Any]:
    """
    Parse JSON with multiple fallback strategies.
    
    Args:
        content: Raw JSON string from LLM
        expected_structure: Optional dict showing expected structure with default values
        max_retries: Number of cleanup attempts
        
    Returns:
        Parsed JSON dict or expected_structure defaults
    """
    if not content:
        return expected_structure or {}
    
    # First attempt: direct parse
    try:
        result = json.loads(content)
        if expected_structure is None or isinstance(expected_structure, dict):
            if isinstance(result, dict):
                return result
        elif isinstance(expected_structure, list):
            if isinstance(result, list):
                return result
        else:
            logger.warning(f"Parsed JSON type mismatch: got {type(result)}, expected {type(expected_structure)}")
            return expected_structure or {}
    except json.JSONDecodeError as e:
        logger.debug(f"Initial JSON parse failed: {e}")
        logger.debug(f"Content preview: {content[:100] if content else 'Empty'}")
    
    # Second attempt: cleanup and parse
    for attempt in range(max_retries):
        try:
            cleaned = cleanup_json(content)
            result = json.loads(cleaned)
            # Check type matches expected structure
            if expected_structure is None:
                logger.info(f"Successfully parsed JSON after {attempt + 1} cleanup attempts")
                return result
            elif isinstance(expected_structure, dict) and isinstance(result, dict):
                logger.info(f"Successfully parsed JSON dict after {attempt + 1} cleanup attempts")
                return result
            elif isinstance(expected_structure, list) and isinstance(result, list):
                logger.info(f"Successfully parsed JSON list after {attempt + 1} cleanup attempts")
                return result
            else:
                logger.debug(f"Type mismatch after cleanup: got {type(result)}, expected {type(expected_structure)}")
        except json.JSONDecodeError as e:
            logger.debug(f"Cleanup attempt {attempt + 1} failed: {e}")
            # Try progressively more aggressive cleanup
            if attempt == 0:
                # Remove any markdown formatting
                content = re.sub(r'^```json\s*', '', content)
                content = re.sub(r'\s*```$', '', content)
            elif attempt == 1:
                # Try to extract just the JSON part
                match = re.search(r'\{.*\}', content, re.DOTALL)
                if match:
                    content = match.group(0)
    
    # Final fallback: return expected structure
    logger.error(f"Failed to parse JSON after all attempts, using default structure")
    return expected_structure or {}


def validate_and_ensure_claims(mem: Any, agent_name: str = "Unknown") -> None:
    """
    Validate that claims exist when techniques are found.
    Creates minimal claims if missing to preserve evidence trail.
    
    Args:
        mem: WorkingMemory object
        agent_name: Name of calling agent for logging
    """
    if not hasattr(mem, 'claims'):
        mem.claims = []
    
    if not hasattr(mem, 'techniques'):
        mem.techniques = {}
    
    # If we have techniques but no claims, this is a critical error
    if mem.techniques and not mem.claims:
        logger.error(f"{agent_name}: Found {len(mem.techniques)} techniques but no claims! Creating minimal claims...")
        
        # Create minimal claims from techniques to preserve evidence trail
        for tech_id, tech_info in mem.techniques.items():
            claim = {
                "external_id": tech_id,
                "name": tech_info.get("name", ""),
                "confidence": tech_info.get("confidence", 50),
                "quotes": tech_info.get("evidence", {}).get("quotes", ["[Evidence lost due to processing error]"]),
                "line_refs": tech_info.get("evidence", {}).get("line_refs", []),
                "source": f"{agent_name}_recovery"
            }
            mem.claims.append(claim)
        
        logger.warning(f"Created {len(mem.claims)} recovery claims to preserve evidence trail")
    
    # Log the state for monitoring
    logger.info(f"{agent_name}: Claims={len(mem.claims)}, Techniques={len(mem.techniques)}")