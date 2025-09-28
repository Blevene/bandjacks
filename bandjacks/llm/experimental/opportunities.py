"""Detection opportunity generator for extracted CTI data."""

import uuid
import json
from typing import Dict, Any, List, Optional, Tuple
from bandjacks.llm.client import LLMClient, validate_json_response
from bandjacks.llm.schemas import DETECTION_OPPORTUNITY_SCHEMA


# Prompt for generating detection opportunities
DETECTION_OPPORTUNITY_PROMPT = """You are a senior detection engineer translating cyber threat intelligence into actionable detection opportunities.

Given the extracted CTI data, create evidence-based detection opportunities that security teams can implement.

## Detection Opportunity Requirements

Each opportunity must include:
- **id**: Unique identifier (opp-UUID format)
- **name**: Descriptive name for the detection
- **technique_id**: MITRE ATT&CK technique ID (e.g., T1055)
- **artefacts**: Observable artifacts (process names, file paths, registry keys)
- **behaviours**: Behavioral patterns (process spawning, network connections)
- **rationale**: Why this detection matters
- **source_refs**: Citations to technique IDs or line numbers
- **confidence**: 0.0-1.0 based on evidence quality
- **source**: One-line citation (≤120 chars)
- **evidence**: Direct quotes supporting the opportunity

## Guidelines

1. **Focus on Detectability**: Propose opportunities for realistically detectable artifacts and behaviors
2. **Evidence-Based**: Every opportunity must be supported by specific CTI data
3. **Avoid Implementation Details**: Focus on what to detect, not specific detection rules
4. **Provide Context**: Include both artifacts and behaviors when possible
5. **Rate Confidence**: Based on evidence quality and detection feasibility

## CTI Data

{cti_data}

## Report Excerpt

{report_excerpt}

Generate up to 10 high-quality detection opportunities based on this intelligence.

Output as JSON array matching the detection opportunity schema."""


class OpportunityGenerator:
    """Generate threat detection opportunities from CTI data."""
    
    def __init__(self, model: str = None):
        """
        Initialize the opportunity generator.
        
        Args:
            model: Optional model override
        """
        self.client = LLMClient()
        self.model = model or self.client.model
    
    def generate(
        self,
        cti_data: Dict[str, Any],
        report_excerpt: str,
        evaluate: bool = True,
        debug: bool = False
    ) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Generate detection opportunities from CTI data.
        
        Args:
            cti_data: Extracted CTI claims and entities
            report_excerpt: Text excerpt from original report
            evaluate: Whether to evaluate opportunity quality
            debug: Whether to return debug information
            
        Returns:
            Tuple of (opportunities list, debug_info dict if debug=True)
        """
        try:
            # Build the prompt
            prompt = self._build_prompt(cti_data, report_excerpt)
            
            # Call LLM to generate opportunities
            messages = [
                {"role": "system", "content": "You are a detection engineer creating evidence-based detection opportunities."},
                {"role": "user", "content": prompt}
            ]
            
            response = self.client.call(
                messages=messages,
                tools=None  # No tools needed for opportunity generation
            )
            
            # Parse and validate response
            opportunities = self._parse_response(response["content"])
            
            # Optionally evaluate the opportunities
            if evaluate and opportunities:
                opportunities = self._evaluate_opportunities(opportunities, cti_data)
            
            debug_info = None
            if debug:
                debug_info = {
                    "prompt_length": len(prompt),
                    "response_length": len(response["content"]),
                    "opportunities_count": len(opportunities),
                    "model": self.model
                }
            
            return opportunities, debug_info
            
        except Exception as e:
            print(f"[ERROR] Failed to generate opportunities: {e}")
            if debug:
                return [], {"error": str(e)}
            return [], None
    
    def _build_prompt(self, cti_data: Dict[str, Any], report_excerpt: str) -> str:
        """Build the detection opportunity prompt."""
        # Truncate CTI data for token efficiency
        cti_truncated = self._truncate_cti_data(cti_data)
        
        # Truncate report excerpt
        report_truncated = report_excerpt[:3000] + "..." if len(report_excerpt) > 3000 else report_excerpt
        
        return DETECTION_OPPORTUNITY_PROMPT.format(
            cti_data=json.dumps(cti_truncated, indent=2),
            report_excerpt=report_truncated
        )
    
    def _truncate_cti_data(self, cti_data: Dict[str, Any]) -> Dict[str, Any]:
        """Truncate CTI data to fit token limits."""
        truncated = {}
        
        # Include key claims
        if "claims" in cti_data:
            truncated["claims"] = cti_data["claims"][:20]  # Limit to 20 claims
        
        # Include entities
        if "entities" in cti_data:
            truncated["entities"] = cti_data["entities"]
        
        # Include temporal info
        if "temporal" in cti_data:
            truncated["temporal"] = cti_data["temporal"]
        
        return truncated
    
    def _parse_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse and validate LLM response."""
        try:
            # Try to parse as JSON array
            if response.startswith("["):
                opportunities = json.loads(response)
            else:
                # Try to extract JSON array from response
                import re
                json_match = re.search(r'\[.*\]', response, re.DOTALL)
                if json_match:
                    opportunities = json.loads(json_match.group(0))
                else:
                    # Wrap single object in array
                    opportunities = [json.loads(response)]
            
            # Validate each opportunity
            validated = []
            for i, opp in enumerate(opportunities):
                # Add ID if missing
                if "id" not in opp:
                    opp["id"] = f"opp-{uuid.uuid4().hex[:8]}"
                
                # Ensure required fields
                if "name" not in opp:
                    opp["name"] = f"Detection Opportunity {i+1}"
                if "technique_id" not in opp:
                    opp["technique_id"] = "T0000"  # Unknown
                if "rationale" not in opp:
                    opp["rationale"] = "No rationale provided"
                if "confidence" not in opp:
                    opp["confidence"] = 0.5
                if "source" not in opp:
                    opp["source"] = "CTI extraction"
                
                # Ensure arrays exist
                opp.setdefault("artefacts", [])
                opp.setdefault("behaviours", [])
                opp.setdefault("source_refs", [])
                opp.setdefault("evidence", [])
                
                validated.append(opp)
            
            return validated
            
        except Exception as e:
            print(f"[ERROR] Failed to parse opportunities: {e}")
            return []
    
    def _evaluate_opportunities(
        self,
        opportunities: List[Dict[str, Any]],
        cti_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Evaluate and score detection opportunities.
        
        Args:
            opportunities: List of generated opportunities
            cti_data: Original CTI data for validation
            
        Returns:
            Opportunities with evaluation scores
        """
        for opp in opportunities:
            criteria = {
                "has_technique_id": bool(opp.get("technique_id") and opp["technique_id"] != "T0000"),
                "has_artefacts": bool(opp.get("artefacts")),
                "has_behaviours": bool(opp.get("behaviours")),
                "has_evidence": bool(opp.get("evidence")),
                "realistic_confidence": 0.1 <= opp.get("confidence", 0) <= 1.0,
                "has_rationale": bool(opp.get("rationale") and len(opp["rationale"]) > 10)
            }
            
            # Calculate quality score (0-100)
            score = sum(criteria.values()) / len(criteria) * 100
            
            # Add evaluation info
            opp["evaluation"] = {
                "quality_score": int(score),
                "criteria": criteria
            }
            
            # Adjust confidence based on quality
            if score < 50:
                opp["confidence"] = min(opp.get("confidence", 0.5), 0.5)
        
        # Sort by quality score
        opportunities.sort(key=lambda x: x.get("evaluation", {}).get("quality_score", 0), reverse=True)
        
        return opportunities


def generate_detection_opportunities(
    extraction_result: Dict[str, Any],
    report_text: str = "",
    evaluate: bool = True
) -> List[Dict[str, Any]]:
    """
    Convenience function to generate detection opportunities.
    
    Args:
        extraction_result: Result from LLM extraction
        report_text: Original report text for context
        evaluate: Whether to evaluate opportunity quality
        
    Returns:
        List of detection opportunities
    """
    generator = OpportunityGenerator()
    
    # Prepare CTI data from extraction
    cti_data = {
        "claims": [],
        "entities": {},
        "temporal": {}
    }
    
    # Aggregate claims from all chunks
    if "chunks" in extraction_result:
        for chunk in extraction_result["chunks"]:
            if "claims" in chunk:
                cti_data["claims"].extend(chunk["claims"])
            if "entities" in chunk:
                for key, values in chunk.get("entities", {}).items():
                    if key not in cti_data["entities"]:
                        cti_data["entities"][key] = []
                    cti_data["entities"][key].extend(values)
            if "temporal" in chunk:
                cti_data["temporal"].update(chunk["temporal"])
    
    # Generate opportunities
    opportunities, _ = generator.generate(
        cti_data=cti_data,
        report_excerpt=report_text,
        evaluate=evaluate
    )
    
    return opportunities