"""Attack flow synthesizer for extracted CTI data."""

import uuid
import json
from typing import Dict, Any, List, Optional, Tuple
from bandjacks.llm.client import LLMClient
from bandjacks.llm.schemas import ATTACK_FLOW_SCHEMA


# Prompt for generating attack flows
ATTACK_FLOW_PROMPT = """You are a senior CTI analyst creating a chronological MITRE ATT&CK flow diagram.

Given the extracted CTI data and report text, create an ordered sequence of attack steps.

## Attack Flow Requirements

1. **Select Key Steps**: Choose up to 25 pivotal steps from the CTI entities
2. **Determine Order**: Use temporal phrases, causal relationships, and narrative flow
3. **Reference Entities**: Every step must reference an existing technique, tool, or malware
4. **Provide Evidence**: Each step needs a description and reason citing evidence
5. **Handle Uncertainty**: If order is unclear, note uncertainty in reasoning

## Step Schema

Each step must include:
- **order**: Integer starting at 1 (use gaps for parallel actions)
- **entity**: Reference to technique/tool/malware with label and ID
- **description**: What action was performed (≤120 chars)
- **reason**: Why this step is positioned here (≤60 chars)

## CTI Data

Entities extracted:
{entities}

Claims with evidence:
{claims}

Temporal information:
{temporal}

## Report Text

{report_text}

Create a logical attack flow showing the sequence of techniques, tools, and infrastructure used.

IMPORTANT:
- Every step MUST reference real entities from the CTI data
- Steps must be supported by evidence from claims or report text
- Include the primary threat actor in the flow name
- If confidence is low, mention uncertainty in notes

Output as JSON matching the attack flow schema."""


class AttackFlowSynthesizer:
    """Synthesize attack flows from CTI data."""
    
    def __init__(self, model: str = None):
        """
        Initialize the flow synthesizer.
        
        Args:
            model: Optional model override
        """
        self.client = LLMClient()
        self.model = model or self.client.model
    
    def synthesize(
        self,
        cti_data: Dict[str, Any],
        report_text: str,
        max_steps: int = 25,
        debug: bool = False
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """
        Synthesize an attack flow from CTI data.
        
        Args:
            cti_data: Extracted CTI claims and entities
            report_text: Original report text for context
            max_steps: Maximum number of flow steps
            debug: Whether to return debug information
            
        Returns:
            Tuple of (attack_flow dict, debug_info dict if debug=True)
        """
        try:
            # Build the prompt
            prompt = self._build_prompt(cti_data, report_text, max_steps)
            
            # Call LLM to generate flow
            messages = [
                {"role": "system", "content": "You are a CTI analyst creating chronological attack flows."},
                {"role": "user", "content": prompt}
            ]
            
            response = self.client.call(
                messages=messages,
                tools=None  # No tools needed for flow generation
            )
            
            # Parse and validate response
            attack_flow = self._parse_response(response["content"])
            
            # Validate flow references
            if attack_flow:
                attack_flow = self._validate_flow(attack_flow, cti_data)
            
            debug_info = None
            if debug:
                debug_info = {
                    "prompt_length": len(prompt),
                    "response_length": len(response["content"]),
                    "steps_count": len(attack_flow.get("steps", [])) if attack_flow else 0,
                    "model": self.model
                }
            
            return attack_flow, debug_info
            
        except Exception as e:
            print(f"[ERROR] Failed to synthesize attack flow: {e}")
            if debug:
                return None, {"error": str(e)}
            return None, None
    
    def _build_prompt(
        self,
        cti_data: Dict[str, Any],
        report_text: str,
        max_steps: int
    ) -> str:
        """Build the attack flow prompt."""
        # Extract entities
        entities = self._extract_entities(cti_data)
        
        # Extract claims with evidence
        claims = self._extract_claims(cti_data)
        
        # Extract temporal info
        temporal = cti_data.get("temporal", {})
        
        # Truncate report text
        report_truncated = report_text[:8000] + "..." if len(report_text) > 8000 else report_text
        
        return ATTACK_FLOW_PROMPT.format(
            entities=json.dumps(entities, indent=2),
            claims=json.dumps(claims, indent=2),
            temporal=json.dumps(temporal, indent=2),
            report_text=report_truncated
        )
    
    def _extract_entities(self, cti_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract unique entities from CTI data."""
        entities = {
            "techniques": [],
            "tools": [],
            "malware": [],
            "threat_actors": [],
            "campaigns": []
        }
        
        # From entities section
        if "entities" in cti_data:
            for key in ["threat_actors", "tools", "malware", "campaigns"]:
                if key in cti_data["entities"]:
                    entities[key] = list(set(cti_data["entities"][key]))
        
        # From claims
        if "claims" in cti_data:
            for claim in cti_data["claims"]:
                # Extract techniques from mappings
                for mapping in claim.get("mappings", []):
                    if mapping.get("external_id"):
                        tech_info = f"{mapping['external_id']}: {mapping.get('name', '')}"
                        if tech_info not in entities["techniques"]:
                            entities["techniques"].append(tech_info)
                
                # Extract actors
                if claim.get("actor") and claim["actor"] not in entities["threat_actors"]:
                    entities["threat_actors"].append(claim["actor"])
                
                # Extract tools
                if claim.get("tool"):
                    tool = claim["tool"]
                    if tool not in entities["tools"] and tool not in entities["malware"]:
                        # Determine if malware or tool based on context
                        if any(mal_ind in tool.lower() for mal_ind in ["trojan", "backdoor", "ransomware", "rat"]):
                            entities["malware"].append(tool)
                        else:
                            entities["tools"].append(tool)
        
        return entities
    
    def _extract_claims(self, cti_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract key claims with evidence."""
        claims = []
        
        if "claims" in cti_data:
            for claim in cti_data["claims"][:30]:  # Limit to 30 claims
                claim_summary = {
                    "type": claim.get("type"),
                    "text": claim.get("span", {}).get("text", ""),
                    "actor": claim.get("actor"),
                    "technique": claim.get("technique"),
                    "evidence": claim.get("evidence", [])[:2]  # Limit evidence
                }
                claims.append(claim_summary)
        
        return claims
    
    def _parse_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse and validate LLM response."""
        try:
            # Parse JSON
            import re
            
            # Try direct parse
            try:
                flow = json.loads(response)
            except json.JSONDecodeError:
                # Extract from code block
                json_match = re.search(r'```(?:json)?\s*\n(.*?)\n```', response, re.DOTALL)
                if json_match:
                    flow = json.loads(json_match.group(1))
                else:
                    # Try to find JSON object
                    json_match = re.search(r'\{.*\}', response, re.DOTALL)
                    if json_match:
                        flow = json.loads(json_match.group(0))
                    else:
                        return None
            
            # Ensure required fields
            if "flow" not in flow:
                flow["flow"] = {
                    "label": "AttackFlow",
                    "pk": f"flow-{uuid.uuid4().hex[:8]}",
                    "properties": {
                        "name": "Unknown Attack Flow",
                        "description": "Extracted attack sequence"
                    }
                }
            
            if "steps" not in flow:
                flow["steps"] = []
            
            # Add missing step fields
            for i, step in enumerate(flow["steps"]):
                if "order" not in step:
                    step["order"] = i + 1
                if "entity" not in step:
                    step["entity"] = {"label": "Technique", "pk": "unknown"}
                if "description" not in step:
                    step["description"] = "Unknown action"
                if "reason" not in step:
                    step["reason"] = "Sequence position"
            
            return flow
            
        except Exception as e:
            print(f"[ERROR] Failed to parse attack flow: {e}")
            return None
    
    def _validate_flow(
        self,
        flow: Dict[str, Any],
        cti_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate flow references against CTI data.
        
        Args:
            flow: Generated attack flow
            cti_data: Original CTI data for validation
            
        Returns:
            Validated attack flow
        """
        # Extract valid entity IDs from CTI data
        valid_techniques = set()
        valid_tools = set()
        
        if "claims" in cti_data:
            for claim in cti_data["claims"]:
                for mapping in claim.get("mappings", []):
                    if mapping.get("external_id"):
                        valid_techniques.add(mapping["external_id"])
                if claim.get("tool"):
                    valid_tools.add(claim["tool"])
        
        # Validate each step
        validated_steps = []
        for step in flow.get("steps", []):
            entity = step.get("entity", {})
            
            # Check if entity is valid
            if entity.get("label") == "Technique":
                # Try to match technique ID
                pk = entity.get("pk", "")
                if pk.startswith("T") and any(pk in tech for tech in valid_techniques):
                    validated_steps.append(step)
                elif len(validated_steps) < 5:  # Keep some steps even if not perfect match
                    validated_steps.append(step)
            elif entity.get("label") in ["Tool", "Malware"]:
                # Check if tool/malware is mentioned
                pk = entity.get("pk", "")
                if pk in valid_tools or len(validated_steps) < 5:
                    validated_steps.append(step)
            else:
                # Keep infrastructure and other types
                validated_steps.append(step)
        
        flow["steps"] = validated_steps
        
        # Add validation note
        if "notes" not in flow:
            flow["notes"] = ""
        flow["notes"] += f" Validated {len(validated_steps)} steps against CTI data."
        
        return flow


def synthesize_attack_flow(
    extraction_result: Dict[str, Any],
    report_text: str = "",
    max_steps: int = 25
) -> Optional[Dict[str, Any]]:
    """
    Convenience function to synthesize attack flow.
    
    Args:
        extraction_result: Result from LLM extraction
        report_text: Original report text for context
        max_steps: Maximum number of flow steps
        
    Returns:
        Attack flow dictionary or None if synthesis fails
    """
    synthesizer = AttackFlowSynthesizer()
    
    # Prepare CTI data from extraction
    cti_data = {
        "claims": [],
        "entities": {},
        "temporal": {}
    }
    
    # Aggregate data from all chunks
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
    
    # Remove duplicates from entities
    for key in cti_data["entities"]:
        cti_data["entities"][key] = list(set(cti_data["entities"][key]))
    
    # Synthesize flow
    attack_flow, _ = synthesizer.synthesize(
        cti_data=cti_data,
        report_text=report_text,
        max_steps=max_steps
    )
    
    return attack_flow