"""LLM-based attack flow synthesis.

Extracted from FlowBuilder to separate synthesis concerns from persistence and export.
"""

import logging
import json
import re
import uuid
from typing import Dict, Any, List, Optional

from bandjacks.llm.client import get_llm_client

logger = logging.getLogger(__name__)


class FlowSynthesizer:
    """Synthesize attack flows from extraction results using LLM."""

    def __init__(self):
        self.llm_client = get_llm_client()

    def synthesize(
        self,
        extraction_result: Dict[str, Any],
        report_text: str = "",
        max_steps: int = 25,
    ) -> Optional[Dict[str, Any]]:
        """Synthesize attack flow from extraction results.

        This is the main public method — equivalent to the old _synthesize_attack_flow.
        Returns the parsed flow dict or None on failure.
        """
        try:
            # Prepare CTI data from extraction
            logger.debug("Synthesizer input keys: %s", list(extraction_result.keys()))
            if "techniques" in extraction_result:
                techs = extraction_result["techniques"]
                logger.debug("Techniques type: %s, count: %s", type(techs).__name__, len(techs) if hasattr(techs, '__len__') else 'N/A')
                if isinstance(techs, dict) and techs:
                    first_key = next(iter(techs))
                    logger.debug("First technique: key=%s, value_type=%s, value=%s", first_key, type(techs[first_key]).__name__, str(techs[first_key])[:200])
            if "chunks" in extraction_result:
                for ci, chunk in enumerate(extraction_result["chunks"][:2]):
                    logger.debug("Chunk %d keys: %s, claims: %d", ci, list(chunk.keys()), len(chunk.get("claims", [])))
            cti_data = self._prepare_cti_data(extraction_result)

            # Build the prompt
            prompt = self._build_flow_prompt(cti_data, report_text, max_steps)

            # Call LLM to generate flow
            messages = [
                {"role": "system", "content": "You are a CTI analyst creating chronological attack flows."},
                {"role": "user", "content": prompt}
            ]

            response = self.llm_client.call(
                messages=messages,
                tools=None,  # No tools needed for flow generation
                max_tokens=12000  # Increased for complex flows with many techniques
            )

            # Parse and validate response
            logger.debug("Raw LLM response for flow: %s...", response['content'][:500])
            attack_flow = self._parse_llm_response(response["content"])

            if attack_flow:
                logger.debug("Flow parsed successfully, validating...")
                # Validate flow references
                attack_flow = self._validate_flow(attack_flow, cti_data)
                logger.debug("Flow validation complete, returning flow")
            else:
                logger.error("Flow parsing failed, attack_flow is None")

            return attack_flow

        except Exception as e:
            logger.error("Failed to synthesize attack flow: %s", e, exc_info=True)
            return None

    def _prepare_cti_data(self, extraction_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare CTI data structure from extraction results.

        Args:
            extraction_result: Extraction results

        Returns:
            Structured CTI data
        """
        cti_data = {
            "claims": [],
            "entities": {
                "techniques": [],
                "tools": [],
                "malware": [],
                "threat_actors": [],
                "campaigns": []
            },
            "temporal": {}
        }

        # Aggregate data from all chunks
        if "chunks" in extraction_result:
            for chunk in extraction_result["chunks"]:
                if "claims" in chunk:
                    cti_data["claims"].extend(chunk["claims"])
                if "entities" in chunk:
                    for key, values in chunk.get("entities", {}).items():
                        if key in cti_data["entities"]:
                            cti_data["entities"][key].extend(values)
                if "temporal" in chunk:
                    cti_data["temporal"].update(chunk["temporal"])

        # Also check top-level extraction_claims
        if "extraction_claims" in extraction_result:
            cti_data["claims"].extend(extraction_result["extraction_claims"])

        # Add techniques from extraction result
        if "techniques" in extraction_result:
            techniques = extraction_result["techniques"]
            if isinstance(techniques, dict):
                for tech_id, tech_data in techniques.items():
                    if isinstance(tech_data, dict):
                        cti_data["entities"]["techniques"].append({
                            "id": tech_id,
                            "name": tech_data.get("name", tech_id),
                            "confidence": tech_data.get("confidence", 0)
                        })
                    else:
                        # Handle case where tech_data is a string (just the name)
                        cti_data["entities"]["techniques"].append({
                            "id": tech_id,
                            "name": str(tech_data) if tech_data else tech_id,
                            "confidence": 50
                        })

        # Add top-level entities if present (legacy format)
        if "threat_actors" in extraction_result:
            cti_data["entities"]["threat_actors"].extend(extraction_result["threat_actors"])
        if "malware" in extraction_result:
            cti_data["entities"]["malware"].extend(extraction_result["malware"])
        if "tools" in extraction_result:
            cti_data["entities"]["tools"].extend(extraction_result["tools"])
        if "campaigns" in extraction_result:
            cti_data["entities"]["campaigns"].extend(extraction_result["campaigns"])

        # Add structured entities (new format)
        if "entities" in extraction_result and isinstance(extraction_result["entities"], dict):
            structured_entities = extraction_result["entities"]
            if "entities" in structured_entities and isinstance(structured_entities["entities"], list):
                for entity in structured_entities["entities"]:
                    if isinstance(entity, dict):
                        entity_name = entity.get("name", "")
                        entity_type = entity.get("type", "")

                        # Map entity types to CTI data categories
                        if entity_type == "group":
                            cti_data["entities"]["threat_actors"].append(entity_name)
                        elif entity_type == "malware":
                            cti_data["entities"]["malware"].append(entity_name)
                        elif entity_type == "tool":
                            cti_data["entities"]["tools"].append(entity_name)
                        elif entity_type == "campaign":
                            cti_data["entities"]["campaigns"].append(entity_name)
                        # Note: 'target' entities don't have a direct mapping in flow data

        # Remove duplicates from entities
        for key in cti_data["entities"]:
            if key == "techniques":
                # For techniques, deduplicate by ID
                seen = set()
                unique_techniques = []
                for tech in cti_data["entities"]["techniques"]:
                    tech_id = tech.get("id") if isinstance(tech, dict) else tech
                    if tech_id not in seen:
                        seen.add(tech_id)
                        unique_techniques.append(tech)
                cti_data["entities"]["techniques"] = unique_techniques
            else:
                # For other entities, check if all items are strings
                items = cti_data["entities"][key]
                if items:
                    if all(isinstance(item, str) for item in items):
                        # All strings, can use set for deduplication
                        cti_data["entities"][key] = list(set(items))
                    else:
                        # Mixed types or dicts, deduplicate carefully
                        seen = set()
                        unique = []
                        for item in items:
                            item_key = str(item) if not isinstance(item, str) else item
                            if item_key not in seen:
                                seen.add(item_key)
                                unique.append(item)
                        cti_data["entities"][key] = unique

        return cti_data

    def _build_flow_prompt(
        self,
        cti_data: Dict[str, Any],
        report_text: str,
        max_steps: int
    ) -> str:
        """
        Build the attack flow generation prompt.

        Args:
            cti_data: Structured CTI data
            report_text: Report text
            max_steps: Max flow steps

        Returns:
            Formatted prompt
        """
        # Extract entities
        entities = self._extract_entities(cti_data)

        # Extract claims with evidence
        claims = self._extract_claims(cti_data)

        # Extract temporal info
        temporal = cti_data.get("temporal", {})

        # Truncate report text if needed
        report_truncated = report_text[:8000] + "..." if len(report_text) > 8000 else report_text

        prompt = """You are a senior CTI analyst creating a chronological MITRE ATT&CK flow diagram.

Given the extracted CTI data and report text, create an ordered sequence of attack steps.

## Attack Flow Requirements

1. **Select Key Steps**: Choose up to {max_steps} pivotal steps from the CTI entities
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

        return prompt.format(
            max_steps=max_steps,
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
            for key in entities.keys():
                if key in cti_data["entities"]:
                    items = cti_data["entities"][key]
                    if key == "techniques":
                        # Handle techniques as dicts - extract formatted strings
                        seen = set()
                        for tech in items:
                            if isinstance(tech, dict):
                                tech_str = f"{tech.get('id', '')}: {tech.get('name', '')}"
                            else:
                                tech_str = str(tech)
                            if tech_str not in seen:
                                seen.add(tech_str)
                                entities[key].append(tech_str)
                    else:
                        # For other entities, handle both strings and dicts
                        seen = set()
                        for item in items:
                            item_str = str(item) if not isinstance(item, str) else item
                            if item_str not in seen:
                                seen.add(item_str)
                                entities[key].append(item_str)

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

                # Extract tools/malware
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
                    "text": claim.get("span", {}).get("text", "") if isinstance(claim.get("span"), dict) else claim.get("span", ""),
                    "actor": claim.get("actor"),
                    "technique": claim.get("technique"),
                    "evidence": claim.get("evidence", [])[:2]  # Limit evidence
                }
                claims.append(claim_summary)

        return claims

    def _parse_llm_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse and validate LLM response."""
        try:
            # Try direct parse
            try:
                flow = json.loads(response)
                logger.debug("Parsed flow directly: %s with keys: %s", type(flow), flow.keys() if isinstance(flow, dict) else 'not dict')
            except json.JSONDecodeError as e:
                logger.debug("Direct JSON parse failed: %s", e)
                # Extract from code block
                json_match = re.search(r'```(?:json)?\s*\n(.*?)\n```', response, re.DOTALL)
                if json_match:
                    flow = json.loads(json_match.group(1))
                    logger.debug("Extracted flow from code block: %s with keys: %s", type(flow), flow.keys() if isinstance(flow, dict) else 'not dict')
                else:
                    # Try to find JSON object
                    json_match = re.search(r'\{.*\}', response, re.DOTALL)
                    if json_match:
                        flow = json.loads(json_match.group(0))
                        logger.debug("Extracted flow from JSON match: %s with keys: %s", type(flow), flow.keys() if isinstance(flow, dict) else 'not dict')
                    else:
                        logger.error("No JSON found in response: %s...", response[:200])
                        return None

            # Handle direct format (flow_name, steps at top level)
            if "flow_name" in flow and "steps" in flow:
                logger.debug("Detected direct format with flow_name: %s", flow.get('flow_name'))
                # Convert to expected nested format
                flow["flow"] = {
                    "label": "AttackFlow",
                    "pk": f"flow-{uuid.uuid4().hex[:8]}",
                    "properties": {
                        "name": flow.get("flow_name", "Generated Attack Flow"),
                        "description": flow.get("description", "LLM-generated attack sequence")
                    }
                }
            elif "flow" not in flow:
                # Create default flow structure
                logger.debug("No flow structure found, creating default")
                flow["flow"] = {
                    "label": "AttackFlow",
                    "pk": f"flow-{uuid.uuid4().hex[:8]}",
                    "properties": {
                        "name": flow.get("name", "Unknown Attack Flow"),
                        "description": "Extracted attack sequence"
                    }
                }

            # Normalize steps field (handle 'steps', 'attack_steps', or 'attack_flow')
            if "steps" not in flow:
                if "attack_steps" in flow:
                    flow["steps"] = flow["attack_steps"]
                elif "attack_flow" in flow:
                    flow["steps"] = flow["attack_flow"]
                else:
                    flow["steps"] = []

            logger.debug("Flow has %d steps", len(flow.get('steps', [])))

            # Add missing step fields
            for i, step in enumerate(flow["steps"]):
                if "order" not in step:
                    step["order"] = i + 1
                if "entity" not in step:
                    step["entity"] = {"label": "Technique", "id": "unknown"}
                elif isinstance(step["entity"], str):
                    # LLM returned entity as a bare string (e.g. "T1566.001")
                    step["entity"] = {"label": "Technique", "pk": step["entity"]}
                elif isinstance(step["entity"], dict):
                    # Ensure entity has either 'pk' or 'id' field
                    entity = step["entity"]
                    if "pk" not in entity and "id" not in entity:
                        entity["id"] = "unknown"
                if "description" not in step:
                    step["description"] = "Unknown action"
                if "reason" not in step:
                    step["reason"] = "Sequence position"

            logger.debug("Successfully parsed flow with %d steps", len(flow['steps']))
            return flow

        except Exception as e:
            logger.error("Failed to parse attack flow: %s", e, exc_info=True)
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

        # Get techniques from entities
        if "entities" in cti_data and "techniques" in cti_data["entities"]:
            for tech in cti_data["entities"]["techniques"]:
                if isinstance(tech, dict):
                    valid_techniques.add(tech.get("id", ""))
                else:
                    valid_techniques.add(str(tech))

        # Get techniques from claims (both old and new format)
        if "claims" in cti_data:
            for claim in cti_data["claims"]:
                # Old format with mappings
                for mapping in claim.get("mappings", []):
                    if mapping.get("external_id"):
                        valid_techniques.add(mapping["external_id"])
                # New format with direct external_id
                if claim.get("external_id"):
                    valid_techniques.add(claim["external_id"])
                if claim.get("technique_id"):
                    valid_techniques.add(claim["technique_id"])
                if claim.get("tool"):
                    valid_tools.add(claim["tool"])

        # Validate each step
        validated_steps = []
        for step in flow.get("steps", []):
            entity = step.get("entity", {})
            if not isinstance(entity, dict):
                # Normalize non-dict entity to dict
                entity = {"label": "Technique", "pk": str(entity)}
                step["entity"] = entity

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
