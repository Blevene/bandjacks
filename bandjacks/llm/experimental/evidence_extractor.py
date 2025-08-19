"""Evidence-based extraction with line tracking for STIX-compatible output."""

import time
import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from bandjacks.llm.client import execute_tool_loop
from bandjacks.llm.tools import get_tool_definitions, get_tool_functions
from bandjacks.loaders.parse_text import extract_text
from bandjacks.loaders.chunker import split_into_chunks


@dataclass
class EvidenceContext:
    """Tracks evidence and context across extraction."""
    
    techniques_found: Dict[str, Dict] = field(default_factory=dict)
    kill_chain_phases: Dict[str, List] = field(default_factory=dict)
    evidence_map: Dict[str, List[str]] = field(default_factory=dict)
    line_references: Dict[str, List[int]] = field(default_factory=dict)
    confidence_boosts: Dict[str, float] = field(default_factory=dict)
    
    def add_evidence(self, technique_id: str, evidence: str, line_num: Optional[int] = None):
        """Add evidence for a technique."""
        if technique_id not in self.evidence_map:
            self.evidence_map[technique_id] = []
            self.line_references[technique_id] = []
        
        self.evidence_map[technique_id].append(evidence)
        if line_num:
            self.line_references[technique_id].append(line_num)
    
    def get_confidence_boost(self, technique_id: str) -> float:
        """Calculate confidence boost based on evidence and context."""
        boost = 0.0
        
        # Multiple evidence points
        evidence_count = len(self.evidence_map.get(technique_id, []))
        if evidence_count > 1:
            boost += min(evidence_count * 5, 15)
        
        # Has line references
        if self.line_references.get(technique_id):
            boost += 5
        
        # Appears multiple times
        if technique_id in self.techniques_found:
            occurrence_count = self.techniques_found[technique_id].get('count', 0)
            if occurrence_count > 1:
                boost += min(occurrence_count * 5, 15)
        
        return boost


class EvidenceBasedExtractor:
    """Extractor that requires evidence and tracks line references."""
    
    def __init__(self, model: str = None):
        """Initialize the evidence-based extractor."""
        self.model = model or "gpt-4o-mini"
        self.tools = get_tool_definitions()
        self.tool_functions = get_tool_functions()
        self.context = EvidenceContext()
        self.all_claims = []
    
    def extract_with_evidence(
        self,
        source_id: str,
        source_type: str,
        content_url: Optional[str] = None,
        inline_text: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Extract claims with evidence requirements and line tracking.
        
        Returns STIX-compatible extraction with enhanced evidence.
        """
        start_time = time.time()
        
        # Handle text extraction
        if inline_text:
            extracted = {'text': inline_text, 'metadata': {}}
        else:
            extracted = extract_text(
                source_type=source_type,
                content_url=content_url,
                inline_text=None
            )
        
        # Add line numbers to text
        text_with_lines = self._add_line_numbers(extracted['text'])
        
        # Chunk with line tracking
        chunks = split_into_chunks(
            source_id=source_id,
            text=text_with_lines,
            target_chars=5000,
            overlap=500
        )
        
        print(f"[EVIDENCE] Processing {len(chunks)} chunks with line tracking...")
        
        # Process each chunk
        for i, chunk in enumerate(chunks):
            print(f"  Chunk {i+1}/{len(chunks)}: {len(chunk['text'])} chars")
            
            # Extract with evidence requirements
            chunk_claims = self._extract_chunk_with_evidence(
                chunk_id=chunk['id'],
                text=chunk['text']
            )
            
            # Update context with evidence
            for claim in chunk_claims:
                self._update_context_with_claim(claim)
                self.all_claims.append(claim)
            
            print(f"    → {len(chunk_claims)} claims with evidence")
        
        # Apply confidence adjustments based on evidence
        final_claims = self._apply_evidence_confidence(self.all_claims)
        
        # Check kill chain coherence
        missing_phases = self._check_kill_chain_gaps()
        
        elapsed = time.time() - start_time
        
        return {
            "source_id": source_id,
            "source_type": source_type,
            "extraction_mode": "evidence-based",
            "chunks_processed": len(chunks),
            "total_claims": len(final_claims),
            "claims": final_claims,
            "evidence_summary": {
                "techniques_with_evidence": len(self.context.evidence_map),
                "total_evidence_points": sum(len(e) for e in self.context.evidence_map.values()),
                "techniques_with_line_refs": len([t for t in self.context.line_references if self.context.line_references[t]])
            },
            "kill_chain_gaps": missing_phases,
            "metrics": {
                "elapsed_seconds": elapsed,
                "claims_per_chunk": len(final_claims) / len(chunks) if chunks else 0
            }
        }
    
    def _add_line_numbers(self, text: str) -> str:
        """Add line numbers to text for citation purposes."""
        lines = text.split('\n')
        numbered_lines = []
        
        for i, line in enumerate(lines, 1):
            if line.strip():
                numbered_lines.append(f"({i}) {line}")
            else:
                numbered_lines.append("")
        
        return '\n'.join(numbered_lines)
    
    def _extract_line_number(self, text: str) -> Optional[int]:
        """Extract line number from text like '(42) Some content'."""
        import re
        match = re.match(r'^\((\d+)\)', text)
        if match:
            return int(match.group(1))
        return None
    
    def _extract_chunk_with_evidence(self, chunk_id: str, text: str) -> List[Dict]:
        """Extract claims from chunk with evidence requirements."""
        
        messages = self._build_evidence_messages(chunk_id, text)
        
        try:
            response = execute_tool_loop(
                messages=messages,
                tools=self.tools,
                tool_functions=self.tool_functions,
                max_iterations=10
            )
            
            # Parse response
            claims = self._parse_evidence_response(response, text)
            return claims
            
        except Exception as e:
            print(f"[ERROR] Chunk {chunk_id}: {e}")
            return []
    
    def _build_evidence_messages(self, chunk_id: str, text: str) -> List[Dict]:
        """Build messages that require evidence extraction."""
        
        system_prompt = """You are a CTI analyst extracting threat techniques with evidence.

## Requirements
1. For EVERY technique you identify, provide:
   - Direct quote from the text as evidence
   - Line number where evidence appears
   - Clear reasoning why this maps to the technique
   - Confidence score based on evidence strength

2. Evidence Quality:
   - Direct mention of technique: 90-100% confidence
   - Clear behavioral match: 70-89% confidence
   - Implied by context: 50-69% confidence
   - Weak inference: 30-49% confidence

3. Line Citations:
   - Text has line numbers like "(42) content"
   - Always include the line number in your evidence

## Discovery Questions
Consider these aspects when analyzing:
- How does the attack initially reach targets? (delivery mechanism)
- What executes and how? (all forms of execution)
- How does the threat maintain presence? (survival mechanisms)
- What data is accessed and transmitted? (collection and movement)
- How does the threat avoid detection? (evasion techniques)

Search for techniques based on WHAT behaviors achieve, not specific keywords."""
        
        user_prompt = f"""Analyze this text and extract techniques with evidence.

Chunk ID: {chunk_id}

{text}

For each technique found:
1. Search for matching ATT&CK techniques
2. Extract direct evidence quotes with line numbers
3. Explain your reasoning
4. Assess confidence based on evidence quality

Output as JSON with this structure:
{{
  "chunk_id": "{chunk_id}",
  "claims": [
    {{
      "type": "uses-technique",
      "technique": "technique name",
      "evidence": ["quote with (line X)", "another quote (line Y)"],
      "source_lines": [X, Y],
      "reasoning": "why this maps to the technique",
      "mappings": [
        {{
          "stix_id": "attack-pattern--xxx",
          "external_id": "T1234",
          "name": "Technique Name",
          "confidence": 85
        }}
      ]
    }}
  ]
}}"""
        
        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]
    
    def _parse_evidence_response(self, response: str, chunk_text: str) -> List[Dict]:
        """Parse response and validate evidence."""
        try:
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
                data = json.loads(json_str)
            else:
                data = json.loads(response)
            
            claims = data.get("claims", [])
            
            # Validate and enhance each claim
            for claim in claims:
                # Extract line numbers from evidence if not provided
                if not claim.get("source_lines") and claim.get("evidence"):
                    lines = []
                    for evidence in claim["evidence"]:
                        # Look for (line X) pattern
                        import re
                        line_match = re.search(r'\(line (\d+)\)', evidence)
                        if line_match:
                            lines.append(int(line_match.group(1)))
                    if lines:
                        claim["source_lines"] = lines
                
                # Ensure STIX compatibility
                if not claim.get("type"):
                    claim["type"] = "uses-technique"
            
            return claims
            
        except json.JSONDecodeError as e:
            print(f"[WARNING] Could not parse JSON response: {e}")
            return []
    
    def _update_context_with_claim(self, claim: Dict):
        """Update context with evidence from claim."""
        for mapping in claim.get("mappings", []):
            tech_id = mapping.get("external_id")
            if tech_id:
                # Track technique
                if tech_id not in self.context.techniques_found:
                    self.context.techniques_found[tech_id] = {
                        "name": mapping.get("name"),
                        "count": 0
                    }
                self.context.techniques_found[tech_id]["count"] += 1
                
                # Track evidence
                for evidence in claim.get("evidence", []):
                    self.context.add_evidence(tech_id, evidence)
                
                # Track line references
                for line_num in claim.get("source_lines", []):
                    if line_num not in self.context.line_references.get(tech_id, []):
                        self.context.line_references.setdefault(tech_id, []).append(line_num)
    
    def _apply_evidence_confidence(self, claims: List[Dict]) -> List[Dict]:
        """Apply confidence adjustments based on evidence."""
        enhanced_claims = []
        
        for claim in claims:
            # Apply confidence boost based on evidence
            for mapping in claim.get("mappings", []):
                tech_id = mapping.get("external_id")
                if tech_id:
                    boost = self.context.get_confidence_boost(tech_id)
                    original = mapping.get("confidence", 50)
                    mapping["confidence"] = min(original + boost, 100)
                    mapping["confidence_factors"] = {
                        "base": original,
                        "evidence_boost": boost,
                        "evidence_count": len(self.context.evidence_map.get(tech_id, [])),
                        "has_line_refs": bool(self.context.line_references.get(tech_id))
                    }
            
            enhanced_claims.append(claim)
        
        return enhanced_claims
    
    def _check_kill_chain_gaps(self) -> List[str]:
        """Check for logical gaps in kill chain coverage."""
        # Map techniques to kill chain phases (simplified)
        phase_mapping = {
            "T1566": "initial-access",
            "T1059": "execution",
            "T1547": "persistence",
            "T1055": "defense-evasion",
            "T1555": "credential-access",
            "T1083": "discovery",
            "T1005": "collection",
            "T1071": "command-and-control",
            "T1041": "exfiltration"
        }
        
        covered_phases = set()
        for tech_id in self.context.techniques_found:
            base_technique = tech_id.split('.')[0]
            if base_technique in phase_mapping:
                covered_phases.add(phase_mapping[base_technique])
        
        # Check for logical gaps
        gaps = []
        
        if len(covered_phases) > 2:  # If we have multiple phases
            if "initial-access" not in covered_phases:
                gaps.append("initial-access - How did the attack begin?")
            
            if "execution" in covered_phases and "persistence" not in covered_phases:
                gaps.append("persistence - How does malware maintain presence?")
            
            if "collection" in covered_phases and "exfiltration" not in covered_phases:
                gaps.append("exfiltration - How is collected data transmitted?")
            
            if "command-and-control" not in covered_phases and len(covered_phases) > 3:
                gaps.append("command-and-control - How does malware communicate?")
        
        return gaps