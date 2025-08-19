"""Adaptive, context-aware extraction pipeline for threat intelligence."""

import time
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from bandjacks.llm.client import execute_tool_loop, validate_json_response
from bandjacks.llm.tools import get_tool_definitions, get_tool_functions
from bandjacks.llm.prompts_v2 import (
    get_messages_for_chunk_v2,
    SYNTHESIS_PROMPT,
    VALIDATION_PROMPT
)
from bandjacks.loaders.parse_text import extract_text
from bandjacks.loaders.chunker import split_into_chunks


@dataclass
class AttackContext:
    """Maintains context about the attack being analyzed."""
    
    threat_actors: List[str] = field(default_factory=list)
    malware: List[str] = field(default_factory=list) 
    objectives: List[str] = field(default_factory=list)
    techniques_found: Dict[str, Dict] = field(default_factory=dict)
    kill_chain_phases: Dict[str, List] = field(default_factory=dict)
    narrative_summary: str = ""
    unique_aspects: List[str] = field(default_factory=list)
    confidence_adjustments: Dict[str, float] = field(default_factory=dict)
    
    def update_from_claims(self, claims: List[Dict]):
        """Update context based on extracted claims."""
        for claim in claims:
            # Track techniques
            for mapping in claim.get('mappings', []):
                tech_id = mapping.get('external_id')
                if tech_id:
                    if tech_id not in self.techniques_found:
                        self.techniques_found[tech_id] = {
                            'name': mapping.get('name'),
                            'count': 0,
                            'confidence_sum': 0
                        }
                    self.techniques_found[tech_id]['count'] += 1
                    self.techniques_found[tech_id]['confidence_sum'] += mapping.get('confidence', 0)
            
            # Track kill chain phases
            phase = claim.get('kill_chain_phase')
            if phase:
                if phase not in self.kill_chain_phases:
                    self.kill_chain_phases[phase] = []
                self.kill_chain_phases[phase].append(claim.get('technique'))
            
            # Extract entities
            if claim.get('actor') and claim['actor'] not in self.threat_actors:
                self.threat_actors.append(claim['actor'])
            if claim.get('malware') and claim['malware'] not in self.malware:
                self.malware.append(claim['malware'])
    
    def get_summary(self) -> str:
        """Generate a summary of current understanding."""
        parts = []
        
        if self.threat_actors:
            parts.append(f"Actors: {', '.join(self.threat_actors)}")
        if self.malware:
            parts.append(f"Malware: {', '.join(self.malware)}")
        if self.techniques_found:
            top_techniques = sorted(
                self.techniques_found.items(),
                key=lambda x: x[1]['count'],
                reverse=True
            )[:5]
            tech_str = ", ".join([f"{t[0]}" for t in top_techniques])
            parts.append(f"Key techniques: {tech_str}")
        if self.kill_chain_phases:
            parts.append(f"Kill chain phases: {', '.join(self.kill_chain_phases.keys())}")
        
        return " | ".join(parts) if parts else "Initial analysis"
    
    def calculate_confidence_boost(self, technique_id: str) -> float:
        """Calculate confidence adjustment based on context."""
        if technique_id not in self.techniques_found:
            return 0.0
        
        tech_info = self.techniques_found[technique_id]
        
        # Boost confidence if technique appears multiple times
        count_boost = min(tech_info['count'] * 5, 15)
        
        # Boost if average confidence is high
        avg_confidence = tech_info['confidence_sum'] / tech_info['count']
        confidence_boost = 5 if avg_confidence > 80 else 0
        
        return count_boost + confidence_boost


class AdaptiveExtractor:
    """Context-aware extraction using adaptive prompting."""
    
    def __init__(self, model: str = None):
        """Initialize the adaptive extractor."""
        self.model = model or "gpt-4o-mini"
        self.tools = get_tool_definitions()
        self.tool_functions = get_tool_functions()
        self.context = AttackContext()
        self.all_claims = []
    
    def extract_chunk_adaptive(
        self,
        chunk_id: str,
        text: str,
        document_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Extract claims from a chunk with adaptive context.
        
        Args:
            chunk_id: Chunk identifier
            text: Chunk text
            document_context: Optional document-level context
            
        Returns:
            Extraction results with claims and insights
        """
        # Get current attack summary
        attack_summary = self.context.get_summary()
        
        # Generate messages with context
        messages = get_messages_for_chunk_v2(
            chunk_id=chunk_id,
            text=text,
            context=document_context,
            attack_summary=attack_summary
        )
        
        try:
            # Dynamic iterations based on chunk size
            # Base of 8, +1 per 1000 chars, max 20
            chunk_size = len(text)
            dynamic_iterations = min(8 + (chunk_size // 1000), 20)
            
            # Execute with dynamic iterations for exploration
            response = execute_tool_loop(
                messages=messages,
                tools=self.tools,
                tool_functions=self.tool_functions,
                max_iterations=dynamic_iterations
            )
            
            # Parse response (handle flexible schema)
            result = self._parse_adaptive_response(response, chunk_id)
            
            # Update context with findings
            if result.get('claims'):
                self.context.update_from_claims(result['claims'])
                self.all_claims.extend(result['claims'])
            
            # Track unique aspects
            if result.get('insights', {}).get('unique_aspects'):
                self.context.unique_aspects.append(result['insights']['unique_aspects'])
            
            return result
            
        except Exception as e:
            print(f"[ERROR] Chunk {chunk_id}: {e}")
            return {
                "chunk_id": chunk_id,
                "claims": [],
                "error": str(e)
            }
    
    def _parse_adaptive_response(self, response: str, chunk_id: str) -> Dict:
        """Parse flexible response format."""
        try:
            # Try to parse as JSON
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0]
                result = json.loads(json_str)
            else:
                result = json.loads(response)
            
            # Ensure required fields
            if "chunk_id" not in result:
                result["chunk_id"] = chunk_id
            if "claims" not in result:
                result["claims"] = []
            
            # Apply confidence adjustments from context
            for claim in result.get("claims", []):
                for mapping in claim.get("mappings", []):
                    tech_id = mapping.get("external_id")
                    if tech_id:
                        boost = self.context.calculate_confidence_boost(tech_id)
                        original = mapping.get("confidence", 50)
                        mapping["confidence"] = min(original + boost, 100)
                        mapping["confidence_adjusted"] = True
            
            return result
            
        except json.JSONDecodeError:
            # Fallback: extract what we can from text
            return {
                "chunk_id": chunk_id,
                "claims": [],
                "raw_response": response[:500]
            }
    
    def extract_document_adaptive(
        self,
        source_id: str,
        source_type: str,
        content_url: Optional[str] = None,
        inline_text: Optional[str] = None,
        chunking_params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Extract from entire document with adaptive strategy.
        
        Returns complete extraction with narrative synthesis.
        """
        start_time = time.time()
        
        # Extract text
        extracted = extract_text(
            source_type=source_type,
            content_url=content_url,
            inline_text=inline_text
        )
        
        # Smart chunking with larger context windows
        chunk_params = chunking_params or {
            "target_chars": 2000,  # Larger chunks
            "overlap": 300  # More overlap
        }
        
        chunks = split_into_chunks(
            source_id=source_id,
            text=extracted['text'],
            **chunk_params
        )
        
        print(f"[ADAPTIVE] Processing {len(chunks)} chunks...")
        
        # Document context from title/metadata
        doc_context = extracted.get('title', f'{source_type} document')
        
        # Process chunks adaptively
        chunk_results = []
        for i, chunk in enumerate(chunks):
            print(f"  Chunk {i+1}/{len(chunks)}: {len(chunk['text'])} chars")
            
            result = self.extract_chunk_adaptive(
                chunk_id=chunk['id'],
                text=chunk['text'],
                document_context=doc_context
            )
            
            chunk_results.append(result)
            
            # Print progress insights
            if result.get('attack_narrative'):
                print(f"    → {result['attack_narrative'][:100]}...")
            print(f"    → Claims: {len(result.get('claims', []))}")
        
        # Synthesize findings
        synthesis = self._synthesize_attack_narrative()
        
        # Validation pass
        validation = self._validation_pass(extracted['text'])
        
        # Build final result
        elapsed = time.time() - start_time
        
        return {
            "source_id": source_id,
            "source_type": source_type,
            "extraction_mode": "adaptive",
            "chunks_processed": len(chunks),
            "total_claims": len(self.all_claims),
            "claims": self._deduplicate_claims(self.all_claims),
            "context": {
                "threat_actors": self.context.threat_actors,
                "malware": self.context.malware,
                "techniques": list(self.context.techniques_found.keys()),
                "kill_chain": dict(self.context.kill_chain_phases),
                "unique_aspects": self.context.unique_aspects
            },
            "synthesis": synthesis,
            "validation": validation,
            "metrics": {
                "elapsed_seconds": elapsed,
                "chunks": len(chunks),
                "claims_per_chunk": len(self.all_claims) / len(chunks) if chunks else 0
            }
        }
    
    def _synthesize_attack_narrative(self) -> Dict[str, Any]:
        """Synthesize complete attack narrative from all claims."""
        if not self.all_claims:
            return {"narrative": "No claims extracted"}
        
        # Group claims by kill chain phase
        by_phase = defaultdict(list)
        for claim in self.all_claims:
            phase = claim.get('kill_chain_phase', 'unknown')
            by_phase[phase].append(claim)
        
        # Build narrative
        narrative_parts = []
        
        # Order by typical kill chain
        phase_order = [
            'reconnaissance', 'initial-access', 'execution',
            'persistence', 'privilege-escalation', 'defense-evasion',
            'credential-access', 'discovery', 'lateral-movement',
            'collection', 'command-and-control', 'exfiltration', 'impact'
        ]
        
        for phase in phase_order:
            if phase in by_phase:
                narrative_parts.append(f"{phase.title()}: {len(by_phase[phase])} techniques")
        
        return {
            "narrative": " → ".join(narrative_parts),
            "technique_count": len(self.context.techniques_found),
            "confidence_avg": self._calculate_average_confidence(),
            "kill_chain_coverage": list(by_phase.keys())
        }
    
    def _validation_pass(self, full_text: str) -> Dict[str, Any]:
        """Run validation to check for missed techniques."""
        # This would run a validation prompt
        # For now, return a placeholder
        return {
            "validation_run": False,
            "additional_techniques": []
        }
    
    def _deduplicate_claims(self, claims: List[Dict]) -> List[Dict]:
        """Deduplicate and merge similar claims."""
        unique = {}
        
        for claim in claims:
            # Create a key based on technique and actor
            key_parts = []
            if claim.get('technique'):
                key_parts.append(claim['technique'])
            if claim.get('actor'):
                key_parts.append(claim['actor'])
            
            # Use first mapping's external_id if available
            for mapping in claim.get('mappings', []):
                if mapping.get('external_id'):
                    key_parts.append(mapping['external_id'])
                    break
            
            key = "|".join(key_parts) if key_parts else str(len(unique))
            
            if key not in unique:
                unique[key] = claim
            else:
                # Merge evidence
                existing = unique[key]
                existing['evidence'] = list(set(
                    existing.get('evidence', []) + claim.get('evidence', [])
                ))
                
                # Update confidence to max
                for mapping in claim.get('mappings', []):
                    tech_id = mapping.get('external_id')
                    for existing_mapping in existing.get('mappings', []):
                        if existing_mapping.get('external_id') == tech_id:
                            existing_mapping['confidence'] = max(
                                existing_mapping.get('confidence', 0),
                                mapping.get('confidence', 0)
                            )
        
        return list(unique.values())
    
    def _calculate_average_confidence(self) -> float:
        """Calculate average confidence across all techniques."""
        if not self.context.techniques_found:
            return 0.0
        
        total_confidence = 0
        total_count = 0
        
        for tech_info in self.context.techniques_found.values():
            if tech_info['count'] > 0:
                avg = tech_info['confidence_sum'] / tech_info['count']
                total_confidence += avg
                total_count += 1
        
        return total_confidence / total_count if total_count > 0 else 0.0