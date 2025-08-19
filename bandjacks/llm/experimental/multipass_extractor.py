"""Multi-pass extraction with progressive refinement and gap analysis."""

import time
import json
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

from bandjacks.llm.adaptive_extractor import AdaptiveExtractor, AttackContext
from bandjacks.llm.client import execute_tool_loop
from bandjacks.llm.tools import get_tool_definitions, get_tool_functions
from bandjacks.llm.prompts_v3 import get_messages_for_multipass
from bandjacks.loaders.parse_text import extract_text
from bandjacks.loaders.chunker import split_into_chunks


@dataclass
class ExtractionPass:
    """Configuration for a single extraction pass."""
    
    name: str
    confidence_threshold: int
    focus: str  # What to focus on in this pass
    max_iterations: int
    chunk_size: int
    overlap: int


@dataclass 
class KillChainAnalysis:
    """Analysis of kill chain coverage and gaps."""
    
    covered_phases: Set[str] = field(default_factory=set)
    missing_phases: Set[str] = field(default_factory=set)
    expected_techniques: Dict[str, List[str]] = field(default_factory=dict)
    
    KILL_CHAIN_ORDER = [
        "reconnaissance", "resource-development", "initial-access",
        "execution", "persistence", "privilege-escalation", 
        "defense-evasion", "credential-access", "discovery",
        "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact"
    ]
    
    def analyze_gaps(self, techniques_found: Dict[str, Any]) -> Dict[str, List[str]]:
        """Identify gaps in kill chain and suggest what to look for."""
        gaps = {}
        
        # Determine covered phases
        for tech_info in techniques_found.values():
            if 'kill_chain_phase' in tech_info:
                self.covered_phases.add(tech_info['kill_chain_phase'])
        
        # Identify logical gaps
        if "initial-access" in self.covered_phases and "execution" not in self.covered_phases:
            gaps["execution"] = ["Look for how the initial payload executes"]
            
        if "execution" in self.covered_phases and "persistence" not in self.covered_phases:
            gaps["persistence"] = ["Look for how malware maintains presence"]
            
        if "collection" in self.covered_phases and "exfiltration" not in self.covered_phases:
            gaps["exfiltration"] = ["Look for how collected data leaves the system"]
            
        if "command-and-control" not in self.covered_phases and len(self.covered_phases) > 2:
            gaps["command-and-control"] = ["Look for communication with external servers"]
            
        return gaps


class MultiPassExtractor:
    """Multi-pass extraction with progressive refinement."""
    
    def __init__(self, model: str = None):
        """Initialize the multi-pass extractor."""
        self.model = model or "gpt-4o-mini"
        self.base_extractor = AdaptiveExtractor(model)
        self.kill_chain = KillChainAnalysis()
        self.all_claims = []
        self.techniques_by_pass = defaultdict(list)
        
    def extract_multi_pass(
        self,
        source_id: str,
        source_type: str,
        content_url: Optional[str] = None,
        inline_text: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Perform multi-pass extraction with progressive refinement.
        
        Returns complete extraction with all passes merged.
        """
        start_time = time.time()
        
        # Handle text extraction
        if inline_text:
            # Text already provided
            extracted = {
                'text': inline_text,
                'metadata': {}
            }
        else:
            # Extract from URL
            extracted = extract_text(
                source_type=source_type,
                content_url=content_url,
                inline_text=None
            )
        
        # Define extraction passes
        passes = [
            ExtractionPass(
                name="primary",
                confidence_threshold=60,
                focus="Extract obvious techniques with high confidence",
                max_iterations=10,
                chunk_size=6000,
                overlap=500
            ),
            ExtractionPass(
                name="exploratory", 
                confidence_threshold=40,
                focus="Find borderline techniques and behavioral patterns",
                max_iterations=8,
                chunk_size=4000,
                overlap=800
            ),
            ExtractionPass(
                name="gap_filling",
                confidence_threshold=30,
                focus="Fill kill chain gaps and find implied techniques",
                max_iterations=12,
                chunk_size=8000,
                overlap=1000
            )
        ]
        
        pass_results = []
        cumulative_techniques = {}
        
        for pass_config in passes:
            print(f"\n[PASS {pass_config.name.upper()}] Starting...")
            
            # Prepare context for this pass
            pass_context = self._prepare_pass_context(
                pass_config, 
                cumulative_techniques,
                extracted['text']
            )
            
            # Run extraction for this pass
            pass_result = self._run_single_pass(
                pass_config=pass_config,
                text=extracted['text'],
                source_id=f"{source_id}-{pass_config.name}",
                context=pass_context
            )
            
            pass_results.append(pass_result)
            
            # Update cumulative techniques
            for claim in pass_result.get('claims', []):
                for mapping in claim.get('mappings', []):
                    tech_id = mapping.get('technique_id')
                    if tech_id:
                        if tech_id not in cumulative_techniques:
                            cumulative_techniques[tech_id] = {
                                'name': mapping.get('technique_name'),
                                'count': 0,
                                'confidence_max': 0,
                                'passes_found': []
                            }
                        cumulative_techniques[tech_id]['count'] += 1
                        cumulative_techniques[tech_id]['confidence_max'] = max(
                            cumulative_techniques[tech_id]['confidence_max'],
                            mapping.get('confidence', 0)
                        )
                        cumulative_techniques[tech_id]['passes_found'].append(pass_config.name)
            
            # Analyze kill chain gaps after each pass
            gaps = self.kill_chain.analyze_gaps(cumulative_techniques)
            if gaps:
                print(f"  Kill chain gaps identified: {list(gaps.keys())}")
        
        # Merge and reconcile all passes
        final_result = self._merge_passes(pass_results, extracted['text'])
        
        # Add inference and gap analysis
        final_result['multi_pass_analysis'] = {
            'passes_completed': len(passes),
            'techniques_by_pass': dict(self.techniques_by_pass),
            'kill_chain_gaps': self.kill_chain.analyze_gaps(cumulative_techniques),
            'cumulative_techniques': cumulative_techniques
        }
        
        elapsed = time.time() - start_time
        final_result['metrics']['elapsed_seconds'] = elapsed
        
        return final_result
    
    def _prepare_pass_context(
        self, 
        pass_config: ExtractionPass,
        cumulative_techniques: Dict,
        full_text: str
    ) -> str:
        """Prepare context for a specific pass."""
        context_parts = []
        
        # Add pass focus
        context_parts.append(f"Extraction focus: {pass_config.focus}")
        context_parts.append(f"Confidence threshold: {pass_config.confidence_threshold}%")
        
        # Add previously found techniques
        if cumulative_techniques:
            tech_list = list(cumulative_techniques.keys())[:10]
            context_parts.append(f"Already found: {', '.join(tech_list)}")
            
            # Identify gaps
            gaps = self.kill_chain.analyze_gaps(cumulative_techniques)
            if gaps:
                gap_hints = []
                for phase, hints in gaps.items():
                    gap_hints.extend(hints)
                context_parts.append(f"Gap analysis suggests: {'; '.join(gap_hints[:3])}")
        
        # Add behavioral hints based on document content
        behavioral_hints = self._extract_behavioral_hints(full_text)
        if behavioral_hints:
            context_parts.append(f"Behavioral patterns detected: {', '.join(behavioral_hints[:5])}")
        
        return " | ".join(context_parts)
    
    def _extract_behavioral_hints(self, text: str) -> List[str]:
        """Extract behavioral hints from text without being prescriptive."""
        hints = []
        text_lower = text.lower()
        
        # Look for action verbs that suggest behaviors
        action_patterns = {
            "downloads": "file transfer behavior",
            "connects": "network communication",
            "encrypts": "data protection or evasion",
            "steals": "data collection behavior",
            "executes": "code execution behavior",
            "modifies": "system modification",
            "creates": "resource creation",
            "deletes": "resource removal",
            "sends": "data transmission",
            "receives": "data reception",
            "hooks": "interception behavior",
            "injects": "code injection behavior",
            "drops": "file deployment",
            "spawns": "process creation",
            "terminates": "process ending"
        }
        
        for pattern, hint in action_patterns.items():
            if pattern in text_lower:
                hints.append(hint)
        
        return hints
    
    def _run_single_pass(
        self,
        pass_config: ExtractionPass,
        text: str,
        source_id: str,
        context: str
    ) -> Dict[str, Any]:
        """Run a single extraction pass with specific configuration."""
        
        # Chunk with pass-specific parameters
        chunks = split_into_chunks(
            source_id=source_id,
            text=text,
            target_chars=pass_config.chunk_size,
            overlap=pass_config.overlap
        )
        
        print(f"  Processing {len(chunks)} chunks (size={pass_config.chunk_size}, overlap={pass_config.overlap})")
        
        # Create a new extractor for this pass
        pass_extractor = AdaptiveExtractor(self.model)
        
        # Use v3 prompts for chain-of-thought reasoning
        tools = get_tool_definitions()
        tool_functions = get_tool_functions()
        
        # Process chunks
        for i, chunk in enumerate(chunks):
            if i >= 3 and pass_config.name != "gap_filling":  # Limit chunks for non-final passes
                break
            
            # Generate messages with v3 prompts
            messages = get_messages_for_multipass(
                chunk_id=chunk['id'],
                text=chunk['text'],
                pass_context=context,
                pass_type=pass_config.name
            )
            
            try:
                # Execute with pass-specific iterations
                response = execute_tool_loop(
                    messages=messages,
                    tools=tools,
                    tool_functions=tool_functions,
                    max_iterations=pass_config.max_iterations
                )
                
                # Parse response and add to claims
                if response:
                    # Try to parse as JSON
                    import json
                    try:
                        if "```json" in response:
                            json_str = response.split("```json")[1].split("```")[0]
                            result_data = json.loads(json_str)
                        else:
                            result_data = json.loads(response)
                        
                        if 'claims' in result_data:
                            pass_extractor.all_claims.extend(result_data['claims'])
                            pass_extractor.context.update_from_claims(result_data['claims'])
                    except json.JSONDecodeError:
                        print(f"  Warning: Could not parse response for chunk {i+1}")
                        
            except Exception as e:
                print(f"  Error processing chunk {i+1}: {e}")
        
        # Track techniques found in this pass
        for claim in pass_extractor.all_claims:
            for mapping in claim.get('mappings', []):
                tech_id = mapping.get('technique_id')
                if tech_id:
                    self.techniques_by_pass[pass_config.name].append(tech_id)
        
        # Build pass result
        return {
            'pass_name': pass_config.name,
            'chunks_processed': min(len(chunks), 3),
            'claims': pass_extractor.all_claims,
            'context': {
                'techniques': list(pass_extractor.context.techniques_found.keys()),
                'kill_chain': dict(pass_extractor.context.kill_chain_phases)
            }
        }
    
    def _merge_passes(self, pass_results: List[Dict], full_text: str) -> Dict[str, Any]:
        """Merge results from all passes with deduplication and confidence boosting."""
        
        merged_claims = []
        seen_techniques = {}
        
        for pass_result in pass_results:
            pass_name = pass_result['pass_name']
            
            for claim in pass_result.get('claims', []):
                # Create unique key for deduplication
                claim_key = self._get_claim_key(claim)
                
                if claim_key not in seen_techniques:
                    # Boost confidence if found in multiple passes
                    pass_bonus = 10 if pass_name == "primary" else 5
                    
                    # Adjust confidence in mappings
                    for mapping in claim.get('mappings', []):
                        if 'confidence' in mapping:
                            mapping['confidence'] = min(
                                mapping['confidence'] + pass_bonus,
                                100
                            )
                        mapping['found_in_pass'] = pass_name
                    
                    merged_claims.append(claim)
                    seen_techniques[claim_key] = claim
                else:
                    # Merge evidence from multiple passes
                    existing = seen_techniques[claim_key]
                    if 'evidence' in claim and 'evidence' in existing:
                        existing['evidence'] = list(set(
                            existing.get('evidence', []) + claim.get('evidence', [])
                        ))
        
        # Infer missing techniques based on capabilities
        inferred_claims = self._infer_techniques(merged_claims, full_text)
        merged_claims.extend(inferred_claims)
        
        return {
            'source_id': 'multi-pass-extraction',
            'source_type': 'multi-pass',
            'extraction_mode': 'multi-pass-progressive',
            'total_claims': len(merged_claims),
            'claims': merged_claims,
            'passes': len(pass_results),
            'metrics': {
                'claims_per_pass': len(merged_claims) / len(pass_results) if pass_results else 0
            }
        }
    
    def _get_claim_key(self, claim: Dict) -> str:
        """Generate unique key for claim deduplication."""
        parts = []
        
        # Use technique name/ID as primary key
        if claim.get('technique'):
            parts.append(claim['technique'])
        
        # Add first mapping ID if available  
        for mapping in claim.get('mappings', []):
            if mapping.get('technique_id'):
                parts.append(mapping['technique_id'])
                break
        
        # Add actor if present
        if claim.get('actor'):
            parts.append(claim['actor'])
        
        return '|'.join(parts) if parts else str(hash(str(claim)))
    
    def _infer_techniques(self, claims: List[Dict], full_text: str) -> List[Dict]:
        """Infer additional techniques based on found techniques and capabilities."""
        inferred = []
        
        # Extract found technique IDs
        found_ids = set()
        for claim in claims:
            for mapping in claim.get('mappings', []):
                if mapping.get('technique_id'):
                    found_ids.add(mapping['technique_id'])
        
        # Inference rules based on capabilities and context
        inferences = {
            # If collection but no exfiltration
            ('T1005' in found_ids and 'T1041' not in found_ids): {
                'technique_id': 'T1041',
                'name': 'Exfiltration Over C2',
                'reason': 'Data collection implies exfiltration capability'
            },
            # If C2 but no exfiltration  
            ('T1071' in found_ids and 'T1041' not in found_ids): {
                'technique_id': 'T1041',
                'name': 'Exfiltration Over C2',
                'reason': 'C2 channel likely used for exfiltration'
            },
            # If execution but no persistence (for malware)
            ('T1059' in found_ids and 'T1547' not in found_ids and 'stealer' in full_text.lower()): {
                'technique_id': 'T1547',
                'name': 'Boot or Logon Autostart Execution',
                'reason': 'Stealers typically establish persistence'
            }
        }
        
        for condition, inference_data in inferences.items():
            if condition and inference_data:
                inferred.append({
                    'type': 'inferred-technique',
                    'technique': inference_data['name'],
                    'mappings': [{
                        'technique_id': inference_data['technique_id'],
                        'technique_name': inference_data['name'],
                        'confidence': 60,
                        'inference_reason': inference_data['reason']
                    }],
                    'evidence': [f"Inferred from capabilities: {inference_data['reason']}"],
                    'source': 'multi-pass-inference'
                })
        
        return inferred