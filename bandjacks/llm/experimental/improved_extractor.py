"""Improved extraction pipeline with full document processing and behavioral discovery."""

import re
import json
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import logging

from bandjacks.llm.client import LLMClient
from bandjacks.loaders.parse_text import extract_text
from bandjacks.loaders.search_nodes import ttx_search_kb
import PyPDF2

logger = logging.getLogger(__name__)


@dataclass
class ExtractionContext:
    """Context maintained across extraction passes."""
    
    # Entities found
    threat_actors: List[str] = field(default_factory=list)
    malware: List[str] = field(default_factory=list) 
    tools: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    
    # Techniques with evidence
    techniques_found: Dict[str, Dict] = field(default_factory=dict)
    technique_evidence: Dict[str, List[str]] = field(default_factory=dict)
    
    # Relationships
    relationships: List[Dict] = field(default_factory=list)
    
    # Kill chain coverage
    kill_chain_phases: Dict[str, List[str]] = field(default_factory=dict)
    
    def add_technique(self, tech_id: str, name: str, evidence: List[str], confidence: float):
        """Add a technique with evidence."""
        if tech_id not in self.techniques_found:
            self.techniques_found[tech_id] = {
                "name": name,
                "confidence": confidence,
                "occurrence_count": 0
            }
            self.technique_evidence[tech_id] = []
        
        self.techniques_found[tech_id]["occurrence_count"] += 1
        self.technique_evidence[tech_id].extend(evidence)
        
        # Update confidence if higher
        if confidence > self.techniques_found[tech_id]["confidence"]:
            self.techniques_found[tech_id]["confidence"] = confidence


class ImprovedExtractor:
    """Enhanced extraction with full document processing and behavioral discovery."""
    
    # Kill chain phase mapping
    TECHNIQUE_TO_PHASE = {
        "T1566": "initial-access", "T1190": "initial-access", "T1078": "initial-access",
        "T1059": "execution", "T1053": "execution", "T1129": "execution",
        "T1547": "persistence", "T1543": "persistence", "T1574": "persistence",
        "T1055": "defense-evasion", "T1140": "defense-evasion", "T1027": "defense-evasion",
        "T1555": "credential-access", "T1003": "credential-access", "T1552": "credential-access",
        "T1057": "discovery", "T1083": "discovery", "T1082": "discovery",
        "T1005": "collection", "T1113": "collection", "T1056": "collection",
        "T1071": "command-and-control", "T1102": "command-and-control", "T1095": "command-and-control",
        "T1041": "exfiltration", "T1048": "exfiltration", "T1020": "exfiltration",
        "T1486": "impact", "T1490": "impact", "T1489": "impact"
    }
    
    def __init__(self, model: str = "gpt-4o-mini", os_url: str = "http://localhost:9200", os_index: str = "bandjacks_attack_nodes-v1"):
        """Initialize the improved extractor."""
        self.model = model
        self.os_url = os_url
        self.os_index = os_index
        self.context = ExtractionContext()
        self.llm_client = LLMClient()
        self.llm_client.model = model  # Override model
    
    def extract_from_report(
        self,
        source_id: str,
        source_type: str,
        content_url: Optional[str] = None,
        inline_text: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Extract techniques with improved recall using full document processing.
        """
        start_time = time.time()
        
        # Extract and clean text
        if inline_text:
            text = inline_text
        else:
            text = self._extract_full_text(source_type, content_url)
        
        if not text:
            return {"error": "No text extracted"}
        
        # Clean text to remove boilerplate
        text = self._clean_text(text)
        
        print(f"[IMPROVED] Processing {len(text)} characters (full document)")
        
        # Chunk text properly (20K chars with 2K overlap)
        chunks = self._chunk_text(text, chunk_size=20000, overlap=2000)
        print(f"[IMPROVED] Created {len(chunks)} chunks")
        
        # Pass 1: Extract entities and relationships
        print("\n=== Pass 1: Entity and Relationship Extraction ===")
        self._extract_entities_and_relationships(chunks)
        
        # Pass 2: Behavioral technique discovery
        print("\n=== Pass 2: Behavioral Technique Discovery ===")
        self._discover_techniques_behavioral(chunks)
        
        # Pass 3: Kill chain gap analysis
        print("\n=== Pass 3: Kill Chain Gap Analysis ===")
        self._analyze_kill_chain_gaps(text[:10000])  # Use beginning for context
        
        # Pass 4: Targeted search for commonly missed techniques
        print("\n=== Pass 4: Targeted Technique Search ===")
        self._search_for_missed_techniques(text)
        
        # Build final results
        elapsed = time.time() - start_time
        
        return self._build_results(source_id, elapsed)
    
    def _extract_full_text(self, source_type: str, content_url: str) -> str:
        """Extract full text from document without truncation."""
        if source_type == "pdf" and content_url:
            return self._extract_pdf_full(Path(content_url))
        elif source_type == "json" and content_url:
            return self._extract_json_full(Path(content_url))
        else:
            # Fallback to existing method
            extracted = extract_text(source_type, content_url, None)
            return extracted.get("text", "")
    
    def _extract_pdf_full(self, pdf_path: Path) -> str:
        """Extract full text from PDF."""
        if not pdf_path.exists():
            return ""
        
        text_parts = []
        try:
            with open(pdf_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                for page_num in range(len(pdf_reader.pages)):
                    page = pdf_reader.pages[page_num]
                    text_parts.append(page.extract_text())
        except Exception as e:
            logger.error(f"Error extracting PDF: {e}")
            return ""
        
        return '\n\n'.join(text_parts)
    
    def _extract_json_full(self, json_path: Path) -> str:
        """Extract full text from JSON report."""
        if not json_path.exists():
            return ""
        
        try:
            with open(json_path) as f:
                data = json.load(f)
            
            text_parts = []
            for obj in data.get("objects", []):
                if "description" in obj:
                    text_parts.append(obj["description"])
                if "pattern" in obj:
                    text_parts.append(obj["pattern"])
            
            return "\n\n".join(text_parts)
        except Exception as e:
            logger.error(f"Error extracting JSON: {e}")
            return ""
    
    def _clean_text(self, text: str) -> str:
        """Clean text to remove vendor boilerplate and marketing."""
        # Remove page numbers
        text = re.sub(r"\b[Pp]age\s+\d+\s*(?:of|/)?\s*\d+", " ", text)
        
        # Remove copyright
        text = re.sub(r"©.*(?:\n|$)", " ", text)
        
        # Remove marketing sections
        lines = text.split('\n')
        cleaned_lines = []
        skip = False
        
        for line in lines:
            # Skip vendor marketing headings
            if re.match(r"^(about|contact us|learn more|why|our solution)", line, re.I):
                skip = True
                continue
            
            if skip and (not line.strip() or line.startswith("#")):
                skip = False
            
            if not skip:
                cleaned_lines.append(line)
        
        text = '\n'.join(cleaned_lines)
        
        # Collapse excessive blank lines
        text = re.sub(r"\n{3,}", "\n\n", text)
        
        return text.strip()
    
    def _chunk_text(self, text: str, chunk_size: int = 20000, overlap: int = 2000) -> List[str]:
        """Chunk text with proper overlap."""
        if len(text) <= chunk_size:
            return [text]
        
        chunks = []
        start = 0
        
        while start < len(text):
            end = min(start + chunk_size, len(text))
            
            # Try to break at paragraph boundary
            if end < len(text):
                for break_point in ['\n\n', '\n', '. ']:
                    last_break = text.rfind(break_point, start, end)
                    if last_break > start + chunk_size // 2:
                        end = last_break + len(break_point)
                        break
            
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            
            # Move forward with overlap
            start = end - overlap if end < len(text) else end
        
        return chunks
    
    def _extract_entities_and_relationships(self, chunks: List[str]):
        """Pass 1: Extract entities and relationships for context."""
        prompt = """Extract cyber threat entities and relationships from this text.

Entities to extract:
- ThreatActor: adversary groups (APT28, Lazarus, etc.)
- Malware: malicious software (DarkCloud, BlackBasta, etc.)  
- Tool: legitimate tools used maliciously (PowerShell, Cobalt Strike, etc.)
- Campaign: named operations
- Infrastructure: IPs, domains, URLs

Relationships to extract:
- Actor USES Tool/Malware
- Malware DROPS/DOWNLOADS other Malware
- Tool/Malware COMMUNICATES_WITH Infrastructure

Output as JSON:
{
  "entities": {
    "threat_actors": ["name1", "name2"],
    "malware": ["malware1", "malware2"],
    "tools": ["tool1", "tool2"],
    "campaigns": ["campaign1"],
    "infrastructure": ["domain1", "ip1"]
  },
  "relationships": [
    {"type": "USES", "from": "APT28", "to": "Cobalt Strike"}
  ]
}

Text to analyze:
"""
        
        for i, chunk in enumerate(chunks[:2]):  # Process first 2 chunks for entities
            try:
                messages = [
                    {"role": "system", "content": "You are a CTI analyst extracting entities."},
                    {"role": "user", "content": prompt + chunk[:5000]}
                ]
                response = self.llm_client.call(messages)
                # Parse content from response - handle both object and dict formats
                if hasattr(response, 'choices'):
                    content = response.choices[0].message.content
                elif isinstance(response, dict) and 'choices' in response:
                    content = response['choices'][0]['message']['content']
                else:
                    logger.error(f"Unexpected response format: {type(response)}")
                    content = '{}'
                
                # Clean JSON from markdown if needed
                if '```json' in content:
                    content = content.split('```json')[1].split('```')[0]
                elif '```' in content:
                    content = content.split('```')[1].split('```')[0]
                
                result = json.loads(content.strip())
                
                # Update context
                entities = result.get("entities", {})
                self.context.threat_actors.extend(entities.get("threat_actors", []))
                self.context.malware.extend(entities.get("malware", []))
                self.context.tools.extend(entities.get("tools", []))
                self.context.campaigns.extend(entities.get("campaigns", []))
                
                self.context.relationships.extend(result.get("relationships", []))
                
                print(f"  Chunk {i+1}: Found {len(entities.get('threat_actors', []))} actors, "
                      f"{len(entities.get('malware', []))} malware, {len(entities.get('tools', []))} tools")
                
            except Exception as e:
                logger.error(f"Entity extraction failed for chunk {i+1}: {e}")
    
    def _discover_techniques_behavioral(self, chunks: List[str]):
        """Pass 2: Discover techniques through behavioral analysis."""
        
        behavioral_prompt = """Analyze this threat report and identify MITRE ATT&CK techniques based on BEHAVIORS, not keywords.

For each behavior, ask:
1. What is the threat trying to achieve? (goal)
2. How is it accomplishing this? (method)
3. What system resources are involved? (targets)
4. What would this look like to a defender? (observables)

Focus on these behavioral categories:
- Initial Contact: How does attack begin? (phishing, exploit, stolen creds)
- Code Execution: What runs and how? (scripts, processes, commands)
- Persistence: How does it survive reboots? (registry, services, scheduled tasks)
- Defense Evasion: How does it hide? (obfuscation, injection, disabled security)
- Discovery: What does it enumerate? (processes, files, network, users)
- Collection: What data is gathered? (files, credentials, screenshots)
- Communication: How does it communicate? (HTTP, DNS, custom protocols)
- Impact: What damage occurs? (encryption, deletion, disruption)

Context about this report:
- Threat Actors: {actors}
- Malware: {malware}
- Tools: {tools}

Output as JSON with evidence:
{{
  "techniques": [
    {{
      "behavior": "description of what happens",
      "goal": "what it achieves",
      "technique_search": "search terms for MITRE technique",
      "evidence": ["quote 1", "quote 2"],
      "confidence": 0-100
    }}
  ]
}}

Text to analyze:
"""
        
        # Format context
        context_str = behavioral_prompt.format(
            actors=", ".join(self.context.threat_actors[:3]) or "Unknown",
            malware=", ".join(self.context.malware[:3]) or "Unknown",
            tools=", ".join(self.context.tools[:3]) or "Unknown"
        )
        
        for i, chunk in enumerate(chunks):
            try:
                messages = [
                    {"role": "system", "content": "You are a CTI analyst focused on behavioral analysis."},
                    {"role": "user", "content": context_str + chunk[:8000]}
                ]
                response = self.llm_client.call(messages)
                content = response.get('choices', [{}])[0].get('message', {}).get('content', '{}')
                
                # Clean JSON from markdown if needed
                if '```json' in content:
                    content = content.split('```json')[1].split('```')[0]
                elif '```' in content:
                    content = content.split('```')[1].split('```')[0]
                
                result = json.loads(content.strip())
                techniques = result.get("techniques", [])
                
                # Search for each discovered behavior
                for tech in techniques:
                    search_terms = tech.get("technique_search", tech.get("behavior", ""))
                    if search_terms:
                        # Search for matching ATT&CK technique
                        matches = ttx_search_kb(
                            self.os_url,
                            self.os_index,
                            search_terms,
                            top_k=3,
                            kb_types=["AttackPattern"]
                        )
                        
                        if matches and matches[0].get("score", 0) > 0.6:
                            best_match = matches[0]
                            tech_id = best_match.get("external_id", "")
                            if tech_id:
                                self.context.add_technique(
                                    tech_id,
                                    best_match.get("name", ""),
                                    tech.get("evidence", []),
                                    tech.get("confidence", 70)
                                )
                
                print(f"  Chunk {i+1}: Discovered {len(techniques)} behavioral patterns")
                
            except Exception as e:
                logger.error(f"Behavioral discovery failed for chunk {i+1}: {e}")
    
    def _analyze_kill_chain_gaps(self, context_text: str):
        """Pass 3: Analyze kill chain for missing techniques."""
        
        # Map found techniques to phases
        covered_phases = set()
        for tech_id in self.context.techniques_found:
            base_tech = tech_id.split('.')[0]
            if base_tech in self.TECHNIQUE_TO_PHASE:
                covered_phases.add(self.TECHNIQUE_TO_PHASE[base_tech])
        
        # Identify gaps
        all_phases = {"initial-access", "execution", "persistence", "defense-evasion",
                     "credential-access", "discovery", "collection", "command-and-control",
                     "exfiltration", "impact"}
        
        missing_phases = all_phases - covered_phases
        
        if not missing_phases:
            print("  All kill chain phases covered")
            return
        
        print(f"  Missing phases: {', '.join(missing_phases)}")
        
        # Search for techniques in missing phases
        gap_prompt = """Based on this threat report, what techniques would fill these kill chain gaps?

Current techniques found: {found}
Missing phases: {missing}

Given the attack flow, what techniques MUST have occurred in the missing phases?
Consider:
- If malware executes, how did it arrive? (initial access)
- If data is stolen, how was it found? (discovery) 
- If commands run, how do they communicate? (C2)
- If malware persists, what ensures it? (persistence)

Search for evidence of techniques in these missing phases.

Output as JSON:
{{
  "gap_techniques": [
    {{
      "phase": "phase name",
      "reasoning": "why this must exist",
      "search_terms": "terms to search for",
      "evidence_hints": ["what to look for"]
    }}
  ]
}}

Report context:
"""
        
        found_str = ", ".join(list(self.context.techniques_found.keys())[:10])
        
        try:
            messages = [
                {"role": "system", "content": "You are a CTI analyst identifying kill chain gaps."},
                {"role": "user", "content": gap_prompt.format(
                    found=found_str,
                    missing=", ".join(missing_phases)
                ) + "\n" + context_text[:3000]}
            ]
            response = self.llm_client.call(messages)
            content = response.get('choices', [{}])[0].get('message', {}).get('content', '{}')
            
            # Clean JSON from markdown if needed
            if '```json' in content:
                content = content.split('```json')[1].split('```')[0]
            elif '```' in content:
                content = content.split('```')[1].split('```')[0]
            
            result = json.loads(content.strip())
            gaps = result.get("gap_techniques", [])
            
            for gap in gaps:
                search_terms = gap.get("search_terms", "")
                if search_terms:
                    matches = ttx_search_kb(
                        self.os_url,
                        self.os_index, 
                        search_terms,
                        top_k=2,
                        kb_types=["AttackPattern"]
                    )
                    
                    if matches and matches[0].get("score", 0) > 0.65:
                        best_match = matches[0]
                        tech_id = best_match.get("external_id", "")
                        if tech_id:
                            self.context.add_technique(
                                tech_id,
                                best_match.get("name", ""),
                                [f"Kill chain analysis: {gap.get('reasoning', '')}"],
                                60
                            )
                            print(f"    Found gap technique: {tech_id} - {best_match.get('name', '')}")
            
        except Exception as e:
            logger.error(f"Kill chain analysis failed: {e}")
    
    def _search_for_missed_techniques(self, text: str):
        """Pass 4: Targeted search for commonly missed techniques."""
        
        # Specific searches for commonly missed techniques
        targeted_searches = [
            # T1055 - Process Injection
            {
                "technique": "T1055",
                "patterns": ["inject", "hollow", "process injection", "WriteProcessMemory", 
                            "CreateRemoteThread", "SetThreadContext", "APC queue"],
                "context": "process manipulation memory modification code injection"
            },
            # T1071 - Application Layer Protocol
            {
                "technique": "T1071",
                "patterns": ["C2", "command and control", "communicates with", "beacons",
                            "HTTP", "HTTPS", "DNS", "protocol", "telegram", "discord"],
                "context": "network communication command control channel"
            },
            # T1547 - Boot or Logon Autostart
            {
                "technique": "T1547",
                "patterns": ["persistence", "startup", "registry", "scheduled task", "service",
                            "RunOnce", "Run key", "autostart", "survives reboot"],
                "context": "persistence mechanism boot logon autostart"
            },
            # T1140 - Deobfuscate/Decode
            {
                "technique": "T1140",
                "patterns": ["decode", "decrypt", "deobfuscate", "unpack", "Base64",
                            "XOR", "AES", "3DES", "RC4", "decompress"],
                "context": "decode decrypt deobfuscate files information"
            },
            # T1057 - Process Discovery
            {
                "technique": "T1057",
                "patterns": ["enumerate process", "list process", "tasklist", "ps aux",
                            "GetProcesses", "EnumProcesses", "process discovery"],
                "context": "process enumeration discovery system information"
            }
        ]
        
        for search_config in targeted_searches:
            tech_id = search_config["technique"]
            
            # Skip if already found with high confidence
            if tech_id in self.context.techniques_found and \
               self.context.techniques_found[tech_id]["confidence"] > 80:
                continue
            
            # Check if any patterns exist in text
            text_lower = text.lower()
            found_patterns = []
            for pattern in search_config["patterns"]:
                if pattern.lower() in text_lower:
                    found_patterns.append(pattern)
            
            if found_patterns:
                # Verify with vector search
                matches = ttx_search_kb(
                    self.os_url,
                    self.os_index,
                    search_config["context"],
                    top_k=3,
                    kb_types=["AttackPattern"]
                )
                
                for match in matches:
                    if match.get("external_id") == tech_id:
                        self.context.add_technique(
                            tech_id,
                            match.get("name", ""),
                            [f"Pattern match: {', '.join(found_patterns[:3])}"],
                            70
                        )
                        print(f"  Found missed technique: {tech_id} - {match.get('name', '')}")
                        break
    
    def _build_results(self, source_id: str, elapsed: float) -> Dict[str, Any]:
        """Build final extraction results."""
        
        # Convert techniques to claims format
        claims = []
        for tech_id, tech_info in self.context.techniques_found.items():
            claim = {
                "type": "uses-technique",
                "technique": tech_info["name"],
                "evidence": self.context.technique_evidence.get(tech_id, []),
                "mappings": [{
                    "external_id": tech_id,
                    "name": tech_info["name"],
                    "confidence": tech_info["confidence"]
                }]
            }
            claims.append(claim)
        
        # Calculate statistics
        techniques_by_phase = {}
        for tech_id in self.context.techniques_found:
            base_tech = tech_id.split('.')[0]
            phase = self.TECHNIQUE_TO_PHASE.get(base_tech, "unknown")
            if phase not in techniques_by_phase:
                techniques_by_phase[phase] = []
            techniques_by_phase[phase].append(tech_id)
        
        return {
            "source_id": source_id,
            "extraction_mode": "improved_behavioral",
            "total_techniques": len(self.context.techniques_found),
            "claims": claims,
            "entities": {
                "threat_actors": list(set(self.context.threat_actors)),
                "malware": list(set(self.context.malware)),
                "tools": list(set(self.context.tools)),
                "campaigns": list(set(self.context.campaigns))
            },
            "relationships": self.context.relationships,
            "kill_chain_coverage": techniques_by_phase,
            "metrics": {
                "elapsed_seconds": elapsed,
                "avg_confidence": sum(t["confidence"] for t in self.context.techniques_found.values()) / len(self.context.techniques_found) if self.context.techniques_found else 0
            }
        }