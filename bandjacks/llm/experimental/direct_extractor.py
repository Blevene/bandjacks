"""Direct TTP extraction using LLM's native ATT&CK knowledge."""

import json
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path
import logging

from bandjacks.llm.client import LLMClient
from bandjacks.loaders.search_nodes import ttx_search_kb
import PyPDF2

logger = logging.getLogger(__name__)


@dataclass
class TTPExtraction:
    """Results from TTP extraction."""
    techniques: Dict[str, Dict] = field(default_factory=dict)
    entities: Dict[str, List] = field(default_factory=dict)
    relationships: List[Dict] = field(default_factory=list)
    evidence: Dict[str, List] = field(default_factory=dict)


class DirectTTPExtractor:
    """Extract TTPs using LLM's direct knowledge of ATT&CK."""
    
    def __init__(self, model: str = "gpt-4o-mini"):
        """Initialize the direct extractor."""
        self.model = model
        self.llm_client = LLMClient()
        self.llm_client.model = model
    
    def extract_ttps(self, text: str, source_id: str) -> Dict[str, Any]:
        """
        Extract TTPs directly using LLM's ATT&CK knowledge.
        
        This approach trusts the LLM to identify techniques directly
        rather than requiring vector search validation.
        """
        start_time = time.time()
        
        # Clean and chunk text if needed
        chunks = self._chunk_text(text, chunk_size=30000)
        print(f"[DIRECT] Processing {len(chunks)} chunks")
        
        extraction = TTPExtraction()
        
        for i, chunk in enumerate(chunks):
            print(f"\n=== Chunk {i+1}/{len(chunks)} ===")
            
            # Extract TTPs directly
            chunk_results = self._extract_chunk_ttps(chunk, i)
            
            # Merge results
            self._merge_results(extraction, chunk_results)
        
        # Optional: Validate high-confidence techniques with vector search
        self._validate_techniques(extraction)
        
        elapsed = time.time() - start_time
        
        return self._format_results(extraction, source_id, elapsed)
    
    def _chunk_text(self, text: str, chunk_size: int = 30000) -> List[str]:
        """Chunk text for processing."""
        if len(text) <= chunk_size:
            return [text]
        
        chunks = []
        start = 0
        
        while start < len(text):
            end = min(start + chunk_size, len(text))
            
            # Try to break at paragraph
            if end < len(text):
                for break_point in ['\n\n', '\n', '. ']:
                    last_break = text.rfind(break_point, start, end)
                    if last_break > start + chunk_size // 2:
                        end = last_break + len(break_point)
                        break
            
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            
            start = end
        
        return chunks
    
    def _extract_chunk_ttps(self, chunk: str, chunk_num: int) -> Dict:
        """Extract TTPs from a single chunk using LLM's knowledge."""
        
        prompt = """You are an expert in MITRE ATT&CK framework. Analyze this threat intelligence and identify ALL ATT&CK techniques demonstrated.

IMPORTANT: Use your knowledge of ATT&CK to identify techniques directly. You know the T-numbers and technique names.

For each technique you identify:
1. Provide the technique ID (T-number)
2. Provide the technique name
3. Quote specific evidence from the text
4. Explain why this maps to that technique
5. Rate confidence (0-100)

Be comprehensive! Look for:
- Initial Access (phishing, exploits, valid accounts)
- Execution (PowerShell, scripts, interpreters, scheduled tasks)
- Persistence (registry, startup folder, services)
- Privilege Escalation (process injection, UAC bypass)
- Defense Evasion (obfuscation, packing, injection)
- Credential Access (credential dumping, keylogging, browser passwords)
- Discovery (system info, process discovery, file enumeration)
- Lateral Movement (RDP, SMB, WMI)
- Collection (data from local system, screenshots, keylogging)
- Command and Control (web protocols, DNS, custom C2)
- Exfiltration (over C2, alternative protocols)
- Impact (encryption, data destruction, defacement)

Output as JSON:
{
  "techniques": [
    {
      "id": "T1566.001",
      "name": "Phishing: Spearphishing Attachment",
      "evidence": ["quote from text"],
      "reasoning": "why this is T1566.001",
      "confidence": 95
    }
  ],
  "entities": {
    "threat_actors": ["APT28"],
    "malware": ["DarkCloud"],
    "tools": ["PowerShell", "Cobalt Strike"],
    "campaigns": ["Operation X"]
  },
  "relationships": [
    {"from": "APT28", "uses": "T1566.001"},
    {"from": "DarkCloud", "uses": "T1055"}
  ]
}

Text to analyze:
"""
        
        try:
            messages = [
                {"role": "system", "content": "You are a MITRE ATT&CK expert. Identify techniques with T-numbers."},
                {"role": "user", "content": prompt + chunk[:15000]}  # Limit chunk size for context window
            ]
            
            response = self.llm_client.call(messages)
            
            # Parse response - handle both object and dict formats
            if hasattr(response, 'choices'):
                # Response is an object with choices attribute
                content = response.choices[0].message.content
            elif isinstance(response, dict) and 'choices' in response:
                # Response is a dict with choices key
                content = response['choices'][0]['message']['content']
            else:
                # Fallback - shouldn't happen
                logger.error(f"Unexpected response format: {type(response)}")
                content = '{}'
            
            # Clean JSON from markdown
            if '```json' in content:
                content = content.split('```json')[1].split('```')[0]
            elif '```' in content:
                content = content.split('```')[1].split('```')[0]
            
            # Remove any remaining whitespace and newlines
            content = content.strip()
            
            print(f"  DEBUG: Content length after cleaning: {len(content)}")
            print(f"  DEBUG: First 200 chars: {content[:200]}")
            
            try:
                result = json.loads(content)
                print(f"  DEBUG: Successfully parsed JSON with {len(result.get('techniques', []))} techniques")
            except json.JSONDecodeError as e:
                logger.error(f"JSON parsing error: {e}")
                logger.error(f"Content was: {content[:500]}")
                result = {"techniques": [], "entities": {}, "relationships": []}
            
            # Display findings
            techniques = result.get('techniques', [])
            print(f"  Found {len(techniques)} techniques in chunk:")
            for tech in techniques[:5]:
                print(f"    - {tech.get('id', 'Unknown')}: {tech.get('name', 'Unknown')} (confidence: {tech.get('confidence', 0)})")
            if len(techniques) > 5:
                print(f"    ... and {len(techniques)-5} more")
            
            print(f"  DEBUG: Returning result with {len(techniques)} techniques")
            return result
            
        except Exception as e:
            logger.error(f"Chunk {chunk_num} extraction failed: {e}")
            return {"techniques": [], "entities": {}, "relationships": []}
    
    def _merge_results(self, extraction: TTPExtraction, chunk_results: Dict):
        """Merge chunk results into overall extraction."""
        
        print(f"  DEBUG _merge_results: Got {len(chunk_results.get('techniques', []))} techniques to merge")
        
        # Merge techniques
        for tech in chunk_results.get('techniques', []):
            tech_id = tech.get('id', '')
            if tech_id and tech_id.startswith('T'):
                if tech_id not in extraction.techniques:
                    extraction.techniques[tech_id] = {
                        'name': tech.get('name', ''),
                        'confidence': tech.get('confidence', 0),
                        'count': 0
                    }
                    print(f"    DEBUG: Added technique {tech_id}")
                
                # Update count and confidence
                extraction.techniques[tech_id]['count'] += 1
                extraction.techniques[tech_id]['confidence'] = max(
                    extraction.techniques[tech_id]['confidence'],
                    tech.get('confidence', 0)
                )
                
                # Store evidence
                if tech_id not in extraction.evidence:
                    extraction.evidence[tech_id] = []
                extraction.evidence[tech_id].extend(tech.get('evidence', []))
        
        print(f"  DEBUG: After merge, total techniques: {len(extraction.techniques)}")
        
        # Merge entities
        entities = chunk_results.get('entities', {})
        for entity_type, entity_list in entities.items():
            if entity_type not in extraction.entities:
                extraction.entities[entity_type] = []
            extraction.entities[entity_type].extend(entity_list)
        
        # Merge relationships
        extraction.relationships.extend(chunk_results.get('relationships', []))
    
    def _validate_techniques(self, extraction: TTPExtraction):
        """Optionally validate techniques with vector search."""
        
        print("\n=== Validating Techniques ===")
        
        # Only validate low-confidence techniques
        for tech_id, info in extraction.techniques.items():
            if info['confidence'] < 70:
                # Try to validate with vector search
                search_query = f"{tech_id} {info['name']}"
                try:
                    matches = ttx_search_kb(
                        "http://localhost:9200",
                        "bandjacks_attack_nodes-v1",
                        search_query,
                        top_k=1,
                        kb_types=["AttackPattern"]
                    )
                    
                    if matches and matches[0].get('external_id') == tech_id:
                        # Boost confidence if validated
                        info['confidence'] = min(info['confidence'] + 20, 95)
                        print(f"  ✓ Validated {tech_id} (confidence: {info['confidence']})")
                except:
                    # Vector search failed, keep original confidence
                    pass
    
    def _format_results(self, extraction: TTPExtraction, source_id: str, elapsed: float) -> Dict:
        """Format extraction results."""
        
        # Deduplicate entities
        for entity_type in extraction.entities:
            extraction.entities[entity_type] = list(set(extraction.entities[entity_type]))
        
        # Build claims for compatibility
        claims = []
        for tech_id, info in extraction.techniques.items():
            claims.append({
                "type": "uses-technique",
                "technique": info['name'],
                "evidence": extraction.evidence.get(tech_id, [])[:3],  # Top 3 evidence
                "mappings": [{
                    "external_id": tech_id,
                    "name": info['name'],
                    "confidence": info['confidence']
                }]
            })
        
        return {
            "source_id": source_id,
            "extraction_mode": "direct_llm",
            "total_techniques": len(extraction.techniques),
            "techniques": extraction.techniques,
            "entities": extraction.entities,
            "relationships": extraction.relationships,
            "claims": claims,
            "metrics": {
                "elapsed_seconds": elapsed,
                "avg_confidence": sum(t['confidence'] for t in extraction.techniques.values()) / len(extraction.techniques) if extraction.techniques else 0
            }
        }


def extract_pdf_text(pdf_path: Path) -> str:
    """Extract text from PDF."""
    if not pdf_path.exists():
        return ""
    
    text_parts = []
    try:
        with open(pdf_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)
            for page in pdf_reader.pages:
                text_parts.append(page.extract_text())
    except Exception as e:
        logger.error(f"PDF extraction error: {e}")
        return ""
    
    return '\n\n'.join(text_parts)


def extract_json_text(json_path: Path) -> str:
    """Extract text from JSON report."""
    if not json_path.exists():
        return ""
    
    try:
        with open(json_path) as f:
            data = json.load(f)
        
        text_parts = []
        for obj in data.get("objects", []):
            if "description" in obj:
                text_parts.append(obj["description"])
        
        return "\n\n".join(text_parts)
    except Exception as e:
        logger.error(f"JSON extraction error: {e}")
        return ""