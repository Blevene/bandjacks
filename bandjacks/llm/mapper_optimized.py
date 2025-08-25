"""Optimized batch mapper for faster extraction."""

import json
from typing import Any, Dict, List
from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.client import LLMClient
from bandjacks.llm.tools import list_subtechniques


class BatchMapperAgent:
    """Batch process all spans in a single LLM call for performance."""
    
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        print(f"[DEBUG] BatchMapperAgent called with {len(mem.spans)} spans")
        
        if not mem.spans:
            return
            
        # Skip if too many spans (fallback to sequential)
        if len(mem.spans) > 10:
            print(f"[DEBUG] Too many spans ({len(mem.spans)}), falling back to sequential")
            return self._run_sequential(mem, config)
        
        # Prepare batch request
        spans_data = []
        for i, span in enumerate(mem.spans):
            cands = mem.candidates.get(i, [])
            
            # Get evidence lines
            line_refs = span.get("line_refs", [])
            evidence_lines = []
            for ref in line_refs:
                if 1 <= ref <= len(mem.line_index):
                    evidence_lines.append(f"Line {ref}: {mem.line_index[ref-1]}")
            
            spans_data.append({
                "span_id": i,
                "text": span["text"][:500],  # Limit length
                "line_refs": line_refs,
                "evidence_lines": evidence_lines[:5],  # Limit evidence
                "candidates": [
                    {"external_id": c["external_id"], "name": c.get("name", ""), "score": c.get("score", 0)} 
                    for c in cands[:5]  # Limit candidates
                ]
            })
        
        # Create batch prompt
        messages = [
            {
                "role": "system",
                "content": (
                    "Analyze multiple text spans and extract ALL ATT&CK techniques mentioned or implied.\n\n"
                    "For EACH span, extract ALL techniques that are:\n"
                    "1. Explicitly mentioned by ID (e.g., T1055, T1566.001)\n"
                    "2. Described by behavior matching a technique\n"
                    "3. Present in the candidate list and relevant\n\n"
                    "Return a JSON array with MULTIPLE techniques per span if applicable:\n"
                    "[{span_id:int, techniques:[{external_id,name,evidence:{quotes,line_refs},confidence}]}]\n\n"
                    "Extract every valid technique. Include explicit IDs even if not in candidates."
                )
            },
            {
                "role": "user",
                "content": f"Process these {len(spans_data)} spans:\n\n" + json.dumps(spans_data, indent=2)
            }
        ]
        
        # Single LLM call for all spans
        print(f"[DEBUG] Calling LLM with batch of {len(spans_data)} spans")
        client = LLMClient()
        try:
            response = client.call(messages)
            content = response.get("content", "")
            print(f"[DEBUG] LLM response received, length: {len(content)}")
            
            # Extract JSON from response
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            results = json.loads(content)
            
            # Process results
            if isinstance(results, list):
                for result in results:
                    span_id = result.get("span_id")
                    if span_id is None or span_id >= len(mem.spans):
                        continue
                    
                    # Handle new format with multiple techniques per span
                    techniques = result.get("techniques", [])
                    
                    # Fallback to old format if needed
                    if not techniques and result.get("technique"):
                        techniques = [{
                            "external_id": result["technique"].get("external_id"),
                            "name": result["technique"].get("name"),
                            "evidence": result.get("evidence", {}),
                            "confidence": result.get("confidence", 60)
                        }]
                    
                    for tech in techniques:
                        if not tech.get("external_id"):
                            continue
                            
                        evidence = tech.get("evidence", {})
                        
                        # Check for sub-technique preference
                        choice_id = tech.get("external_id", "")
                        if choice_id and "." not in choice_id:
                            subs = list_subtechniques(choice_id)
                            if isinstance(subs, list) and subs:
                                for s in subs:
                                    nm = (s.get("name", "") or "").lower()
                                    if nm and any(nm in (q or "").lower() for q in evidence.get("quotes", [])):
                                        tech["external_id"] = s.get("external_id", choice_id)
                                        tech["name"] = s.get("name", tech.get("name", ""))
                                        break
                        
                        mem.claims.append({
                            "span_idx": span_id,
                            "external_id": tech["external_id"],
                            "name": tech.get("name", ""),
                            "quotes": evidence.get("quotes", []),
                            "line_refs": evidence.get("line_refs", []),
                            "confidence": int(tech.get("confidence", 60)),
                            "source": "batch_mapper"
                        })
                        
        except Exception as e:
            print(f"[DEBUG] Batch mapping failed: {e}, falling back to sequential")
            return self._run_sequential(mem, config)
    
    def _run_sequential(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        """Fallback to sequential processing if batch fails."""
        from bandjacks.llm.agents_v2 import MapperAgent
        MapperAgent().run(mem, config)