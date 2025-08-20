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
                    "Analyze multiple text spans and map each to ATT&CK techniques.\n\n"
                    "For EACH span, provide:\n"
                    "1. The best matching technique (from candidates or propose new)\n"
                    "2. Direct quotes as evidence (1-2 quotes)\n"
                    "3. Confidence score (0-100)\n\n"
                    "Return a JSON array with one object per span:\n"
                    "[{span_id:int, technique:{external_id,name}, evidence:{quotes,line_refs}, confidence:int}]\n\n"
                    "Be concise. Skip spans with no clear techniques."
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
                        
                    technique = result.get("technique", {})
                    evidence = result.get("evidence", {})
                    
                    if technique.get("external_id") and evidence.get("quotes"):
                        # Check for sub-technique preference
                        choice_id = technique.get("external_id", "")
                        if choice_id and "." not in choice_id:
                            subs = list_subtechniques(choice_id)
                            if isinstance(subs, list) and subs:
                                for s in subs:
                                    nm = (s.get("name", "") or "").lower()
                                    if nm and any(nm in (q or "").lower() for q in evidence.get("quotes", [])):
                                        technique["external_id"] = s.get("external_id", choice_id)
                                        technique["name"] = s.get("name", technique.get("name", ""))
                                        break
                        
                        mem.claims.append({
                            "span_idx": span_id,
                            "external_id": technique["external_id"],
                            "name": technique.get("name", ""),
                            "quotes": evidence.get("quotes", []),
                            "line_refs": evidence.get("line_refs", []),
                            "confidence": int(result.get("confidence", 60)),
                            "source": "batch_mapper"
                        })
                        
        except Exception as e:
            print(f"[DEBUG] Batch mapping failed: {e}, falling back to sequential")
            return self._run_sequential(mem, config)
    
    def _run_sequential(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        """Fallback to sequential processing if batch fails."""
        from bandjacks.llm.agents_v2 import MapperAgent
        MapperAgent().run(mem, config)