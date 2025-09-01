"""Optimized extraction pipeline with performance improvements."""

from typing import Any, Dict

from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.agents_v2 import (
    SpanFinderAgent,
    RetrieverAgent,
    DiscoveryAgent,
    MapperAgent,
    EvidenceVerifierAgent,
    ConsolidatorAgent,
    KillChainSuggestionsAgent,
    AssemblerAgent,
)
from bandjacks.llm.mapper_optimized import BatchMapperAgent
from bandjacks.llm.tracker import ExtractionTracker


def run_agentic_v2_optimized(report_text: str, config: Dict[str, Any], tracker: ExtractionTracker | None = None) -> Dict[str, Any]:
    """Optimized extraction pipeline with performance enhancements.
    
    Config options for optimization:
    - use_batch_mapper: Use single LLM call for all spans (default: True)
    - disable_discovery: Skip discovery agent (default: False)
    - disable_targeted_extraction: Skip second pass for missing tactics (default: True)
    - max_spans: Maximum number of spans to process (default: 10)
    - span_score_threshold: Minimum score for span inclusion (default: 0.8)
    - max_tool_iterations: Maximum iterations for tool loops (default: 2)
    - skip_verification: Skip evidence verification for speed (default: False)
    """
    # Preprocess text to ensure better span detection
    import re
    processed_text = report_text
    
    # If text is mostly on one line, split on sentence boundaries
    lines = report_text.splitlines()
    if len(lines) <= 2 and len(report_text) > 100:
        # Split on sentence endings followed by capital letter or end
        sentences = re.split(r'(?<=[.!?])\s+(?=[A-Z])', report_text)
        # Also split on explicit technique mentions for better span isolation
        expanded = []
        for sent in sentences:
            # Split further on technique IDs to isolate them
            parts = re.split(r'(T\d{4}(?:\.\d{3})?)', sent)
            for i, part in enumerate(parts):
                if part and part.strip():
                    # Recombine technique ID with surrounding context
                    if re.match(r'^T\d{4}', part):
                        if i > 0 and parts[i-1]:
                            expanded[-1] = expanded[-1] + ' ' + part
                            if i < len(parts) - 1 and parts[i+1]:
                                expanded[-1] = expanded[-1] + ' ' + parts[i+1].strip()
                                parts[i+1] = ''  # Clear to avoid duplication
                    elif part.strip():
                        expanded.append(part.strip())
        lines = expanded if expanded else sentences
    
    mem = WorkingMemory(document_text=report_text, line_index=lines)
    tracker = tracker or ExtractionTracker()
    
    # Apply optimization defaults
    if "use_batch_mapper" not in config:
        config["use_batch_mapper"] = True
    if "disable_targeted_extraction" not in config:
        config["disable_targeted_extraction"] = True
    if "max_spans" not in config:
        config["max_spans"] = 10
    if "span_score_threshold" not in config:
        config["span_score_threshold"] = 0.8
    if "max_tool_iterations" not in config:
        config["max_tool_iterations"] = 2

    # Pass 1: Initial extraction
    tracker.set_stage("SpanFinder")
    span_finder = OptimizedSpanFinder(score_threshold=config.get("span_score_threshold", 0.8))
    span_finder.run(mem, config)
    
    # Limit spans for performance
    max_spans = config.get("max_spans", 10)
    if len(mem.spans) > max_spans:
        # Keep only highest scoring spans
        mem.spans = sorted(mem.spans, key=lambda x: x.get("score", 0), reverse=True)[:max_spans]
    
    tracker.set_spans_total(len(mem.spans))
    
    # Skip if no spans found
    if not mem.spans:
        tracker.set_stage("Assembler")
        result = AssemblerAgent().run(mem, config)
        result["metrics"] = tracker.snapshot()
        return result

    tracker.set_stage("Retriever")
    RetrieverAgent().run(mem, config)

    # Skip discovery if disabled
    if not config.get("disable_discovery", False):
        tracker.set_stage("Discovery")
        # Only run discovery if retrieval didn't find good matches
        avg_score = sum(c.get("score", 0) for candidates in mem.candidates.values() 
                       for c in candidates) / max(1, sum(len(c) for c in mem.candidates.values()))
        if avg_score < 0.7:  # Low retrieval confidence
            DiscoveryAgent().run(mem, config)
    else:
        # Skip discovery entirely
        tracker.log("info", "discovery_skipped", reason="disabled")

    tracker.set_stage("Mapper")
    if config.get("use_batch_mapper", True):
        # Use optimized batch mapper
        BatchMapperAgent().run(mem, config)
    else:
        # Fallback to sequential mapper
        MapperAgent().run(mem, config)
    
    tracker.spans_processed = len({c.get("span_idx", -1) for c in mem.claims if c.get("span_idx", -1) >= 0})

    # Skip verification if configured for speed
    if not config.get("skip_verification", False):
        tracker.set_stage("Verifier")
        before = len(mem.claims)
        EvidenceVerifierAgent().run(mem, config)
        tracker.counters["verified_claims"] = len(mem.claims)
        tracker.log("info", "claims_verified", before=before, after=len(mem.claims))
    else:
        tracker.counters["verified_claims"] = len(mem.claims)

    tracker.set_stage("Consolidator")
    ConsolidatorAgent().run(mem, config)
    tracker.counters["techniques"] = len(mem.techniques)

    # Skip targeted extraction if disabled or enough techniques found
    if not config.get("disable_targeted_extraction", True):
        tracker.set_stage("Suggestions")
        KillChainSuggestionsAgent().run(mem, config)
        
        # Only do targeted extraction if very few techniques found
        if len(mem.techniques) < 2 and hasattr(mem, "inferred_suggestions"):
            missing_tactics = [s["tactic"] for s in mem.inferred_suggestions][:3]  # Limit to 3 tactics
            if missing_tactics:
                tracker.log("info", "targeted_extraction_start", missing=len(missing_tactics))
                _run_limited_targeted_extraction(mem, missing_tactics, config)
                
                # Quick re-process of new spans only
                new_span_start = tracker.spans_total
                tracker.set_spans_total(len(mem.spans))
                
                if len(mem.spans) > new_span_start:
                    # Process only new spans
                    tracker.set_stage("Mapper")
                    if config.get("use_batch_mapper", True):
                        BatchMapperAgent().run(mem, config)
                    else:
                        MapperAgent().run(mem, config)
                    
                    tracker.set_stage("Consolidator")
                    ConsolidatorAgent().run(mem, config)

    # Pass 3: Final assembly
    tracker.set_stage("Assembler")
    result = AssemblerAgent().run(mem, config)
    result["metrics"] = tracker.snapshot()
    
    # Convert techniques to claims format for backward compatibility
    claims = []
    for tid, info in mem.techniques.items():
        claims.append({
            "technique_id": tid,
            "technique_name": info.get("name", tid),
            "confidence": info.get("confidence", 50),
            "evidence": {
                "quotes": info.get("evidence", []),
                "line_refs": info.get("line_refs", [])
            }
        })
    
    # Also add claims directly from mem.claims if not consolidated
    if not claims and mem.claims:
        for claim in mem.claims:
            claims.append({
                "technique_id": claim.get("external_id", ""),
                "technique_name": claim.get("name", ""),
                "confidence": claim.get("confidence", 50),
                "evidence": {
                    "quotes": claim.get("quotes", []),
                    "line_refs": claim.get("line_refs", [])
                }
            })
    
    # Fallback: Convert top discovery candidates to claims if nothing else worked
    if not claims and mem.candidates:
        print(f"[DEBUG] No claims found, converting {len(mem.candidates)} candidate sets to claims")
        seen_techniques = set()
        for span_idx, candidates in mem.candidates.items():
            for cand in candidates[:5]:  # Take top 5 per span
                tid = cand.get("external_id", "")
                if tid and tid not in seen_techniques:
                    seen_techniques.add(tid)
                    claims.append({
                        "technique_id": tid,
                        "technique_name": cand.get("name", tid),
                        "confidence": cand.get("confidence", 50),
                        "evidence": {
                            "quotes": [mem.spans[span_idx]["text"][:200]] if span_idx < len(mem.spans) else [],
                            "line_refs": mem.spans[span_idx].get("line_refs", []) if span_idx < len(mem.spans) else []
                        }
                    })
    
    result["claims"] = claims
    return result


class OptimizedSpanFinder:
    """Optimized span finder with deduplication and higher threshold."""
    
    def __init__(self, score_threshold: float = 0.8):
        from bandjacks.llm.agents_v2 import SpanFinderAgent
        self.base_finder = SpanFinderAgent()
        self.score_threshold = score_threshold
    
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        # Run base span finder
        self.base_finder.run(mem, config)
        
        # Filter by score threshold
        mem.spans = [s for s in mem.spans if s.get("score", 0) >= self.score_threshold]
        
        # Deduplicate overlapping spans
        if len(mem.spans) > 1:
            mem.spans = self._deduplicate_spans(mem.spans)
    
    def _deduplicate_spans(self, spans):
        """Remove overlapping spans, keeping highest scoring ones."""
        if not spans:
            return spans
            
        # Sort by score descending
        sorted_spans = sorted(spans, key=lambda x: x.get("score", 0), reverse=True)
        kept_spans = []
        used_lines = set()
        
        for span in sorted_spans:
            line_refs = set(span.get("line_refs", []))
            
            # Check overlap
            if not line_refs.intersection(used_lines):
                kept_spans.append(span)
                used_lines.update(line_refs)
            elif len(line_refs - used_lines) >= 2:  # Keep if at least 2 new lines
                kept_spans.append(span)
                used_lines.update(line_refs)
        
        return kept_spans


def _run_limited_targeted_extraction(mem: WorkingMemory, missing_tactics: list, config: Dict[str, Any]) -> None:
    """Limited targeted extraction for only the most important missing tactics."""
    import re
    
    # Only search for most important tactics
    priority_tactics = ["execution", "persistence", "lateral-movement", "exfiltration"]
    tactics_to_search = [t for t in missing_tactics if t in priority_tactics][:2]  # Max 2
    
    if not tactics_to_search:
        return
    
    # Tactic-specific keywords
    tactic_keywords = {
        "execution": ["execute", "run", "script", "powershell", "cmd"],
        "persistence": ["persist", "startup", "registry", "scheduled"],
        "lateral-movement": ["lateral", "rdp", "ssh", "remote", "pivot"],
        "exfiltration": ["exfiltrate", "transfer", "upload", "send"]
    }
    
    added_spans = 0
    max_new_spans = 3
    
    for tactic in tactics_to_search:
        if added_spans >= max_new_spans:
            break
            
        keywords = tactic_keywords.get(tactic, [])
        if not keywords:
            continue
            
        pattern = re.compile(r"\b(" + "|".join(keywords) + r")\b", re.I)
        
        for idx, line in enumerate(mem.line_index):
            if added_spans >= max_new_spans:
                break
                
            if pattern.search(line) and line.strip():
                # Check if line not already covered
                line_num = idx + 1
                already_covered = any(line_num in s.get("line_refs", []) for s in mem.spans)
                
                if not already_covered:
                    mem.spans.append({
                        "text": line.strip(),
                        "line_refs": [line_num],
                        "score": 0.85,
                        "tactics": [tactic],
                        "targeted": True
                    })
                    added_spans += 1