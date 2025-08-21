"""Async extraction pipeline with parallel processing for maximum performance."""

import asyncio
from typing import Any, Dict, List
import hashlib
import json

from bandjacks.llm.memory import WorkingMemory
from bandjacks.llm.agents_v2 import (
    SpanFinderAgent,
    RetrieverAgent,
    DiscoveryAgent,
    EvidenceVerifierAgent,
    ConsolidatorAgent,
    KillChainSuggestionsAgent,
    AssemblerAgent,
)
from bandjacks.llm.mapper_optimized import BatchMapperAgent
from bandjacks.llm.tracker import ExtractionTracker
from bandjacks.llm.client import LLMClient


class AsyncRetrieverAgent:
    """Async version of RetrieverAgent for parallel processing."""
    
    def __init__(self):
        self.base_agent = RetrieverAgent()
    
    async def process_span(self, span_idx: int, span: Dict, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        """Process a single span asynchronously."""
        from bandjacks.llm.tools import vector_search_ttx
        from bandjacks.llm.agents_v2 import _hinted_query
        
        top_k = int(config.get("top_k", 8))
        
        # Run vector search in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            None,
            vector_search_ttx,
            _hinted_query(span["text"]),
            ["AttackPattern"],
            top_k
        )
        
        mem.candidates.setdefault(span_idx, [])
        seen = {c.get("external_id") for c in mem.candidates[span_idx]}
        
        for rank, r in enumerate(results[:top_k], start=1):
            ext_id = r.get("external_id") or r.get("id")
            if not ext_id or ext_id in seen:
                continue
                
            mem.candidates[span_idx].append({
                "external_id": ext_id,
                "name": r.get("name", ""),
                "score": r.get("score", 0.0),
                "rank": rank,
                "source": "retrieval",
            })
            seen.add(ext_id)
    
    async def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        """Process all spans in parallel."""
        tasks = []
        for i, span in enumerate(mem.spans):
            task = self.process_span(i, span, mem, config)
            tasks.append(task)
        
        # Process all spans concurrently
        await asyncio.gather(*tasks)


class OptimizedSpanFinder:
    """Optimized span finder with deduplication and higher threshold."""
    
    def __init__(self, score_threshold: float = 0.8):
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


class SinglePassExtractor:
    """Extract techniques from small documents in a single LLM call."""
    
    def __init__(self):
        self.client = LLMClient()
        self.cache = {}  # Simple in-memory cache
    
    def _get_cache_key(self, content: str) -> str:
        """Generate cache key from content."""
        return hashlib.md5(content.encode()).hexdigest()
    
    async def extract(self, content: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Extract all techniques in one pass for small documents."""
        
        # Check cache first
        cache_key = self._get_cache_key(content)
        if cache_key in self.cache:
            print(f"[DEBUG] Cache hit for content hash {cache_key}")
            return self.cache[cache_key]
        
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a MITRE ATT&CK expert. Extract all attack techniques from the text.\n\n"
                    "For each technique found, provide:\n"
                    "1. ATT&CK ID (e.g., T1059.001)\n"
                    "2. Technique name\n"
                    "3. Direct quote from text as evidence\n"
                    "4. Confidence score (0-100)\n\n"
                    "Return JSON array:\n"
                    "[{\"id\": \"Txxxx\", \"name\": \"...\", \"evidence\": \"...\", \"confidence\": 95}]\n\n"
                    "Be precise. Only extract techniques explicitly described in the text."
                )
            },
            {
                "role": "user",
                "content": f"Extract techniques from:\n\n{content}"
            }
        ]
        
        # Run in executor to avoid blocking
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            self.client.call,
            messages
        )
        
        result_text = response.get("content", "")
        
        # Parse JSON from response
        if "```json" in result_text:
            result_text = result_text.split("```json")[1].split("```")[0]
        elif "```" in result_text:
            result_text = result_text.split("```")[1].split("```")[0]
        
        try:
            techniques = json.loads(result_text)
            result = {"techniques": techniques, "source": "single_pass"}
            
            # Cache the result
            self.cache[cache_key] = result
            
            return result
        except:
            return {"techniques": [], "source": "single_pass", "error": "Failed to parse"}


async def run_agentic_v2_async(
    report_text: str,
    config: Dict[str, Any],
    tracker: ExtractionTracker | None = None
) -> Dict[str, Any]:
    """Async extraction pipeline with parallel processing and optimizations.
    
    Config options:
    - single_pass_threshold: Max tokens for single-pass extraction (default: 500)
    - use_async_retriever: Use parallel retriever (default: True)
    - cache_llm_responses: Cache LLM responses (default: True)
    - early_termination_confidence: Skip verification above this (default: 90)
    """
    
    tracker = tracker or ExtractionTracker()
    
    # Check if document is small enough for single-pass
    word_count = len(report_text.split())
    single_pass_threshold = config.get("single_pass_threshold", 500)
    
    if word_count < single_pass_threshold:
        # Use single-pass extraction for small documents
        tracker.set_stage("SinglePass")
        tracker.log("info", "single_pass_mode", word_count=word_count)
        
        extractor = SinglePassExtractor()
        result = await extractor.extract(report_text, config)
        
        # Convert to standard format
        techniques = {}
        for tech in result.get("techniques", []):
            tech_id = tech.get("id", "")
            if tech_id:
                techniques[tech_id] = {
                    "name": tech.get("name", ""),
                    "confidence": tech.get("confidence", 50),
                    "evidence": [tech.get("evidence", "")],
                    "line_refs": [],
                    "tactic": "",
                    "claim_count": 1
                }
        
        tracker.set_stage("Complete")
        return {
            "techniques": techniques,
            "bundle": {"type": "bundle", "objects": []},
            "flow": {},
            "notes": ["Single-pass extraction used"],
            "metrics": tracker.snapshot()
        }
    
    # Standard pipeline for larger documents
    mem = WorkingMemory(document_text=report_text, line_index=report_text.splitlines())
    
    # Apply optimization defaults
    if "span_score_threshold" not in config:
        config["span_score_threshold"] = 0.8
    if "max_spans" not in config:
        config["max_spans"] = 10
    if "use_batch_mapper" not in config:
        config["use_batch_mapper"] = True
    if "disable_targeted_extraction" not in config:
        config["disable_targeted_extraction"] = True
    
    # Phase 1: Span finding
    tracker.set_stage("SpanFinder")
    span_finder = OptimizedSpanFinder(score_threshold=config.get("span_score_threshold", 0.8))
    span_finder.run(mem, config)
    
    # Limit spans
    max_spans = config.get("max_spans", 10)
    if len(mem.spans) > max_spans:
        mem.spans = sorted(mem.spans, key=lambda x: x.get("score", 0), reverse=True)[:max_spans]
    
    tracker.set_spans_total(len(mem.spans))
    
    if not mem.spans:
        tracker.set_stage("Complete")
        result = AssemblerAgent().run(mem, config)
        result["metrics"] = tracker.snapshot()
        return result
    
    # Phase 2: Parallel retrieval
    tracker.set_stage("Retriever")
    if config.get("use_async_retriever", True):
        # Use async parallel retriever
        async_retriever = AsyncRetrieverAgent()
        await async_retriever.run(mem, config)
    else:
        # Fallback to synchronous
        RetrieverAgent().run(mem, config)
    
    # Phase 3: Discovery (if needed)
    if not config.get("disable_discovery", False):
        tracker.set_stage("Discovery")
        # Check if discovery is needed based on retrieval scores
        avg_score = sum(c.get("score", 0) for candidates in mem.candidates.values() 
                       for c in candidates) / max(1, sum(len(c) for c in mem.candidates.values()))
        if avg_score < 0.7:
            DiscoveryAgent().run(mem, config)
    
    # Phase 4: Mapping
    tracker.set_stage("Mapper")
    if config.get("use_batch_mapper", True):
        BatchMapperAgent().run(mem, config)
    else:
        from bandjacks.llm.agents_v2 import MapperAgent
        MapperAgent().run(mem, config)
    
    tracker.spans_processed = len({c.get("span_idx", -1) for c in mem.claims if c.get("span_idx", -1) >= 0})
    
    # Phase 5: Verification (with early termination)
    early_termination_confidence = config.get("early_termination_confidence", 90)
    
    if not config.get("skip_verification", False):
        tracker.set_stage("Verifier")
        before = len(mem.claims)
        
        # Filter claims for verification
        claims_to_verify = []
        claims_to_keep = []
        
        for claim in mem.claims:
            if claim.get("confidence", 0) >= early_termination_confidence:
                # Skip verification for high-confidence claims
                claims_to_keep.append(claim)
            else:
                claims_to_verify.append(claim)
        
        # Only verify low-confidence claims
        mem.claims = claims_to_verify
        if claims_to_verify:
            EvidenceVerifierAgent().run(mem, config)
        
        # Combine verified and high-confidence claims
        mem.claims.extend(claims_to_keep)
        
        tracker.counters["verified_claims"] = len(mem.claims)
        tracker.log("info", "claims_verified", before=before, after=len(mem.claims), skipped=len(claims_to_keep))
    
    # Phase 6: Consolidation
    tracker.set_stage("Consolidator")
    ConsolidatorAgent().run(mem, config)
    tracker.counters["techniques"] = len(mem.techniques)
    
    # Skip targeted extraction if disabled or enough techniques found
    if not config.get("disable_targeted_extraction", True) and len(mem.techniques) < 2:
        tracker.set_stage("Suggestions")
        KillChainSuggestionsAgent().run(mem, config)
        # Limited targeted extraction logic here if needed
    
    # Phase 7: Assembly
    tracker.set_stage("Assembler")
    result = AssemblerAgent().run(mem, config)
    result["metrics"] = tracker.snapshot()
    
    return result


def run_extraction_async(report_text: str, config: Dict[str, Any], tracker: ExtractionTracker | None = None) -> Dict[str, Any]:
    """Wrapper to run async extraction in sync context."""
    return asyncio.run(run_agentic_v2_async(report_text, config, tracker))