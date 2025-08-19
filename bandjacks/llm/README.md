# LLM Module Structure

This directory contains the LLM-based extraction and analysis components for Bandjacks.

## Production Files

### Core Extraction Pipeline (Legacy)
- `extractor.py` - Main LLM extractor using tool-grounded approach
- `prompts.py` - System and user prompts for extraction
- `schemas.py` - JSON schemas for LLM output validation
- `client.py` - LiteLLM client wrapper for model access

### Agentic v2 Pipeline (New)
- `agentic_v2.py` - Multi-pass orchestrator for agent pipeline
- `agents_v2.py` - Specialized agents (SpanFinder, Retriever, Discovery, Mapper, etc.)
- `memory.py` - Shared working memory for agent coordination

### STIX & Graph Integration
- `stix_builder.py` - Converts extraction results to STIX 2.1 bundles
- `bundle_validator.py` - Validates STIX bundles before graph upsert
- `entity_resolver.py` - Resolves entities to existing KB entries
- `provenance_tracker.py` - Tracks extraction provenance and lineage

### Attack Flows
- `flow_builder.py` - Builds attack flows from extraction results
- `flows.py` - LLM-based flow synthesis and sequencing
- `opportunities.py` - Opportunity analysis for defense recommendations

### Tools & Utilities
- `tools.py` - Tool adapters for LLM to interact with APIs
- `__init__.py` - Package initialization

## Experimental Code

The `experimental/` subdirectory contains:
- Alternative extraction approaches that were tested
- Removed/deprecated files for reference
- Experimental prompting strategies

These files are preserved for reference but are not used in production.

## Usage

### Using the Agentic v2 Pipeline (Recommended)

```python
from bandjacks.llm.agentic_v2 import run_agentic_v2

config = {
    "neo4j_uri": "bolt://localhost:7687",
    "neo4j_user": "neo4j",
    "neo4j_password": "password",
    "model": "gemini/gemini-2.5-flash",
    "title": "Report Title",
}

result = run_agentic_v2(report_text, config)
techniques = result["techniques"]  # Extracted techniques with evidence
bundle = result["bundle"]  # STIX 2.1 bundle ready for graph upsert
```

### Using the Legacy Pipeline

```python
from bandjacks.llm.extractor import LLMExtractor

extractor = LLMExtractor()
result = extractor.extract_document(
    source_id="doc-1",
    source_type="pdf",
    inline_text=document_text
)
```

## Performance

The agentic v2 pipeline is retrieval-first and evidence-anchored. Actual
runtime depends on report size and configuration knobs.

- Small reports (5–10 pages): ~3–8 minutes
- Medium reports (10–25 pages): ~8–20 minutes
- Large reports (>25 pages): 20–30+ minutes unless capped

Speed levers (recommended defaults):
- top_k=5 in Retriever; limit max spans to ~30 highest-score spans
- DiscoveryAgent disabled for large docs (or max_discovery_per_span=1)
- Tool loop iterations=3; LLM timeout ~20s
- Evidence min_quotes=2

Output quality targets (typical):
- Techniques extracted: 10–25 per report (varies by content)
- Kill chain coverage: 5–8 tactics when evidence present

The orchestrator now returns a `metrics` snapshot for transparency: stage,
percent, spans_total/processed, verified_claims, techniques, duration.

---

## Extractor v2 Execution Flow & Transparency

### Stages
1. SpanFinder: Detects behavioral spans (with section-aware priors) and line refs
2. Retriever: Semantic search for `AttackPattern` candidates (`top_k`)
3. Discovery (optional): LLM proposes techniques from text (free-propose)
4. Mapper: Selects one technique (candidate or proposed) + quotes + line_refs
5. Evidence Verifier: Verifies quotes in document (±2 line window) and technique resolution
6. Consolidator: Merges claims into techniques; calibrates confidence
7. KillChain Suggestions: Notes missing tactics (no auto-commit)
8. Assembler: Builds STIX 2.1 bundle and Attack Flow

### WorkingMemory (shared state)
- spans: `{text, line_refs, score, tactics?, prior}`
- candidates: per-span `{external_id, name, score, rank?, meta?, source}`
- claims: `{span_idx, external_id, name, quotes[], line_refs[], confidence, source}`
- techniques: `external_id -> {name, confidence, evidence[], line_refs[], tactic?, claim_count}`
- graph_cache, notes

### Tools (grounding)
- vector_search_ttx, graph_lookup, list_tactics,
  resolve_technique_by_external_id, list_techniques_for_tactic, list_subtechniques

### Evidence & confidence policy
- Acceptance requires: resolvable `external_id` and valid quotes/line_refs
- Confidence calibration considers: quotes density, consensus, evidence score,
  candidate rank (top-3 boost), and span prior

### Transparency & metrics
- Internals recorded by `ExtractionTracker` and returned as `result["metrics"]`:
  - stage, percent, spans_total, spans_processed
  - counters: llm_calls (placeholder), candidates, verified_claims, techniques, spans_found
  - dur_sec, cost_usd (placeholder), recent events

---

## Configuration Knobs (via `config` in `run_agentic_v2`)
- `top_k`: retrieval candidates (default 8; use 5 for speed)
- `disable_discovery`: bool (default false) — skip Discovery on large docs
- `max_discovery_per_span`: int (default 1–3)
- `min_quotes`: int (default 2)
- LLM/runtime via env: `LITELLM_TIMEOUT_MS` (~20000), `PRIMARY_LLM`, `GOOGLE_MODEL`