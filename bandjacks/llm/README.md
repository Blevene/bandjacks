# LLM Module Structure

This directory contains the LLM-based extraction and analysis components for Bandjacks.

## Production Files

### Core Extraction Pipelines

#### Async Pipeline (Default - Recommended)
- `agentic_v2_async.py` - High-performance async extraction with parallel processing
- **Performance**: 12-40 seconds for most documents
- **Features**: Single-pass for small docs, parallel span processing, LLM caching

#### Optimized Pipeline (Fallback)
- `agentic_v2_optimized.py` - Synchronous optimized pipeline
- **Performance**: 30-60 seconds typical
- **Features**: Batch mapping, span deduplication, configurable thresholds

#### Core Components
- `agents_v2.py` - Specialized agents (SpanFinder, Retriever, Discovery, Mapper, etc.)
- `memory.py` - Shared working memory for agent coordination
- `mapper_optimized.py` - Batch mapper for single LLM call processing
- `cache.py` - Thread-safe LLM response caching with TTL support
- `client.py` - LiteLLM client wrapper with caching integration
- `tracker.py` - Extraction metrics and progress tracking

### STIX & Graph Integration
- `stix_builder.py` - Converts extraction results to STIX 2.1 bundles
- `stix_converter.py` - Merges LLM and vector extraction results
- `bundle_validator.py` - Validates STIX bundles before graph upsert
- `entity_resolver.py` - Resolves entities to existing KB entries
- `provenance_tracker.py` - Tracks extraction provenance and lineage

### Attack Flows
- `flow_builder.py` - Builds attack flows from extraction results
- `flows.py` - LLM-based flow synthesis and sequencing
- `opportunities.py` - Opportunity analysis for defense recommendations

### Tools & Utilities
- `tools.py` - Tool adapters for LLM to interact with APIs
- `prompts.py` - System and user prompts for extraction
- `schemas.py` - JSON schemas for LLM output validation

## Usage

### Using the Async Pipeline (Default - Recommended)

```python
from bandjacks.llm.agentic_v2_async import run_agentic_v2_async
import asyncio

config = {
    "use_async": True,  # Default
    "single_pass_threshold": 500,  # Use single-pass for small docs
    "cache_llm_responses": True,  # Enable caching
    "early_termination_confidence": 90,  # Skip verification above this
    "max_spans": 20,
    "span_score_threshold": 0.7,
    "top_k": 5
}

# Run async extraction
result = asyncio.run(run_agentic_v2_async(report_text, config))
techniques = result["techniques"]  # Extracted techniques with evidence
bundle = result["bundle"]  # STIX 2.1 bundle ready for graph upsert
metrics = result["metrics"]  # Performance metrics
```

### Using via API (Recommended for Production)

```python
import requests

# Start extraction (async by default)
response = requests.post(
    "http://localhost:8000/v1/extract/runs",
    json={
        "method": "agentic_v2",
        "content": report_text,
        "title": "Report Title",
        "config": {
            "use_async": True,  # Default
            "cache_llm_responses": True
        }
    }
)
run_id = response.json()["run_id"]

# Check status
status = requests.get(f"http://localhost:8000/v1/extract/runs/{run_id}/status")

# Get results when complete
if status.json()["state"] == "finished":
    result = requests.get(f"http://localhost:8000/v1/extract/runs/{run_id}/result")
    techniques = result.json()["techniques"]
```

### Using the Optimized Synchronous Pipeline

```python
from bandjacks.llm.agentic_v2_optimized import run_agentic_v2_optimized

config = {
    "use_batch_mapper": True,  # Single LLM call for all spans
    "disable_targeted_extraction": True,  # Skip second pass
    "max_spans": 10,
    "span_score_threshold": 0.8,
    "top_k": 5
}

result = run_agentic_v2_optimized(report_text, config)
```

## Performance

The async pipeline provides dramatic performance improvements over earlier versions:

### Performance by Document Size

| Document Size | Single-Pass | Async Pipeline | Optimized Pipeline |
|--------------|-------------|----------------|-------------------|
| Small (<500 words) | 4-8 seconds | N/A | 15-30 seconds |
| Medium (500-2000 words) | N/A | 12-40 seconds | 30-60 seconds |
| Large (>2000 words) | N/A | 40-120 seconds | 60-180 seconds |

### Key Performance Features

1. **Single-Pass Extraction**: Documents under threshold processed in one LLM call
2. **Parallel Processing**: All spans processed concurrently in async pipeline
3. **Batch Mapping**: Single LLM call processes all spans together
4. **LLM Response Caching**: 87.5% speedup on repeated extractions
5. **Early Termination**: Skip verification for high-confidence claims (>90%)
6. **Span Optimization**: Deduplication and quality filtering

### Configuration for Performance

```python
# Maximum performance (may reduce quality slightly)
fast_config = {
    "use_async": True,
    "single_pass_threshold": 1000,  # Higher threshold
    "max_spans": 5,  # Fewer spans
    "span_score_threshold": 0.9,  # Higher quality threshold
    "skip_verification": True,  # Skip verification
    "top_k": 3,  # Fewer candidates
    "cache_llm_responses": True
}

# Balanced performance and quality (recommended)
balanced_config = {
    "use_async": True,
    "single_pass_threshold": 500,
    "max_spans": 10,
    "span_score_threshold": 0.8,
    "early_termination_confidence": 90,
    "top_k": 5,
    "cache_llm_responses": True
}

# Maximum quality (slower)
quality_config = {
    "use_async": True,
    "single_pass_threshold": 200,  # Lower threshold
    "max_spans": 20,  # More spans
    "span_score_threshold": 0.6,  # Lower threshold
    "skip_verification": False,
    "disable_discovery": False,  # Enable discovery
    "top_k": 10,  # More candidates
    "min_quotes": 3  # More evidence required
}
```

## Cache Management

The LLM module includes built-in caching for improved performance:

```python
from bandjacks.llm.cache import get_cache_stats, clear_cache

# Get cache statistics
stats = get_cache_stats()
print(f"Cache hit rate: {stats['hit_rate']}")
print(f"Cache size: {stats['size']} entries")

# Clear cache when needed
clear_cache()
```

Via API:
```bash
# Get cache stats
curl http://localhost:8000/v1/cache/stats

# Clear cache
curl -X POST http://localhost:8000/v1/cache/clear
```

## Execution Flow

### Async Pipeline Stages
1. **Document Analysis**: Determine if single-pass applicable
2. **Single-Pass** (small docs): Extract all techniques in one LLM call
3. **SpanFinder** (larger docs): Detect behavioral spans with section-aware priors
4. **AsyncRetriever**: Parallel semantic search for candidates
5. **BatchMapper**: Map all spans to techniques in single LLM call
6. **EvidenceVerifier**: Verify quotes and technique resolution
7. **Consolidator**: Merge claims and calibrate confidence
8. **Assembler**: Build STIX bundle and attack flow

### Working Memory Structure
- `spans`: Behavioral text segments with scores and line references
- `candidates`: Per-span technique candidates from vector search
- `claims`: Mapped techniques with evidence and confidence
- `techniques`: Final consolidated techniques with aggregated evidence

## Quality Metrics

Typical extraction quality targets:
- **Techniques extracted**: 10-25 per report (varies by content)
- **Confidence scores**: 85-95% for well-evidenced techniques
- **Kill chain coverage**: 5-8 tactics when evidence present
- **False positive rate**: <10% with default thresholds

## Monitoring

The extraction tracker provides detailed metrics:

```python
result = await run_agentic_v2_async(text, config)
metrics = result["metrics"]

print(f"Run ID: {metrics['run_id']}")
print(f"Duration: {metrics['dur_sec']} seconds")
print(f"Spans processed: {metrics['spans_processed']}")
print(f"Techniques found: {metrics['counters']['techniques']}")
print(f"Stage timings: {metrics['stage_timings']}")
```

## Environment Variables

Key configuration via environment:
- `GOOGLE_API_KEY`: Gemini API key (primary LLM)
- `OPENAI_API_KEY`: OpenAI API key (fallback)
- `PRIMARY_LLM`: "gemini" or "openai" (default: "gemini")
- `GOOGLE_MODEL`: Gemini model name (default: "gemini-2.5-flash")
- `LITELLM_TIMEOUT_MS`: LLM timeout in milliseconds (default: 60000)
- `LITELLM_TEMPERATURE`: Temperature for LLM (default: 0.3)
- `LITELLM_MAX_TOKENS`: Max tokens for response (default: 8000)