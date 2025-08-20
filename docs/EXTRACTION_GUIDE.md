# Extraction Pipeline Guide

## Overview

The Bandjacks extraction pipeline uses advanced LLM-based techniques to extract MITRE ATT&CK techniques from threat intelligence reports. The system now features a high-performance async pipeline that processes documents in 12-40 seconds, a 94% improvement over earlier versions.

## Pipeline Architecture

### Available Pipelines

1. **Async Pipeline (Default)** - Recommended for production
   - Performance: 12-40 seconds typical
   - Features: Parallel processing, single-pass for small docs, LLM caching
   - Best for: All document sizes, production deployments

2. **Optimized Pipeline (Fallback)** - Synchronous alternative
   - Performance: 30-60 seconds typical
   - Features: Batch mapping, span optimization
   - Best for: When async not available, debugging

## Quick Start

### Via API (Recommended)

```python
import requests
import time

# Start extraction
response = requests.post(
    "http://localhost:8000/v1/extract/runs",
    json={
        "method": "agentic_v2",
        "content": "Your threat report text here...",
        "title": "APT Report Analysis"
    }
)
run_id = response.json()["run_id"]

# Poll for completion
while True:
    status = requests.get(f"http://localhost:8000/v1/extract/runs/{run_id}/status")
    if status.json()["state"] == "finished":
        break
    time.sleep(1)

# Get results
result = requests.get(f"http://localhost:8000/v1/extract/runs/{run_id}/result")
techniques = result.json()["techniques"]
```

### Via Python Module

```python
from bandjacks.llm.agentic_v2_async import run_agentic_v2_async
import asyncio

# Simple extraction
result = asyncio.run(run_agentic_v2_async(
    report_text="Your report text...",
    config={}  # Uses optimized defaults
))

techniques = result["techniques"]
bundle = result["bundle"]  # STIX 2.1 bundle
```

## Configuration Options

### Performance Profiles

#### Fast Extraction (4-15 seconds)
Best for: Quick analysis, development, testing

```json
{
  "use_async": true,
  "single_pass_threshold": 1000,
  "max_spans": 5,
  "span_score_threshold": 0.9,
  "skip_verification": true,
  "top_k": 3,
  "cache_llm_responses": true
}
```

#### Balanced (12-40 seconds) - DEFAULT
Best for: Production, most use cases

```json
{
  "use_async": true,
  "single_pass_threshold": 500,
  "max_spans": 10,
  "span_score_threshold": 0.8,
  "early_termination_confidence": 90,
  "top_k": 5,
  "cache_llm_responses": true
}
```

#### High Quality (40-120 seconds)
Best for: Critical analysis, comprehensive extraction

```json
{
  "use_async": true,
  "single_pass_threshold": 200,
  "max_spans": 20,
  "span_score_threshold": 0.6,
  "skip_verification": false,
  "disable_discovery": false,
  "top_k": 10,
  "min_quotes": 3
}
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `use_async` | bool | `true` | Use async pipeline (recommended) |
| `single_pass_threshold` | int | `500` | Max words for single-pass extraction |
| `cache_llm_responses` | bool | `true` | Enable LLM response caching |
| `max_spans` | int | `10` | Maximum text spans to process |
| `span_score_threshold` | float | `0.8` | Minimum quality score for spans |
| `early_termination_confidence` | int | `90` | Skip verification above this confidence |
| `top_k` | int | `5` | Number of candidate techniques per span |
| `skip_verification` | bool | `false` | Skip evidence verification (faster) |
| `disable_discovery` | bool | `false` | Skip discovery agent |
| `disable_targeted_extraction` | bool | `true` | Skip second-pass extraction |
| `min_quotes` | int | `2` | Minimum evidence quotes required |
| `use_batch_mapper` | bool | `true` | Process all spans in one LLM call |

## Processing Stages

### 1. Document Analysis
- Determines if document qualifies for single-pass extraction
- Threshold: <500 words (configurable)

### 2. Single-Pass Extraction (Small Documents)
- Entire document processed in one LLM call
- Performance: 4-8 seconds
- Best for: Executive summaries, alerts, short reports

### 3. Multi-Stage Pipeline (Larger Documents)

#### Stage 1: Span Finding
- Identifies behavioral text segments
- Scores and ranks spans by relevance
- Deduplicates overlapping content

#### Stage 2: Retrieval (Parallel)
- Vector search for ATT&CK techniques
- Processes all spans concurrently
- Returns top-k candidates per span

#### Stage 3: Mapping (Batch)
- Maps spans to techniques in single LLM call
- Extracts evidence quotes
- Assigns confidence scores

#### Stage 4: Verification
- Validates evidence in source text
- Resolves technique IDs
- Filters low-confidence claims

#### Stage 5: Consolidation
- Merges duplicate techniques
- Aggregates evidence
- Calibrates final confidence

#### Stage 6: Assembly
- Builds STIX 2.1 bundle
- Generates attack flow
- Compiles metrics

## Performance Optimization

### Caching

The pipeline includes automatic LLM response caching:

```python
# Check cache statistics
response = requests.get("http://localhost:8000/v1/cache/stats")
print(response.json())
# {"hits": 42, "misses": 15, "hit_rate": "73.7%", "size": 54}

# Clear cache when needed
requests.post("http://localhost:8000/v1/cache/clear")
```

Benefits:
- 87.5% speedup on repeated extractions
- 15-minute TTL (configurable)
- Thread-safe implementation

### Batch Processing

Enable batch processing for multiple documents:

```python
documents = ["doc1.txt", "doc2.txt", "doc3.txt"]
results = []

for doc in documents:
    response = requests.post(
        "http://localhost:8000/v1/extract/runs",
        json={
            "method": "agentic_v2",
            "content": read_file(doc),
            "config": {"cache_llm_responses": true}
        }
    )
    results.append(response.json()["run_id"])

# Process results...
```

## Monitoring & Metrics

### Extraction Metrics

Each extraction returns detailed metrics:

```json
{
  "metrics": {
    "run_id": "ex-abc123",
    "dur_sec": 15.3,
    "stage": "Complete",
    "percent": 100,
    "spans_total": 10,
    "spans_processed": 10,
    "counters": {
      "techniques": 12,
      "verified_claims": 15,
      "llm_calls": 3
    },
    "stage_timings": {
      "SpanFinder": 2.1,
      "AsyncRetriever": 3.5,
      "BatchMapper": 4.2,
      "Verifier": 2.8,
      "Consolidator": 1.5,
      "Assembler": 1.2
    }
  }
}
```

### Progress Tracking

Monitor extraction progress in real-time:

```python
while True:
    status = requests.get(f"http://localhost:8000/v1/extract/runs/{run_id}/status")
    data = status.json()
    
    print(f"Stage: {data['stage']}")
    print(f"Progress: {data['percent']}%")
    print(f"Spans: {data['spans_processed']}/{data['spans_total']}")
    
    if data["state"] == "finished":
        break
    time.sleep(1)
```

## Document Types

### Supported Formats
- **Text**: Plain text, Markdown
- **PDF**: Via pdfplumber extraction
- **HTML**: Automatic text extraction
- **JSON**: Structured threat feeds
- **CSV**: Indicator lists

### Optimal Document Sizes
- **Small** (<500 words): Single-pass extraction, 4-8 seconds
- **Medium** (500-2000 words): Full pipeline, 12-40 seconds
- **Large** (>2000 words): Span-limited processing, 40-120 seconds

### PDF Processing

For PDF documents, install pdfplumber:

```bash
UV_LINK_MODE=copy uv add pdfplumber
```

Then extract:

```python
import pdfplumber

def extract_pdf_text(pdf_path):
    text_parts = []
    with pdfplumber.open(pdf_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                text_parts.append(text)
    return "\n\n".join(text_parts)

pdf_text = extract_pdf_text("report.pdf")
# Now use pdf_text with the extraction API
```

## Quality Assurance

### Confidence Thresholds

Techniques are assigned confidence scores:
- **95-100%**: High confidence, strong evidence
- **85-94%**: Good confidence, clear evidence
- **75-84%**: Moderate confidence, some evidence
- **<75%**: Low confidence, may need review

### Evidence Requirements

Each technique requires:
- Minimum 2 evidence quotes (configurable)
- Line references for traceability
- Resolvable ATT&CK ID

### Validation

Results include evidence for verification:

```python
for tech_id, tech in techniques.items():
    print(f"{tech_id}: {tech['name']}")
    print(f"Confidence: {tech['confidence']}%")
    print(f"Evidence:")
    for quote in tech['evidence']:
        print(f"  - {quote}")
    print(f"Line refs: {tech['line_refs']}")
```

## Troubleshooting

### Common Issues

#### Slow Extraction
- Increase `span_score_threshold` to process fewer spans
- Reduce `max_spans` limit
- Enable `skip_verification` for speed
- Ensure caching is enabled

#### Low Quality Results
- Decrease `span_score_threshold` for more spans
- Increase `top_k` for more candidates
- Enable discovery agent
- Increase `min_quotes` requirement

#### Cache Not Working
- Check cache stats: `GET /v1/cache/stats`
- Verify `cache_llm_responses: true` in config
- Clear stale cache: `POST /v1/cache/clear`

#### Memory Issues
- Limit document size to 10,000 characters
- Reduce `max_spans` to 5-10
- Process documents sequentially, not in parallel

### Debug Mode

Enable detailed logging:

```python
config = {
    "debug": true,  # Enable debug output
    "track_metrics": true  # Detailed metrics
}
```

## Best Practices

1. **Always enable caching** for development and testing
2. **Use async pipeline** for production deployments
3. **Start with balanced config** and tune as needed
4. **Monitor metrics** to identify bottlenecks
5. **Batch similar documents** to maximize cache hits
6. **Truncate very large documents** to first 10,000 characters
7. **Review low-confidence results** (<85%) manually
8. **Clear cache periodically** in production (daily/weekly)

## API Reference

See [API Documentation](API_DOCUMENTATION.md#document-extraction) for complete endpoint details.

## Performance Benchmarks

| Document | Words | Techniques | Original | Optimized | Async | Improvement |
|----------|-------|-----------|----------|-----------|--------|-------------|
| Small Alert | 126 | 3 | 228s | 32s | 12.7s | 94.4% |
| Medium Report | 1,493 | 12 | N/A | 45s | 36.1s | N/A |
| Large Analysis | 3,000 | 25 | N/A | 120s | 85s | N/A |

## Conclusion

The Bandjacks extraction pipeline provides state-of-the-art performance for threat intelligence extraction. With the async pipeline as default, most documents process in under 40 seconds while maintaining high extraction quality. The combination of parallel processing, intelligent caching, and configurable optimization makes it suitable for both development and production use cases.