# Report Processing Pipeline Documentation

## Overview

The Bandjacks report processing pipeline is a sophisticated system for extracting MITRE ATT&CK techniques from cyber threat intelligence reports. It intelligently routes documents through either synchronous or asynchronous processing based on size, uses advanced NLP and LLM techniques for extraction, and generates attack flows from the identified techniques.

## Architecture

### Processing Modes

The system automatically selects the appropriate processing mode based on document size:

| Document Size | Processing Mode | Response Time | Method |
|--------------|----------------|---------------|---------|
| < 10KB | Synchronous | 5-10 seconds | Direct extraction pipeline |
| 10-50KB | Asynchronous | 20-30 seconds | Chunked parallel processing |
| 50-200KB | Asynchronous | 30-60 seconds | Chunked with dynamic spans |
| > 200KB | Asynchronous | 60-120 seconds | Maximum chunking strategy |

### System Components

```
┌─────────────────┐
│   API Gateway   │
│  (FastAPI)      │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
┌───▼───┐ ┌──▼──────────┐
│ Sync  │ │   Async     │
│ Path  │ │   Queue     │
└───┬───┘ └──────┬──────┘
    │            │
    │     ┌──────▼──────┐
    │     │JobProcessor │
    │     │ (4 workers) │
    │     └──────┬──────┘
    │            │
    └────────────┴──────────┐
                            │
                    ┌───────▼────────┐
                    │  Extraction    │
                    │   Pipeline     │
                    └───────┬────────┘
                            │
                    ┌───────▼────────┐
                    │  Agent Chain   │
                    └───────┬────────┘
                            │
                    ┌───────▼────────┐
                    │  Flow Builder  │
                    └───────┬────────┘
                            │
                    ┌───────▼────────┐
                    │   Storage      │
                    │ (OpenSearch/   │
                    │   Neo4j)       │
                    └────────────────┘
```

## API Endpoints

### Synchronous Endpoints

#### `POST /v1/reports/ingest`
Processes text or URL content synchronously.

**Request:**
```json
{
  "text": "Report content here...",
  "name": "APT28 Campaign Report",
  "use_batch_mapper": true,
  "skip_verification": false
}
```

**Response:**
```json
{
  "report_id": "report--abc123",
  "techniques_count": 15,
  "provisional": false,
  "rubric": {"criteria_met": 3},
  "entities": {...},
  "extraction_metrics": {...}
}
```

#### `POST /v1/reports/ingest/upload`
Processes uploaded files synchronously (small files only).

**Form Data:**
- `file`: PDF/TXT/MD file (< 5KB content)
- `use_batch_mapper`: boolean
- `skip_verification`: boolean

### Asynchronous Endpoints

#### `POST /v1/reports/ingest_file_async`
Processes large files asynchronously with job tracking.

**Form Data:**
- `file`: PDF/TXT/MD file (any size)
- `use_batch_mapper`: boolean (default: true)
- `skip_verification`: boolean (default: false)
- `auto_generate_flow`: boolean (default: true)

**Response:**
```json
{
  "job_id": "job-abc123",
  "status": "queued",
  "progress": 0,
  "message": "File uploaded successfully, queued for processing"
}
```

#### `GET /v1/reports/jobs/{job_id}/status`
Check job processing status.

**Response:**
```json
{
  "job_id": "job-abc123",
  "status": "processing",
  "progress": 60,
  "message": "Processing chunk 3/6",
  "result": {
    "techniques_count": 12,
    "chunks_processed": 3
  }
}
```

## Processing Pipeline

### 1. Document Ingestion

The pipeline begins when a document is uploaded or text is submitted:

```python
# Entry point for file upload
async def ingest_file_async(file: UploadFile):
    # 1. Validate file type (.pdf, .txt, .md)
    # 2. Save to temporary disk location
    # 3. Create job in FileJobStore
    # 4. Return job_id immediately
```

### 2. Job Processing

Background workers continuously poll for queued jobs:

```python
class JobProcessor:
    async def _process_loop(self):
        while self.running:
            jobs = self.job_store.get_queued_jobs()
            for job_id in jobs:
                await self._process_job(job_id)
```

Key features:
- **Retry Logic**: 3 attempts with exponential backoff (10s, 20s, 40s)
- **Error Recovery**: Handles rate limits, timeouts, and service errors
- **Progress Tracking**: Real-time updates at each stage
- **Checkpoint Support**: Can resume from last successful stage

### 3. Text Extraction

PDF documents are converted to text using a two-tier approach:

```python
async def _extract_pdf_text(self, pdf_path: str) -> str:
    # Primary: pdfplumber for high-quality extraction
    # Fallback: PyPDF2 for compatibility
    return extracted_text
```

### 4. Processing Strategy Selection

The system dynamically selects processing strategy based on document size:

```python
def calculate_chunks_and_spans(text_length: int) -> Tuple[int, int, int]:
    if text_length < 10_000:      # Small docs
        max_chunks = 5
        spans_per_chunk = 15
    elif text_length < 50_000:    # Medium docs
        max_chunks = 15
        spans_per_chunk = 12
    elif text_length < 200_000:   # Large docs
        max_chunks = 30
        spans_per_chunk = 10
    else:                          # Very large docs
        max_chunks = 50
        spans_per_chunk = 8
```

### 5. Extraction Pipeline

#### Direct Pipeline (Small Documents)

For documents under 10KB, the entire text is processed at once:

```python
run_extraction_pipeline(
    report_text=text_content,
    config={
        "use_batch_mapper": True,
        "use_batch_retriever": True,
        "max_spans": 30,
        "disable_discovery": False,
        "disable_targeted_extraction": True
    }
)
```

#### Chunked Pipeline (Large Documents)

For larger documents, text is split into overlapping chunks:

```python
ChunkedExtractor(
    chunk_size=3000,      # Characters per chunk
    overlap=200,          # Overlap between chunks
    max_chunks=calculated_max,
    parallel_workers=3
).extract(text, config)
```

## Agent Chain

The extraction pipeline uses a chain of specialized agents:

### 1. SpanFinderAgent
**Purpose**: Identify text spans likely containing technique information

**Method**:
- Regex patterns for each MITRE tactic
- Behavioral pattern matching
- Score calculation (0.6-2.0)
- Multi-line context aggregation

**Output**: Ranked list of text spans with confidence scores

### 2. BatchRetrieverAgent
**Purpose**: Find candidate ATT&CK techniques for each span

**Method**:
- Groups all spans into single batch
- OpenSearch msearch for vector similarity
- Returns top-5 candidates per span
- 4x faster than sequential retrieval

**Output**: Candidate techniques with similarity scores

### 3. DiscoveryAgent (Optional)
**Purpose**: Find additional techniques when retrieval confidence is low

**Method**:
- Direct LLM analysis of spans
- No tool usage for efficiency
- Triggered when avg score < 0.7

**Output**: Additional technique suggestions

### 4. BatchMapperAgent
**Purpose**: Map spans to specific ATT&CK techniques

**Method**:
- Processes spans in batches of 5
- Single LLM call per batch
- Enforced JSON output format
- 16,000 token limit
- Extracts multiple techniques per span

**Output**: Technique claims with evidence

### 5. EvidenceVerifierAgent (Optional)
**Purpose**: Validate evidence quality

**Method**:
- Checks quote relevance
- Verifies line references
- Filters low-quality claims

**Output**: Verified claims only

### 6. ConsolidatorAgent
**Purpose**: Deduplicate and merge technique claims

**Method**:
- Groups by technique ID
- Deduplicates evidence quotes
- Calibrates confidence scores
- Keeps top 5 evidence per technique

**Output**: Consolidated technique list

### 7. AssemblerAgent
**Purpose**: Create STIX bundle

**Method**:
- Generates STIX 2.1 objects
- Creates attack-pattern objects
- Adds provenance metadata
- Links to report object

**Output**: Complete STIX bundle

## Attack Flow Generation

After extraction, the system generates attack flows:

### LLM-Based Synthesis

```python
AttackFlowSynthesizer.synthesize_attack_flow(
    extraction_result=techniques,
    report_text=original_text,
    max_steps=25
)
```

**Capabilities**:
- Temporal phrase detection ("first", "then", "next")
- Causal relationship inference
- Evidence-backed sequencing
- Up to 25 ordered steps

### Heuristic Ordering

When LLM synthesis fails or isn't applicable:

```python
FlowBuilder._order_steps(techniques)
# Uses kill chain progression:
# Recon → Initial Access → Execution → Persistence → ...
```

### Edge Generation

```python
FlowBuilder._compute_next_edges(ordered_steps)
# Creates NEXT edges with probabilities (0.1-1.0)
# Based on:
# - Historical patterns in Neo4j
# - Tactic alignment
# - Confidence scores
# - Temporal indicators
```

## Configuration

### Key Parameters

```yaml
# Chunking
chunk_size: 3000          # Characters per chunk
chunk_overlap: 200        # Overlap between chunks
max_chunks: 10-50         # Based on document size

# Batching
retriever_batch_size: all # All spans in one call
mapper_batch_size: 5      # Spans per LLM call
parallel_chunks: 3        # Concurrent chunk workers

# Token Limits
default_max_tokens: 8000
batch_mapper_tokens: 16000

# Thresholds
span_score_threshold: 0.85
confidence_threshold: 50
discovery_trigger: 0.7

# Timeouts
job_timeout: 600          # 10 minutes
chunk_timeout: 60         # 1 minute per chunk
llm_timeout: 30           # 30 seconds per call
```

### Environment Variables

```bash
# Neo4j Configuration
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password

# OpenSearch Configuration
OPENSEARCH_URL=http://opensearch:9200
OPENSEARCH_INDEX=attack-techniques

# LLM Configuration
LITELLM_MODEL=gemini/gemini-2.0-flash-exp
LITELLM_API_KEY=your-api-key

# Worker Configuration
WORKERS=4                 # Number of uvicorn workers
POLL_INTERVAL=2          # Job polling interval (seconds)
```

## Error Handling

### Retry Strategy

```python
retryable_errors = ["503", "overloaded", "rate_limit", "timeout", "429"]
if is_retryable and retry_count < max_retries:
    wait_time = (2 ** retry_count) * 5  # 10s, 20s, 40s
    # Re-queue with exponential backoff
```

### JSON Response Cleanup

```python
def cleanup_json(json_str: str) -> str:
    # Remove extra quotes after closing braces
    json_str = re.sub(r'\}"\s*,', '},', json_str)
    # Remove trailing commas
    json_str = re.sub(r',\s*\}', '}', json_str)
    return json_str
```

### Graceful Degradation

- Failed chunks don't stop processing
- Partial results are saved
- Techniques from successful chunks are retained
- Error details logged for debugging

## Performance Optimization

### Multi-Worker Architecture

```python
# Start with 4 workers (no --reload for stability)
uvicorn bandjacks.services.api.main:app --workers 4
```

- Each worker has its own embedding model
- FileJobStore provides persistence across workers
- Job locking prevents duplicate processing

### Embedding Model Optimization

```python
# Global model per worker (CPU placement)
_model = None

def get_model():
    global _model
    if _model is None:
        _model = SentenceTransformer(
            "sentence-transformers/all-mpnet-base-v2",
            device='cpu'  # Avoid meta tensor issues
        )
    return _model
```

### Batch Processing Benefits

| Operation | Sequential Time | Batch Time | Improvement |
|-----------|----------------|------------|-------------|
| Retrieval (20 spans) | 20 seconds | 5 seconds | 4x faster |
| Mapping (20 spans) | 20 LLM calls | 4 LLM calls | 5x fewer calls |
| Chunk processing | Sequential | Parallel (3 workers) | 3x faster |

## Monitoring and Debugging

### Progress Tracking

```python
# Real-time progress updates
progress_callback(60, "Processing chunk 3/6")
```

Progress stages:
- 0-10%: File upload and validation
- 10-30%: Text extraction
- 30-35%: Span finding
- 35-65%: Technique extraction
- 65-70%: Consolidation
- 70-80%: Flow generation
- 80-90%: Database storage
- 90-100%: Finalization

### Logging

```python
# Detailed logging at each stage
logger.info(f"Processing document of {text_length} characters")
logger.info(f"Using chunked extraction: {max_chunks} chunks")
logger.debug(f"Batch {batch_start}-{batch_end}: {claims} claims")
```

### Metrics Collection

```json
{
  "extraction_duration_ms": 45000,
  "spans_found": 85,
  "techniques_extracted": 36,
  "confidence_avg": 78.5,
  "chunks_processed": 12,
  "failed_chunks": 1,
  "total_time_sec": 52.3
}
```

## Best Practices

### Document Preparation

1. **PDF Quality**: Ensure PDFs have extractable text (not scanned images)
2. **Text Structure**: Well-formatted documents with clear sections extract better
3. **Explicit References**: Documents with technique IDs (T1055) have higher accuracy

### Configuration Tuning

1. **Span Limits**: Increase for comprehensive extraction, decrease for speed
2. **Confidence Thresholds**: Lower for more techniques, higher for precision
3. **Batch Sizes**: Larger batches are faster but may hit token limits
4. **Worker Count**: Match CPU cores for optimal parallelism

### Error Recovery

1. **Monitor Job Status**: Poll `/jobs/{job_id}/status` for progress
2. **Check Logs**: Detailed error information in server logs
3. **Retry Failed Jobs**: Most errors are transient and resolve on retry
4. **Partial Results**: Even failed jobs may have useful partial results

## Troubleshooting

### Common Issues

#### 1. Slow Processing
- **Cause**: Large document with many chunks
- **Solution**: Increase parallel workers or reduce max_chunks

#### 2. JSON Parse Errors
- **Cause**: Malformed LLM response
- **Solution**: Already handled by cleanup_json(), check logs for patterns

#### 3. Low Technique Count
- **Cause**: High confidence threshold or few spans
- **Solution**: Lower thresholds or increase max_spans

#### 4. Memory Issues
- **Cause**: Too many workers or large embeddings
- **Solution**: Reduce workers or use CPU device for embeddings

#### 5. Job Stuck in Queue
- **Cause**: JobProcessor not running
- **Solution**: Ensure using `--workers` mode, not `--reload`

## Future Enhancements

### Planned Improvements

1. **Advanced Temporal Parsing**: Use specialized NLP models for temporal relationships
2. **ML-Based Sequencing**: Train models on historical attack patterns
3. **Adaptive Chunking**: Dynamic chunk sizes based on content density
4. **GPU Acceleration**: Support GPU for embeddings and LLM inference
5. **Streaming Processing**: Real-time extraction as documents upload
6. **Multi-Language Support**: Extract from non-English reports

### Experimental Features

1. **Confidence Calibration**: ML model for better confidence scoring
2. **Evidence Ranking**: Neural ranker for evidence quality
3. **Cross-Document Correlation**: Link techniques across multiple reports
4. **Active Learning**: Improve extraction based on user feedback

## Conclusion

The Bandjacks report processing pipeline represents a state-of-the-art approach to automated threat intelligence extraction. By combining traditional NLP, vector search, and LLM capabilities with intelligent routing and error handling, it achieves both high accuracy and practical performance for real-world CTI analysis.

Key achievements:
- **36+ techniques** extracted from complex reports
- **30-60 second** processing for typical threat reports
- **Resilient** to errors with retry and recovery
- **Scalable** with parallel processing and chunking
- **Accurate** with multi-stage verification and consolidation

For questions or issues, please refer to the GitHub repository or contact the development team.