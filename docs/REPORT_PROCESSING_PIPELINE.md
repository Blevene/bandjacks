# Report Processing Pipeline - Complete Documentation

## Table of Contents
1. [Overview](#overview)
2. [Entry Points](#entry-points)
3. [Processing Flow](#processing-flow)
4. [Core Components](#core-components)
5. [Configuration Options](#configuration-options)
6. [Output Structure](#output-structure)
7. [Storage Architecture](#storage-architecture)
8. [Error Handling](#error-handling)

## Overview

The Bandjacks report processing pipeline is a sophisticated multi-stage system for extracting MITRE ATT&CK techniques, threat entities, and attack flows from cyber threat intelligence reports. It uses advanced NLP, vector search, and LLM-powered analysis to produce structured, evidence-backed intelligence.

### Key Features
- **Smart routing**: Automatic sync/async processing based on content size
- **Chunked extraction**: Handles large documents (15KB+ PDFs) efficiently
- **Entity recognition**: Extracts threat actors, malware, campaigns, and tools
- **Evidence-based claims**: Every technique linked to source text with line references
- **Attack flow generation**: Temporal sequencing using LLM synthesis
- **Confidence scoring**: Probabilistic confidence for each extraction

## Entry Points

### 1. Synchronous Endpoints (< 5KB content)

```
POST /v1/reports/ingest
POST /v1/reports/ingest/upload
```

**Request Structure:**
```python
{
    "text": str,              # Raw text content
    "name": str,              # Report name
    "use_batch_mapper": bool, # Use optimized batch processing (default: true)
    "skip_verification": bool,# Skip evidence verification (default: false)
    "confidence_threshold": float # Min confidence (default: 50.0)
}
```

### 2. Asynchronous Endpoints (> 5KB content)

```
POST /v1/reports/ingest_async
POST /v1/reports/ingest_file_async
GET  /v1/reports/jobs/{job_id}/status
```

**Async Job Response:**
```python
{
    "job_id": str,
    "status": "queued|processing|completed|failed",
    "progress": int,          # 0-100
    "message": str,           # Current stage
    "result": {...}           # Final result when completed
}
```

### 3. File Upload Support

Supported formats:
- PDF (`.pdf`) - Extracted using pdfplumber
- Text (`.txt`)
- Markdown (`.md`, `.markdown`)

Size limits:
- Sync: Max 5KB
- Async: Max 10MB (configurable)

## Processing Flow

### Stage 1: Document Preparation

```python
# routes/reports.py → ingest_report()
if len(content) > 5000:
    # Route to async processing
    job_id = job_processor.submit_job(content)
else:
    # Direct sync processing
    result = run_extraction_pipeline(content)
```

### Stage 2: Chunking (for large documents)

```python
# llm/chunked_extractor.py → ChunkedExtractor
class ChunkedExtractor:
    chunk_size = 3000      # Characters per chunk
    overlap = 150          # Overlap between chunks
    max_chunks = 10        # Maximum chunks to process
    
    def process_chunks(text):
        chunks = create_chunks(text)  # Smart sentence-aware splitting
        for chunk in chunks:
            result = extract_from_chunk(chunk)
            merge_results(result)
```

### Stage 3: Entity Extraction

```python
# llm/entity_extractor.py → EntityExtractionAgent
Extracts:
- Primary entity (main threat actor/campaign)
- Threat actors (APT groups)
- Malware families
- Software/tools
- Campaigns
- Attribution confidence
```

### Stage 4: Technique Extraction Pipeline

#### 4.1 Span Finding
```python
# llm/agents_v2.py → SpanFinderAgent
- Pattern-based detection (T[0-9]{4}(\.[0-9]{3})?)
- Tactic keyword matching (persistence, execution, etc.)
- Behavioral phrase detection
- Outputs: List of text spans with potential techniques
```

#### 4.2 Batch Retrieval
```python
# llm/batch_retriever.py → BatchRetrieverAgent
- Vector search using OpenSearch KNN
- Retrieves top-10 candidate techniques per span
- Uses embeddings for semantic similarity
- Caches results for efficiency
```

#### 4.3 Technique Mapping
```python
# llm/mapper_optimized.py → BatchMapperAgent
- LLM verification of retrieved candidates
- Batch processes all spans in single call
- Extracts ALL relevant techniques per span
- Confidence scoring (0-100)
```

#### 4.4 Evidence Consolidation
```python
# llm/agents_v2.py → ConsolidatorAgent
- Deduplicates techniques across spans
- Merges evidence from multiple sources
- Tracks line references
- Aggregates confidence scores
```

### Stage 5: Attack Flow Generation

```python
# llm/flow_builder.py → FlowBuilder
def build_from_extraction(extraction_data):
    # Try LLM synthesis first
    llm_flow = synthesize_attack_flow(
        extraction_data,
        report_text,
        max_steps=25
    )
    
    if not llm_flow:
        # Fallback to deterministic ordering
        flow = build_deterministic_flow()
    
    # Generate NEXT edges with probabilities
    add_probabilistic_edges(flow)
    return flow
```

#### Flow Generation Methods:

1. **LLM Synthesis** (Primary)
   - Analyzes temporal keywords ("first", "then", "finally")
   - Identifies causal relationships
   - Produces ordered sequence with reasoning

2. **Deterministic Ordering** (Fallback)
   - Uses MITRE kill chain progression
   - Groups by tactics
   - Orders by confidence scores

3. **Co-occurrence Modeling** (No temporal evidence)
   - Creates weak edges within tactic groups
   - Marked as `flow_type="co-occurrence"`

### Stage 6: Storage & Response

```python
# services/api/opensearch_store.py
class OpenSearchReportStore:
    def save_report(report_data):
        # Index in OpenSearch
        index_name = "reports"
        doc = {
            "report_id": uuid,
            "extraction": {...},
            "entities": {...},
            "flow": {...},
            "timestamp": datetime.now(),
            "status": "extracted"  # Pending review
        }
        opensearch.index(index_name, doc)
```

### Stage 7: Unified Review Process

After extraction, reports enter the unified review system where human analysts validate and refine the extractions.

```python
# routes/unified_review.py → submit_unified_review()
Review Process:
1. Load report with all extraction data
2. Convert to unified ReviewableItem format
3. Present single interface for all item types
4. Collect decisions (approve/reject/edit)
5. Apply decisions atomically
6. Update OpenSearch and Neo4j
7. Mark report as "reviewed"
```

#### Review Item Types

The unified review system handles three types of extracted items:

- **Entities**: Threat actors, malware, campaigns, tools
- **Techniques**: MITRE ATT&CK technique claims with evidence
- **Flow Steps**: Attack sequence steps with temporal ordering

#### Review Decisions

Each item can receive one of three decisions:
- **Approve**: Accept extraction as correct
- **Reject**: Mark as incorrect or irrelevant  
- **Edit**: Modify extraction details (name, confidence, etc.)

#### Atomic Updates

All review decisions are applied atomically:
- Update extraction data in OpenSearch
- Create approved entities as Neo4j nodes
- Link approved techniques to report node
- Store review metadata and statistics

```python
# Example review submission
{
    "decisions": [
        {
            "item_id": "entity-malware-0",
            "action": "approve",
            "timestamp": "2025-08-31T10:30:00Z"
        },
        {
            "item_id": "technique-5", 
            "action": "edit",
            "edited_value": {
                "name": "Spear Phishing Attachment",
                "external_id": "T1566.001"
            },
            "confidence_adjustment": 85
        }
    ]
}
```

## Core Components

### Agent Classes

| Agent | Purpose | Input | Output |
|-------|---------|-------|--------|
| EntityExtractionAgent | Extract threat entities | Full text | Entities dict |
| SpanFinderAgent | Find technique indicators | Full text | Text spans |
| BatchRetrieverAgent | Vector search candidates | Spans | Candidate techniques |
| BatchMapperAgent | LLM verification | Spans + candidates | Verified techniques |
| ConsolidatorAgent | Merge & deduplicate | All techniques | Final claims list |

### LLM Integration

```python
# llm/client.py → LLMClient
Models:
- Primary: Claude 3.5 Sonnet (extraction, mapping)
- Fallback: GPT-4 (if Claude unavailable)
- Cache: SQLite-based response caching

Rate limiting:
- 5 requests/second per model
- Automatic retry with exponential backoff
- Fallback to alternate model on failure
```

### Vector Search

```python
# OpenSearch KNN Configuration
Index: attack_nodes
Dimensions: 768 (sentence-transformers)
Algorithm: HNSW
Similarity: Cosine

Query:
{
    "knn": {
        "embedding": {
            "vector": [0.1, 0.2, ...],
            "k": 10
        }
    }
}
```

## Configuration Options

### Extraction Configuration

```python
{
    # Chunking
    "chunk_size": 3000,        # Characters per chunk
    "max_chunks": 10,          # Max chunks to process
    "chunk_overlap": 150,      # Overlap between chunks
    
    # Extraction
    "max_spans": 20,           # Max spans per chunk
    "confidence_threshold": 50.0, # Min confidence (0-100)
    "use_batch_mapper": true,  # Batch vs sequential
    "skip_verification": false, # Skip evidence verification
    
    # Flow generation
    "auto_generate_flow": true, # Generate attack flow
    "max_flow_steps": 25,      # Max steps in flow
    "flow_confidence_min": 0.3 # Min edge probability
}
```

### Performance Tuning

| Parameter | Default | Impact |
|-----------|---------|--------|
| chunk_size | 3000 | Larger = fewer API calls, less context |
| max_chunks | 10 | Controls max document size |
| parallel_workers | 1 | Parallel chunk processing |
| batch_size | 20 | Spans per LLM call |
| cache_ttl | 3600 | LLM response cache duration |

## Output Structure

### Extraction Result

```python
{
    "report_id": "report--uuid",
    "name": "Report Name",
    "status": "completed",
    
    "extraction": {
        "techniques_count": 15,
        "claims_count": 22,
        "confidence_avg": 85.5,
        
        "claims": [
            {
                "external_id": "T1566.001",
                "name": "Spearphishing Attachment",
                "quotes": ["sent malicious PDF attachments..."],
                "line_refs": [45, 46],
                "confidence": 92.0,
                "span_idx": 3,
                "evidence_score": 0.89,
                "source": "batch_mapper",
                "source_chunk": 0
            }
        ],
        
        "entities": {
            "primary_entity": {
                "type": "threat-actor",
                "id": "APT29",
                "name": "APT29",
                "confidence": 95.0
            },
            "threat_actors": ["APT29"],
            "malware": ["SUNBURST", "TEARDROP"],
            "tools": ["Cobalt Strike"],
            "campaigns": ["SolarWinds"]
        },
        
        "flow": {
            "flow_type": "sequential",
            "confidence": 78.5,
            "steps": [
                {
                    "order": 1,
                    "technique_id": "T1566.001",
                    "name": "Spearphishing Attachment",
                    "tactic": "initial-access",
                    "confidence": 92.0,
                    "evidence": "Email campaign with attachments"
                }
            ],
            "edges": [
                {
                    "from": "T1566.001",
                    "to": "T1059.001",
                    "probability": 0.85,
                    "relationship": "NEXT"
                }
            ]
        },
        
        "metrics": {
            "extraction_time_ms": 8234,
            "chunks_processed": 3,
            "spans_analyzed": 47,
            "llm_calls": 5,
            "cache_hits": 2
        }
    },
    
    "unified_review": {
        "reviewer_id": "reviewer-001",
        "reviewed_at": "2025-08-31T11:30:00Z",
        "global_notes": "Review completed. High confidence extractions overall.",
        "statistics": {
            "total_reviewed": 25,
            "approved": 18,
            "rejected": 4,
            "edited": 3
        },
        "decisions": [
            {
                "item_id": "entity-malware-0",
                "action": "approve",
                "timestamp": "2025-08-31T11:25:00Z"
            },
            {
                "item_id": "technique-5",
                "action": "edit",
                "edited_value": {
                    "name": "Spear Phishing Attachment",
                    "external_id": "T1566.001"
                },
                "confidence_adjustment": 85,
                "notes": "Corrected technique ID",
                "timestamp": "2025-08-31T11:27:00Z"
            }
        ]
    },
    
    "status": "reviewed"  # extracted -> reviewed
}
```

### Job Status Response

```python
{
    "job_id": "job-abc123",
    "status": "processing",
    "progress": 60,
    "message": "Processing chunk 3/5",
    "stage": "BatchMapper",
    "created_at": "2025-08-31T10:00:00Z",
    "result": null  # Populated when completed
}
```

## Storage Architecture

### OpenSearch Indices

```
reports
├── report_id (keyword)
├── name (text)
├── extraction (object)
│   ├── claims (nested)
│   ├── entities (object)
│   └── flow (object)
├── created (date)
└── embeddings (dense_vector)

attack_nodes
├── stix_id (keyword)
├── name (text)
├── description (text)
├── embedding (dense_vector[768])
└── kill_chain_phases (keyword)
```

### Neo4j Graph Schema

```cypher
// Report node
(r:Report {
    stix_id: "report--uuid",
    name: "Report Name",
    created: datetime
})

// Extraction relationship
(r)-[:EXTRACTED {
    confidence: 85.5,
    technique_count: 15
}]->(t:AttackPattern)

// Attack flow
(e:AttackEpisode {
    episode_id: "episode--uuid",
    source_ref: "report--uuid"
})

(e)-[:CONTAINS]->(a:AttackAction {
    action_id: "action--uuid",
    technique_ref: "attack-pattern--uuid"
})

(a1)-[:NEXT {probability: 0.85}]->(a2)
```

## Error Handling

### Retry Logic

```python
# Automatic retry with exponential backoff
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
def call_llm(prompt):
    return llm_client.complete(prompt)
```

### Fallback Strategies

1. **LLM Failures**
   - Primary: Claude 3.5 Sonnet
   - Fallback: GPT-4
   - Emergency: Cached similar responses

2. **Extraction Failures**
   - Chunk too large → Split further
   - No techniques found → Adjust confidence threshold
   - Timeout → Process fewer chunks

3. **Flow Generation Failures**
   - LLM synthesis fails → Use deterministic ordering
   - No temporal evidence → Generate co-occurrence flow
   - Invalid flow → Skip flow generation

### Error Response

```python
{
    "error": "Extraction failed",
    "detail": "Timeout processing chunk 3",
    "trace_id": "trace-xyz",
    "suggestions": [
        "Reduce chunk_size to 2000",
        "Increase timeout to 120s"
    ]
}
```

## Performance Metrics

### Typical Processing Times

| Document Size | Chunks | Techniques | Time | Method |
|--------------|--------|------------|------|---------|
| 2KB | 1 | 3-5 | 5s | Sync |
| 5KB | 2 | 8-12 | 10s | Sync |
| 15KB | 5 | 15-25 | 30s | Async |
| 50KB | 10 | 30-50 | 60s | Async |

### Optimization Tips

1. **For speed**: 
   - Enable `use_batch_mapper=true`
   - Reduce `max_chunks` if full coverage not needed
   - Increase `confidence_threshold` to reduce false positives

2. **For accuracy**:
   - Decrease `chunk_size` for better context
   - Disable `skip_verification`
   - Lower `confidence_threshold` for more coverage

3. **For large documents**:
   - Use async endpoints
   - Increase `max_chunks` limit
   - Enable parallel processing

## API Examples

### Simple Text Extraction

```bash
curl -X POST http://localhost:8000/v1/reports/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "text": "APT29 uses spearphishing emails with malicious attachments...",
    "name": "APT29 Campaign Report"
  }'
```

### File Upload with Options

```bash
curl -X POST http://localhost:8000/v1/reports/ingest_file_async \
  -F "file=@report.pdf" \
  -F 'config={"chunk_size": 4000, "confidence_threshold": 70}'
```

### Check Job Status

```bash
curl http://localhost:8000/v1/reports/jobs/job-abc123/status
```

### Submit Review

```bash
curl -X POST http://localhost:8000/v1/reports/report-123/unified-review \
  -H "Content-Type: application/json" \
  -d '{
    "report_id": "report-123",
    "reviewer_id": "reviewer-001",
    "decisions": [
      {
        "item_id": "entity-malware-0",
        "action": "approve",
        "timestamp": "2025-08-31T11:00:00Z"
      },
      {
        "item_id": "technique-5",
        "action": "edit",
        "edited_value": {
          "name": "Spear Phishing Attachment",
          "external_id": "T1566.001"
        },
        "confidence_adjustment": 85,
        "notes": "Corrected technique ID",
        "timestamp": "2025-08-31T11:01:00Z"
      }
    ],
    "global_notes": "Review completed successfully",
    "review_timestamp": "2025-08-31T11:05:00Z"
  }'
```

### Frontend Integration

```typescript
// Smart routing based on size
const useAsync = file.size > 5000;

if (useAsync) {
  const job = await api.reports.ingestFileAsync(file, config);
  // Poll for status
  const result = await pollJobStatus(job.job_id);
} else {
  const result = await api.reports.ingestUpload(file, config);
}

// After extraction, handle review process
const navigateToReview = (reportId: string) => {
  router.push(`/reports/${reportId}/review`);
};

// Submit unified review
const submitReview = async (reportId: string, decisions: ReviewDecision[]) => {
  const response = await api.reports.submitUnifiedReview(reportId, {
    report_id: reportId,
    reviewer_id: getCurrentUserId(),
    decisions,
    review_timestamp: new Date().toISOString()
  });
  
  if (response.success) {
    // Navigate to report detail
    router.push(`/reports/${reportId}`);
  }
};
```

## Monitoring & Debugging

### Log Files

```
extraction_pipeline.log
├── Agent execution traces
├── LLM prompts and responses
├── Chunk processing progress
└── Error stack traces
```

### Debug Environment Variables

```bash
LOG_LEVEL=DEBUG           # Verbose logging
LOG_FILE=pipeline.log     # Log file location
LLM_CACHE_ENABLED=false   # Disable caching for testing
CHUNK_SIZE_OVERRIDE=2000  # Override default chunk size
```

### Performance Monitoring

```python
# Access metrics endpoint
GET /v1/analytics/statistics

Response:
{
    "total_reports": 79,
    "avg_extraction_time_ms": 12500,
    "avg_techniques_per_report": 18,
    "cache_hit_rate": 0.65
}
```

## Conclusion

The Bandjacks report processing pipeline provides a comprehensive, end-to-end solution for transforming unstructured threat intelligence reports into validated, structured knowledge. The multi-stage architecture progresses from document ingestion through extraction, flow generation, and finally human review validation.

Key strengths of the system:

- **Intelligent Processing**: Smart routing between sync/async based on document size
- **Evidence-Based**: All extractions linked to source text with line references  
- **Scalable Architecture**: Handles documents from 2KB to 50KB+ efficiently
- **Comprehensive Coverage**: Extracts entities, techniques, and attack flows
- **Quality Assurance**: Unified review system ensures human validation
- **Production Ready**: Robust error handling, fallback strategies, and monitoring

The unified review system completes the pipeline by providing analysts with a streamlined interface to validate and refine extractions, ensuring high-quality threat intelligence suitable for operational use. This human-in-the-loop approach maintains accuracy while leveraging automation for efficiency.