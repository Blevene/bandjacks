# Mapper API Endpoints

The mapper endpoints analyze documents and propose ATT&CK technique mappings using vector similarity, LLM extraction, or hybrid approaches.

## POST /mapper/propose

Analyze a document and propose TTP mappings with confidence scores.

### Request

```http
POST /v1/mapper/propose?engine=hybrid
Content-Type: application/json
```

```json
{
  "source_id": "report-2024-001",
  "source_type": "md",
  "inline_text": "## APT29 Campaign Analysis\n\nThe threat actor uses spearphishing emails with malicious attachments...",
  "url": null,
  "max_candidates": 5,
  "chunking_params": {
    "target_chars": 800,
    "overlap": 100
  }
}
```

### Parameters

- **source_id** (required): Unique identifier for the document
- **source_type** (required): Document format
  - Options: `"pdf"`, `"html"`, `"md"`, `"json"`, `"csv"`, `"txt"`
- **inline_text** (optional): Document content as string
  - Provide either `inline_text` or `url`
- **url** (optional): URL to fetch document from
  - Provide either `inline_text` or `url`
- **max_candidates** (optional): Max techniques per chunk
  - Default: `5`
  - Range: 1-20
- **chunking_params** (optional): Text chunking configuration
  - **target_chars**: Target chunk size (default: 800)
  - **overlap**: Character overlap between chunks (default: 100)

### Query Parameters

- **engine** (optional): Extraction engine to use
  - `"vector"`: Traditional vector similarity (default)
  - `"llm"`: LLM-based extraction with GPT-5/Gemini-2.5-Flash
  - `"hybrid"`: Combined vector and LLM approach

### Response

```json
{
  "source_id": "report-2024-001",
  "chunks": [
    {
      "chunk_id": "chunk_0",
      "text": "The threat actor uses spearphishing emails with malicious attachments...",
      "start_char": 0,
      "end_char": 156,
      "mappings": [
        {
          "stix_id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
          "type": "attack-pattern",
          "name": "Spearphishing Attachment",
          "external_id": "T1566.001",
          "confidence": 92,
          "score": 0.876,
          "evidence": "spearphishing emails with malicious attachments",
          "rationale": "Direct mention of spearphishing with attachments matches T1566.001",
          "engine": "llm"
        },
        {
          "stix_id": "intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7",
          "type": "intrusion-set",
          "name": "APT29",
          "external_id": "G0016",
          "confidence": 95,
          "score": 0.912,
          "evidence": "APT29 Campaign Analysis",
          "rationale": "Explicit mention of APT29 threat actor",
          "engine": "llm"
        }
      ]
    },
    {
      "chunk_id": "chunk_1",
      "text": "Once on the system, they use PowerShell scripts for execution...",
      "start_char": 157,
      "end_char": 298,
      "mappings": [
        {
          "stix_id": "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736",
          "type": "attack-pattern",
          "name": "PowerShell",
          "external_id": "T1059.001",
          "confidence": 88,
          "score": 0.834,
          "evidence": "PowerShell scripts for execution",
          "rationale": "PowerShell used for command execution maps to T1059.001",
          "engine": "hybrid"
        }
      ]
    }
  ],
  "aggregated": {
    "techniques": [
      {
        "stix_id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
        "name": "Spearphishing Attachment",
        "external_id": "T1566.001",
        "confidence": 92,
        "occurrences": 1,
        "tactics": ["initial-access"]
      },
      {
        "stix_id": "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736",
        "name": "PowerShell",
        "external_id": "T1059.001",
        "confidence": 88,
        "occurrences": 1,
        "tactics": ["execution"]
      }
    ],
    "groups": [
      {
        "stix_id": "intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7",
        "name": "APT29",
        "external_id": "G0016",
        "confidence": 95,
        "occurrences": 1
      }
    ],
    "tools": [],
    "mitigations": []
  },
  "metadata": {
    "engine": "hybrid",
    "total_chunks": 2,
    "processing_time_ms": 1847,
    "llm_calls": 2,
    "vector_searches": 2
  }
}
```

### Engine Comparison

| Feature | Vector | LLM | Hybrid |
|---------|--------|-----|--------|
| Speed | Fast (~200ms) | Slower (~2s) | Medium (~1.5s) |
| Accuracy | Good | Excellent | Best |
| Context Understanding | Limited | Deep | Deep |
| Hallucination Risk | None | Low (grounded) | Minimal |
| Cost | Low | Higher | Medium |
| Technique Phrases | 150+ | Full understanding | Both |

### Vector Engine

Uses embeddings and KNN search:
- Fast and deterministic
- Good for clear technique mentions
- Recognizes 150+ technique phrases
- No external API calls

### LLM Engine

Uses GPT-5 or Gemini-2.5-Flash with tool grounding:
- Deep semantic understanding
- Handles implicit references
- Provides detailed rationales
- Uses tool calls to prevent hallucination
- Validates all IDs against knowledge base

### Hybrid Engine

Combines both approaches:
- Runs vector and LLM in parallel
- Merges results with weighted confidence
- Best overall accuracy
- Balanced speed and cost

### Example Usage

```bash
# Basic vector-based extraction
curl -X POST "http://localhost:8000/v1/mapper/propose" \
  -H "Content-Type: application/json" \
  -d '{
    "source_id": "doc-001",
    "source_type": "txt",
    "inline_text": "The attacker uses Mimikatz for credential dumping"
  }'

# LLM-based extraction with rationales
curl -X POST "http://localhost:8000/v1/mapper/propose?engine=llm" \
  -H "Content-Type: application/json" \
  -d '{
    "source_id": "report-002",
    "source_type": "md",
    "inline_text": "## Incident Report\n\nSuspicious PowerShell activity detected...",
    "max_candidates": 10
  }'

# Hybrid extraction for best accuracy
curl -X POST "http://localhost:8000/v1/mapper/propose?engine=hybrid" \
  -H "Content-Type: application/json" \
  -d '{
    "source_id": "apt-analysis",
    "source_type": "pdf",
    "url": "https://example.com/threat-report.pdf",
    "chunking_params": {
      "target_chars": 1000,
      "overlap": 150
    }
  }'
```

### Processing Pipeline

1. **Document Parsing**
   - Extract text from various formats (PDF, HTML, etc.)
   - Clean and normalize text
   - Preserve structure and metadata

2. **Text Chunking**
   - Split into overlapping chunks
   - Maintain context boundaries
   - Track character positions

3. **Extraction** (varies by engine)
   - **Vector**: Generate embeddings, KNN search
   - **LLM**: Tool-grounded extraction with GPT-5
   - **Hybrid**: Both in parallel

4. **Validation**
   - Verify STIX IDs exist in knowledge base
   - Apply confidence safeguards
   - Remove duplicates

5. **Aggregation**
   - Combine chunk-level results
   - Calculate aggregate confidence
   - Group by type and tactic

### Confidence Scoring

Confidence scores (0-100) are calculated based on:

- **Text similarity**: How closely text matches technique descriptions
- **Explicit mentions**: Direct technique names or IDs
- **Context signals**: Supporting evidence in surrounding text
- **Multiple confirmations**: Same technique found in multiple chunks
- **Safeguards**: Capped at 85% unless high-signal evidence

### Error Responses

- **400 Bad Request**: Invalid parameters

```json
{
  "detail": "Must provide either inline_text or url"
}
```

- **422 Unprocessable Entity**: Unsupported document type

```json
{
  "detail": "Unsupported source_type: docx"
}
```

- **502 Bad Gateway**: LLM service unavailable

```json
{
  "detail": "LLM service unavailable (engine=llm)"
}
```

### Performance Considerations

- **Vector engine**: Use for high-volume, real-time processing
- **LLM engine**: Use for detailed analysis with rationales
- **Hybrid engine**: Use for critical documents requiring highest accuracy
- **Chunking**: Larger chunks provide more context but slower processing
- **Caching**: Results are cached by source_id for 15 minutes

### Integration with Review

Proposed mappings can be reviewed and validated:

```bash
# Review a proposed mapping
curl -X POST http://localhost:8000/v1/review/mapping \
  -d '{
    "source_id": "report-2024-001",
    "object_id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
    "decision": "accept",
    "confidence_override": 95,
    "note": "Confirmed by analyst"
  }'
```