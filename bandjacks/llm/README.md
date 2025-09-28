# LLM Module Structure

This directory contains the LLM-based extraction and analysis components for Bandjacks.

## Module Status Classification

All modules in this directory are classified with one of the following statuses:
- **PRODUCTION**: Core production modules actively used in the extraction pipeline
- **EXPERIMENTAL**: Research/experimental modules, may change or be removed
- **DEPRECATED**: Modules scheduled for removal, use alternatives
- **INFRASTRUCTURE**: Supporting infrastructure modules

## Production Modules

### Core Extraction Pipeline
- `extraction_pipeline.py` - **PRODUCTION** - Main extraction pipeline coordinator
- `chunked_extractor.py` - **PRODUCTION** - Standard chunked document processing
- `optimized_chunked_extractor.py` - **PRODUCTION** - Advanced chunked processing with optimizations

### Agent Components
- `agents_v2.py` - **PRODUCTION** - Core extraction agents (SpanFinder, Consolidator, etc.)
- `mapper_optimized.py` - **PRODUCTION** - BatchMapperAgent for efficient mapping
- `batch_retriever.py` - **PRODUCTION** - BatchRetrieverAgent for vector search
- `entity_extractor.py` - **PRODUCTION** - Entity extraction agent
- `entity_consolidator.py` - **PRODUCTION** - Entity consolidation and deduplication
- `entity_batch_extractor.py` - **PRODUCTION** - Batch entity extraction

### Infrastructure Modules
- `memory.py` - **INFRASTRUCTURE** - WorkingMemory class for agent coordination
- `tools.py` - **INFRASTRUCTURE** - Vector search and ATT&CK lookup tools
- `client.py` - **INFRASTRUCTURE** - LLM client wrapper with caching
- `flow_builder.py` - **PRODUCTION** - Attack flow generation from extractions
- `tracker.py` - **INFRASTRUCTURE** - Extraction metrics and progress tracking

### Utilities
- `consolidator_base.py` - **INFRASTRUCTURE** - Base consolidation class with evidence extraction
- `accumulator.py` - **INFRASTRUCTURE** - ThreadSafeAccumulator for parallel processing
- `token_utils.py` - **INFRASTRUCTURE** - Token estimation and budget management
- `semantic_dedup.py` - **INFRASTRUCTURE** - Semantic deduplication utilities
- `vector_cache.py` - **INFRASTRUCTURE** - Vector search caching layer
- `entity_ignorelist.py` - **INFRASTRUCTURE** - Entity filtering configuration
- `json_utils.py` - **INFRASTRUCTURE** - JSON parsing utilities
- `cache.py` - **INFRASTRUCTURE** - LLM response caching
- `batch_neo4j.py` - **INFRASTRUCTURE** - Batch Neo4j operations for performance

### Validators
- `detection_validator.py` - **PRODUCTION** - Detection rule validation
- `sigma_validator.py` - **PRODUCTION** - Sigma rule validation
- `bundle_validator.py` - **PRODUCTION** - STIX bundle validation
- `attack_flow_validator.py` - **PRODUCTION** - Attack flow validation

### STIX Components
- `stix_builder.py` - **PRODUCTION** - STIX 2.1 bundle builder
- `stix_converter.py` - **PRODUCTION** - Extraction to STIX conversion
- `flow_exporter.py` - **PRODUCTION** - Attack flow export utilities

### Experimental Modules
- `sequence_proposal.py` - **EXPERIMENTAL** - Judge-validated sequence proposals (used by /sequence endpoints)
- `entity_resolver.py` - **EXPERIMENTAL** - Entity resolution to KB (not fully integrated)
- `provenance_tracker.py` - **EXPERIMENTAL** - Extraction provenance tracking (future use)

### Deprecated Modules
- `tactic_priors.py` - **DEPRECATED** - Not currently used, candidate for removal
- `rate_limiter.py` - **DEPRECATED** - Use `middleware/rate_limit.py` instead

### Other Modules
- `schemas.py` - **INFRASTRUCTURE** - JSON schemas for output validation

## Usage

### Using the Main Extraction Pipeline

```python
from bandjacks.llm.extraction_pipeline import run_extraction_pipeline

config = {
    "max_spans": 20,
    "span_score_threshold": 0.7,
    "top_k": 5,
    "use_optimized_extractor": True,  # Use optimized chunking for large docs
    "chunk_size": 2000,
    "max_chunks": 100
}

# Run extraction
result = run_extraction_pipeline(
    report_text,
    config,
    source_id="report_123",
    neo4j_config=neo4j_config
)

techniques = result["techniques"]  # Extracted techniques with evidence
bundle = result.get("bundle")  # STIX 2.1 bundle if configured
entities = result.get("entities")  # Extracted entities

# Example result structure:
# {
#   "techniques": {
#     "T1566.001": {
#       "name": "Phishing: Spearphishing Attachment",
#       "confidence": 95,
#       "evidence": ["APT29 sent spearphishing emails..."],
#       "line_refs": [42, 43]
#     },
#     "T1059.001": {
#       "name": "Command and Scripting Interpreter: PowerShell",
#       "confidence": 85,
#       "evidence": ["PowerShell scripts were executed..."],
#       "line_refs": [51]
#     }
#   },
#   "entities": {
#     "entities": [
#       {"name": "APT29", "type": "group", "confidence": 100},
#       {"name": "SUNBURST", "type": "malware", "confidence": 100}
#     ]
#   },
#   "flow": {
#     "steps": [
#       {"order": 1, "technique_id": "T1566.001", "description": "Initial access"},
#       {"order": 2, "technique_id": "T1059.001", "description": "Execution"}
#     ]
#   },
#   "metrics": {
#     "extraction_time": 15.3,
#     "chunks_processed": 5,
#     "spans_found": 12
#   }
# }
```

### Using via API (Recommended for Production)

```python
import requests

# For small documents (<5KB) - Synchronous
response = requests.post(
    "http://localhost:8000/v1/reports/ingest/upload",
    files={"file": open("report.pdf", "rb")},
    data={"config": json.dumps(config)}
)
result = response.json()

# For large documents (>5KB) - Asynchronous
response = requests.post(
    "http://localhost:8000/v1/reports/ingest_file_async",
    files={"file": open("large_report.pdf", "rb")},
    data={"config": json.dumps(config)}
)
job_id = response.json()["job_id"]

# Check job status
status = requests.get(f"http://localhost:8000/v1/reports/jobs/{job_id}/status")
if status.json()["status"] == "completed":
    result = status.json()["result"]
```

## Performance

### Processing Times by Document Size

| Document Size | Optimized Pipeline | Standard Pipeline |
|--------------|-------------------|-------------------|
| Small (<10KB) | 10-20 seconds | 20-40 seconds |
| Medium (10-50KB) | 20-60 seconds | 40-120 seconds |
| Large (>50KB) | 60-180 seconds | 120-300 seconds |

### Key Performance Features

1. **Smart Chunking**: Documents processed in optimal chunks with context sharing
2. **Batch Processing**: Multiple operations batched into single LLM calls
3. **Parallel Processing**: Chunks processed concurrently when possible
4. **Caching**: LLM responses and vector searches cached for efficiency
5. **Early Termination**: High-confidence extractions can skip verification

### Configuration for Performance

```python
# Maximum performance (may reduce quality slightly)
fast_config = {
    "use_optimized_extractor": True,
    "max_spans": 10,
    "span_score_threshold": 0.9,
    "top_k": 3,
    "chunk_size": 2000,
    "enable_early_termination": True,
    "early_termination_threshold": 100.0
}

# Balanced performance and quality (recommended)
balanced_config = {
    "use_optimized_extractor": True,
    "max_spans": 20,
    "span_score_threshold": 0.7,
    "top_k": 5,
    "chunk_size": 2000,
    "max_chunks": 100
}

# Maximum quality (slower)
quality_config = {
    "use_optimized_extractor": False,  # Use standard extraction
    "max_spans": 30,
    "span_score_threshold": 0.5,
    "top_k": 10,
    "enable_sentence_evidence": True,
    "semantic_dedup_threshold": 0.85
}
```

## Working Memory Structure

The extraction pipeline uses a shared WorkingMemory object:

- `line_index`: Document lines for reference
- `spans`: Behavioral text segments with scores
- `candidates`: Per-span technique candidates from vector search
- `claims`: Mapped techniques with evidence
- `techniques`: Final consolidated techniques
- `entities`: Extracted entities with evidence
- `entity_claims`: Entity claims for consolidation

## Environment Variables

Key configuration via environment:
- `GOOGLE_API_KEY`: Gemini API key (primary LLM)
- `OPENAI_API_KEY`: OpenAI API key (fallback)
- `PRIMARY_LLM`: "gemini" or "openai" (default: "gemini")
- `USE_OPTIMIZED_EXTRACTOR`: Enable optimized pipeline (default: "true")
- `CHUNK_SIZE`: Document chunk size (default: 2000)
- `MAX_CHUNKS`: Maximum chunks to process (default: 100)
- `ENABLE_SENTENCE_EVIDENCE`: Use sentence-based evidence (default: "true")

## Module Maintenance Notes

When working with these modules:
1. Check module status in docstring before making changes
2. Avoid modifying DEPRECATED modules - use alternatives
3. EXPERIMENTAL modules may change frequently
4. Test thoroughly when modifying PRODUCTION modules
5. Consider impact on API endpoints when changing validators

## Prompts and Templates

All LLM prompts are defined inline within their respective agent modules. Here's where to find each prompt:

### Production Prompts

#### **agents_v2.py** - Core Extraction Agents

- **SpanFinderAgent** (line 42): Behavioral text span detection
  - Purpose: Identify text spans containing threat behaviors
  - Output: Scored spans with line references
  - Example output:
    ```python
    {
      "spans": [
        {
          "text": "The attackers sent spearphishing emails with malicious PDF attachments to executives.",
          "score": 0.95,
          "line_refs": [42, 43],
          "span_idx": 0,
          "technique_ids": ["T1566.001"]  # If explicit ID found
        },
        {
          "text": "PowerShell scripts were used to download and execute additional payloads.",
          "score": 0.88,
          "line_refs": [51],
          "span_idx": 1
        }
      ]
    }
    ```
- **DiscoveryAgent** (line 341): Simple ATT&CK technique identification
  - Purpose: Quick technique discovery from text spans
  - Output: JSON list of technique IDs (T1055, T1003.001, etc.)
  - Features: Minimal prompt for fast processing
  - Example output:
    ```json
    {
      "techniques": ["T1055", "T1003.001", "T1059.001"]
    }
    ```

- **MapperAgent** (line 442): Technique mapping with evidence
  - Purpose: Map text spans to best-matching ATT&CK techniques
  - Output: Selected technique, evidence quotes, confidence scores
  - Features: Extracts 2-3 complete sentences as evidence with line numbers
  - Example output:
    ```json
    {
      "selected": {
        "external_id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment"
      },
      "proposed": null,
      "evidence": {
        "quotes": [
          "The attackers sent spearphishing emails with malicious PDF attachments.",
          "These attachments contained embedded macros that executed upon opening."
        ],
        "line_refs": [42, 43]
      },
      "confidence": 95
    }
    ```

- **ConsolidatorAgent** (line 751): Technique consolidation and deduplication
  - Purpose: Merge duplicate techniques and aggregate evidence
  - Output: Consolidated techniques with aggregated evidence
  - Example output:
    ```python
    {
      "techniques": {
        "T1566.001": {
          "external_id": "T1566.001",
          "name": "Phishing: Spearphishing Attachment",
          "confidence": 95,
          "evidence": [
            "The attackers sent spearphishing emails with malicious PDF attachments.",
            "APT29 used spearphishing with weaponized documents.",
            "Initial access was gained through phishing emails."
          ],
          "line_refs": [42, 43, 67, 89],
          "span_idxs": [0, 3, 7],
          "evidence_score": 92,
          "source": "consolidated"
        },
        "T1059.001": {
          "external_id": "T1059.001",
          "name": "Command and Scripting Interpreter: PowerShell",
          "confidence": 88,
          "evidence": [
            "PowerShell scripts were used to download and execute additional payloads.",
            "The malware used PowerShell for persistence."
          ],
          "line_refs": [51, 102],
          "span_idxs": [1, 9],
          "evidence_score": 85,
          "source": "consolidated"
        }
      },
      "summary": {
        "total_claims": 15,
        "consolidated_to": 8,
        "dedup_rate": 46.7
      }
    }
    ```

#### **entity_extractor.py** - Entity Recognition
- **ENTITY_EXTRACTION_SYSTEM_PROMPT** (lines 15-75): Comprehensive entity extraction
  - Extracts: Threat groups, malware, tools, targets, campaigns
  - Features:
    - Detailed classification rules (malware vs tool distinction)
    - Few-shot examples for each entity type
    - Context tracking (primary mention, alias, coreference)
  - Output: JSON with entities, confidence scores, and evidence
  - Example output:
    ```json
    {
      "entities": [
        {
          "name": "APT29",
          "type": "group",
          "confidence": 100,
          "evidence": "APT29, also known as Cozy Bear, conducted the campaign",
          "context": "primary_mention"
        },
        {
          "name": "Cozy Bear",
          "type": "group",
          "confidence": 100,
          "evidence": "APT29, also known as Cozy Bear, conducted the campaign",
          "context": "alias"
        },
        {
          "name": "SUNBURST",
          "type": "malware",
          "confidence": 100,
          "evidence": "The threat actors deployed SUNBURST malware through the supply chain",
          "context": "primary_mention"
        },
        {
          "name": "PowerShell",
          "type": "tool",
          "confidence": 95,
          "evidence": "They used PowerShell scripts for execution and discovery",
          "context": "primary_mention"
        }
      ]
    }
    ```

#### **entity_batch_extractor.py** - Batch Entity Processing
- **_get_batch_system_prompt()** (line 346): Multi-window entity extraction
  - Purpose: Process multiple text chunks in single LLM call
  - Features: Sliding window approach for large documents
  - Output: Entities per window with deduplication
  - Example output:
    ```json
    {
      "windows": [
        {
          "window_id": 0,
          "entities": [
            {"name": "Lazarus Group", "type": "group", "confidence": 95},
            {"name": "WannaCry", "type": "malware", "confidence": 100}
          ]
        },
        {
          "window_id": 1,
          "entities": [
            {"name": "EternalBlue", "type": "tool", "confidence": 90},
            {"name": "healthcare sector", "type": "target", "confidence": 85}
          ]
        }
      ]
    }
    ```

#### **mapper_optimized.py** - Optimized Batch Mapping
- **BatchMapperAgent** (line 128): Lightweight technique extraction
  - Purpose: Fast batch processing of multiple spans
  - Output: Compact JSON with span index, technique ID, confidence
  - Features: Minimal prompt for efficiency
  - Example output:
    ```json
    {
      "techniques": [
        {"span": 0, "tid": "T1566.001", "conf": 95},
        {"span": 0, "tid": "T1059.001", "conf": 80},
        {"span": 1, "tid": "T1055", "conf": 75},
        {"span": 2, "tid": "T1003.001", "conf": 90}
      ]
    }
    ```

#### **flow_builder.py** - Attack Flow Generation
- **_build_flow_prompt()** (lines 1505-1548): Attack flow synthesis
  - Purpose: Create chronological attack sequences from CTI data
  - Features:
    - Analyzes temporal markers ("first", "then", "after")
    - References extracted entities and techniques
    - Provides reasoning for step ordering
  - Output: Ordered attack flow with up to 25 steps
  - Example output:
    ```json
    {
      "flow_name": "APT29 SolarWinds Campaign",
      "steps": [
        {
          "order": 1,
          "entity": {
            "label": "Spearphishing Attachment",
            "id": "T1566.001"
          },
          "description": "Initial access via spearphishing emails with malicious attachments",
          "reason": "Report states 'initially compromised' indicating first step"
        },
        {
          "order": 2,
          "entity": {
            "label": "PowerShell",
            "id": "T1059.001"
          },
          "description": "Executed PowerShell scripts from malicious documents",
          "reason": "Follows spearphishing with 'upon opening' temporal marker"
        },
        {
          "order": 3,
          "entity": {
            "label": "SUNBURST",
            "id": "malware--abc123"
          },
          "description": "Deployed SUNBURST backdoor for persistence",
          "reason": "Text indicates 'then installed' showing sequence"
        }
      ],
      "confidence": 85,
      "notes": "High confidence in sequence based on temporal markers"
    }
    ```

### Experimental Prompts

#### **experimental/prompts.py** - Legacy Templates
- **SYSTEM_PROMPT** (lines 9-121): Comprehensive CTI extraction prompt
  - Status: EXPERIMENTAL - Only used by tests
  - Features: Detailed extraction rules, tool usage instructions
  - Note: Production pipeline uses inline prompts instead
  - Example output (legacy format):
    ```json
    {
      "chunk_id": "doc1#c0",
      "claims": [
        {
          "type": "uses-technique",
          "span": {"text": "APT29 uses spearphishing", "start": 45, "end": 70},
          "line_refs": [3, 4],
          "actor": "APT29",
          "technique": "Spearphishing",
          "mappings": [
            {
              "stix_id": "attack-pattern--abc123",
              "name": "Spearphishing Attachment",
              "external_id": "T1566.001",
              "confidence": 92,
              "rationale": "Explicit spearphishing mention"
            }
          ],
          "evidence": [
            "• 'APT29 uses spearphishing emails' (line 3)",
            "• 'malicious attachments to executives' (line 4)"
          ]
        }
      ],
      "entities": {
        "threat_actors": ["APT29"],
        "malware": [],
        "tools": []
      }
    }
    ```

- **USER_PROMPT_TEMPLATE** (lines 124-148): Chunk analysis template
  - Purpose: Format text chunks for extraction
  - Used by: test_llm_integration.py only

### Prompt Modification Guidelines

1. **Testing Requirements**:
   - Run relevant agent tests when modifying prompts
   - Verify JSON schema compliance for structured outputs
   - Test with real threat reports for quality assurance

2. **Version Tracking**:
   - Document significant prompt changes in git commits
   - Consider A/B testing for major prompt revisions
   - Keep prompt version comments if iterating frequently

3. **Best Practices**:
   - Keep prompts concise for token efficiency
   - Use few-shot examples for consistency
   - Specify exact output formats (JSON schemas preferred)
   - Include confidence scoring instructions
   - Request evidence/rationale for transparency

4. **Performance Considerations**:
   - Shorter prompts = faster processing
   - Batch operations where possible
   - Cache LLM responses for identical prompts
   - Use structured output formats to reduce parsing errors

## Archived Modules

Experimental and research modules have been moved to `experimental/` subdirectory:
- Judge system components
- PTG (Procedural Threat Graph) builders
- Attack flow simulators
- Sequence extractors
- `prompts.py` - Legacy prompt templates (only used by tests)

These remain available but are not part of the core production pipeline.