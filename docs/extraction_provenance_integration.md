# CTI Extraction with STIX 2.1 and Provenance Integration

## Overview

We have successfully integrated the LLM extraction capabilities with STIX 2.1 data modeling and comprehensive provenance tracking. This enables Bandjacks to extract threat intelligence from reports, maintain full traceability, and preserve the source's provenance throughout the knowledge graph.

## Key Components Implemented

### 1. STIX Bundle Builder (`bandjacks/llm/stix_builder.py`)
- Converts raw extraction results to STIX 2.1 bundles
- Maps entities to proper STIX Domain Objects (SDOs):
  - Threat actors → `intrusion-set`
  - Malware/tools → `malware`/`tool`
  - Techniques → `attack-pattern` (with ATT&CK extensions)
  - Vulnerabilities → `vulnerability`
  - Infrastructure → `indicator`
- Creates STIX Relationship Objects (SROs):
  - Actor USES technique
  - Malware USES technique
  - Technique relationships with proper directionality
- Adds custom STIX extensions for provenance (`x_bj_*` fields)

### 2. Entity Resolver (`bandjacks/llm/entity_resolver.py`)
- Matches extracted entities to existing STIX IDs in Neo4j
- Handles entity aliasing and normalization
- Features:
  - Exact match on aliases
  - Pattern-based matching for APT groups
  - Fuzzy matching with configurable threshold (85% default)
  - Database search across all entity types
  - Batch resolution for efficiency
- Resolves common entities like APT29 to their official STIX IDs

### 3. Provenance Tracker (`bandjacks/llm/provenance_tracker.py`)
- Comprehensive metadata tracking:
  - Source documents (URL, hash, timestamp)
  - Extraction runs (method, model, parameters)
  - Object lineage (complete history)
- Key features:
  - Hash-based source identification
  - Extraction run tracking with statistics
  - STIX-compatible provenance extensions
  - Provenance chain validation
  - Aggregate confidence calculation
  - Provenance report generation

### 4. Enhanced Graph Upserter (`bandjacks/loaders/attack_upsert.py`)
- Added support for report-derived objects:
  - `Report` nodes with source metadata
  - `Indicator` nodes for IOCs
  - `Vulnerability` nodes for CVEs
  - `EXTRACTED_FROM` relationships
- Provenance preservation on all nodes/edges:
  ```cypher
  SET n.x_bj_sources = coalesce(n.x_bj_sources, []) + [{
    report_id: $report_id,
    extraction_ts: $ts,
    method: $method,
    confidence: $conf,
    evidence: $evidence,
    line_refs: $lines
  }]
  ```

### 5. Extraction API Endpoints (Async)
- `/v1/extract/runs` - Start an async extraction run (agentic v2)
- `/v1/extract/runs/{run_id}/status` - Poll run status
- `/v1/extract/runs/{run_id}/result` - Retrieve final results and metrics
  - Registers source documents
  - Extracts techniques and evidence (quotes + line refs)
  - Resolves entities to KB
  - Builds STIX bundle with provenance
  - Optional auto-ingestion to graph
  - Confidence threshold filtering

## Data Flow

```
Report Text
    ↓
Source Registration (hash-based ID)
    ↓
Text Chunking (1200 chars, 150 overlap)
    ↓
LLM Extraction (claims + entities)
    ↓
Entity Resolution (match to KB)
    ↓
STIX Bundle Creation (2.1 compliant)
    ↓
ADM Validation
    ↓
Graph Upsert with Provenance
    ↓
Vector Index Update
```

## Provenance Schema

Each extracted object carries comprehensive provenance:

```json
{
  "x_bj_provenance": {
    "report_id": "report--uuid",
    "extraction": {
      "timestamp": "2025-08-17T...",
      "method": "llm",
      "model": "gemini-2.5-flash",
      "confidence": 95
    },
    "evidence": {
      "text": "sophisticated attacks using spearphishing (T1566.001)",
      "lines": [4, 5],
      "activity": "Conducting spearphishing attacks"
    }
  },
  "x_bj_confidence": 95,
  "x_bj_evidence": "sophisticated attacks...",
  "x_bj_line_refs": [4, 5]
}
```

## Graph Structure

### New Node Types
- `Report` - Source documents with metadata
- `Indicator` - IOCs from extraction
- `Vulnerability` - CVEs mentioned in reports

### New Relationships
- `EXTRACTED_FROM` - Links objects to source reports
- Includes confidence and evidence properties

### Provenance Properties
- `x_bj_sources` - Array of provenance records
- `source_url`, `source_hash` - Document tracking
- `extraction_method`, `extraction_model` - Method metadata

## Example Usage

### Via API

```python
import requests

# Extract from report
response = requests.post(
    "http://localhost:8000/v1/extract/report",
    json={
        "content": threat_report_text,
        "source_url": "https://example.com/report",
        "title": "APT29 Analysis",
        "method": "llm",
        "confidence_threshold": 70.0,
        "auto_ingest": True
    }
)

result = response.json()
print(f"Extracted {len(result['bundle']['objects'])} objects")
print(f"Ingested: {result['ingested']}")
```

### Programmatically

```python
from bandjacks.llm.stix_builder import STIXBuilder
from bandjacks.llm.entity_resolver import EntityResolver
from bandjacks.llm.provenance_tracker import ProvenanceTracker

# Initialize components
tracker = ProvenanceTracker()
resolver = EntityResolver(neo4j_uri, user, password)
builder = STIXBuilder(resolver)

# Register source
source_id = tracker.register_source(content, url, title)

# Build STIX bundle
bundle = builder.build_bundle(
    extraction_results,
    source_metadata,
    extraction_metadata
)

# Ingest to graph
upsert_to_graph_and_vectors(bundle, ...)
```

## Benefits

1. **Full Traceability**: Every piece of extracted intelligence can be traced back to its source document, extraction method, and specific text evidence.

2. **ADM Compliance**: All STIX objects follow the ATT&CK Data Model specifications while adding custom extensions for provenance.

3. **Entity Deduplication**: Intelligent entity resolution prevents duplicate nodes in the graph by matching to existing KB entries.

4. **Confidence Management**: Multi-level confidence scoring with aggregate calculations across multiple sources.

5. **Incremental Learning**: Provenance accumulates over time, showing how confidence in an entity/relationship grows with additional sources.

6. **Audit Trail**: Complete extraction history for compliance and quality control.

7. **Source Validation**: Hash-based source identification prevents duplicate processing and ensures data integrity.

## Next Steps

1. **Active Learning Integration**: Use low-confidence extractions for analyst review
2. **Provenance Queries**: Build Neo4j queries for provenance-based analytics
3. **Confidence Calibration**: Fine-tune confidence thresholds based on feedback
4. **Source Reputation**: Weight provenance by source reliability
5. **Temporal Analysis**: Track how intelligence evolves over time
6. **Export Formats**: Generate provenance reports in various formats