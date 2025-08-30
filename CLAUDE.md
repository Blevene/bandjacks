# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Bandjacks is a Cyber Threat Defense World Modeling system designed to:
- Ingest and process cyber threat intelligence from multiple sources
- Build a comprehensive knowledge graph of threat actors, techniques, and defenses
- Model attack flows and sequences based on MITRE ATT&CK framework
- Integrate with D3FEND ontology for defensive recommendations
- Provide simulation and prediction capabilities for threat behaviors

## Current Status

The project is in **active development** with core extraction and modeling capabilities implemented:
- **Report Ingestion**: Async/sync PDF processing with TTP extraction
- **Attack Flow Generation**: LLM-based sequence synthesis with probabilistic edges
- **Graph Modeling**: Neo4j-based knowledge graph with STIX 2.1 objects
- **Frontend Interface**: React UI for report upload and job tracking
- **Optimized Pipeline**: Chunked processing for large documents (no timeouts)

## Architecture Overview

The system consists of these main components:

1. **Ingestion & Mapping**: Parser, vector retriever, IE & linker, STIX mapper with ADM validation
2. **Knowledge Layer**: Neo4j property graph, RDF/OWL store via n10s, OpenSearch KNN vector store
3. **World Model**: Attack flow builder, D3FEND overlay, simulation/prediction, coverage analytics
4. **Feedback & Operations**: Review API/UI, active learning queue, model refresh, RBAC

Key technologies and standards:
- **FastAPI** with **uv** for Python package management
- **Neo4j** with neosemantics (n10s) for RDF bridge
- **OpenSearch KNN** for vector embeddings
- **STIX 2.1** with strict **ATT&CK Data Model (ADM)** validation
- **ATT&CK release pinning** via official `index.json` catalog
- **D3FEND** ontology integration for defensive mappings
- Optional Node.js sidecar for ADM validation or JSON-Schema export

## Development Commands

```bash
# Project setup
uv sync                    # Install dependencies
uv run pytest             # Run tests

# Start services 
# For development (with hot reload):
# IMPORTANT: Always use 4 workers for proper async job handling and concurrency
uv run uvicorn bandjacks.services.api.main:app --workers 4 --host 0.0.0.0 --port 8000
# For development with auto-reload (single worker only):
# uv run uvicorn bandjacks.services.api.main:app --reload --host 0.0.0.0 --port 8000
cd ui && npm run dev      # Frontend (Next.js) on port 3000

# Development tasks
uv run ruff check .       # Lint code
uv run mypy .            # Type checking
uv run pytest tests/unit  # Run unit tests only

# Batch processing
python -m bandjacks.cli.batch_extract ./reports/  # Process multiple PDFs
python -m bandjacks.cli.batch_extract --api ./reports/  # Use async API

# Database setup
# Neo4j: Create constraints/indexes via DDL
# OpenSearch: Index templates created on startup
```

## Implementation Roadmap

The functional spec defines feature-based sprints:

**Sprint 1 (2 weeks)** - Foundations: Catalog, Loader, ADM Validation, TTP Search
- ATT&CK catalog API with release pinning
- STIX bundle ingestion with ADM validation
- Vector embeddings and TTP search endpoint

**Sprint 2 (2 weeks)** - Mapper MVP & Review Hooks
- Report-derived bundle processing
- Analyst review decisions API

**Sprint 3 (3 weeks)** - Attack Flow Builder v1 + Flow Search
- Episode assembly and sequencing
- STIX Attack Flow generation
- Similar flow search

**Sprint 4 (2 weeks)** - D3FEND Overlay & Defense Recommendations
- D3FEND ontology integration
- COUNTERS edges and artifact hints
- Minimal-cut defensive recommendations

**Sprint 5 (3 weeks)** - Feedback → Active Learning & Coverage Analytics
- Uncertainty queues and retraining
- Coverage gap analysis by tactic/platform

## Report Extraction & Attack Flow Modeling

### Extraction Pipeline

The system uses a multi-agent LLM pipeline to extract structured threat intelligence:

#### **1. Text Processing**
- **PDF Extraction**: Uses `pdfplumber` for high-quality text extraction
- **Chunking**: Large documents split into 3KB overlapping chunks for processing
- **Preprocessing**: Handles single-line text by splitting on sentence boundaries

#### **2. Span Detection** (`SpanFinderAgent`)
- **Pattern-based**: Detects explicit technique IDs (T1566.001) and behavioral patterns
- **Tactic-aware**: Uses regex patterns for each MITRE tactic (recon, execution, persistence, etc.)
- **Scoring**: Confidence-based filtering with deduplication

#### **3. Technique Mapping** (`BatchMapperAgent`)
- **Vector Search**: Uses OpenSearch KNN to find candidate techniques
- **LLM Verification**: Batch processes all spans in single LLM call for efficiency
- **Multi-extraction**: Extracts ALL relevant techniques per span (not just one)

#### **4. Evidence Consolidation** (`ConsolidatorAgent`)
- **Deduplication**: Merges techniques found across multiple spans
- **Confidence Aggregation**: Combines evidence from different text locations
- **Line Reference Tracking**: Maintains provenance to source text

### Attack Flow Generation

The system creates temporal sequences using multiple approaches:

#### **1. LLM-Based Sequence Synthesis** (`AttackFlowSynthesizer`)
```python
# Analyzes temporal phrases, causal relationships, and narrative flow
llm_flow = synthesize_attack_flow(
    extraction_result=extraction_data,
    report_text=report_text,
    max_steps=25
)
```

**Capabilities**:
- Temporal keyword detection ("first", "then", "next", "finally")
- Causal relationship inference from report narrative
- Evidence-backed step placement with reasoning
- Up to 25 sequenced attack steps

#### **2. Heuristic Sequential Ordering** (`FlowBuilder._order_steps()`)
- **Kill Chain Ordering**: Maps tactics to MITRE sequence (recon→access→execution→persistence...)
- **Temporal Prioritization**: Weights techniques by temporal indicators in descriptions
- **Confidence Weighting**: Prioritizes high-confidence extractions

#### **3. Probabilistic Edge Generation**
```python
# NEXT edges with probabilities 0.1-1.0 based on:
probability = self._calculate_probability(action1, action2)
# - Historical adjacency patterns in Neo4j
# - Tactic alignment/progression
# - Confidence scores
# - Temporal indicators
```

#### **4. Fallback Co-occurrence Modeling**
When sequential evidence is lacking:
- **Tactic-grouped clustering**: Creates edges within tactic groups
- **Cross-tactic bridging**: Connects adjacent tactics in kill chain
- **Sparse connectivity**: Avoids edge explosion with hub-and-spoke patterns

### Flow Types Generated

#### **Sequential Flows** (when evidence supports temporal order):
- **STIX Attack Flow objects** with ordered actions
- **AttackEpisode/AttackAction nodes** in Neo4j
- **NEXT edges** with probabilities and rationale
- **Evidence provenance** linking back to source text spans

#### **Co-occurrence Flows** (for intrusion sets, some campaigns):
- **Technique clustering** by shared tactics
- **Weak probabilistic edges** indicating co-occurrence
- **Explicitly marked** as `flow_type="co-occurrence"`

### Current Capabilities

✅ **Extract 10-15 techniques** from complex threat reports
✅ **Generate temporal sequences** when narrative evidence exists
✅ **Create probabilistic flows** with NEXT edge probabilities
✅ **Handle large documents** via chunked async processing
✅ **Maintain evidence provenance** throughout pipeline
✅ **Support both individual and batch processing**

### Limitations & Future Enhancements

❌ **Limited temporal NLP**: Basic keyword detection, could use advanced temporal parsers
❌ **Static tactic ordering**: Could learn from historical attack patterns
❌ **No ML sequence models**: Could train on attack flow datasets
❌ **Simple co-occurrence patterns**: Could use graph ML for better edge inference

## Key Design Decisions

- **ATT&CK release pinning**: Use official `index.json` catalog for version control
- **ADM-gated validation**: All STIX content must pass ATT&CK Data Model validation
- **Dual representation**: RDF/OWL for semantics, Neo4j property graph for analytics
- **TTP-centric**: Focus on behaviors, IOCs out of scope except for context
- **Hybrid retrieval**: Vector KNN to seed candidates, graph for precise linking
- **Attack Flow first-class**: Materialized as STIX extension and graph structure
- **Provenance tracking**: Every node/edge stamped with source metadata
- **No downgrades**: Prevent accidental version rollbacks unless forced

## Graph Schema

Primary node types:
- AttackPattern (techniques & sub-techniques with `x_mitre_is_subtechnique`)
- Tactic, IntrusionSet, Software, Mitigation
- DataSource, DataComponent
- AttackEpisode, AttackAction (operational)
- D3fendTechnique, DigitalArtifact (defense overlay)

Primary edge types:
- USES (Group→Technique, Software→Technique)
- HAS_TACTIC (Technique→Tactic via kill_chain_phases)
- MITIGATES (Mitigation→Technique)
- NEXT {p} (AttackAction→AttackAction with probability)
- COUNTERS (D3fendTechnique→Technique/AttackAction)

Core properties (all nodes):
- `stix_id`, `type`, `name`, `description`, `created`, `modified`, `revoked`
- `source`: `{collection, version, modified, url, adm_spec, adm_sha}`

## Report Processing Architecture

### Sync vs Async Processing

The system intelligently routes reports based on size:

#### **Synchronous Processing** (< 5KB content)
```bash
POST /v1/reports/ingest        # Text/URL ingestion
POST /v1/reports/ingest/upload # File upload
```
- **Immediate response** with full results
- **Optimal for**: Small reports, quick analysis
- **Timeout**: 2 minutes maximum

#### **Asynchronous Processing** (> 5KB content) 
```bash
POST /v1/reports/ingest_async      # Text/URL async
POST /v1/reports/ingest_file_async # File async
GET  /v1/reports/jobs/{job_id}/status # Poll job status
```
- **Immediate job ID** response for progress tracking  
- **Background processing** with chunked extraction
- **No timeouts**: Can handle large PDFs (15KB+)
- **Real-time updates** via status polling

#### **Job Status Tracking**
```json
{
  "job_id": "job-abc123",
  "status": "processing",  // pending|processing|completed|failed
  "progress": 60,
  "message": "Processing chunk 3/6",
  "result": {
    "techniques_count": 12,
    "chunks_processed": 3
  }
}
```

#### **Batch CLI Processing**
```bash
# Process directory of PDFs
python -m bandjacks.cli.batch_extract ./reports/

# Use async API with 5 workers  
python -m bandjacks.cli.batch_extract --api --workers 5 ./reports/

# Custom chunking parameters
python -m bandjacks.cli.batch_extract --chunk-size 4000 --max-chunks 15 ./reports/
```

**Performance**: Successfully processes full threat reports (15KB PDFs) in ~30-60 seconds with 12+ techniques extracted.

## API Endpoints (v1)

All endpoints under `/v1` with OpenAPI spec:

**Catalog & Loading**
- `GET /v1/catalog/attack/releases` - List ATT&CK collections/versions
- `POST /v1/stix/load/attack?collection=&version=&adm_strict=true` - Load ATT&CK release
- `POST /v1/stix/bundles?strict=true` - Import validated STIX bundles

**Search**
- `POST /v1/search/ttx` - Text→ATT&CK technique candidates (KNN)
- `POST /v1/search/flows` - Find similar attack flows

**Flows**
- `POST /v1/flows/build?source_id=` - Build attack flow from observations
- `GET /v1/flows/{flow_id}` - Get flow steps and NEXT edges

**Defense**
- `GET /v1/defense/overlay/{flow_id}` - D3FEND techniques per step
- `POST /v1/defense/mincut` - Compute minimal defensive set

**Review & Feedback**
- `POST /v1/review/mapping` - Accept/edit/reject object mappings
- `POST /v1/review/flowedge` - Review flow edge decisions
- `GET /v1/analytics/coverage` - Coverage gap analysis

## Environment Configuration

Key environment variables:
```bash
ATTACK_INDEX_URL=.../attack-stix-data/master/index.json
ATTACK_COLLECTION=enterprise-attack
ATTACK_VERSION=latest

ADM_MODE=sidecar|schema
ADM_BASE_URL=http://adm-validate:8080
ADM_SPEC_MIN=3.3.0

NEO4J_URI=bolt://neo4j:7687
OPENSEARCH_URL=http://opensearch:9200
BLOB_BASE=s3://world-model/
```

## Performance Targets (Dev)

- `/search/ttx` P95 ≤ 300ms (top_k ≤ 10)
- Initial ATT&CK load ≤ 5 min
- Flow build for small episode (≤ 10 actions) ≤ 2s

## Frontend Integration

### React UI Features (`ui/`)

- **Next.js 14** with TypeScript and Tailwind CSS
- **Report Upload Interface** (`/reports/new`):
  - Drag-and-drop PDF upload or text paste
  - Smart sync/async routing based on content size
  - Real-time job progress tracking with stage indicators
  - Auto-redirect to report details on completion

- **Job Status Component**:
  - Adaptive polling (2s → 5s → 10s intervals)
  - Live metrics display (chunks, techniques, time elapsed)
  - Stage-specific progress with icons (SpanFinder → Mapper → Consolidator)
  - Error handling and retry capabilities

- **API Integration**:
  - Type-safe API client with OpenAPI-generated types
  - Async job management endpoints
  - Background job listing and cleanup

### Usage Examples

```typescript
// Smart routing in frontend
const contentSize = selectedFile ? selectedFile.size : textContent.length;
const useAsync = contentSize > 5000; // Use async for large content

if (useAsync) {
  const jobResponse = await typedApi.reports.ingestFileAsync(file, config);
  // Show job status component for progress tracking
} else {
  const result = await typedApi.reports.ingestUpload(file, config);  
  // Show immediate results
}
```

### Performance Optimizations

- **Chunked Processing**: Handles 15KB+ PDFs without timeouts
- **Parallel Workers**: Batch CLI supports concurrent processing  
- **Caching**: Common technique lookups cached for efficiency
- **Progressive Results**: Techniques displayed as they're found

## Important Notes

- **Defensive security focus**: Designed for threat analysis and defense only
- **TTP-centric**: No IOC lifecycle management (out of scope)
- **Strict validation**: All STIX content must pass ADM validation
- **Version control**: ATT&CK releases are pinned, no accidental downgrades
- **Analyst-in-the-loop**: Designed for review and feedback integration
- **Production ready**: Handles real-world CTI reports with robust error handling