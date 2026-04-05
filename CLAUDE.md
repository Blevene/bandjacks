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

The project is in **production-ready state** with comprehensive threat intelligence capabilities implemented:
- **Report Ingestion**: Full async/sync PDF processing with advanced TTP extraction pipeline
- **Attack Flow Generation**: LLM-based sequence synthesis with probabilistic edges and co-occurrence modeling
- **Graph Modeling**: Neo4j-based knowledge graph with STIX 2.1 objects and RDF/OWL bridge
- **Frontend Interface**: Next.js 15.5 React UI with analytics dashboards and job tracking
- **Unified Review System**: Comprehensive human-in-the-loop validation interface
- **Optimized Pipeline**: Chunked processing for large documents with no timeouts
- **Analytics Engine**: Co-occurrence analysis, coverage analytics, and drift detection
- **Advanced APIs**: 30+ endpoints covering catalog, search, flows, defense, compliance, and more
- **Middleware Stack**: Authentication, rate limiting, tracing, and error handling
- **Caching Systems**: TechniqueCache and ActorCache for O(1) lookups
- **Testing Framework**: Comprehensive test suite with Jest and Testing Library

## Architecture Overview

The system consists of these main components:

1. **Ingestion & Mapping**: Parser, vector retriever, IE & linker, STIX mapper with ADM validation
2. **Knowledge Layer**: Neo4j property graph, RDF/OWL store via n10s, OpenSearch KNN vector store
3. **World Model**: Attack flow builder, D3FEND overlay, simulation/prediction, coverage analytics
4. **Feedback & Operations**: Review API/UI, active learning queue, model refresh, RBAC

Key technologies and standards:
- **FastAPI** with **uv** for Python package management and uvicorn server
- **Neo4j** with neosemantics (n10s) for RDF bridge and property graph storage
- **OpenSearch KNN** for vector embeddings and semantic search
- **Redis** for job queues and caching
- **STIX 2.1** with strict **ATT&CK Data Model (ADM)** validation
- **ATT&CK release pinning** via official `index.json` catalog
- **D3FEND** ontology integration for defensive mappings
- **LiteLLM** for multi-provider LLM integration
- **Middleware Stack**: Authentication (JWT), rate limiting, tracing, error handling
- **Frontend**: Next.js 15.5, React 19.1, TypeScript 5, Tailwind CSS 4
- **Testing**: Jest, Testing Library, pytest with comprehensive coverage
- **Dependencies**: Pydantic 2.5+, Sentence Transformers, PyTorch, pdfplumber
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
uv run pytest            # Run all tests
uv run pytest tests/unit  # Run unit tests only
uv run pytest --coverage # Run tests with coverage

# Frontend development
cd ui && npm run dev      # Start frontend dev server
cd ui && npm run build    # Build for production
cd ui && npm test         # Run frontend tests
cd ui && npm run test:coverage # Run frontend tests with coverage

# Batch processing
python -m bandjacks.cli.batch_extract ./reports/  # Process multiple PDFs
python -m bandjacks.cli.batch_extract --api ./reports/  # Use async API

# Database setup (automatic on API startup)
# Manual initialization if needed:
python -m bandjacks.loaders.neo4j_ddl    # Create Neo4j constraints/indexes
python -m bandjacks.loaders.opensearch_index  # Create OpenSearch indexes
```

## Database Initialization & Data Loading

### Neo4j Schema Setup

The system automatically creates comprehensive Neo4j constraints and indexes on startup via `ensure_ddl()`:

**Constraints (44 total)** - Ensuring uniqueness for:
- Core STIX nodes: `AttackPattern`, `IntrusionSet`, `Software`, `Mitigation`, `Tactic`
- Operational nodes: `AttackEpisode`, `AttackAction`, `AttackFlow`
- Detection nodes: `DetectionStrategy`, `Analytic`, `LogSource`, `SigmaRule`
- Defense nodes: `D3fendTechnique`, `DigitalArtifact`
- Review/ML nodes: `CandidateAttackPattern`, `ReviewProvenance`, `JudgeVerdict`

**Indexes (100+)** - Performance optimization for:
- Name and ID lookups across all node types
- Temporal queries (created, modified, timestamp)
- Status fields (revoked, deprecated, status)
- Categorical fields (platforms, tactics, type)

### OpenSearch Index Creation

Three primary indexes with KNN vector support (768 dimensions):

**1. attack_patterns index**
```json
{
  "knn": true,
  "properties": {
    "stix_id": "keyword",
    "embedding": {
      "type": "knn_vector",
      "dimension": 768,
      "method": "hnsw"
    }
  }
}
```

**2. attack_flows index** - For flow similarity search
**3. attack_edges index** - For relationship embeddings
**4. reports index** - For document storage and search

### Redis Configuration

Redis serves as the distributed job store with:
- Job queue management (`job:queue`)
- Processing state tracking (`job:processing`)
- Worker heartbeats for failure detection
- Distributed locking for atomic operations
- Default configuration: `localhost:6379`, DB 0

### STIX Data Ingestion Process

**1. Load ATT&CK Data via API:**
```bash
# Load latest enterprise ATT&CK
curl -X POST "http://localhost:8000/v1/stix/load/attack?collection=enterprise-attack&version=latest&adm_strict=false"

# Load specific version with strict validation
curl -X POST "http://localhost:8000/v1/stix/load/attack?collection=enterprise-attack&version=14.1&adm_strict=true"
```

**2. Ingestion Workflow:**
1. **Bundle Resolution**: Fetches from official ATT&CK catalog index
2. **ADM Validation**: Validates STIX objects against ATT&CK Data Model
3. **Neo4j Population**: Creates nodes for techniques, groups, software, mitigations
4. **Relationship Creation**: USES, MITIGATES, HAS_TACTIC edges
5. **Embedding Generation**: Creates 768-dim vectors for each technique
6. **OpenSearch Indexing**: Stores embeddings for vector search
7. **Cache Warming**: Loads TechniqueCache and ActorCache

**3. Embedding Generation:**
- Combines name, description, detection, tactics, platforms
- Includes T-numbers for better search matching
- Uses Sentence Transformers (all-MiniLM-L6-v2 or similar)
- Stored in OpenSearch for KNN similarity search

**4. Provenance Tracking:**
Every loaded object includes:
```json
{
  "source_collection": "enterprise-attack",
  "source_version": "14.1",
  "source_modified": "2024-04-23T00:00:00.000Z",
  "source_url": "https://...",
  "adm_spec": "3.3.0"
}
```

## Implementation Status

The system has achieved comprehensive coverage of the original PRD objectives with advanced capabilities:

**✅ Foundations (Complete)**
- ATT&CK catalog API with release pinning
- STIX bundle ingestion with ADM validation
- Vector embeddings and TTP search endpoint
- Neo4j DDL and OpenSearch index management
- Technique and Actor caching systems

**✅ Core Processing (Complete)**
- Report-derived bundle processing with chunked extraction
- Advanced LLM agents for span detection, mapping, and consolidation
- Async/sync processing with job management
- Comprehensive analyst review system (unified and entity-specific)

**✅ Attack Flow Modeling (Complete)**
- Episode assembly and sequencing with LLM synthesis
- STIX Attack Flow generation with probabilistic edges
- Co-occurrence modeling for intrusion sets
- Similar flow search and comparison

**✅ Analytics & Intelligence (Complete)**
- Co-occurrence analysis for techniques, actors, and campaigns
- Coverage gap analysis by tactic/platform
- Drift detection and monitoring
- Compliance metrics and reporting
- ML model performance tracking

**✅ Defense Integration (Complete)**
- D3FEND ontology integration
- Detection strategies and analytics management
- Sigma rule integration
- Coverage analysis across detections and mitigations

**✅ Advanced Features (Complete)**
- Graph traversal and exploration endpoints
- Attack simulation and prediction
- Provenance tracking and lineage
- Notification and alerting systems
- Comprehensive middleware stack (auth, rate limiting, tracing)

**🔄 Continuous Improvement**
- Active learning integration for model enhancement
- Performance optimization and scaling
- Extended analytics and visualization capabilities

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
- **TechniqueCache singleton**: Loads all ~1376 ATT&CK techniques at startup for O(1) lookups
  - Eliminates database queries during extraction pipeline
  - Ensures consistent human-readable names (e.g., "Adversary-in-the-Middle" instead of "T1557")
  - Thread-safe implementation shared across all workers
  - Loaded once from Neo4j with tactics, platforms, and metadata

## Graph Schema

### Node Types

Primary node types:
- **Report** - Threat intelligence reports with extracted content
- **AttackPattern** - Techniques & sub-techniques with `x_mitre_is_subtechnique`
- **Tactic**, **IntrusionSet**, **Software**, **Mitigation**, **Campaign** - Core STIX entities
- **DataSource**, **DataComponent** - Detection components
- **AttackEpisode**, **AttackAction** - Attack flow operational nodes
- **D3fendTechnique**, **DigitalArtifact** - Defense overlay

### Relationship Types

#### Report-to-Entity Relationships (Native Graph Traversal)
- **EXTRACTED_ENTITY** - Report→Entity (generic relationship)
- **IDENTIFIED_ACTOR** - Report→IntrusionSet (threat actors)
- **EXTRACTED_MALWARE** - Report→Software[type=malware]
- **MENTIONS_TOOL** - Report→Software[type=tool]
- **DESCRIBES_CAMPAIGN** - Report→Campaign
- **EXTRACTED_TECHNIQUE** - Report→AttackPattern
- **HAS_FLOW** - Report→AttackEpisode {step_count, flow_type}

#### Entity and Flow Relationships
- **USES** - Group→Technique, Software→Technique
- **HAS_TACTIC** - Technique→Tactic via kill_chain_phases
- **MITIGATES** - Mitigation→Technique
- **CONTAINS** - AttackEpisode→AttackAction (structural)
- **NEXT** {probability, reasoning} - AttackAction→AttackAction
- **COUNTERS** - D3fendTechnique→Technique/AttackAction

### Core Properties

All nodes include:
- `stix_id`, `type`, `name`, `description`, `created`, `modified`, `revoked`
- `source`: `{collection, version, modified, url, adm_spec, adm_sha}`
- `confidence` (extracted entities)
- `source_report` (entities linked to reports)

### Migration for Native Relationships

For existing data using property-based connections, run:
```bash
python migrations/add_native_relationships.py
```
This creates all native relationships for existing entities and flows.

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

## Unified Review System

After extraction, reports enter a comprehensive review system where human analysts validate all extracted items in a single interface:

### **Review Architecture**
- **Single Interface**: Combined review of entities, techniques, and flow steps
- **Universal Item Model**: All extractions converted to `ReviewableItem` format
- **Atomic Operations**: All decisions saved together in single transaction
- **Evidence-Based**: Direct links to source text with line references

### **Key Components**
```typescript
// Frontend Components (ui/components/reports/)
- unified-review.tsx        // Main review interface with tabs
- review-item-card.tsx      // Universal item card component
- review-progress.tsx       // Visual progress tracking
- review-utils.ts          // State management utilities

// Backend API
POST /v1/reports/{id}/unified-review  // Submit all review decisions
```

### **Review Workflow**
```typescript
// Convert extractions to reviewable format
const reviewableItems = [
  ...entitiesToReviewableItems(report.extraction.entities),
  ...claimsToReviewableItems(report.extraction.claims),  
  ...flowStepsToReviewableItems(report.extraction.flow.steps)
];

// Collect decisions
const decisions = reviewableItems.map(item => ({
  item_id: item.id,           // "entity-malware-0", "technique-5", "flow-step-123"
  action: "approve|reject|edit",
  edited_value?: {...},       // Modified item data
  confidence_adjustment?: number,
  notes?: string
}));

// Submit atomically
await api.submitUnifiedReview(reportId, { decisions, globalNotes });
```

### **Features**
- **Keyboard Shortcuts**: A/R/E for approve/reject/edit, Space for navigation
- **Bulk Operations**: Select and approve/reject multiple items
- **Smart Filtering**: Filter by type, status, confidence level
- **Progress Tracking**: Real-time completion status
- **Evidence Expansion**: Click to view supporting text and line references

### **Review Item Types**
1. **Entities** (`entity-{category}-{index}`)
   - Threat actors, malware, campaigns, tools
   - Edit names, descriptions, confidence scores
   
2. **Techniques** (`technique-{index}`) 
   - MITRE ATT&CK technique claims
   - Verify technique IDs and evidence quality
   
3. **Flow Steps** (`flow-{step_id}`)
   - Attack sequence steps with temporal ordering
   - Validate technique assignments and sequence logic

### **Backend Processing**
```python
# routes/unified_review.py
- Parse decisions by item ID pattern
- Apply changes to report extraction data
- Update OpenSearch document with review metadata
- Create approved entities as Neo4j nodes
- Link approved techniques to report
- Return statistics (approved/rejected/edited counts)
```

### **Documentation**
- `docs/UNIFIED_REVIEW_SYSTEM.md` - Technical architecture
- `docs/UNIFIED_REVIEW_USER_GUIDE.md` - User guide for analysts
- `docs/UNIFIED_REVIEW_API.md` - API documentation

## API Endpoints (v1)

All endpoints under `/v1` with comprehensive OpenAPI spec and 30+ implemented routes:

**Catalog & Loading**
- `GET /v1/catalog/attack/releases` - List ATT&CK collections/versions
- `POST /v1/stix/load/attack?collection=&version=&adm_strict=true` - Load ATT&CK release
- `POST /v1/stix/bundles?strict=true` - Import validated STIX bundles

**Search & Query**
- `POST /v1/search/ttx` - Text→ATT&CK technique candidates (KNN)
- `POST /v1/search/flows` - Find similar attack flows
- `POST /v1/query/*` - Natural language query and hybrid search

**Graph Operations**
- `GET /v1/graph/*` - Graph traversal and exploration endpoints

**Flows & Attack Modeling**
- `POST /v1/flows/build?source_id=` - Build attack flow from observations
- `GET /v1/flows/{flow_id}` - Get flow steps and NEXT edges
- `POST /v1/attackflow/*` - Attack Flow 2.0 ingestion, export, and interoperability
- `POST /v1/sequence/*` - Attack sequence modeling and analysis

**Defense & Coverage**
- `GET /v1/defense/overlay/{flow_id}` - D3FEND techniques per step
- `POST /v1/defense/mincut` - Compute minimal defensive set
- `GET /v1/coverage/*` - Technique coverage analysis across detections, mitigations, and D3FEND

**Reports & Review**
- `POST /v1/reports/ingest` - Synchronous report extraction
- `POST /v1/reports/ingest_async` - Asynchronous report extraction
- `GET /v1/reports/jobs/{job_id}/status` - Job status polling
- `POST /v1/reports/{id}/unified-review` - Submit unified review decisions
- `POST /v1/entity-review/*` - Entity-specific review workflows

**Analytics & Intelligence**
- `GET /v1/analytics/*` - Coverage analytics and gap analysis
- `GET /v1/actors/*` - Threat actor analysis and co-occurrence
- `POST /v1/simulate/*` - Attack path simulation and prediction
- `POST /v1/analyze/*` - Intelligence analysis operations

**Detection & Security**
- `POST /v1/detections/*` - Detection strategies, analytics, and log sources management
- `POST /v1/sigma/*` - Sigma rule management and integration with analytics

**Quality & Monitoring**
- `GET /v1/compliance/*` - Compliance metrics and reporting for ADM validation
- `GET /v1/ml-metrics/*` - Machine learning model performance metrics and monitoring
- `GET /v1/drift/*` - Drift detection and monitoring for data quality
- `GET /v1/provenance/*` - Object provenance and lineage tracking
- `GET /v1/notifications/*` - System notifications and alerts

**Health & Status**
- `GET /health` - Basic health check (always returns 200 if API is running)
- `GET /health/live` - Kubernetes liveness probe (process alive check)
- `GET /health/ready` - Kubernetes readiness probe with full dependency checks
- `GET /health/components/{component}` - Individual component health (neo4j, opensearch, redis, caches, system)

**Review & Feedback**
- `POST /v1/review/*` - Review decisions and workflows
- `POST /v1/mapper/*` - Text to ATT&CK technique mapping
- `POST /v1/feedback/*` - User feedback collection and management
- `GET /v1/review-queue/*` - Candidate review queue management
- `GET /v1/candidates/*` - Candidate attack pattern review workflow

**Cache Management**
- `GET /v1/cache/stats` - Get LLM cache statistics
- `POST /v1/cache/clear` - Clear the LLM response cache

## Health Monitoring System

The API includes comprehensive health monitoring for Kubernetes deployments and operational monitoring:

### **Health Endpoints**

#### `/health` - Basic Health Check
- **Purpose**: Simple liveness check for load balancers and uptime monitoring
- **Response**: Always returns 200 if API process is running
- **Use Case**: Basic "is it alive?" checks

#### `/health/live` - Kubernetes Liveness Probe
- **Purpose**: Determines if the container should be restarted
- **Response**: 200 if process is responsive, regardless of dependencies
- **Use Case**: Kubernetes to detect hung processes

#### `/health/ready` - Kubernetes Readiness Probe
- **Purpose**: Determines if container can receive traffic
- **Response**: 200 if all critical dependencies are healthy, 503 if not
- **Checks**: Neo4j, OpenSearch, Redis, caches, system resources
- **Use Case**: Kubernetes to route traffic only to healthy pods

#### `/health/components/{component}` - Individual Component Health
- **Components**: `neo4j`, `opensearch`, `redis`, `caches`, `system`
- **Response**: Detailed status and metrics for specific component
- **Use Case**: Targeted debugging and monitoring

### **Health Status Levels**
- **healthy**: Component fully operational
- **degraded**: Partially functional (e.g., missing indices but cluster OK)
- **unhealthy**: Component failed or unreachable

### **Monitored Components**
1. **Neo4j**: Connection test with latency measurement
2. **OpenSearch**: Cluster health and index verification
3. **Redis**: Connection test and memory usage
4. **Caches**: Technique and actor cache loading status
5. **System**: CPU, memory, and disk utilization

### **Example Health Response**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-28T17:43:30.184036Z",
  "version": "1.0.0",
  "components": {
    "neo4j": {"status": "healthy", "latency_ms": 5},
    "opensearch": {"status": "degraded", "cluster_status": "yellow"},
    "redis": {"status": "healthy", "memory_mb": 1.69},
    "caches": {"technique_cache": {"count": 993, "loaded": true}},
    "system": {"memory": {"percent_used": 72.4}, "disk": {"percent_used": 2.9}}
  }
}
```

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

# Local OpenAI-compatible API (vLLM, llama.cpp, Ollama, LocalAI, LM Studio)
LOCAL_LLM_API_BASE=http://192.168.1.100:8080/v1
LOCAL_LLM_API_KEY=no-key
LOCAL_LLM_MODEL=mistral-nemo
```

## Performance Targets (Dev)

- `/search/ttx` P95 ≤ 300ms (top_k ≤ 10)
- Initial ATT&CK load ≤ 5 min
- Flow build for small episode (≤ 10 actions) ≤ 2s

## Frontend Integration

### React UI Features (`ui/`)

- **Next.js 15.5** with React 19.1, TypeScript 5, and Tailwind CSS 4
- **Report Upload Interface** (`/reports/new`):
  - Drag-and-drop PDF upload or text paste
  - Smart sync/async routing based on content size
  - Real-time job progress tracking with stage indicators
  - Auto-redirect to report details on completion

- **Unified Review Interface** (`/reports/{id}/review`):
  - Single interface for entities, techniques, and flow steps
  - Tabbed navigation with filtering and search
  - Keyboard shortcuts for efficient review (A/R/E)
  - Bulk operations and progress tracking
  - Evidence expansion with source line references

- **Analytics Dashboards** (`/analytics/cooccurrence/`):
  - Co-occurrence analysis for techniques, actors, and campaigns
  - Conditional probability calculations and visualizations
  - Bridging analysis for technique relationships
  - Bundle-based analytics for group behaviors

- **Job Status Component**:
  - Adaptive polling (2s → 5s → 10s intervals)
  - Live metrics display (chunks, techniques, time elapsed)
  - Stage-specific progress with icons (SpanFinder → Mapper → Consolidator)
  - Error handling and retry capabilities

- **API Integration**:
  - Type-safe API client with OpenAPI-generated types
  - Async job management endpoints
  - Background job listing and cleanup
  - React Query for state management and caching

- **Component Library**:
  - Radix UI components for accessibility and consistency
  - Custom form handling with React Hook Form and Zod validation
  - Lucide React icons throughout interface
  - ReactFlow for graph visualizations
  - Recharts for analytics and metrics display

- **Testing Infrastructure**:
  - Jest with JSDOM environment for unit testing
  - Testing Library for component testing
  - MSW for API mocking
  - Comprehensive accessibility testing with jest-axe

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
- **LLM Cost Tracking**: Every LLM call records tokens and cost via `litellm.completion_cost()`. Per-report costs in extraction metrics, daily aggregates at `GET /v1/costs/stats`
- **Mapper Batch Size**: `MAX_MAPPER_BATCH_SIZE` env var (default 25) controls spans per LLM call. Higher = fewer calls but larger prompts
- **Pre-filter**: Before the LLM mapper, spans are limited to `max_spans_per_technique` (default 2) per candidate technique. Reduces mapper calls ~46% with minimal technique loss. Set to 0 to disable
- **Span Dedup** (opt-in): `enable_span_dedup: true` in config removes exact-duplicate span text before mapping. Saves ~40% spans but may lose ~15% of techniques. Disabled by default

### Extraction Config Options

```python
config = {
    "max_spans_per_technique": 2,     # Pre-filter: max spans per candidate technique (0=disabled, default=2)
    "enable_span_dedup": False,       # Text-based span deduplication (default=False)
    "max_spans": 0,                   # Hard cap on total spans (0=unlimited)
    "skip_entity_extraction": False,  # Skip entity extraction phase
    "disable_discovery": False,       # Skip LLM discovery for low-confidence spans
    "skip_verification": False,       # Skip evidence verification
}
```

## Important Notes

- **Defensive security focus**: Designed for threat analysis and defense only
- **TTP-centric**: No IOC lifecycle management (out of scope)
- **Strict validation**: All STIX content must pass ADM validation
- **Version control**: ATT&CK releases are pinned, no accidental downgrades
- **Analyst-in-the-loop**: Designed for review and feedback integration
- **Production ready**: Handles real-world CTI reports with robust error handling