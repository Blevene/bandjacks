# Bandjacks

Cyber Threat Defense World Modeling System

## Overview

Bandjacks is a comprehensive cyber threat intelligence (CTI) system that:
- Extracts MITRE ATT&CK techniques from threat reports in **12-40 seconds**
- Builds a knowledge graph of threat actors, techniques, and defenses
- Generates STIX 2.1 compliant bundles with full provenance tracking
- Integrates D3FEND ontology for defensive recommendations
- Provides vector search and graph analytics capabilities
- Computes **co-occurrence analytics** to identify technique patterns
- Features **94% faster** extraction than earlier versions with LLM response caching
- Includes a **Next.js frontend** for report review and analytics visualization

## Architecture Highlights

### TechniqueCache
- **In-memory cache** of all MITRE ATT&CK techniques loaded at startup
- **O(1) lookups** by external_id (e.g., T1557) for instant name resolution
- **1376 techniques** cached with full metadata (name, description, tactics, platforms)
- **Consistent naming** ensures review UI always shows human-readable technique names

### ActorCache
- **In-memory cache** of all intrusion sets and threat actors
- Fast lookups for actor name resolution and search
- Supports alias matching and fuzzy search

## Quick Start

### Prerequisites

- Python 3.11+
- Neo4j 5.x (graph database)
- OpenSearch 2.x (vector store)
- Redis (optional, for caching)
- Node.js 18+ (for frontend)
- API keys for LLM access (Gemini or OpenAI)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/bandjacks.git
cd bandjacks

# Install Python dependencies with uv (recommended)
uv sync

# Or with pip
pip install -e .

# Install frontend dependencies
cd ui && npm install && cd ..
```

### Environment Setup

**IMPORTANT:** You must configure environment variables before starting the application. The application requires `NEO4J_PASSWORD` to be set.

Create a `.env` file in the project root:

```bash
# Copy the sample file
cp infra/env.sample .env

# Edit .env and set your actual passwords
nano .env
```

Required configuration in `.env`:

```bash
# Neo4j Configuration (REQUIRED)
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your-actual-neo4j-password  # MUST BE SET - no default provided

# OpenSearch Configuration
OPENSEARCH_URL=http://localhost:9200
OPENSEARCH_USER=admin
OPENSEARCH_PASSWORD=your-opensearch-password  # Optional if security is disabled

# LLM Configuration (Required for LLM features)
PRIMARY_LLM=gemini
GOOGLE_API_KEY=your-gemini-api-key

# Optional: OpenAI as fallback
OPENAI_API_KEY=your-openai-api-key

# ATT&CK Configuration
ATTACK_INDEX_URL=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json
ATTACK_COLLECTION=enterprise-attack
ATTACK_VERSION=latest

# Redis (optional, for caching)
REDIS_URL=redis://localhost:6379
```

**Note:** The application will fail to start if `NEO4J_PASSWORD` is not set. See [Environment Variables Fix](ENV_VARIABLES_FIX.md) for details.

### Starting the Services

```bash
# Start the FastAPI backend server
uv run uvicorn bandjacks.services.api.main:app --reload --port 8000

# In another terminal, start the Next.js frontend
cd ui && npm run dev

# Access the applications
open http://localhost:8000/docs    # API documentation
open http://localhost:3000         # Frontend UI
```

## Command-Line Interface (CLI)

Bandjacks includes a comprehensive CLI for threat intelligence operations:

```bash
# Show all available commands
uv run python -m bandjacks.cli.main --help
```

> **Note:** The CLI requires environment variables to be set (NEO4J_PASSWORD, etc.). Run from the project root where `.env` is located.

### Query Commands

```bash
# Search for threat intelligence
uv run python -m bandjacks.cli.main query search "ransomware encryption techniques" --top-k 10

# Explore graph relationships
uv run python -m bandjacks.cli.main query graph "attack-pattern--abc123" --depth 2
```

### Review Queue Management

```bash
# Show review queue
uv run python -m bandjacks.cli.main review queue --status pending --limit 20

# Approve a candidate
uv run python -m bandjacks.cli.main review approve "candidate-123" --reviewer analyst-1

# Reject with reason
uv run python -m bandjacks.cli.main review reject "candidate-456" --reviewer analyst-1 --reason "False positive"
```

### Document Extraction

```bash
# Extract CTI from a document
uv run python -m bandjacks.cli.main extract document ./report.pdf --confidence-threshold 80 --show-evidence
```

### Analytics Commands

> **Note:** Analytics commands require `AttackEpisode` data in Neo4j to return results.

```bash
# Show top co-occurring technique pairs
uv run python -m bandjacks.cli.main analytics top-cooccurrence --limit 25 --min-episode-size 2

# Compute conditional co-occurrence P(B|A) for a technique
uv run python -m bandjacks.cli.main analytics conditional "attack-pattern--abc123" --limit 25

# Analyze a specific threat actor
uv run python -m bandjacks.cli.main analytics actor "intrusion-set--xyz789" --metric npmi

# Extract technique bundles
uv run python -m bandjacks.cli.main analytics bundles --min-support 3 --min-size 3 --max-size 5 --format json --output bundles.json

# Global co-occurrence metrics
uv run python -m bandjacks.cli.main analytics global --min-support 2 --limit 50 --format csv --output pairs.csv
```

### Workflow Commands

```bash
# Process a directory of reports with analytics
uv run python -m bandjacks.cli.main workflow process-reports ./reports/ --workers 3 --analyze --export-dir ./results/

# Bulk export all analytics data
uv run python -m bandjacks.cli.main workflow bulk-export --export-dir ./analytics_export/
```

### Admin Commands

```bash
# Check system health
uv run python -m bandjacks.cli.main admin health

# View cache statistics
uv run python -m bandjacks.cli.main admin cache-stats

# Clear cache
uv run python -m bandjacks.cli.main admin cache-clear --pattern "search:*"

# Optimize database
uv run python -m bandjacks.cli.main admin optimize
```

## Frontend UI

The Next.js frontend provides a modern interface for working with the system.

### Report Management (`/reports`)
- **Report List**: View all ingested reports with status and technique counts
- **New Report** (`/reports/new`): Upload PDF/TXT files or paste report content
- **Report Detail** (`/reports/[id]`): View extracted techniques, entities, and evidence
- **Review Interface** (`/reports/[id]/review`): Human-in-the-loop review workflow

### Co-occurrence Analytics (`/analytics/cooccurrence`)

> **Note:** These pages require `AttackEpisode` data in Neo4j. Process reports through the extraction pipeline first, or use `POST /v1/flows/build` to generate episodes from intrusion set data.

- **Hub Page**: Overview with episode/technique/actor counts
- **Top Pairs** (`/pairs`): Co-occurring technique pairs with NPMI/Lift metrics
- **Conditional** (`/conditional`): P(B|A) conditional probabilities
- **Bundles** (`/bundles`): Frequently co-occurring technique bundles
- **Actors** (`/actors`): Actor-specific technique patterns
- **Bridging** (`/bridging`): Techniques used across multiple actors

### System Health (`/health`)
- Real-time health status of all components (Neo4j, OpenSearch, Redis)
- Cache statistics and memory usage
- Kubernetes-compatible health endpoints

### Starting the Frontend

```bash
cd ui
npm run dev     # Development mode with hot reload
npm run build   # Production build
npm run start   # Start production server

# Ensure backend is running
# API_URL defaults to http://localhost:8000/v1
```

## Usage Guide

### 1. Loading MITRE ATT&CK Data

First, load the MITRE ATT&CK framework into your knowledge graph:

```bash
# Load the latest enterprise ATT&CK release
curl -X POST "http://localhost:8000/v1/stix/load/attack" \
  -H "Content-Type: application/json" \
  -d '{
    "collection": "enterprise-attack",
    "version": "latest",
    "adm_strict": false
  }'
```

### 2. Extracting Techniques from Reports

Extract MITRE ATT&CK techniques from threat intelligence reports:

```python
import httpx
import time

# For small reports (<5KB) - synchronous processing
response = httpx.post(
    "http://localhost:8000/v1/reports/ingest",
    json={
        "content": "APT29 used spearphishing emails with malicious attachments...",
        "title": "APT29 Campaign Analysis",
        "config": {
            "use_optimized_extractor": True,
            "span_score_threshold": 0.7,
            "top_k": 5
        }
    }
)

result = response.json()
print(f"Extracted {len(result['extraction']['techniques'])} techniques")

# For large reports (>5KB) - asynchronous processing
response = httpx.post(
    "http://localhost:8000/v1/reports/ingest_async",
    json={
        "content": large_report_text,
        "title": "Large Report Analysis"
    }
)

job_id = response.json()["job_id"]

# Check job status
status = httpx.get(f"http://localhost:8000/v1/reports/jobs/{job_id}/status")
while status.json()["status"] == "processing":
    time.sleep(2)
    status = httpx.get(f"http://localhost:8000/v1/reports/jobs/{job_id}/status")

# Get results from completed job
result = status.json()["result"]
print(f"Extracted {result['techniques_count']} techniques in {result['elapsed_time']} seconds")
```

### 3. Direct Python Usage

For programmatic access without the API:

```python
from bandjacks.llm.extraction_pipeline import run_extraction_pipeline

# Configure extraction
config = {
    "use_optimized_extractor": True,  # Use optimized pipeline
    "span_score_threshold": 0.7,      # Minimum span confidence
    "max_spans": 20,
    "top_k": 5,
    "chunk_size": 2000,               # For large documents
    "max_chunks": 100
}

# Run extraction pipeline
result = run_extraction_pipeline(
    report_text,
    config,
    source_id="report_123",
    neo4j_config=neo4j_config
)

# Access results
techniques = result["techniques"]  # Dict of technique_id -> details
bundle = result.get("bundle")      # STIX 2.1 bundle if configured
entities = result.get("entities")  # Extracted entities

# Example: Print extracted techniques
for tech_id, info in techniques.items():
    print(f"{tech_id}: {info['name']}")
    print(f"  Confidence: {info['confidence']}%")
    print(f"  Evidence: {info['evidence']}")
```

## Extraction Pipeline Architecture

The Bandjacks extraction pipeline uses a multi-agent architecture to extract structured threat intelligence:

### Pipeline Components

#### 1. **SpanFinderAgent** - Behavioral Text Detection
- Detects text spans containing threat behaviors using pattern matching
- Identifies explicit technique IDs (T1566.001) and behavioral patterns
- Scores spans by confidence and deduplicates overlapping detections
- Processes documents in chunks for scalability

#### 2. **BatchMapperAgent** - Technique Mapping
- Uses vector search (OpenSearch KNN) to find candidate techniques
- Batch processes all spans in a single LLM call for efficiency
- Extracts ALL relevant techniques per span (not just best match)
- Provides confidence scores and evidence for each mapping

#### 3. **ConsolidatorAgent** - Evidence Consolidation
- Merges duplicate techniques found across multiple spans
- Aggregates evidence from different text locations
- Tracks line references for provenance
- Produces final technique list with consolidated confidence scores

#### 4. **EntityExtractor** - Entity Recognition
- Extracts threat actors, malware, tools, and campaigns
- Uses few-shot prompting with examples for consistency
- Tracks entity mentions with line references
- Identifies aliases and coreferences

#### 5. **AttackFlowSynthesizer** - Sequence Generation
- Analyzes temporal markers ("first", "then", "after")
- Infers causal relationships from narrative
- Creates STIX Attack Flow objects with probabilistic edges
- Falls back to co-occurrence modeling when sequence unclear

### Performance Optimizations

- **Smart Chunking**: Documents split into 2KB chunks with overlap
- **Batch Processing**: Multiple operations combined in single LLM calls
- **Parallel Processing**: Chunks processed concurrently
- **Response Caching**: LLM responses cached for 15 minutes
- **Early Termination**: High-confidence extractions skip verification
- **TechniqueCache**: All ATT&CK techniques loaded at startup for O(1) lookups

### Processing Times

| Document Size | Processing Time | Techniques Extracted |
|--------------|-----------------|---------------------|
| Small (<5KB) | 10-20 seconds | 5-10 techniques |
| Medium (5-15KB) | 20-40 seconds | 10-15 techniques |
| Large (>15KB) | 30-60 seconds | 15-25 techniques |

## Co-occurrence Analytics

Bandjacks provides analytics for understanding technique relationships. 

> **Note:** Analytics require `AttackEpisode` and `AttackAction` data in Neo4j. These are created when:
> - Reports are processed through the extraction pipeline
> - Attack flows are built via `/v1/flows/build`
> - STIX bundles with attack episodes are ingested
>
> If no episodes exist, analytics will return empty results.

### Global Co-occurrence

Compute which techniques frequently appear together across all attack episodes:

```python
# Via API
response = httpx.post(
    "http://localhost:8000/v1/analytics/cooccurrence/global",
    json={"min_support": 2, "min_episodes_per_pair": 2, "limit": 50}
)

for pair in response.json()["pairs"]:
    print(f"{pair['name_a']} + {pair['name_b']}: NPMI={pair['npmi']:.3f}")
```

### Conditional Probability

Calculate P(B|A) - given technique A was used, what's the probability of technique B:

```python
response = httpx.get(
    "http://localhost:8000/v1/analytics/cooccurrence/conditional",
    params={"technique_id": "attack-pattern--abc123", "limit": 25}
)
```

### Technique Bundles

Identify frequently co-occurring technique bundles (3-5 techniques):

```python
response = httpx.post(
    "http://localhost:8000/v1/analytics/cooccurrence/bundles",
    json={"min_support": 3, "min_size": 3, "max_size": 5}
)
```

### Actor-Specific Analysis

Analyze technique patterns for specific threat actors:

```python
response = httpx.post(
    "http://localhost:8000/v1/analytics/cooccurrence/actor",
    json={"intrusion_set_id": "intrusion-set--xyz789", "min_support": 1}
)
```

## Human-in-the-Loop Review System

Bandjacks includes a comprehensive review system for validating extracted intelligence:

### Unified Review Interface

The review system presents all extracted items in a single interface:

```typescript
// Review workflow
1. Upload/ingest report → Extraction pipeline runs
2. Navigate to /reports/{id}/review
3. Review extracted items across three tabs:
   - Entities (threat actors, malware, tools)
   - Techniques (ATT&CK mappings with evidence)
   - Attack Flow (sequenced steps)
4. Take actions on each item:
   - Approve: Accept as correct
   - Reject: Mark as incorrect
   - Edit: Modify details (name, confidence, etc.)
5. Submit all decisions atomically
```

### Review Features

- **Evidence Links**: Direct links to source text with line numbers
- **Confidence Adjustment**: Modify confidence scores based on analyst knowledge
- **Bulk Operations**: Select multiple items for batch approve/reject
- **Keyboard Shortcuts**: A (approve), R (reject), E (edit), Space (next)
- **Progress Tracking**: Visual indicators of review completion
- **Filtering**: Filter by type, confidence level, or status

### API Integration

```python
# Submit review decisions
response = httpx.post(
    f"http://localhost:8000/v1/reports/{report_id}/unified-review",
    json={
        "decisions": [
            {
                "item_id": "technique-0",
                "action": "approve",
                "confidence_adjustment": 5,
                "notes": "Confirmed via external CTI"
            },
            {
                "item_id": "entity-malware-1",
                "action": "edit",
                "edited_value": {
                    "name": "Corrected Malware Name",
                    "confidence": 95
                }
            }
        ],
        "global_notes": "Review completed by analyst-1"
    }
)

# Review creates:
# - Approved entities as Neo4j nodes
# - Technique-to-report relationships
# - Audit trail of decisions
```

### 4. Searching for Techniques

Search for ATT&CK techniques using natural language:

```python
# Vector search for similar techniques
response = httpx.post(
    "http://localhost:8000/v1/search/ttx",
    json={
        "query": "ransomware that encrypts files and demands payment",
        "top_k": 5
    }
)

techniques = response.json()["results"]
for tech in techniques:
    print(f"{tech['external_id']}: {tech['name']} (score: {tech['score']:.2f})")
```

### 5. Graph Queries

Query the knowledge graph for relationships:

```python
# Get all techniques used by a specific group
response = httpx.get(
    "http://localhost:8000/v1/graph/group/G0016/techniques"
)

# Get defensive techniques for an attack
response = httpx.get(
    "http://localhost:8000/v1/defense/technique/T1566.001"
)
```

### 6. Generating AttackFlow Models

Create co-occurrence models that show how threat actors use techniques together:

```python
# Generate flow for a specific intrusion set (e.g., APT29)
response = httpx.post(
    "http://localhost:8000/v1/flows/build",
    json={
        "intrusion_set_id": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542"
    }
)

flow = response.json()
print(f"Generated flow '{flow['name']}' with {len(flow['steps'])} techniques")
print(f"Co-occurrence edges: {len(flow['edges'])}")
```

**Bulk Generation**: Generate flows for all threat actors with techniques:

```bash
# Run the bulk generation script
uv run python scripts/build_intrusion_flows_simple.py

# Monitor progress - creates flows for 165+ intrusion sets
# Handles rate limiting automatically
# Skips existing flows to avoid duplicates
```

AttackFlow models use **co-occurrence** rather than sequential ordering since intrusion sets don't have inherent sequence information. Techniques are connected by:
- **Intra-tactic edges**: Between techniques in the same kill chain tactic
- **Cross-tactic edges**: Between techniques across adjacent tactics
- **Hub-spoke patterns**: For large technique sets to avoid edge explosion

See the [AttackFlow Generation Guide](docs/ATTACKFLOW_GENERATION.md) for detailed usage.

## Supported Input Formats

The extraction pipeline supports multiple input formats:

- **Plain Text** - Direct text content
- **Markdown** - Formatted markdown documents
- **PDF** - Via pdfplumber extraction
- **HTML** - Via BeautifulSoup parsing
- **JSON** - Structured data extraction

### Extract from Plain Text

```python
# Direct text extraction
plaintext_report = """
The threat actors used spearphishing emails with malicious attachments.
After gaining access, they deployed Mimikatz to harvest credentials and
used RDP for lateral movement across the network.
"""

result = asyncio.run(run_agentic_v2_async(plaintext_report, {
    "cache_llm_responses": True,
    "single_pass_threshold": 500
}))
```

### Extract from Markdown

```python
# Markdown document extraction
markdown_report = """
# APT Campaign Analysis

## Attack Methods
- **Initial Access**: Spearphishing with malicious Office documents
- **Execution**: PowerShell scripts and scheduled tasks
- **Persistence**: Registry modifications and service installation

## Tools Used
| Tool | Purpose |
|------|---------|
| Mimikatz | Credential dumping |
| PsExec | Remote execution |
| Cobalt Strike | C2 communications |
"""

result = run_extraction_pipeline(markdown_report, {
    "use_optimized_extractor": True,
    "span_score_threshold": 0.7
}, source_id="markdown_report")
```

### Extract from PDF

```python
import pdfplumber
from bandjacks.llm.extraction_pipeline import run_extraction_pipeline

# Read PDF with pdfplumber (recommended)
with pdfplumber.open("threat_report.pdf") as pdf:
    text = ""
    for page in pdf.pages:
        page_text = page.extract_text()
        if page_text:
            text += page_text + "\n"

# Extract techniques using extraction pipeline
result = run_extraction_pipeline(text, {
    "use_optimized_extractor": True,
    "span_score_threshold": 0.7,
    "chunk_size": 2000
}, source_id="threat_report")

print(f"Found {len(result['techniques'])} techniques")
```

### Batch Processing Reports

```python
from pathlib import Path
import json

reports_dir = Path("./reports")
results = []

for pdf_file in reports_dir.glob("*.pdf"):
    # Extract text and techniques
    # ... (see above)
    
    results.append({
        "file": pdf_file.name,
        "techniques": list(result["techniques"].keys()),
        "count": len(result["techniques"])
    })

# Save summary
with open("extraction_summary.json", "w") as f:
    json.dump(results, f, indent=2)
```

### Building Attack Flows

```python
# Generate attack flow from extracted techniques
response = httpx.post(
    "http://localhost:8000/v1/flows/build",
    json={
        "source_id": "report-123",
        "technique_ids": ["T1566.001", "T1059.001", "T1003.001"]
    }
)

flow = response.json()
print(f"Generated flow with {len(flow['steps'])} steps")
```

## Testing

Run the test suite to verify your installation:

```bash
# Run all tests
uv run pytest

# Test extraction pipeline
python tests/test_optimized_extraction.py

# Test graph integration
python tests/test_graph_upsert.py

# Test STIX validation
python tests/test_bundle_validation.py

# Run frontend tests
cd ui && npm test
```

## API Endpoints

### Core Endpoints

- `POST /v1/stix/load/attack` - Load MITRE ATT&CK data
- `POST /v1/reports/ingest` - Synchronous report ingestion (<5KB)
- `POST /v1/reports/ingest_async` - Asynchronous report ingestion (>5KB)
- `POST /v1/reports/ingest/upload` - Upload PDF/TXT files
- `GET /v1/reports/jobs/{id}/status` - Check job status
- `POST /v1/reports/{id}/unified-review` - Submit review decisions
- `POST /v1/search/ttx` - Search for techniques
- `GET /v1/graph/technique/{id}` - Get technique details

### Attack Flows

- `POST /v1/flows/build` - Generate AttackFlow co-occurrence models
- `GET /v1/flows/{flow_id}` - Retrieve specific AttackFlow details
- `POST /v1/flows/search` - Search for similar attack flows

### Analytics

- `GET /v1/analytics/cooccurrence/global` - Global co-occurrence metrics
- `GET /v1/analytics/cooccurrence/conditional` - Conditional probabilities
- `GET /v1/analytics/cooccurrence/bundles` - Technique bundles
- `GET /v1/analytics/cooccurrence/actor` - Actor-specific patterns
- `GET /v1/coverage/gaps` - Technique coverage gaps

### Defense & Detection

- `GET /v1/defense/technique/{id}` - Get defensive recommendations
- `GET /v1/detections/technique/{id}` - Detection strategies
- `POST /v1/sigma/validate` - Validate Sigma rules

### Monitoring

- `GET /health` - Basic health check
- `GET /health/live` - Kubernetes liveness probe
- `GET /health/ready` - Kubernetes readiness probe
- `GET /health/components/{component}` - Individual component health
- `GET /v1/cache/stats` - Get LLM cache statistics
- `POST /v1/cache/clear` - Clear LLM cache
- `GET /v1/compliance/report` - Compliance metrics
- `GET /v1/drift/status` - Drift detection status
- `GET /v1/ml-metrics/performance` - ML model metrics

### Actors & Provenance

- `GET /v1/actors` - List threat actors
- `GET /v1/actors/{id}` - Get actor details
- `GET /v1/provenance/{object_id}` - Object provenance
- `GET /v1/provenance/{object_id}/lineage` - Full lineage chain
- `GET /v1/provenance/{object_id}/evidence` - Evidence snippets

### API-Only Features (No UI/CLI)

These endpoints are fully functional but are accessed via REST API only (no frontend pages or CLI commands):

#### Attack Path Simulation
- `POST /v1/simulation/paths` - Simulate attack paths from starting technique/group
- `POST /v1/simulation/predict` - Predict next likely techniques given current state
- `POST /v1/simulation/whatif` - What-if analysis for defensive scenarios
- `POST /v1/simulation/scenario` - Simulate from sets of groups/software/techniques
- `GET /v1/simulation/statistics/{technique_id}` - Technique usage statistics
- `GET /v1/simulation/groups/{group_id}/patterns` - Group attack patterns
- `POST /v1/simulation/compare` - Compare multiple attack paths

#### MDP Policy & Rollout
- `POST /v1/simulate/rollout` - PTG rollout simulation
- `POST /v1/simulate/mdp` - Compute MDP optimal defense policy
- `GET /v1/simulate/models` - List available PTG models

#### Drift Detection & Monitoring
- `GET /v1/drift/status` - Current drift status across all metrics
- `POST /v1/drift/analyze` - Run drift analysis with custom thresholds
- `GET /v1/drift/alerts` - Get active drift alerts
- `POST /v1/drift/alerts/{alert_id}/acknowledge` - Acknowledge alert
- `GET /v1/drift/metrics/{metric_name}` - Get specific drift metric

#### ML Metrics Tracking
- `POST /v1/ml-metrics/prediction` - Record model prediction for tracking
- `POST /v1/ml-metrics/review` - Record review decision metrics
- `POST /v1/ml-metrics/coverage-gap` - Record coverage gap
- `GET /v1/ml-metrics/performance` - Get model performance metrics
- `GET /v1/ml-metrics/dashboard` - Export dashboard metrics

#### Notifications
- `GET /v1/notifications/history` - Get notification history
- `POST /v1/notifications/clear-history` - Clear notification history
- `GET /v1/notifications/config` - Get notification configuration
- `POST /v1/notifications/test` - Send test notification

#### Vector Update Management
- `GET /v1/vectors/status` - Vector update system status
- `GET /v1/vectors/metrics` - Detailed vector update metrics
- `POST /v1/vectors/update` - Manually trigger vector update
- `POST /v1/vectors/process-batch` - Force batch processing
- `DELETE /v1/vectors/queue` - Clear pending update queue
- `GET /v1/vectors/health` - Vector system health check

#### Entity Ignorelist
- `GET /v1/ignorelist` - Get current ignorelist status
- `POST /v1/ignorelist/add` - Add entity to ignorelist
- `DELETE /v1/ignorelist/remove` - Remove entity from ignorelist
- `POST /v1/ignorelist/reload` - Reload ignorelist from disk

#### Candidate Pattern Review
- `GET /v1/review/candidates` - List candidate attack patterns
- `POST /v1/review/candidates` - Create candidate pattern
- `GET /v1/review/candidates/{id}` - Get candidate details
- `POST /v1/review/candidates/{id}/approve` - Approve candidate
- `POST /v1/review/candidates/{id}/reject` - Reject candidate
- `GET /v1/review/candidates/{id}/similar` - Find similar patterns
- `GET /v1/review/candidates/stats/summary` - Candidate statistics

### Complete API Documentation

Access the full API documentation at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI JSON: http://localhost:8000/openapi.json

## Architecture

### Project Structure

```
bandjacks/
├── bandjacks/
│   ├── analysis/         # Graph analysis & interdiction
│   │   ├── graph_analyzer.py
│   │   └── interdiction.py
│   ├── analytics/        # Co-occurrence & clustering
│   │   ├── clustering.py
│   │   ├── cooccurrence.py
│   │   └── detection_bundles.py
│   ├── cli/              # Command-line interface
│   │   ├── main.py       # CLI entry point
│   │   ├── batch_extract.py
│   │   ├── formatters.py
│   │   └── workflows.py
│   ├── config/           # Configuration files
│   │   └── entity_ignorelist.yaml
│   ├── core/             # Core utilities
│   │   ├── cache.py      # Redis caching
│   │   ├── connection_pool.py
│   │   └── query_optimizer.py
│   ├── llm/              # Extraction pipeline
│   │   ├── extraction_pipeline.py
│   │   ├── agents_v2.py  # Core extraction agents
│   │   ├── chunked_extractor.py
│   │   ├── optimized_chunked_extractor.py
│   │   ├── entity_extractor.py
│   │   ├── flow_builder.py
│   │   ├── cache.py      # LLM response caching
│   │   └── experimental/ # Experimental features
│   ├── loaders/          # Data loading & indexing
│   │   ├── attack_catalog.py
│   │   ├── attack_upsert.py
│   │   ├── opensearch_index.py
│   │   ├── hybrid_search.py
│   │   └── sigma_loader.py
│   ├── monitoring/       # Metrics & monitoring
│   │   ├── compliance_metrics.py
│   │   ├── defense_metrics.py
│   │   ├── drift_detector.py
│   │   └── ml_metrics.py
│   ├── services/         # API & services
│   │   ├── api/          # FastAPI application
│   │   │   ├── main.py
│   │   │   ├── routes/   # API route handlers
│   │   │   └── middleware/
│   │   ├── technique_cache.py
│   │   └── actor_cache.py
│   ├── simulation/       # Attack simulation
│   │   ├── attack_simulator.py
│   │   ├── mdp_solver.py
│   │   └── ptg_rollout.py
│   └── store/            # Data stores
│       ├── report_store.py
│       ├── candidate_store.py
│       └── review_store.py
├── ui/                   # Next.js frontend
│   ├── app/              # App Router pages
│   │   ├── reports/      # Report management
│   │   ├── analytics/    # Analytics dashboards
│   │   └── health/       # Health monitoring
│   ├── components/       # React components
│   └── hooks/            # Custom React hooks
├── tests/                # Test suite
├── samples/              # Sample reports
├── scripts/              # Utility scripts
└── docs/                 # Documentation
```

### Components

1. **Extraction Pipeline** (`bandjacks/llm/`)
   - `extraction_pipeline.py` - Main extraction orchestrator
   - `chunked_extractor.py` - Standard chunked processing
   - `optimized_chunked_extractor.py` - Advanced optimized processing
   - `agents_v2.py` - Core extraction agents (SpanFinder, Mapper, Consolidator)
   - `entity_extractor.py` - Entity recognition agent
   - `flow_builder.py` - Attack flow generation
   - `memory.py` - Shared working memory
   - `cache.py` - LLM response caching

2. **Data Layer** (`bandjacks/loaders/`)
   - Neo4j property graph for relationships
   - OpenSearch for vector embeddings
   - STIX 2.1 data model

3. **API Layer** (`bandjacks/services/api/`)
   - FastAPI REST endpoints
   - WebSocket support for real-time updates
   - Comprehensive OpenAPI documentation

4. **Frontend** (`ui/`)
   - Next.js 15 with App Router
   - React Query for data fetching
   - Radix UI + Tailwind for components
   - ReactFlow for graph visualization

### Performance

- **Extraction Speed**: 12-40 seconds per report (94% faster than v1)
- **Small Documents**: 4-8 seconds with single-pass extraction
- **Cache Hit Rate**: 87.5% speedup on repeated extractions
- **Search**: <300ms for vector similarity search
- **Graph queries**: <100ms for most traversals

## Configuration

### Model Selection

The system supports multiple LLMs:

```python
# In your .env or config
PRIMARY_LLM=gemini/gemini-2.5-flash  # Recommended
# PRIMARY_LLM=gpt-4o-mini            # Alternative
# PRIMARY_LLM=gpt-4-turbo            # Higher quality, higher cost
```

### Extraction Configuration

The system uses a single high-performance async pipeline with configurable options:

```python
{
    "cache_llm_responses": True,         # Enable LLM caching (default: True)
    "single_pass_threshold": 500,        # Max words for single-pass (default: 500)
    "early_termination_confidence": 90,  # Skip verification above this (default: 90)
    "disable_discovery": False,          # Disable LLM discovery agent
    "max_spans": 20,                    # Maximum spans to process
    "span_score_threshold": 0.7,        # Minimum span quality
    "top_k": 5                          # Candidates per span
}
```

### Confidence Thresholds

Control extraction quality:

```python
{
    "confidence_threshold": 50.0,  # Minimum confidence (0-100)
    "auto_ingest": True            # Auto-add high-confidence results
}
```

## Health Monitoring

The API provides comprehensive health monitoring endpoints for operational oversight and Kubernetes deployments:

### Health Endpoints

```bash
# Basic health check (always returns 200 if API is running)
curl http://localhost:8000/health

# Kubernetes liveness probe (process alive check)
curl http://localhost:8000/health/live

# Kubernetes readiness probe (full dependency checks)
curl http://localhost:8000/health/ready

# Individual component health
curl http://localhost:8000/health/components/neo4j
curl http://localhost:8000/health/components/opensearch
curl http://localhost:8000/health/components/redis
curl http://localhost:8000/health/components/caches
curl http://localhost:8000/health/components/system
```

### Health Response Example

```json
{
  "status": "healthy",
  "timestamp": "2025-01-28T17:43:30.184036Z",
  "version": "1.0.0",
  "components": {
    "neo4j": {
      "status": "healthy",
      "latency_ms": 5
    },
    "opensearch": {
      "status": "degraded",
      "cluster_status": "yellow",
      "indices": {
        "attack_nodes": false,
        "bandjacks_reports": true
      }
    },
    "redis": {
      "status": "healthy",
      "latency_ms": 2,
      "memory_mb": 1.69
    },
    "caches": {
      "status": "healthy",
      "technique_cache": {
        "count": 993,
        "loaded": true
      },
      "actor_cache": {
        "count": 145,
        "loaded": true
      }
    },
    "system": {
      "status": "healthy",
      "memory": {
        "available_gb": 8.84,
        "percent_used": 72.4
      },
      "disk": {
        "available_gb": 353.11,
        "percent_used": 2.9
      },
      "cpu": {
        "percent_used": 7.7
      }
    }
  }
}
```

### Status Levels

- **healthy**: Component fully operational
- **degraded**: Partially functional (e.g., missing some indices but operational)
- **unhealthy**: Component failed or unreachable

### Kubernetes Integration

For Kubernetes deployments, configure probes as follows:

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8000
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8000
  initialDelaySeconds: 45
  periodSeconds: 5
```

## Performance Optimization

### Caching

The system includes automatic LLM response caching for improved performance:

```python
# Check cache statistics
response = httpx.get("http://localhost:8000/v1/cache/stats")
stats = response.json()
print(f"Cache hit rate: {stats['hit_rate']}")

# Clear cache if needed
httpx.post("http://localhost:8000/v1/cache/clear")
```

### Performance Profiles

Choose a profile based on your needs:

```python
# Fast extraction (4-15 seconds)
fast_config = {
    "single_pass_threshold": 1000,
    "max_spans": 5,
    "skip_verification": True,
    "top_k": 3
}

# Balanced (default, 12-40 seconds)
balanced_config = {
    "single_pass_threshold": 500,
    "max_spans": 10,
    "early_termination_confidence": 90,
    "top_k": 5
}

# High quality (40-120 seconds)
quality_config = {
    "single_pass_threshold": 200,
    "max_spans": 20,
    "disable_discovery": False,
    "min_quotes": 3,
    "top_k": 10
}
```

## Advanced Features

### Provenance Tracking

Every extracted entity includes full provenance:

```python
# Get provenance for an object
response = httpx.get(
    "http://localhost:8000/v1/provenance/attack-pattern--abc123"
)
```

### Active Learning

The system includes a review queue for improving extraction:

```python
# Get next item for review
response = httpx.get("http://localhost:8000/v1/review_queue/next")

# Submit feedback
response = httpx.post(
    "http://localhost:8000/v1/feedback/extraction",
    json={
        "extraction_id": "ext-123",
        "correct": True,
        "corrections": []
    }
)
```

### Coverage Analytics

Analyze your threat intelligence coverage:

```python
# Get coverage analysis
response = httpx.get("http://localhost:8000/v1/analytics/coverage")
coverage = response.json()

print(f"Summary: {coverage['summary']}")
for tactic in coverage['tactics']:
    print(f"  {tactic['tactic']}: {tactic['coverage_percentage']}%")
```

> **Note:** Platform coverage (`_analyze_platforms_coverage`) currently returns placeholder data. Tactic and group coverage use real Neo4j queries.

### Attack Simulation (Experimental)

The simulation module provides MDP-based attack path prediction:

```python
# Note: This feature is experimental and may require additional setup
from bandjacks.simulation.attack_simulator import AttackSimulator
from bandjacks.simulation.mdp_solver import MDPSolver

# See bandjacks/simulation/ for implementation details
```

## Feature Status

This section provides transparency about the implementation status of various features:

### Fully Functional ✅
- **Report Extraction Pipeline** - LLM-based technique extraction works end-to-end
- **MITRE ATT&CK Loading** - Load enterprise/mobile/ICS ATT&CK data into Neo4j
- **Vector Search** - OpenSearch-based semantic search for techniques
- **Review System** - Human-in-the-loop review workflow via API and UI
- **Health Monitoring** - Component health checks and Kubernetes probes
- **CLI Query/Admin Commands** - Search, graph traversal, cache management
- **Attack Flow Generation** - Co-occurrence-based flow building for intrusion sets
- **Attack Simulation** - MDP-based path simulation via `/simulation/*` and `/simulate/*`
- **Coverage Reports** - JSON reports for executive, technical, tactical, operational views

### Functional with Data Dependencies ⚠️
- **Co-occurrence Analytics** - Requires `AttackEpisode` nodes from report processing
- **Actor Analytics** - Requires episodes attributed to intrusion sets
- **Technique Bundles** - Requires sufficient episode data for pattern mining
- **CLI Analytics Commands** - Work but return empty if no episodes exist

### API-Only (No UI/CLI) 🔌
These are fully implemented features accessible only via REST API:
- **Attack Path Simulation** - `/simulation/*` routes for path prediction and what-if analysis
- **MDP Policy Solver** - `/simulate/mdp` for optimal defense policy computation
- **Drift Detection** - `/drift/*` routes for monitoring data quality drift
- **ML Metrics** - `/ml-metrics/*` for tracking model performance over time
- **Vector Management** - `/vectors/*` for managing vector embeddings
- **Entity Ignorelist** - `/ignorelist/*` for filtering false positive entities
- **Candidate Patterns** - `/review/candidates/*` for novel technique candidates
- **Notifications** - `/notifications/*` for alert configuration and history
- **Provenance** - `/provenance/*` for extraction lineage tracking
- **Compliance** - `/compliance/*` for compliance metrics reporting

### Experimental (in `llm/experimental/`) 🧪
- **PTG (Probabilistic Threat Graph)** - Core logic implemented, limited testing
- **Judge Integration** - LLM-based sequence validation
- **Attack Flow Simulator** - Flow-based simulation engine
- **Sequence Extractor** - Extract sequences from flows

### Removed/Cleaned Up 🗑️
The following stub features have been removed from the API:
- ~~Platform Coverage Analysis~~ - Was returning hardcoded stub data
- ~~Trend Analysis~~ - Was returning random synthetic data
- ~~CSV/PDF Report Export~~ - Was returning 501; JSON-only now
- ~~Gemini Sequence Inference~~ - Was 501 stub; use `/sequence/propose` instead

### Connectivity Matrix

| Feature Area | Frontend UI | CLI | REST API |
|--------------|-------------|-----|----------|
| Report Management | ✅ | ✅ | ✅ |
| Review Workflow | ✅ | ✅ | ✅ |
| Search (TTX) | ✅ | ✅ | ✅ |
| Co-occurrence Analytics | ✅ | ✅ | ✅ |
| Coverage Analytics | ✅ | - | ✅ |
| Health Monitoring | ✅ | - | ✅ |
| Detections/Sigma | ✅ | - | ✅ |
| Attack Flows | ✅ | - | ✅ |
| Defense Overlay | ✅ | - | ✅ |
| Sequences/PTG | ✅ | - | ✅ |
| Actors | ✅ | - | ✅ |
| Attack Simulation | - | - | ✅ |
| Drift Detection | - | - | ✅ |
| ML Metrics | - | - | ✅ |
| Vector Management | - | - | ✅ |
| Entity Ignorelist | - | - | ✅ |
| Candidate Patterns | - | - | ✅ |
| Notifications | - | - | ✅ |
| Provenance | - | - | ✅ |
| Compliance | - | - | ✅ |

### Frontend Pages
| Page | Status | Notes |
|------|--------|-------|
| `/reports` | ✅ Working | List, create, view reports |
| `/reports/[id]/review` | ✅ Working | Full review workflow |
| `/analytics/cooccurrence` | ⚠️ Data-dependent | Shows KPIs if episodes exist |
| `/analytics/cooccurrence/pairs` | ⚠️ Data-dependent | Calls real API |
| `/analytics/cooccurrence/bundles` | ⚠️ Data-dependent | Calls real API |
| `/analytics/cooccurrence/actors` | ⚠️ Data-dependent | Calls real API |
| `/health` | ✅ Working | Real-time health status |

## Troubleshooting

### Common Issues

1. **OpenSearch connection failed**
   - Ensure OpenSearch is running: `curl http://localhost:9200`
   - Check index exists: `curl http://localhost:9200/bandjacks_attack_nodes-v1`

2. **Neo4j connection failed**
   - Verify Neo4j is running: `neo4j status`
   - Check that `NEO4J_PASSWORD` is set in `.env` file
   - Ensure the password matches your Neo4j instance
   - If you see "NEO4J_PASSWORD environment variable is required", you need to set it in your `.env` file

3. **Low extraction recall**
   - Ensure you're using `agentic_v2` method
   - Check LLM API key is valid
   - Verify model name is correct (gemini-2.5-flash)

4. **Timeout errors**
   - Increase timeout settings for large documents
   - Consider chunking very large reports

5. **Frontend not connecting to API**
   - Ensure API is running on port 8000
   - Check CORS settings in API configuration

### Debug Mode

Enable detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Run extraction with debug output
result = run_agentic_v2(text, config)
```

## Development

### Running Tests

```bash
# Unit tests
uv run pytest tests/unit

# Integration tests
uv run pytest tests/integration

# Specific test
uv run pytest tests/test_agentic_v2.py::test_extraction

# With coverage
uv run pytest --cov=bandjacks

# Frontend tests
cd ui && npm test
cd ui && npm run test:coverage
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `uv run pytest`
5. Run linting: `uv run ruff check`
6. Submit a pull request

### Code Quality

```bash
# Format code
uv run ruff format

# Check linting
uv run ruff check

# Type checking
uv run mypy bandjacks
```

## License

[Your License Here]

## Support

- GitHub Issues: [Report bugs or request features]
- Documentation: [Link to full docs]
- Email: support@bandjacks.io

## Acknowledgments

- MITRE ATT&CK® framework
- D3FEND ontology
- STIX 2.1 specification
