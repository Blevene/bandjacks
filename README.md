# Bandjacks

Cyber Threat Defense World Modeling System

## Overview

Bandjacks is a comprehensive cyber threat intelligence (CTI) system that:
- Extracts MITRE ATT&CK techniques from threat reports in **12-40 seconds**
- Builds a knowledge graph of threat actors, techniques, and defenses
- Generates STIX 2.1 compliant bundles with full provenance tracking
- Integrates D3FEND ontology for defensive recommendations
- Provides vector search and graph analytics capabilities
- Features **94% faster** extraction than earlier versions with LLM response caching

## Architecture Highlights

### TechniqueCache
- **In-memory cache** of all MITRE ATT&CK techniques loaded at startup
- **O(1) lookups** by external_id (e.g., T1557) for instant name resolution
- **1376 techniques** cached with full metadata (name, description, tactics, platforms)
- **Consistent naming** ensures review UI always shows human-readable technique names

## Quick Start

### Prerequisites

- Python 3.11+
- Neo4j 5.x (graph database)
- OpenSearch 2.x (vector store)
- API keys for LLM access (Gemini or OpenAI)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/bandjacks.git
cd bandjacks

# Install with uv (recommended)
uv sync

# Or with pip
pip install -e .
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
```

**Note:** The application will fail to start if `NEO4J_PASSWORD` is not set. See [Environment Variables Fix](ENV_VARIABLES_FIX.md) for details.

### Starting the API Server

```bash
# Start the FastAPI server
uv run uvicorn bandjacks.services.api.main:app --reload --port 8000

# Access the interactive API documentation
open http://localhost:8000/docs
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
- `POST /v1/flows/build` - Generate AttackFlow co-occurrence models
- `GET /v1/flows/{flow_id}` - Retrieve specific AttackFlow details
- `POST /v1/flows/search` - Search for similar attack flows
- `GET /v1/defense/technique/{id}` - Get defensive recommendations
- `GET /v1/cache/stats` - Get LLM cache statistics
- `POST /v1/cache/clear` - Clear LLM cache

### Complete API Documentation

Access the full API documentation at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI JSON: http://localhost:8000/openapi.json

## Architecture

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

## Performance Optimization

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
    "http://localhost:8000/v1/extract/provenance/attack-pattern--abc123"
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
# Get coverage gaps
response = httpx.get("http://localhost:8000/v1/analytics/coverage")
gaps = response.json()

print(f"Uncovered tactics: {gaps['uncovered_tactics']}")
print(f"Technique coverage: {gaps['coverage_percentage']}%")
```

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

### Debug Mode

Enable detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Run extraction with debug output
result = run_agentic_v2(text, config)
```

## Development

### Project Structure

```
bandjacks/
├── bandjacks/
│   ├── llm/              # Extraction pipeline
│   ├── loaders/          # Data loading and indexing
│   ├── services/api/     # REST API
│   └── simulation/       # Attack simulation
├── tests/                # Test suite
├── samples/              # Sample reports
└── docs/                 # Documentation
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `uv run pytest`
5. Submit a pull request

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