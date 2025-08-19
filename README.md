# Bandjacks

Cyber Threat Defense World Modeling System

## Overview

Bandjacks is a comprehensive cyber threat intelligence (CTI) system that:
- Extracts MITRE ATT&CK techniques from threat reports with **87.5% recall**
- Builds a knowledge graph of threat actors, techniques, and defenses
- Generates STIX 2.1 compliant bundles with full provenance tracking
- Integrates D3FEND ontology for defensive recommendations
- Provides vector search and graph analytics capabilities

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

Create a `.env` file in the project root:

```bash
# Neo4j Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password

# OpenSearch Configuration
OPENSEARCH_URL=http://localhost:9200

# LLM Configuration
PRIMARY_LLM=gemini/gemini-2.5-flash
GEMINI_API_KEY=your-gemini-api-key

# Optional: OpenAI as fallback
OPENAI_API_KEY=your-openai-api-key

# ATT&CK Configuration
ATTACK_INDEX_URL=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json
ATTACK_COLLECTION=enterprise-attack
ATTACK_VERSION=latest
```

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

# Using the API
response = httpx.post(
    "http://localhost:8000/v1/extract/report",
    json={
        "content": "APT29 used spearphishing emails with malicious attachments...",
        "method": "agentic_v2",  # Use our 87.5% recall pipeline
        "auto_ingest": True,      # Automatically add to graph
        "title": "APT29 Campaign Analysis"
    }
)

result = response.json()
print(f"Extracted {len(result['bundle']['objects'])} STIX objects")
print(f"Techniques found: {result['stats']['claims_extracted']}")
```

### 3. Direct Python Usage

For programmatic access without the API:

```python
from bandjacks.llm.agentic_v2 import run_agentic_v2

# Configure extraction
config = {
    "neo4j_uri": "bolt://localhost:7687",
    "neo4j_user": "neo4j",
    "neo4j_password": "password",
    "model": "gemini/gemini-2.5-flash",
    "title": "My Threat Report",
}

# Run extraction
result = run_agentic_v2(report_text, config)

# Access results
techniques = result["techniques"]  # Dict of technique_id -> details
bundle = result["bundle"]          # STIX 2.1 bundle

# Example: Print extracted techniques
for tech_id, info in techniques.items():
    print(f"{tech_id}: {info['name']}")
    print(f"  Confidence: {info['confidence']}%")
    print(f"  Evidence: {info['evidence']}")
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

## Common Workflows

### Extract Techniques from PDF

```python
import PyPDF2
from bandjacks.llm.agentic_v2 import run_agentic_v2

# Read PDF
with open("threat_report.pdf", "rb") as f:
    reader = PyPDF2.PdfReader(f)
    text = ""
    for page in reader.pages:
        text += page.extract_text()

# Extract techniques
result = run_agentic_v2(text, {
    "neo4j_uri": "bolt://localhost:7687",
    "neo4j_user": "neo4j",
    "neo4j_password": "password",
    "model": "gemini/gemini-2.5-flash",
    "title": "Threat Report"
})

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
- `POST /v1/extract/report` - Extract techniques from text
- `POST /v1/search/ttx` - Search for techniques
- `GET /v1/graph/technique/{id}` - Get technique details
- `POST /v1/flows/build` - Generate attack flows
- `GET /v1/defense/technique/{id}` - Get defensive recommendations

### Complete API Documentation

Access the full API documentation at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI JSON: http://localhost:8000/openapi.json

## Architecture

### Components

1. **Extraction Pipeline** (`bandjacks/llm/`)
   - `agentic_v2.py` - Multi-agent orchestrator (87.5% recall)
   - `agents_v2.py` - Specialized extraction agents
   - `memory.py` - Shared working memory

2. **Data Layer** (`bandjacks/loaders/`)
   - Neo4j property graph for relationships
   - OpenSearch for vector embeddings
   - STIX 2.1 data model

3. **API Layer** (`bandjacks/services/api/`)
   - FastAPI REST endpoints
   - WebSocket support for real-time updates
   - Comprehensive OpenAPI documentation

### Performance

- **Extraction**: 87.5% recall on MITRE ATT&CK techniques
- **Processing**: ~7 seconds per report
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

### Extraction Methods

- `agentic_v2` - Best accuracy (87.5% recall), recommended
- `llm` - Legacy single-pass extraction
- `vector` - Pure vector search without LLM
- `hybrid` - Combination of vector and LLM

### Confidence Thresholds

Control extraction quality:

```python
{
    "confidence_threshold": 50.0,  # Minimum confidence (0-100)
    "auto_ingest": True            # Auto-add high-confidence results
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
   - Check credentials in `.env`

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