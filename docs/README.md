# Bandjacks Documentation

## Overview
Bandjacks is a Cyber Threat Defense World Modeling system that ingests and processes cyber threat intelligence, builds a comprehensive knowledge graph of threat actors, techniques, and defenses based on the MITRE ATT&CK framework.

## Quick Links

- **[API Documentation](API_DOCUMENTATION.md)** - Complete REST API reference with all endpoints
- **[Extraction Guide](EXTRACTION_GUIDE.md)** - How to use the high-performance extraction pipeline
- **[CLI Usage Guide](CLI_USAGE.md)** - Comprehensive command-line interface documentation
- **[Optimization Summary](OPTIMIZATION_SUMMARY.md)** - Performance improvements and benchmarks
- **[OpenAPI Specification](openapi.json)** - Machine-readable API specification
- **[Architecture Overview](../product_management_stuff/architecture.md)** - System design
- **[Functional Specification](../product_management_stuff/functional_spec.md)** - Detailed requirements

## Key Features

### Core Capabilities
- **ATT&CK Integration**: Full support for MITRE ATT&CK framework with ADM validation
- **Natural Language Search**: Hybrid vector and graph search with query expansion
- **High-Performance Extraction**: Async pipeline extracts techniques in 12-40 seconds
- **Technique Phrase Recognition**: 150+ technique phrases and tool associations
- **Knowledge Graph**: Neo4j-based graph with RDF/OWL semantics
- **Vector Search**: OpenSearch KNN for semantic similarity
- **Review Pipeline**: Analyst-in-the-loop validation and feedback
- **STIX 2.1 Compliance**: Full STIX bundle generation and validation

### Performance Features
- **Async Processing**: Parallel extraction with 94% performance improvement
- **LLM Response Caching**: 87.5% speedup on repeated extractions
- **Single-Pass Extraction**: Optimized processing for small documents (<500 words)
- **Batch Operations**: Single LLM call processes multiple spans
- **Early Termination**: Skip verification for high-confidence claims (>90%)
- **Connection Pooling**: Efficient database connection management

## System Components

1. **Ingestion & Mapping**
   - Document parsers (PDF, HTML, Markdown, JSON, CSV)
   - Async extraction pipeline with parallel processing
   - Single-pass extraction for small documents
   - LLM-based extraction with tool grounding
   - Vector similarity search

2. **Knowledge Layer**
   - Neo4j property graph
   - OpenSearch vector store
   - ATT&CK catalog management
   - Tactic and technique storage
   - In-memory LLM response cache

3. **API Services**
   - FastAPI REST endpoints
   - Async extraction runs with status tracking
   - Bundle validation
   - Review and feedback
   - Cache management endpoints

## Documentation Structure

```
docs/
├── README.md                 # This file
├── API_DOCUMENTATION.md     # Complete API reference
├── CLI_USAGE.md             # CLI commands and usage
├── EXTRACTION_GUIDE.md      # Extraction pipeline guide
├── OPTIMIZATION_SUMMARY.md  # Performance optimization details
└── openapi.json             # OpenAPI specification
```

## Getting Started

1. **Install Dependencies**
   ```bash
   uv sync
   ```

2. **Configure Environment**
   ```bash
   cp infra/env.sample .env
   # Edit .env and set NEO4J_PASSWORD (required) and your API keys
   # The application will not start without NEO4J_PASSWORD
   ```

3. **Start Services**
   ```bash
   # Start Neo4j
   docker-compose up -d neo4j
   
   # Start OpenSearch
   docker-compose up -d opensearch
   
   # Start API
   uv run uvicorn bandjacks.services.api.main:app --reload
   ```

4. **Load ATT&CK Data**
   ```bash
   curl -X POST http://localhost:8000/v1/stix/load/attack \
     -d '{"collection": "enterprise-attack", "version": "latest"}'
   ```

5. **Use the CLI**
   ```bash
   # Search for techniques
   python -m bandjacks.cli.main query search "lateral movement"
   
   # Check system health
   python -m bandjacks.cli.main admin health
   
   # View help
   python -m bandjacks.cli.main --help
   ```

## API Base URL

```
http://localhost:8000/v1
```

## Support

For issues or questions:
- GitHub Issues: [Report bugs or request features](https://github.com/anthropics/claude-code/issues)
- Documentation: See the `/docs` folder for detailed guides