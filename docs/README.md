# Bandjacks Documentation

## Overview
Bandjacks is a Cyber Threat Defense World Modeling system that ingests and processes cyber threat intelligence, builds a comprehensive knowledge graph of threat actors, techniques, and defenses based on the MITRE ATT&CK framework.

## Quick Links

- [API Documentation](./api/README.md) - Complete API reference
- [Quick Start Guide](./QUICKSTART.md) - Get up and running quickly
- [Environment Setup](./SETUP.md) - Configuration and dependencies
- [Architecture Overview](../product_management_stuff/architecture.md) - System design
- [Functional Specification](../product_management_stuff/functional_spec.md) - Detailed requirements

## Key Features

- **ATT&CK Integration**: Full support for MITRE ATT&CK framework with ADM validation
- **Multi-Engine Extraction**: Vector-based, LLM-based (GPT-5/Gemini-2.5-Flash), and hybrid approaches
- **Technique Phrase Recognition**: 150+ technique phrases and tool associations
- **Knowledge Graph**: Neo4j-based graph with RDF/OWL semantics
- **Vector Search**: OpenSearch KNN for semantic similarity
- **Review Pipeline**: Analyst-in-the-loop validation and feedback
- **STIX 2.1 Compliance**: Full STIX bundle generation and validation

## System Components

1. **Ingestion & Mapping**
   - Document parsers (PDF, HTML, Markdown, JSON, CSV)
   - Text chunking with overlap
   - LLM-based extraction with tool grounding
   - Vector similarity search

2. **Knowledge Layer**
   - Neo4j property graph
   - OpenSearch vector store
   - ATT&CK catalog management
   - Tactic and technique storage

3. **API Services**
   - FastAPI REST endpoints
   - Real-time extraction
   - Bundle validation
   - Review and feedback

## Documentation Structure

```
docs/
├── README.md                 # This file
├── QUICKSTART.md            # Quick start guide
├── SETUP.md                 # Environment setup
└── api/                     # API documentation
    ├── README.md            # API overview
    ├── catalog.md           # Catalog endpoints
    ├── stix-loader.md       # STIX loading endpoints
    ├── search.md            # Search endpoints
    ├── mapper.md            # Mapper/proposal endpoints
    ├── llm.md               # LLM extraction endpoints
    └── review.md            # Review endpoints
```

## Getting Started

1. **Install Dependencies**
   ```bash
   uv sync
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env
   # Add your API keys and configuration
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

## API Base URL

```
http://localhost:8000/v1
```

## Support

For issues or questions:
- GitHub Issues: [Report bugs or request features](https://github.com/anthropics/claude-code/issues)
- Documentation: See the `/docs` folder for detailed guides