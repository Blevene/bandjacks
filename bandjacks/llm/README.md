# LLM Module Structure

This directory contains the LLM-based extraction and analysis components for Bandjacks.

## Production Files

### Core Extraction Pipeline (Legacy)
- `extractor.py` - Main LLM extractor using tool-grounded approach
- `prompts.py` - System and user prompts for extraction
- `schemas.py` - JSON schemas for LLM output validation
- `client.py` - LiteLLM client wrapper for model access

### Agentic v2 Pipeline (New - 87.5% Recall)
- `agentic_v2.py` - Multi-pass orchestrator for agent pipeline
- `agents_v2.py` - Specialized agents (SpanFinder, Retriever, Discovery, Mapper, etc.)
- `memory.py` - Shared working memory for agent coordination

### STIX & Graph Integration
- `stix_builder.py` - Converts extraction results to STIX 2.1 bundles
- `bundle_validator.py` - Validates STIX bundles before graph upsert
- `entity_resolver.py` - Resolves entities to existing KB entries
- `provenance_tracker.py` - Tracks extraction provenance and lineage

### Attack Flows
- `flow_builder.py` - Builds attack flows from extraction results
- `flows.py` - LLM-based flow synthesis and sequencing
- `opportunities.py` - Opportunity analysis for defense recommendations

### Tools & Utilities
- `tools.py` - Tool adapters for LLM to interact with APIs
- `__init__.py` - Package initialization

## Experimental Code

The `experimental/` subdirectory contains:
- Alternative extraction approaches that were tested
- Removed/deprecated files for reference
- Experimental prompting strategies

These files are preserved for reference but are not used in production.

## Usage

### Using the Agentic v2 Pipeline (Recommended)

```python
from bandjacks.llm.agentic_v2 import run_agentic_v2

config = {
    "neo4j_uri": "bolt://localhost:7687",
    "neo4j_user": "neo4j",
    "neo4j_password": "password",
    "model": "gemini/gemini-2.5-flash",
    "title": "Report Title",
}

result = run_agentic_v2(report_text, config)
techniques = result["techniques"]  # Extracted techniques with evidence
bundle = result["bundle"]  # STIX 2.1 bundle ready for graph upsert
```

### Using the Legacy Pipeline

```python
from bandjacks.llm.extractor import LLMExtractor

extractor = LLMExtractor()
result = extractor.extract_document(
    source_id="doc-1",
    source_type="pdf",
    inline_text=document_text
)
```

## Performance

- **Agentic v2**: 87.5% recall on test documents
- **Processing time**: ~7 seconds per report
- **Techniques extracted**: Average 17.5 per report
- **Kill chain coverage**: 6-7 tactics average