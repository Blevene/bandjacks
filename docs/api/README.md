# Bandjacks API Documentation

## Overview

The Bandjacks API provides RESTful endpoints for cyber threat intelligence extraction, ATT&CK mapping, and knowledge graph management. All endpoints follow OpenAPI 3.0 specifications.

## Base URL

```
http://localhost:8000/v1
```

## Authentication

Currently, the API does not require authentication for local development. Production deployments should implement appropriate authentication mechanisms.

## Content Types

- **Request**: `application/json`
- **Response**: `application/json`

## API Endpoints by Category

### 1. Catalog Management
Manage ATT&CK releases and tactics.

- [`GET /catalog/attack/releases`](./catalog.md#get-catalogattackreleases) - List available ATT&CK releases
- [`GET /catalog/tactics`](./catalog.md#get-catalogtactics) - Get all ATT&CK tactics

### 2. STIX Data Loading
Load and manage STIX bundles.

- [`POST /stix/load/attack`](./stix-loader.md#post-stixloadattack) - Load ATT&CK collection
- [`POST /stix/bundles`](./stix-loader.md#post-stixbundles) - Ingest custom STIX bundle

### 3. Search
Search for techniques and entities.

- [`POST /search/ttx`](./search.md#post-searchttx) - Text-to-technique search with optional filtering

### 4. Document Mapping
Extract TTPs from documents.

- [`POST /mapper/propose`](./mapper.md#post-mapperpropose) - Analyze document and propose mappings

### 5. Report Ingestion
Process threat intelligence reports and extract techniques.

- [`POST /reports/ingest`](./reports.md#post-reportsingest) - Synchronous report ingestion (<5KB)
- [`POST /reports/ingest_async`](./reports.md#post-reportsingest_async) - Asynchronous report ingestion (>5KB)
- [`GET /reports/jobs/{job_id}/status`](./reports.md#get-reportsjobsjob_idstatus) - Check job status

### 6. LLM Extraction
Advanced extraction using LLMs.

- [`POST /llm/extract`](./llm.md#post-llmextract) - Extract with LLM and tool grounding
- [`POST /llm/to-stix`](./llm.md#post-llmto-stix) - Convert LLM output to STIX

### 6. Review & Feedback
Analyst review and validation.

- [`POST /review/mapping`](./review.md#post-reviewmapping) - Review proposed mapping
- [`POST /review/object`](./review.md#post-reviewobject) - Review existing object
- [`GET /stix/objects/{id}`](./review.md#get-stixobjectsid) - Get object with provenance

## Common Response Formats

### Success Response
```json
{
  "status": "success",
  "data": { ... }
}
```

### Error Response
```json
{
  "detail": "Error message describing what went wrong"
}
```

### HTTP Status Codes

- `200 OK` - Request succeeded
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request parameters
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error
- `502 Bad Gateway` - External service error

## Rate Limiting

No rate limiting in development. Production deployments should implement appropriate limits.

## Pagination

Endpoints returning lists support pagination:
- `limit` - Number of results (default: 20, max: 100)
- `offset` - Skip first N results (default: 0)

## Filtering

Many endpoints support filtering via query parameters:
- `kb_types` - Filter by knowledge base type
- `confidence_min` - Minimum confidence threshold
- `strict` - Enable strict validation

## Engine Parameters

The mapper endpoint supports different extraction engines:
- `vector` - Traditional vector similarity (default)
- `llm` - LLM-based extraction with GPT-5/Gemini-2.5-Flash
- `hybrid` - Combined vector and LLM approach

## Example Workflow

1. **Load ATT&CK Data**
   ```bash
   POST /v1/stix/load/attack
   {
     "collection": "enterprise-attack",
     "version": "latest"
   }
   ```

2. **Extract TTPs from Document**
   ```bash
   POST /v1/mapper/propose?engine=llm
   {
     "source_id": "report-001",
     "source_type": "md",
     "inline_text": "APT29 uses spearphishing...",
     "max_candidates": 5
   }
   ```

3. **Review and Validate**
   ```bash
   POST /v1/review/mapping
   {
     "object_id": "attack-pattern--...",
     "decision": "accept",
     "note": "Confirmed by analyst"
   }
   ```

## WebSocket Support

Not currently implemented. Future versions may include WebSocket support for real-time updates.

## API Versioning

The API uses URL versioning. Current version: `v1`

Future versions will be available at `/v2`, `/v3`, etc.