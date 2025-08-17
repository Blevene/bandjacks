# Bandjacks API Documentation

## Overview

The Bandjacks API provides RESTful endpoints for cyber threat intelligence operations including ATT&CK data management, natural language search, graph traversal, extraction workflows, and feedback collection.

**Base URL:** `http://localhost:8000/v1`  
**API Version:** `1.0.0`  
**OpenAPI Spec:** Available at `/docs` when running the API server

## Authentication

Currently, the API does not require authentication for development. Production deployments should implement appropriate authentication mechanisms.

## Common Response Formats

### Success Response

```json
{
  "status": "success",
  "data": {...},
  "message": "Operation completed successfully"
}
```

### Error Response

```json
{
  "detail": "Error description",
  "status_code": 400,
  "errors": [...]
}
```

## Endpoints

### Catalog Management

#### List ATT&CK Releases

```http
GET /v1/catalog/attack/releases
```

Lists available ATT&CK releases and versions from the official catalog.

**Response:**

```json
{
  "releases": [
    {
      "collection": "enterprise-attack",
      "version": "14.1",
      "modified": "2024-01-15T00:00:00Z",
      "url": "https://raw.githubusercontent.com/mitre/cti/..."
    }
  ]
}
```

**Example:**

```bash
curl http://localhost:8000/v1/catalog/attack/releases
```

### STIX Data Loading

#### Load ATT&CK Release

```http
POST /v1/stix/load/attack
```

Load a specific ATT&CK release into the knowledge graph.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `collection` | string | Yes | Collection name (e.g., "enterprise-attack") |
| `version` | string | No | Version to load (default: "latest") |
| `adm_strict` | boolean | No | Enforce ADM validation (default: true) |

**Response:**

```json
{
  "status": "success",
  "loaded": {
    "nodes": 15234,
    "edges": 45123,
    "version": "14.1"
  }
}
```

**Example:**

```bash
curl -X POST "http://localhost:8000/v1/stix/load/attack?collection=enterprise-attack&version=14.1"
```

#### Import STIX Bundle

```http
POST /v1/stix/bundles
```

Import a STIX 2.1 bundle with validation.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `strict` | boolean | No | Enforce strict validation (default: true) |

**Request Body:**

```json
{
  "type": "bundle",
  "id": "bundle--...",
  "objects": [
    {
      "type": "attack-pattern",
      "id": "attack-pattern--...",
      "name": "Technique Name",
      "description": "..."
    }
  ]
}
```

**Response:**

```json
{
  "status": "success",
  "imported": {
    "objects": 10,
    "relationships": 5
  },
  "validation_errors": []
}
```

### Search Operations

#### Natural Language Search

```http
POST /v1/query/search
```

Search for threat intelligence using natural language with hybrid vector and graph fusion.

**Request Body:**

```json
{
  "query": "lateral movement techniques used by APT groups",
  "top_k": 20,
  "filters": {
    "entity_type": "attack-pattern",
    "exclude_revoked": true
  },
  "include_context": true,
  "fusion_weights": {
    "vector": 0.6,
    "graph": 0.4
  }
}
```

**Response:**

```json
{
  "results": [
    {
      "stix_id": "attack-pattern--...",
      "type": "attack-pattern",
      "name": "Remote Desktop Protocol",
      "fusion_score": 0.892,
      "fusion_rank": 1,
      "preview": "Adversaries may use Valid Accounts to...",
      "graph_context": {
        "neighbors": [...],
        "relationships": [...],
        "neighbor_count": 5
      }
    }
  ],
  "query_expansion": ["lateral movement", "pivoting", "spread"],
  "total_results": 15
}
```

**Example:**

```bash
curl -X POST http://localhost:8000/v1/query/search \
  -H "Content-Type: application/json" \
  -d '{"query": "ransomware techniques", "top_k": 10}'
```

#### Query Expansion Suggestions

```http
POST /v1/query/expand
```

Get query expansion suggestions for improved search.

**Request Body:**

```json
{
  "query": "creds"
}
```

**Response:**

```json
{
  "original": "creds",
  "expanded": "creds credentials passwords authentication",
  "suggestions": [
    "credential dumping",
    "credential access",
    "password attacks"
  ]
}
```

#### Technique Text Search

```http
POST /v1/search/ttx
```

Search for techniques using vector similarity.

**Request Body:**

```json
{
  "text": "The attacker used PowerShell to download malware",
  "top_k": 5
}
```

**Response:**

```json
{
  "candidates": [
    {
      "technique_id": "T1059.001",
      "name": "PowerShell",
      "score": 0.923,
      "description": "..."
    }
  ]
}
```

### Graph Traversal

#### Build Attack Flow

```http
POST /v1/graph/attack_flow
```

Build an attack flow from a center node.

**Request Body:**

```json
{
  "center_id": "attack-pattern--3ccef7ae-cb5e-48f6-8302-897105fbf55c",
  "depth": 2,
  "relationships": ["USES", "MITIGATES", "NEXT"],
  "include_tactics": true,
  "max_nodes": 50
}
```

**Response:**

```json
{
  "flow_id": "flow--abc123",
  "nodes": [
    {
      "id": "attack-pattern--...",
      "type": "attack-pattern",
      "name": "Credential Dumping",
      "distance": 0
    }
  ],
  "edges": [
    {
      "source": "attack-pattern--...",
      "target": "attack-pattern--...",
      "type": "NEXT",
      "properties": {"probability": 0.75}
    }
  ],
  "statistics": {
    "total_nodes": 15,
    "total_edges": 23,
    "max_distance": 2
  }
}
```

#### Get Node Neighbors

```http
GET /v1/graph/neighbors/{node_id}
```

Get immediate neighbors of a node.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `node_id` | string | STIX ID of the node |

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `direction` | string | "incoming", "outgoing", or "both" (default: "both") |
| `relationships` | array | Relationship types to include |
| `limit` | integer | Maximum neighbors (default: 20) |

**Response:**

```json
{
  "center": {
    "id": "attack-pattern--...",
    "name": "Credential Dumping"
  },
  "neighbors": [
    {
      "id": "intrusion-set--...",
      "name": "APT28",
      "type": "intrusion-set",
      "relationship": "USES",
      "direction": "incoming"
    }
  ],
  "total_neighbors": 8
}
```

#### Find Paths

```http
POST /v1/graph/paths
```

Find paths between two nodes.

**Request Body:**

```json
{
  "source_id": "attack-pattern--abc",
  "target_id": "attack-pattern--xyz",
  "max_length": 5,
  "limit": 10
}
```

**Response:**

```json
{
  "paths": [
    {
      "length": 3,
      "nodes": ["attack-pattern--abc", "intrusion-set--def", "attack-pattern--xyz"],
      "edges": [
        {"source": "...", "target": "...", "type": "USES"},
        {"source": "...", "target": "...", "type": "USES"}
      ]
    }
  ],
  "total_paths": 2
}
```

### Document Extraction

#### Extract from Document

```http
POST /v1/extract/document
```

Extract CTI entities from a document.

**Request Body (multipart/form-data):**

| Field | Type | Description |
|-------|------|-------------|
| `file` | file | Document file (PDF, TXT, MD, HTML) |
| `confidence_threshold` | float | Auto-approval threshold (default: 80.0) |
| `extract_relationships` | boolean | Extract relationships (default: true) |

**Response:**

```json
{
  "status": "success",
  "extraction_id": "extraction--abc123",
  "entities": [
    {
      "type": "attack-pattern",
      "name": "Spearphishing Attachment",
      "confidence": 92.5,
      "evidence": [
        {
          "line": 15,
          "text": "The attackers sent spearphishing emails with malicious attachments"
        }
      ]
    }
  ],
  "relationships": [
    {
      "source": "intrusion-set--...",
      "target": "attack-pattern--...",
      "type": "uses",
      "confidence": 88.0
    }
  ],
  "candidates_created": 5
}
```

#### Get Provenance

```http
GET /v1/extract/provenance/{source_id}
```

Get extraction provenance for a source document.

**Response:**

```json
{
  "source_id": "report--abc123",
  "source_metadata": {
    "filename": "apt28_report.pdf",
    "hash": "sha256:abc...",
    "extracted_at": "2024-01-15T10:30:00Z"
  },
  "extraction_metadata": {
    "method": "llm",
    "model": "gemini-2.0-flash",
    "confidence_threshold": 80.0
  },
  "entities_extracted": 12,
  "relationships_extracted": 8
}
```

### Feedback Collection

#### Submit Relevance Feedback

```http
POST /v1/feedback/relevance
```

Submit relevance feedback for search results.

**Request Body:**

```json
{
  "query_id": "query--abc123",
  "result_id": "attack-pattern--...",
  "relevance": "relevant",
  "user_id": "analyst-1",
  "notes": "Exactly what I was looking for"
}
```

**Response:**

```json
{
  "status": "success",
  "feedback_id": "feedback--xyz789",
  "message": "Relevance feedback recorded"
}
```

#### Submit Correction

```http
POST /v1/feedback/correction
```

Submit corrections for entity fields.

**Request Body:**

```json
{
  "object_id": "attack-pattern--...",
  "field": "description",
  "old_value": "Old description text",
  "new_value": "Corrected description text",
  "user_id": "analyst-1",
  "reason": "Outdated information"
}
```

**Response:**

```json
{
  "status": "success",
  "correction_id": "correction--abc123",
  "review_status": "pending"
}
```

### Review Queue Management

#### Get Review Queue

```http
GET /v1/review_queue/queue
```

Get candidates pending review.

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status |
| `entity_type` | string | Filter by STIX type |
| `min_confidence` | float | Minimum confidence |
| `limit` | integer | Maximum results (default: 50) |
| `offset` | integer | Pagination offset |

**Response:**

```json
{
  "candidates": [
    {
      "id": "candidate--abc123",
      "stix_id": "attack-pattern--...",
      "type": "attack-pattern",
      "name": "New Technique",
      "extraction_confidence": 85.5,
      "status": "pending",
      "created_at": "2024-01-15T10:30:00Z",
      "source_report": "report--xyz"
    }
  ],
  "total": 25,
  "offset": 0,
  "limit": 50
}
```

#### Approve Candidate

```http
POST /v1/review_queue/approve/{candidate_id}
```

Approve a candidate node.

**Request Body:**

```json
{
  "reviewer_id": "analyst-1",
  "merge_to_graph": true,
  "notes": "Verified against external sources"
}
```

**Response:**

```json
{
  "status": "success",
  "candidate_id": "candidate--abc123",
  "approved": true,
  "merged": true,
  "merged_stix_id": "attack-pattern--new123"
}
```

#### Reject Candidate

```http
POST /v1/review_queue/reject/{candidate_id}
```

Reject a candidate node.

**Request Body:**

```json
{
  "reviewer_id": "analyst-1",
  "reason": "Duplicate of existing technique T1003"
}
```

**Response:**

```json
{
  "status": "success",
  "candidate_id": "candidate--abc123",
  "rejected": true,
  "reason": "Duplicate of existing technique T1003"
}
```

#### Batch Approve

```http
POST /v1/review_queue/batch/approve
```

Approve multiple candidates at once.

**Request Body:**

```json
{
  "candidate_ids": ["candidate--abc", "candidate--def", "candidate--ghi"],
  "reviewer_id": "analyst-1",
  "merge_to_graph": true
}
```

**Response:**

```json
{
  "status": "success",
  "total_processed": 3,
  "approved_count": 3,
  "merged_count": 2,
  "failed_count": 0,
  "details": {
    "approved": ["candidate--abc", "candidate--def", "candidate--ghi"],
    "merged": ["attack-pattern--new1", "attack-pattern--new2"],
    "failed": []
  }
}
```

#### Get Queue Statistics

```http
GET /v1/review_queue/stats
```

Get review queue statistics.

**Response:**

```json
{
  "total_candidates": 156,
  "by_status": {
    "pending": 45,
    "under_review": 12,
    "auto_approved": 78,
    "approved": 15,
    "rejected": 6
  },
  "by_type": {
    "attack-pattern": 89,
    "intrusion-set": 34,
    "malware": 23,
    "tool": 10
  },
  "confidence_stats": {
    "pending": {
      "avg": 72.5,
      "min": 45.0,
      "max": 89.9
    }
  },
  "recent_24h": 23,
  "pending_review": 45,
  "auto_approved": 78
}
```

### Mapper Operations

#### Create Mapping

```http
POST /v1/mapper/create
```

Create a mapping from extracted text to ATT&CK technique.

**Request Body:**

```json
{
  "text": "The attacker used PowerShell to execute commands",
  "technique_id": "T1059.001",
  "confidence": 85.0,
  "source": "manual"
}
```

**Response:**

```json
{
  "status": "success",
  "mapping_id": "mapping--abc123",
  "technique": {
    "id": "T1059.001",
    "name": "PowerShell"
  }
}
```

### Review Operations

#### Submit Review Decision

```http
POST /v1/review/decision
```

Submit a review decision for a mapping or extraction.

**Request Body:**

```json
{
  "object_id": "mapping--abc123",
  "decision": "approve",
  "reviewer_id": "analyst-1",
  "notes": "Confirmed through threat intel"
}
```

**Response:**

```json
{
  "status": "success",
  "decision_id": "decision--xyz789",
  "applied": true
}
```

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request - Invalid parameters |
| 404 | Not Found - Resource doesn't exist |
| 422 | Unprocessable Entity - Validation error |
| 500 | Internal Server Error |

## Rate Limiting

Currently no rate limiting is implemented. Production deployments should implement appropriate rate limiting.

## Webhooks

The API supports webhooks for async operations:

```json
{
  "webhook_url": "https://your-server.com/webhook",
  "events": ["extraction.complete", "review.decision"]
}
```

## WebSocket Support

Real-time updates are available via WebSocket at:

```
ws://localhost:8000/v1/ws
```

Events:
- `search.update` - Search result updates
- `queue.change` - Review queue changes
- `extraction.progress` - Extraction progress

## SDK Examples

### Python

```python
import requests

# Search example
response = requests.post(
    "http://localhost:8000/v1/query/search",
    json={
        "query": "lateral movement",
        "top_k": 10
    }
)
results = response.json()

# Review queue example
response = requests.get(
    "http://localhost:8000/v1/review_queue/queue",
    params={"status": "pending", "limit": 20}
)
candidates = response.json()
```

### JavaScript

```javascript
// Search example
const response = await fetch('http://localhost:8000/v1/query/search', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    query: 'lateral movement',
    top_k: 10
  })
});
const results = await response.json();

// Approve candidate
const approveResponse = await fetch(
  'http://localhost:8000/v1/review_queue/approve/candidate--abc123',
  {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      reviewer_id: 'analyst-1',
      merge_to_graph: true
    })
  }
);
```

### cURL

```bash
# Search
curl -X POST http://localhost:8000/v1/query/search \
  -H "Content-Type: application/json" \
  -d '{"query": "ransomware", "top_k": 5}'

# Get queue statistics
curl http://localhost:8000/v1/review_queue/stats

# Approve candidate
curl -X POST http://localhost:8000/v1/review_queue/approve/candidate--abc123 \
  -H "Content-Type: application/json" \
  -d '{"reviewer_id": "cli-user", "merge_to_graph": true}'
```

## Postman Collection

A Postman collection is available at `/docs/postman_collection.json` with all endpoints pre-configured.

## OpenAPI Specification

The full OpenAPI 3.0 specification is available at:
- JSON: `http://localhost:8000/openapi.json`
- Interactive docs: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`