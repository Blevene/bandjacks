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

## Response Schemas

### Entity Structure

Entities extracted from threat intelligence reports follow this structure:

```json
{
  "entities": {
    "entities": [
      {
        "name": "APT29",                    // Entity name
        "type": "group",                    // Entity type (see types below)
        "confidence": 100,                  // Confidence score (0-100)
        "mentions": [                       // All mentions of this entity in text
          {
            "quote": "APT29, also known as Cozy Bear, used PowerShell...",
            "line_refs": [1, 2],            // Line numbers where mentioned
            "context": "primary_mention"    // Context type (see below)
          }
        ],
        "aliases": ["Cozy Bear", "The Dukes"]  // Alternative names (optional)
      }
    ],
    "extraction_status": "completed"        // Status of extraction
  }
}
```

**Entity Types:**
- `group` - Threat actor groups (APT29, Lazarus Group)
- `malware` - Malware families (SUNBURST, Emotet)
- `tool` - Legitimate or dual-use tools (PowerShell, Mimikatz)
- `target` - Victim organizations or sectors
- `campaign` - Named threat campaigns

**Context Types:**
- `primary_mention` - Direct mention of the entity
- `alias` - Alternative name (e.g., "Cozy Bear" for APT29)
- `coreference` - Reference like "the group" referring to a previously mentioned entity

### Technique/Claim Structure

Extracted MITRE ATT&CK techniques follow this structure:

```json
{
  "claims": [
    {
      "external_id": "T1059.001",           // MITRE ATT&CK technique ID
      "name": "PowerShell",                 // Technique name
      "quotes": [                            // Evidence supporting this extraction
        "APT29 used PowerShell and Mimikatz for credential harvesting..."
      ],
      "line_refs": [1, 2],                  // Line numbers in source
      "confidence": 85,                     // Confidence score (0-100)
      "span_idx": 0,                        // Which text span this came from
      "evidence_score": 75,                 // Quality of evidence
      "source": "batch_mapper",             // Which agent extracted this
      "technique_meta": {                   // Additional metadata
        "stix_id": "attack-pattern--4d4aee57-...",
        "name": "PowerShell",
        "external_id": "T1059.001",
        "tactic": "execution",              // Kill chain phase
        "description": "Adversaries may...", // Technique description
        "platforms": ["Windows", "Linux"],  // Target platforms
        "subtechnique_of": "T1059"          // Parent technique if subtechnique
      }
    }
  ]
}
```

**Key Fields:**
- `external_id` - The MITRE ATT&CK technique ID (e.g., T1059.001)
- `quotes` - Actual text evidence supporting this technique extraction
- `confidence` - How confident the system is (0-100 scale)
- `evidence_score` - Quality of the evidence (0-100 scale)
- `technique_meta` - Additional metadata from the ATT&CK knowledge base

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

### Report Ingestion

#### Ingest Report (Synchronous)

```http
POST /v1/reports/ingest
```

Ingest a threat intelligence report from text (synchronous processing for small reports <5KB).

**Request Body:**

```json
{
  "text": "Report text content",
  "title": "Optional report title",
  "use_batch_mapper": true,
  "skip_verification": false
}
```

**Response:**

```json
{
  "report_id": "report--abc123",
  "status": "pending_review",
  "extraction": {
    "techniques_count": 12,
    "claims_count": 15,
    "confidence_avg": 85.5,
    "entities": {
      "entities": [
        {"name": "APT28", "type": "group", "confidence": 90}
      ]
    }
  }
}
```

#### Ingest Report from File Upload

```http
POST /v1/reports/ingest/upload
```

Ingest a report from file upload (PDF, TXT, MD, HTML).

**Request Body (multipart/form-data):**

| Field | Type | Description |
|-------|------|-------------|
| `file` | file | Document file |
| `title` | string | Optional report title |
| `use_batch_mapper` | boolean | Use batch mapping (default: true) |
| `skip_verification` | boolean | Skip verification (default: false) |

**Response:** Same as `/ingest` endpoint

#### Ingest Report (Asynchronous)

```http
POST /v1/reports/ingest_async
```

For larger reports (>5KB), use asynchronous processing.

**Request Body:**

```json
{
  "text": "Large report text content",
  "title": "Large Report Analysis"
}
```

**Response:**

```json
{
  "job_id": "job--abc123",
  "status": "processing",
  "message": "Report ingestion started",
  "progress": 0
}
```

#### Ingest File (Asynchronous)

```http
POST /v1/reports/ingest_file_async
```

Ingest a file asynchronously.

**Request Body (multipart/form-data):**

| Field | Type | Description |
|-------|------|-------------|
| `file` | file | Document file |
| `title` | string | Optional report title |

**Response:** Same as `/ingest_async` endpoint

#### Get Job Status

```http
GET /v1/reports/jobs/{job_id}/status
```

Check the status of an asynchronous ingestion job.

**Response:**

```json
{
  "job_id": "job--abc123",
  "status": "processing",
  "progress": 60,
  "current_stage": "Mapper",
  "message": "Processing chunk 3/5",
  "result": {
    "techniques_count": 8,
    "claims_count": 12,
    "chunks_processed": 3
  }
}
```

#### List Jobs

```http
GET /v1/reports/jobs
```

List all background jobs.

**Query Parameters:**
- `status` (optional): Filter by status (pending, processing, completed, failed)
- `limit` (optional): Maximum results (default: 100)

**Response:**

```json
{
  "jobs": [
    {
      "job_id": "job--abc123",
      "status": "completed",
      "created_at": "2024-01-15T10:30:00Z",
      "completed_at": "2024-01-15T10:31:30Z",
      "report_id": "report--def456"
    }
  ],
  "total": 25
}
```

### Report Management

#### List Reports

```http
GET /v1/reports
```

List all ingested reports with pagination and filtering.

**Query Parameters:**
- `skip` (int): Number of reports to skip (default: 0)
- `limit` (int): Maximum reports to return (default: 20)
- `status` (string): Filter by status (pending, processing, completed, reviewed)
- `sort` (string): Sort field (created_at, title, techniques_count)
- `order` (string): Sort order (asc, desc)

**Response:**
```json
{
  "reports": [
    {
      "id": "report-abc123",
      "title": "APT29 Campaign Analysis",
      "source": "upload",
      "status": "completed",
      "created_at": "2024-01-15T10:30:00Z",
      "techniques_count": 12,
      "review_status": "pending"
    }
  ],
  "total": 45,
  "skip": 0,
  "limit": 20
}
```

#### Get Report Details

```http
GET /v1/reports/{report_id}
```

Get comprehensive details about a specific report including extraction results.

**Response:**
```json
{
  "id": "report-abc123",
  "title": "APT29 Campaign Analysis",
  "content": "Full report text...",
  "metadata": {
    "source": "upload",
    "filename": "apt29-report.pdf",
    "size_bytes": 15234,
    "pages": 8
  },
  "extraction": {
    "techniques": {
      "T1566.001": {
        "technique_id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "confidence": 95,
        "evidence": ["email with malicious attachment"],
        "line_refs": [42]
      }
    },
    "entities": [...],
    "flow": {...}
  },
  "review": {
    "status": "completed",
    "reviewed_at": "2024-01-15T14:30:00Z",
    "reviewed_by": "analyst-1",
    "decisions": [...]
  }
}
```

#### Delete Report

```http
DELETE /v1/reports/{report_id}
```

Delete a report and all associated data.

**Response:**
```json
{
  "message": "Report deleted successfully",
  "report_id": "report-abc123"
}
```

### Review & Approval

#### Submit Unified Review

```http
POST /v1/reports/{report_id}/unified-review
```

Submit review decisions for all extracted items (entities, techniques, flow steps) in a single transaction.

**Request Body:**
```json
{
  "decisions": [
    {
      "item_id": "technique-0",
      "action": "approve",
      "confidence_adjustment": 5,
      "notes": "Verified against CTI database"
    },
    {
      "item_id": "entity-malware-1",
      "action": "edit",
      "edited_value": {
        "name": "Updated Malware Name",
        "description": "Corrected description"
      }
    },
    {
      "item_id": "flow-step-3",
      "action": "reject",
      "notes": "Insufficient evidence"
    }
  ],
  "global_notes": "Overall review notes for the report"
}
```

**Response:**
```json
{
  "message": "Review submitted successfully",
  "report_id": "report-abc123",
  "review_id": "review-xyz789",
  "statistics": {
    "total_items": 25,
    "approved": 18,
    "rejected": 4,
    "edited": 3
  },
  "entities_created": [
    {
      "stix_id": "malware--...",
      "name": "Updated Malware Name"
    }
  ]
}
```

### Attribution

#### Link Report to Intrusion Set

```http
POST /v1/reports/{report_id}/attribution
```

Attribute a report's findings to a specific threat actor or intrusion set.

**Request Body:**
```json
{
  "intrusion_set_id": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
  "confidence": 85,
  "attribution_notes": "TTPs match APT29 historical patterns"
}
```

**Response:**
```json
{
  "message": "Attribution created successfully",
  "attribution": {
    "report_id": "report-abc123",
    "intrusion_set": {
      "stix_id": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542",
      "name": "APT29"
    },
    "confidence": 85,
    "created_at": "2024-01-15T15:00:00Z"
  }
}
```

### Attack Flow Generation

#### Generate Attack Flow from Report

```http
POST /v1/reports/{report_id}/generate-flow
```

Generate an attack flow from the report's extracted techniques using LLM-based sequencing.

**Request Body:**
```json
{
  "max_steps": 25,
  "include_evidence": true,
  "flow_type": "sequential"
}
```

**Response:**
```json
{
  "flow": {
    "id": "flow--abc123",
    "name": "APT29 Attack Flow",
    "type": "sequential",
    "steps": [
      {
        "step_id": 1,
        "technique_id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "initial-access",
        "evidence": ["email with malicious attachment"],
        "temporal_marker": "initial"
      },
      {
        "step_id": 2,
        "technique_id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "execution",
        "evidence": ["PowerShell scripts were executed"],
        "temporal_marker": "then"
      }
    ],
    "edges": [
      {
        "source": 1,
        "target": 2,
        "probability": 0.85,
        "relationship": "NEXT"
      }
    ]
  },
  "metadata": {
    "total_techniques": 12,
    "sequenced_techniques": 10,
    "generation_method": "llm_synthesis",
    "confidence": 78
  }
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

### Cache Management

#### Get Cache Statistics

```http
GET /v1/cache/stats
```

Get LLM response cache statistics.

**Response:**

```json
{
  "hits": 42,
  "misses": 15,
  "evictions": 3,
  "hit_rate": "73.7%",
  "size": 54
}
```

**Example:**

```bash
curl http://localhost:8000/v1/cache/stats
```

#### Clear Cache

```http
POST /v1/cache/clear
```

Clear the LLM response cache.

**Response:**

```json
{
  "message": "Cache cleared successfully"
}
```

**Example:**

```bash
curl -X POST http://localhost:8000/v1/cache/clear
```

## Performance Optimizations

### TechniqueCache
The API initializes a global technique cache at startup:
- Loads all AttackPattern nodes from Neo4j (~1376 techniques)
- Provides O(1) lookups for technique name resolution
- Eliminates thousands of database queries per extraction session
- Ensures review interface displays correct human-readable names
- Thread-safe singleton pattern for multi-worker deployments

**Benefits:**
- Extraction pipeline runs 50-70% faster for technique resolution
- Consistent technique naming across all API endpoints
- Reduced Neo4j load during high-volume extraction
- Instant technique metadata access for review UI

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