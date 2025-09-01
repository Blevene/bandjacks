# Unified Review System - API Documentation

## Table of Contents
1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Endpoints](#endpoints)
4. [Data Models](#data-models)
5. [Request Examples](#request-examples)
6. [Response Examples](#response-examples)
7. [Error Handling](#error-handling)
8. [Client Libraries](#client-libraries)

## Overview

The Unified Review API provides endpoints for submitting and managing comprehensive review decisions for threat intelligence reports. It processes reviews for entities, MITRE ATT&CK techniques, and attack flow steps in a single atomic operation.

### Base URL
```
Development: http://localhost:8000/v1
Production:  https://api.bandjacks.io/v1
```

### API Version
Current version: `v1`

### Content Type
All requests and responses use `application/json` unless otherwise specified.

## Authentication

Currently, no authentication is required in development mode. Production deployments should implement appropriate authentication mechanisms.

Future authentication will use JWT tokens:
```http
Authorization: Bearer <jwt-token>
```

## Endpoints

### Submit Unified Review

Submit review decisions for all items in a report.

**Endpoint:** `POST /reports/{report_id}/unified-review`

**Path Parameters:**
- `report_id` (string, required): The unique identifier of the report

**Request Body:**
```typescript
{
  report_id: string;
  reviewer_id: string;
  decisions: UnifiedReviewDecision[];
  global_notes?: string;
  review_timestamp: string; // ISO 8601 format
}
```

**Response:**
```typescript
{
  success: boolean;
  message: string;
  items_reviewed: number;
  items_approved: number;
  items_rejected: number;
  items_edited: number;
}
```

**HTTP Status Codes:**
- `200 OK`: Review submitted successfully
- `400 Bad Request`: Invalid request data
- `404 Not Found`: Report not found
- `500 Internal Server Error`: Server error during processing

### Get Review Status (Future)

Get the current review status of a report.

**Endpoint:** `GET /reports/{report_id}/review-status`

**Response:**
```typescript
{
  report_id: string;
  status: "pending" | "in_progress" | "completed" | "needs_revision";
  reviewer_id?: string;
  reviewed_at?: string;
  total_items: number;
  reviewed_items: number;
  progress_percentage: number;
  statistics: {
    approved: number;
    rejected: number;
    edited: number;
    pending: number;
  };
}
```

### Save Review Draft (Future)

Save a draft of review decisions without finalizing.

**Endpoint:** `POST /reports/{report_id}/review-draft`

**Request Body:**
```typescript
{
  reviewer_id: string;
  decisions: UnifiedReviewDecision[];
  global_notes?: string;
  save_timestamp: string;
}
```

### Get Review History (Future)

Get the review history for a report.

**Endpoint:** `GET /reports/{report_id}/review-history`

**Response:**
```typescript
{
  report_id: string;
  reviews: {
    reviewer_id: string;
    reviewed_at: string;
    decisions_count: number;
    statistics: ReviewStatistics;
    global_notes?: string;
  }[];
}
```

## Data Models

### UnifiedReviewDecision

Represents a single review decision for any type of extracted item.

```typescript
interface UnifiedReviewDecision {
  item_id: string;                    // Unique item identifier
  action: "approve" | "reject" | "edit";
  edited_value?: {                    // Only for action: "edit"
    [key: string]: any;
  };
  confidence_adjustment?: number;     // 0-100, overrides original confidence
  notes?: string;                     // Reviewer's notes
  timestamp: string;                  // ISO 8601 format
}
```

### UnifiedReviewSubmission

Complete review submission payload.

```typescript
interface UnifiedReviewSubmission {
  report_id: string;
  reviewer_id: string;
  decisions: UnifiedReviewDecision[];
  global_notes?: string;
  review_timestamp: string;
}
```

### UnifiedReviewResponse

Response after successful review submission.

```typescript
interface UnifiedReviewResponse {
  success: boolean;
  message: string;
  items_reviewed: number;
  items_approved: number;
  items_rejected: number;
  items_edited: number;
}
```

### Item ID Patterns

Items are identified using consistent patterns:

- **Entities**: `entity-{category}-{index}`
  - Examples: `entity-malware-0`, `entity-threat_actors-2`
- **Techniques**: `technique-{index}`
  - Examples: `technique-0`, `technique-15`
- **Flow Steps**: `flow-{step_id}`
  - Examples: `flow-action-123`, `flow-step-abc`

### Edited Value Structure

The `edited_value` field structure depends on the item type:

#### Entity Edits
```typescript
{
  name?: string;
  description?: string;
  aliases?: string[];
  entity_type?: string;
}
```

#### Technique Edits
```typescript
{
  name?: string;
  external_id?: string;    // MITRE ATT&CK ID (e.g., T1566.001)
  description?: string;
}
```

#### Flow Step Edits
```typescript
{
  name?: string;
  description?: string;
  technique_id?: string;
  order?: number;
}
```

## Request Examples

### Basic Review Submission

```http
POST /v1/reports/report-123/unified-review
Content-Type: application/json

{
  "report_id": "report-123",
  "reviewer_id": "reviewer-001",
  "decisions": [
    {
      "item_id": "entity-malware-0",
      "action": "approve",
      "timestamp": "2025-08-31T10:30:00Z"
    },
    {
      "item_id": "technique-5",
      "action": "reject",
      "notes": "Generic term without specific technique context",
      "timestamp": "2025-08-31T10:31:00Z"
    },
    {
      "item_id": "entity-threat_actors-1",
      "action": "edit",
      "edited_value": {
        "name": "Lazarus Group",
        "description": "North Korean state-sponsored APT group"
      },
      "confidence_adjustment": 85,
      "notes": "Corrected name and added context",
      "timestamp": "2025-08-31T10:32:00Z"
    }
  ],
  "global_notes": "Review completed. High confidence extractions overall.",
  "review_timestamp": "2025-08-31T10:35:00Z"
}
```

### Bulk Approval

```http
POST /v1/reports/report-456/unified-review
Content-Type: application/json

{
  "report_id": "report-456",
  "reviewer_id": "reviewer-002",
  "decisions": [
    {
      "item_id": "technique-0",
      "action": "approve",
      "timestamp": "2025-08-31T11:00:00Z"
    },
    {
      "item_id": "technique-1",
      "action": "approve",
      "timestamp": "2025-08-31T11:00:01Z"
    },
    {
      "item_id": "technique-2",
      "action": "approve",
      "timestamp": "2025-08-31T11:00:02Z"
    }
  ],
  "global_notes": "Bulk approved high-confidence technique extractions",
  "review_timestamp": "2025-08-31T11:05:00Z"
}
```

### Complex Edit Example

```http
POST /v1/reports/report-789/unified-review
Content-Type: application/json

{
  "report_id": "report-789",
  "reviewer_id": "reviewer-003",
  "decisions": [
    {
      "item_id": "flow-step-001",
      "action": "edit",
      "edited_value": {
        "name": "Initial Access via Spear Phishing",
        "description": "Attackers sent targeted phishing emails to executives",
        "technique_id": "T1566.001",
        "order": 1
      },
      "confidence_adjustment": 90,
      "notes": "Updated with specific sub-technique and corrected sequence order",
      "timestamp": "2025-08-31T12:15:00Z"
    }
  ],
  "global_notes": "Flow sequence required significant editing for accuracy",
  "review_timestamp": "2025-08-31T12:20:00Z"
}
```

## Response Examples

### Successful Review Submission

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "message": "Unified review submitted successfully",
  "items_reviewed": 25,
  "items_approved": 18,
  "items_rejected": 4,
  "items_edited": 3
}
```

### Validation Error

```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "detail": "Validation error: Item entity-malware-5 marked as edited but no edited_value provided"
}
```

### Report Not Found

```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{
  "detail": "Report report-999 not found"
}
```

### Server Error

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{
  "detail": "Failed to save unified review: Database connection error"
}
```

## Error Handling

### Common Error Scenarios

#### Validation Errors (400)
- Missing required fields
- Invalid item_id format
- Edit action without edited_value
- Invalid confidence values (outside 0-100 range)
- Invalid timestamp format

#### Not Found Errors (404)
- Report doesn't exist
- Invalid report_id format

#### Server Errors (500)
- Database connection failures
- Neo4j update failures
- OpenSearch update failures
- Internal processing errors

### Error Response Format

All errors return a consistent format:
```typescript
{
  "detail": string;           // Human-readable error description
  "error_code"?: string;      // Machine-readable error code (future)
  "field_errors"?: {          // Field-specific validation errors (future)
    [field: string]: string[];
  };
}
```

### Retry Logic

For 5xx errors, clients should implement exponential backoff:
- Initial delay: 1 second
- Maximum delay: 30 seconds
- Maximum retries: 3 attempts

## Client Libraries

### TypeScript/JavaScript

Using the generated API client:

```typescript
import { Api } from './generated-api-client';

const api = new Api({
  baseURL: 'http://localhost:8000/v1'
});

// Submit review
const response = await api.reports.submitUnifiedReview(
  'report-123',
  {
    report_id: 'report-123',
    reviewer_id: 'reviewer-001',
    decisions: decisions,
    global_notes: 'Review completed',
    review_timestamp: new Date().toISOString()
  }
);

if (response.success) {
  console.log(`Reviewed ${response.items_reviewed} items`);
}
```

### Python

Using `requests` library:

```python
import requests
from datetime import datetime
from typing import List, Dict, Any

def submit_unified_review(
    base_url: str,
    report_id: str,
    reviewer_id: str,
    decisions: List[Dict[str, Any]],
    global_notes: str = None
) -> Dict[str, Any]:
    """Submit a unified review for a report."""
    
    payload = {
        "report_id": report_id,
        "reviewer_id": reviewer_id,
        "decisions": decisions,
        "global_notes": global_notes,
        "review_timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    response = requests.post(
        f"{base_url}/reports/{report_id}/unified-review",
        json=payload,
        headers={"Content-Type": "application/json"}
    )
    
    response.raise_for_status()
    return response.json()

# Usage example
decisions = [
    {
        "item_id": "entity-malware-0",
        "action": "approve",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
]

result = submit_unified_review(
    base_url="http://localhost:8000/v1",
    report_id="report-123",
    reviewer_id="reviewer-001",
    decisions=decisions,
    global_notes="Review completed successfully"
)

print(f"Items reviewed: {result['items_reviewed']}")
```

### cURL Examples

#### Basic submission:
```bash
curl -X POST http://localhost:8000/v1/reports/report-123/unified-review \
  -H "Content-Type: application/json" \
  -d '{
    "report_id": "report-123",
    "reviewer_id": "reviewer-001",
    "decisions": [
      {
        "item_id": "entity-malware-0",
        "action": "approve",
        "timestamp": "2025-08-31T10:30:00Z"
      }
    ],
    "global_notes": "Quick approval",
    "review_timestamp": "2025-08-31T10:35:00Z"
  }'
```

#### With edited item:
```bash
curl -X POST http://localhost:8000/v1/reports/report-456/unified-review \
  -H "Content-Type: application/json" \
  -d '{
    "report_id": "report-456",
    "reviewer_id": "reviewer-002",
    "decisions": [
      {
        "item_id": "technique-5",
        "action": "edit",
        "edited_value": {
          "name": "Spear Phishing Attachment",
          "external_id": "T1566.001"
        },
        "confidence_adjustment": 85,
        "notes": "Corrected technique ID",
        "timestamp": "2025-08-31T11:00:00Z"
      }
    ],
    "review_timestamp": "2025-08-31T11:05:00Z"
  }'
```

## Rate Limiting (Future)

When rate limiting is implemented:
- **Rate Limit**: 100 requests per hour per user
- **Burst Limit**: 10 requests per minute
- **Headers**: 
  - `X-RateLimit-Limit`: Total requests allowed
  - `X-RateLimit-Remaining`: Requests remaining
  - `X-RateLimit-Reset`: Unix timestamp when limit resets

## Webhooks (Future)

Future webhook support for review events:
- `review.submitted`: When a review is completed
- `review.draft.saved`: When a draft is saved
- `review.conflict.detected`: When multiple reviewers conflict

## OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:
- **Development**: http://localhost:8000/openapi.json
- **Interactive Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Best Practices

### API Usage Guidelines

1. **Batch Decisions**: Include all decisions in a single request
2. **Atomic Operations**: Don't split reviews across multiple API calls
3. **Validation**: Validate item IDs match the expected format
4. **Timestamps**: Use ISO 8601 format with timezone
5. **Notes**: Include meaningful notes for rejected/edited items

### Performance Optimization

1. **Minimize Payload Size**: Only include necessary fields in edited_value
2. **Use Compression**: Enable gzip compression for large payloads
3. **Connection Pooling**: Reuse HTTP connections when possible
4. **Timeout Handling**: Set appropriate request timeouts (30s recommended)

### Error Handling

1. **Retry Logic**: Implement exponential backoff for 5xx errors
2. **Validation**: Validate data before sending requests
3. **Logging**: Log API errors with request context
4. **Graceful Degradation**: Handle API unavailability gracefully

## Version History

### v1.0.0 (Current)
- Initial release of unified review API
- Support for entities, techniques, and flow steps
- Basic CRUD operations for review decisions
- OpenSearch and Neo4j integration

### Future Versions

#### v1.1.0 (Planned)
- Draft saving functionality
- Review history endpoints
- Enhanced validation

#### v1.2.0 (Planned)
- Collaborative review features
- Review templates
- Webhook support

#### v2.0.0 (Future)
- Authentication and authorization
- Rate limiting
- Enhanced analytics
- Breaking changes to data models