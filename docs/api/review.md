# Review API Endpoints

The review endpoints enable analyst validation, feedback, and correction of proposed mappings and existing objects.

## POST /review/mapping

Review and validate a proposed TTP mapping with analyst feedback.

### Request

```http
POST /v1/review/mapping
Content-Type: application/json
```

```json
{
  "source_id": "report-2024-001",
  "object_id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
  "decision": "accept",
  "confidence_override": 95,
  "corrected_id": null,
  "note": "Confirmed by analyst - clear evidence of spearphishing attachment",
  "reviewer": "analyst-01"
}
```

### Parameters

- **source_id** (required): Document/source identifier
- **object_id** (required): STIX ID of proposed mapping
- **decision** (required): Review decision
  - `"accept"`: Approve the mapping
  - `"reject"`: Reject as incorrect
  - `"edit"`: Accept with modifications
- **confidence_override** (optional): New confidence score (0-100)
  - Overrides system-generated confidence
- **corrected_id** (optional): Replacement STIX ID
  - Required when decision="edit" and changing the mapped object
  - Must be valid STIX ID in knowledge base
- **note** (optional): Review comments
  - Max length: 500 characters
- **reviewer** (optional): Reviewer identifier
  - Default: "anonymous"

### Response

```json
{
  "status": "accepted",
  "review": {
    "source_id": "report-2024-001",
    "object_id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
    "decision": "accept",
    "confidence": 95,
    "note": "Confirmed by analyst - clear evidence of spearphishing attachment",
    "reviewer": "analyst-01",
    "reviewed_at": "2024-01-15T14:45:23.000Z"
  },
  "object": {
    "stix_id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
    "name": "Spearphishing Attachment",
    "external_id": "T1566.001"
  },
  "feedback_stored": true,
  "model_update_queued": true
}
```

### Decision Types

#### Accept
Confirms the mapping is correct:
```json
{
  "decision": "accept",
  "confidence_override": 98,
  "note": "Verified with additional context"
}
```

#### Reject
Marks the mapping as incorrect:
```json
{
  "decision": "reject",
  "note": "False positive - referring to different technique"
}
```

#### Edit
Accepts with corrections:
```json
{
  "decision": "edit",
  "corrected_id": "attack-pattern--different-technique-id",
  "confidence_override": 75,
  "note": "Should be mapped to parent technique instead"
}
```

### Example Usage

```bash
# Accept a mapping with high confidence
curl -X POST http://localhost:8000/v1/review/mapping \
  -H "Content-Type: application/json" \
  -d '{
    "source_id": "apt-report-123",
    "object_id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
    "decision": "accept",
    "confidence_override": 95
  }'

# Reject an incorrect mapping
curl -X POST http://localhost:8000/v1/review/mapping \
  -H "Content-Type: application/json" \
  -d '{
    "source_id": "incident-045",
    "object_id": "attack-pattern--wrong-id",
    "decision": "reject",
    "note": "Not related to this technique"
  }'

# Edit to correct technique
curl -X POST http://localhost:8000/v1/review/mapping \
  -H "Content-Type: application/json" \
  -d '{
    "source_id": "malware-analysis",
    "object_id": "attack-pattern--old-id",
    "decision": "edit",
    "corrected_id": "attack-pattern--correct-id",
    "confidence_override": 80
  }'
```

---

## POST /review/object

Review and update properties of an existing STIX object.

### Request

```http
POST /v1/review/object
Content-Type: application/json
```

```json
{
  "object_id": "intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7",
  "updates": {
    "aliases": ["APT29", "Cozy Bear", "The Dukes", "IRON HEMLOCK"],
    "description": "Updated description with latest intelligence...",
    "x_bj_confidence": 98,
    "x_bj_verified": true
  },
  "note": "Added new alias from recent report",
  "reviewer": "analyst-02"
}
```

### Parameters

- **object_id** (required): STIX ID of object to review
- **updates** (required): Properties to update
  - Can update any mutable property
  - Cannot change: `id`, `type`, `created`
  - Common updates: `description`, `aliases`, custom properties
- **note** (optional): Review comments
- **reviewer** (optional): Reviewer identifier

### Response

```json
{
  "status": "updated",
  "object": {
    "id": "intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7",
    "type": "intrusion-set",
    "name": "APT29",
    "aliases": ["APT29", "Cozy Bear", "The Dukes", "IRON HEMLOCK"],
    "description": "Updated description with latest intelligence...",
    "modified": "2024-01-15T15:00:00.000Z",
    "x_bj_confidence": 98,
    "x_bj_verified": true,
    "x_bj_last_reviewed": "2024-01-15T15:00:00.000Z",
    "x_bj_reviewed_by": "analyst-02"
  },
  "changes": {
    "aliases": {
      "before": ["APT29", "Cozy Bear", "The Dukes"],
      "after": ["APT29", "Cozy Bear", "The Dukes", "IRON HEMLOCK"]
    },
    "x_bj_confidence": {
      "before": 85,
      "after": 98
    }
  }
}
```

### Example Usage

```bash
# Update group aliases
curl -X POST http://localhost:8000/v1/review/object \
  -H "Content-Type: application/json" \
  -d '{
    "object_id": "intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7",
    "updates": {
      "aliases": ["APT29", "Cozy Bear", "IRON HEMLOCK"]
    }
  }'

# Mark technique as verified
curl -X POST http://localhost:8000/v1/review/object \
  -H "Content-Type: application/json" \
  -d '{
    "object_id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
    "updates": {
      "x_bj_verified": true,
      "x_bj_confidence": 100
    },
    "note": "Verified through incident response"
  }'
```

---

## GET /stix/objects/{id}

Retrieve a STIX object with full details and provenance information.

### Request

```http
GET /v1/stix/objects/{id}?include_relationships=true
```

### Parameters

- **id** (required): STIX ID to retrieve
- **include_relationships** (optional): Include related objects
  - Default: `false`
  - When `true`, includes relationships and related objects

### Response

```json
{
  "object": {
    "id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
    "type": "attack-pattern",
    "created": "2023-05-15T10:00:00.000Z",
    "modified": "2024-01-10T12:00:00.000Z",
    "name": "Spearphishing Attachment",
    "description": "Adversaries may send spearphishing emails with a malicious attachment...",
    "external_references": [
      {
        "source_name": "mitre-attack",
        "external_id": "T1566.001",
        "url": "https://attack.mitre.org/techniques/T1566/001"
      }
    ],
    "kill_chain_phases": [
      {
        "kill_chain_name": "mitre-attack",
        "phase_name": "initial-access"
      }
    ],
    "x_mitre_is_subtechnique": true,
    "x_mitre_platforms": ["Windows", "macOS", "Linux"],
    "x_mitre_detection": "Monitor for suspicious email attachments..."
  },
  "provenance": {
    "source": {
      "collection": "enterprise-attack",
      "version": "15.1",
      "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-15.1.json",
      "imported_at": "2024-01-05T09:00:00.000Z"
    },
    "reviews": [
      {
        "reviewed_at": "2024-01-15T14:45:23.000Z",
        "reviewer": "analyst-01",
        "decision": "accept",
        "confidence": 95,
        "note": "Confirmed by analyst"
      }
    ],
    "extractions": [
      {
        "source_id": "report-2024-001",
        "extracted_at": "2024-01-15T14:30:00.000Z",
        "engine": "llm:gpt-5",
        "confidence": 92
      }
    ]
  },
  "relationships": [
    {
      "type": "relationship",
      "relationship_type": "uses",
      "source_ref": "intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7",
      "target_ref": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
      "source_name": "APT29",
      "confidence": 90
    }
  ],
  "statistics": {
    "times_extracted": 47,
    "times_reviewed": 12,
    "average_confidence": 88.5,
    "last_seen": "2024-01-15T16:00:00.000Z"
  }
}
```

### Example Usage

```bash
# Get technique details
curl -X GET http://localhost:8000/v1/stix/objects/attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5

# Get with relationships
curl -X GET "http://localhost:8000/v1/stix/objects/attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5?include_relationships=true"

# Get threat group
curl -X GET http://localhost:8000/v1/stix/objects/intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7
```

### Error Responses

- **404 Not Found**: Object doesn't exist

```json
{
  "detail": "STIX object not found: attack-pattern--invalid-id"
}
```

---

## Review Workflow

### 1. Initial Extraction
Document is processed and mappings proposed:
```bash
POST /v1/mapper/propose?engine=llm
```

### 2. Analyst Review
Analyst reviews each proposed mapping:
```bash
# Review each mapping
POST /v1/review/mapping
{
  "source_id": "doc-001",
  "object_id": "attack-pattern--...",
  "decision": "accept"
}
```

### 3. Feedback Integration
Reviews are used to:
- Update confidence scores
- Train active learning models
- Identify common errors
- Improve future extractions

### 4. Quality Metrics
Track review statistics:
- Acceptance rate
- Common corrections
- Reviewer agreement
- Confidence accuracy

## Feedback Loop

All review decisions contribute to model improvement:

1. **Immediate Impact**
   - Updates object confidence
   - Corrects mappings
   - Adds to knowledge base

2. **Learning Queue**
   - Uncertain cases queued for review
   - High-disagreement items prioritized
   - Pattern recognition for common errors

3. **Model Retraining**
   - Periodic retraining with feedback
   - Fine-tuning for domain adaptation
   - Confidence calibration

## Custom Properties

Review system adds these properties:

- `x_bj_verified`: Boolean, analyst-verified
- `x_bj_confidence`: Integer (0-100), confidence score
- `x_bj_last_reviewed`: ISO timestamp
- `x_bj_reviewed_by`: Reviewer identifier
- `x_bj_review_count`: Number of reviews
- `x_bj_review_notes`: Array of review comments

## Best Practices

1. **Review Prioritization**
   - Focus on low-confidence mappings (<70%)
   - Review novel or rare techniques
   - Validate critical intelligence

2. **Consistency**
   - Use standard review criteria
   - Document decision rationale
   - Maintain reviewer calibration

3. **Feedback Quality**
   - Provide specific notes
   - Correct misclassifications
   - Suggest improvements

4. **Continuous Improvement**
   - Monitor acceptance rates
   - Track confidence accuracy
   - Identify systematic issues