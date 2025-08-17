# LLM API Endpoints

The LLM endpoints provide advanced extraction capabilities using Large Language Models (GPT-5, Gemini-2.5-Flash) with tool grounding to prevent hallucination.

## POST /llm/extract

Extract cyber threat intelligence from text using LLM with tool-calling for grounding.

### Request

```http
POST /v1/llm/extract
Content-Type: application/json
```

```json
{
  "text": "APT29 uses spearphishing emails with PDF attachments containing malicious macros. Once executed, they establish persistence through registry keys and scheduled tasks.",
  "source_id": "report-001",
  "model": "gpt-5",
  "temperature": 0.2,
  "max_tokens": 800,
  "tools_enabled": true
}
```

### Parameters

- **text** (required): Text to analyze for threat intelligence
  - Min length: 20 characters
  - Max length: 5000 characters
- **source_id** (optional): Identifier for tracking
  - Default: auto-generated UUID
- **model** (optional): LLM model to use
  - Default: `"gpt-5"`
  - Options: `"gpt-5"`, `"gemini-2.5-flash"`
- **temperature** (optional): Model temperature for creativity
  - Default: `0.2`
  - Range: 0.0-1.0 (lower = more deterministic)
- **max_tokens** (optional): Maximum response tokens
  - Default: `800`
  - Range: 100-2000
- **tools_enabled** (optional): Enable tool grounding
  - Default: `true`
  - Set to `false` for faster but less accurate extraction

### Response

```json
{
  "source_id": "report-001",
  "extraction": {
    "claims": [
      {
        "type": "uses-technique",
        "actor": "APT29",
        "technique": "Spearphishing Attachment",
        "span": {
          "text": "APT29 uses spearphishing emails with PDF attachments",
          "start": 0,
          "end": 53
        },
        "mappings": [
          {
            "stix_id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
            "name": "Spearphishing Attachment",
            "external_id": "T1566.001",
            "confidence": 95,
            "rationale": "Explicit mention of spearphishing with PDF attachments"
          }
        ]
      },
      {
        "type": "uses-technique",
        "actor": "APT29",
        "technique": "Boot or Logon Autostart Execution: Registry Run Keys",
        "span": {
          "text": "establish persistence through registry keys",
          "start": 98,
          "end": 142
        },
        "mappings": [
          {
            "stix_id": "attack-pattern--9efb1ea7-c37b-4595-9640-b7680cd84279",
            "name": "Registry Run Keys / Startup Folder",
            "external_id": "T1547.001",
            "confidence": 88,
            "rationale": "Registry keys for persistence maps to T1547.001"
          }
        ]
      },
      {
        "type": "uses-technique",
        "actor": "APT29",
        "technique": "Scheduled Task/Job",
        "span": {
          "text": "scheduled tasks",
          "start": 147,
          "end": 162
        },
        "mappings": [
          {
            "stix_id": "attack-pattern--005c5a57-5ede-4f6e-8b40-8e3f0f93e6d2",
            "name": "Scheduled Task",
            "external_id": "T1053.005",
            "confidence": 85,
            "rationale": "Scheduled tasks for persistence"
          }
        ]
      }
    ],
    "entities": {
      "groups": ["APT29"],
      "techniques": ["T1566.001", "T1547.001", "T1053.005"],
      "tactics": ["initial-access", "persistence"],
      "tools": [],
      "malware": []
    },
    "confidence_overall": 89
  },
  "metadata": {
    "model": "gpt-5",
    "tools_called": [
      "vector_search_ttx",
      "graph_lookup",
      "list_tactics"
    ],
    "tool_calls_count": 7,
    "processing_time_ms": 2341,
    "tokens_used": {
      "prompt": 1245,
      "completion": 687,
      "total": 1932
    }
  }
}
```

### Tool Grounding Process

The LLM uses these tools to ground its analysis:

1. **vector_search_ttx**: Search for techniques matching text
2. **graph_lookup**: Verify STIX IDs and get details
3. **list_tactics**: Get valid ATT&CK tactics

Example tool-calling flow:
```
User Text → LLM analyzes → Calls vector_search_ttx("spearphishing PDF")
→ Gets candidates → Calls graph_lookup("attack-pattern--7e33...")
→ Validates → Returns grounded claim
```

### Example Usage

```bash
# Basic extraction with GPT-5
curl -X POST http://localhost:8000/v1/llm/extract \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Lazarus group deploys ransomware after gaining access through supply chain compromise"
  }'

# Use Gemini model with higher temperature
curl -X POST http://localhost:8000/v1/llm/extract \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Advanced persistent threat uses novel techniques...",
    "model": "gemini-2.5-flash",
    "temperature": 0.5
  }'

# Disable tools for faster processing
curl -X POST http://localhost:8000/v1/llm/extract \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Simple malware analysis report...",
    "tools_enabled": false
  }'
```

---

## POST /llm/to-stix

Convert LLM extraction output to a STIX 2.1 bundle with ADM validation.

### Request

```http
POST /v1/llm/to-stix
Content-Type: application/json
```

```json
{
  "llm_output": {
    "claims": [
      {
        "type": "uses-technique",
        "actor": "APT29",
        "technique": "Spearphishing Attachment",
        "span": {
          "text": "APT29 uses spearphishing",
          "start": 0,
          "end": 24
        },
        "mappings": [
          {
            "stix_id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
            "name": "Spearphishing Attachment",
            "external_id": "T1566.001",
            "confidence": 92
          }
        ]
      }
    ]
  },
  "source_metadata": {
    "source_id": "report-001",
    "source_url": "https://example.com/report.pdf",
    "source_date": "2024-01-15"
  },
  "apply_safeguards": true,
  "validate_ids": true
}
```

### Parameters

- **llm_output** (required): Extraction output from /llm/extract
- **source_metadata** (optional): Provenance information
  - **source_id**: Document identifier
  - **source_url**: Original document URL
  - **source_date**: Document publication date
- **apply_safeguards** (optional): Apply confidence capping
  - Default: `true`
  - Caps confidence at 85% unless high-signal
- **validate_ids** (optional): Verify STIX IDs exist in KB
  - Default: `true`
  - Rejects unknown/hallucinated IDs

### Response

```json
{
  "bundle": {
    "type": "bundle",
    "id": "bundle--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created": "2024-01-15T14:30:00.000Z",
    "modified": "2024-01-15T14:30:00.000Z",
    "objects": [
      {
        "type": "attack-pattern",
        "id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
        "created": "2024-01-15T14:30:00.000Z",
        "modified": "2024-01-15T14:30:00.000Z",
        "name": "Spearphishing Attachment",
        "external_references": [
          {
            "source_name": "mitre-attack",
            "external_id": "T1566.001"
          }
        ],
        "kill_chain_phases": [
          {
            "kill_chain_name": "mitre-attack",
            "phase_name": "initial-access"
          }
        ],
        "x_bj_confidence": 85,
        "x_bj_confidence_capped": true,
        "x_bj_evidence": "APT29 uses spearphishing",
        "x_bj_source": {
          "source_id": "report-001",
          "source_url": "https://example.com/report.pdf",
          "extracted_by": "llm:gpt-5"
        }
      },
      {
        "type": "intrusion-set",
        "id": "intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7",
        "created": "2024-01-15T14:30:00.000Z",
        "modified": "2024-01-15T14:30:00.000Z",
        "name": "APT29",
        "external_references": [
          {
            "source_name": "mitre-attack",
            "external_id": "G0016"
          }
        ]
      },
      {
        "type": "relationship",
        "id": "relationship--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "created": "2024-01-15T14:30:00.000Z",
        "modified": "2024-01-15T14:30:00.000Z",
        "relationship_type": "uses",
        "source_ref": "intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7",
        "target_ref": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
        "description": "APT29 uses Spearphishing Attachment"
      }
    ]
  },
  "validation": {
    "adm_valid": true,
    "safeguards_applied": true,
    "ids_validated": true,
    "objects_created": 3,
    "confidence_capped": 1,
    "invalid_ids_rejected": 0
  }
}
```

### Safeguards Applied

1. **Confidence Capping**: Limited to 85% unless:
   - Explicit technique ID mentioned (T-codes)
   - Multiple independent confirmations
   - High-confidence tool validation

2. **Negation Detection**: Reduces confidence when detecting:
   - "not observed"
   - "did not use"
   - "no evidence of"

3. **ID Validation**: Rejects objects with:
   - Non-existent STIX IDs
   - Malformed IDs
   - Hallucinated references

### Example Usage

```bash
# Convert extraction to STIX with safeguards
curl -X POST http://localhost:8000/v1/llm/to-stix \
  -H "Content-Type: application/json" \
  -d '{
    "llm_output": {
      "claims": [...]
    },
    "apply_safeguards": true
  }'

# Without safeguards (not recommended)
curl -X POST http://localhost:8000/v1/llm/to-stix \
  -H "Content-Type: application/json" \
  -d '{
    "llm_output": {
      "claims": [...]
    },
    "apply_safeguards": false,
    "validate_ids": false
  }'
```

### STIX Bundle Structure

Generated bundles include:

1. **Attack Patterns**: Techniques and sub-techniques
2. **Intrusion Sets**: Threat groups mentioned
3. **Malware/Tools**: If identified
4. **Relationships**: "uses" relationships between entities
5. **Custom Properties**:
   - `x_bj_confidence`: Confidence score
   - `x_bj_evidence`: Supporting text
   - `x_bj_source`: Provenance metadata
   - `x_bj_confidence_capped`: Whether safeguard was applied

### Error Responses

- **400 Bad Request**: Invalid LLM output format

```json
{
  "detail": "Invalid LLM output: missing 'claims' field"
}
```

- **422 Unprocessable Entity**: Validation failed

```json
{
  "detail": "STIX ID validation failed",
  "invalid_ids": [
    "attack-pattern--fake-id-12345"
  ]
}
```

### Integration Example

Complete pipeline from text to STIX:

```python
# 1. Extract with LLM
extraction = requests.post(
    "http://localhost:8000/v1/llm/extract",
    json={"text": threat_report}
).json()

# 2. Convert to STIX
stix_bundle = requests.post(
    "http://localhost:8000/v1/llm/to-stix",
    json={
        "llm_output": extraction["extraction"],
        "source_metadata": {
            "source_id": "report-123",
            "source_date": "2024-01-15"
        }
    }
).json()

# 3. Ingest into knowledge graph
requests.post(
    "http://localhost:8000/v1/stix/bundles",
    json=stix_bundle["bundle"]
)
```

### Performance Notes

- LLM extraction: 1-3 seconds depending on text length
- STIX conversion: <100ms
- ID validation adds ~50ms per unique ID
- Safeguards processing: <20ms
- Results cached for 15 minutes by source_id