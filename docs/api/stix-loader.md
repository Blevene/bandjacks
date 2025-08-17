# STIX Loader API Endpoints

The STIX loader endpoints handle ingestion of ATT&CK collections and custom STIX bundles into the knowledge graph.

## POST /stix/load/attack

Load an ATT&CK collection into the knowledge graph with ADM validation.

### Request

```http
POST /v1/stix/load/attack
Content-Type: application/json
```

```json
{
  "collection": "enterprise-attack",
  "version": "latest",
  "adm_strict": true,
  "overwrite": false
}
```

### Parameters

- **collection** (required): ATT&CK collection to load
  - Values: `"enterprise-attack"`, `"mobile-attack"`, `"ics-attack"`
- **version** (optional): Version to load
  - Default: `"latest"`
  - Examples: `"15.1"`, `"14.0"`, `"latest"`
- **adm_strict** (optional): Enforce strict ADM validation
  - Default: `true`
  - Set to `false` only for legacy data
- **overwrite** (optional): Replace existing data
  - Default: `false`
  - If `false`, will skip if version already loaded

### Response

```json
{
  "status": "success",
  "collection": "enterprise-attack",
  "version": "15.1",
  "stats": {
    "total_objects": 18265,
    "techniques": 637,
    "subtechniques": 424,
    "tactics": 14,
    "groups": 143,
    "software": 718,
    "mitigations": 322,
    "data_sources": 96,
    "relationships": 15842,
    "load_time_ms": 4823
  },
  "validation": {
    "adm_spec": "3.3.0",
    "adm_valid": true,
    "warnings": []
  }
}
```

### Example

```bash
# Load latest enterprise ATT&CK
curl -X POST http://localhost:8000/v1/stix/load/attack \
  -H "Content-Type: application/json" \
  -d '{
    "collection": "enterprise-attack",
    "version": "latest"
  }'

# Load specific version without overwrite
curl -X POST http://localhost:8000/v1/stix/load/attack \
  -H "Content-Type: application/json" \
  -d '{
    "collection": "enterprise-attack",
    "version": "14.0",
    "overwrite": false
  }'
```

### Process Flow

1. Fetches the specified collection from MITRE's repository
2. Validates the bundle against ADM specification
3. Creates Neo4j nodes for all STIX objects
4. Creates edges for all relationships
5. Generates vector embeddings for techniques
6. Indexes in OpenSearch for fast retrieval

### Error Responses

- **400 Bad Request**: Invalid collection or version

```json
{
  "detail": "Invalid collection: must be one of ['enterprise-attack', 'mobile-attack', 'ics-attack']"
}
```

- **409 Conflict**: Version already loaded (when overwrite=false)

```json
{
  "detail": "Version 15.1 already loaded. Set overwrite=true to replace."
}
```

- **502 Bad Gateway**: Failed to fetch from MITRE repository

```json
{
  "detail": "Failed to download ATT&CK bundle: Connection timeout"
}
```

---

## POST /stix/bundles

Ingest a custom STIX bundle with optional ADM validation.

### Request

```http
POST /v1/stix/bundles?strict=true
Content-Type: application/json
```

```json
{
  "type": "bundle",
  "id": "bundle--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "created": "2024-01-15T12:00:00.000Z",
  "modified": "2024-01-15T12:00:00.000Z",
  "objects": [
    {
      "type": "attack-pattern",
      "id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
      "created": "2024-01-15T12:00:00.000Z",
      "modified": "2024-01-15T12:00:00.000Z",
      "name": "Spearphishing Attachment",
      "description": "Adversaries send spearphishing emails with a malicious attachment...",
      "kill_chain_phases": [
        {
          "kill_chain_name": "mitre-attack",
          "phase_name": "initial-access"
        }
      ],
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "T1566.001",
          "url": "https://attack.mitre.org/techniques/T1566/001"
        }
      ],
      "x_mitre_is_subtechnique": true,
      "x_mitre_platforms": ["Windows", "macOS", "Linux"],
      "x_mitre_detection": "Monitor for suspicious email attachments..."
    },
    {
      "type": "intrusion-set",
      "id": "intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7",
      "created": "2024-01-15T12:00:00.000Z",
      "modified": "2024-01-15T12:00:00.000Z",
      "name": "APT29",
      "description": "APT29 is a threat group attributed to Russia's SVR...",
      "aliases": ["APT29", "Cozy Bear", "The Dukes"],
      "external_references": [
        {
          "source_name": "mitre-attack",
          "external_id": "G0016",
          "url": "https://attack.mitre.org/groups/G0016"
        }
      ]
    },
    {
      "type": "relationship",
      "id": "relationship--44298802-8337-4b1e-9714-3d5c04e7a53c",
      "created": "2024-01-15T12:00:00.000Z",
      "modified": "2024-01-15T12:00:00.000Z",
      "relationship_type": "uses",
      "source_ref": "intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7",
      "target_ref": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
      "description": "APT29 uses spearphishing attachments for initial access."
    }
  ]
}
```

### Query Parameters

- **strict** (optional): Enable strict ADM validation
  - Default: `true`
  - Set to `false` for non-ATT&CK STIX content

### Response

```json
{
  "status": "success",
  "bundle_id": "bundle--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
  "stats": {
    "total_objects": 3,
    "attack_patterns": 1,
    "intrusion_sets": 1,
    "relationships": 1,
    "created": 3,
    "updated": 0,
    "skipped": 0,
    "errors": 0
  },
  "validation": {
    "adm_valid": true,
    "warnings": []
  }
}
```

### Supported STIX Object Types

- **attack-pattern**: Techniques and sub-techniques
- **intrusion-set**: Threat groups
- **malware**: Malware families
- **tool**: Software tools
- **course-of-action**: Mitigations
- **identity**: Organizations and sectors
- **relationship**: Connections between objects
- **x-mitre-tactic**: ATT&CK tactics
- **x-mitre-data-source**: Data sources
- **x-mitre-data-component**: Data components

### Validation Rules

When `strict=true`, the following ADM rules are enforced:

1. All ATT&CK objects must have valid `external_references`
2. Techniques must have `kill_chain_phases`
3. Sub-techniques must have `x_mitre_is_subtechnique: true`
4. Relationships must use valid types (uses, mitigates, etc.)
5. All timestamps must be valid ISO 8601 format

### Example

```bash
# Ingest custom bundle with strict validation
curl -X POST "http://localhost:8000/v1/stix/bundles?strict=true" \
  -H "Content-Type: application/json" \
  -d @custom_bundle.json

# Ingest without ADM validation
curl -X POST "http://localhost:8000/v1/stix/bundles?strict=false" \
  -H "Content-Type: application/json" \
  -d @threat_intel_bundle.json
```

### Error Responses

- **400 Bad Request**: Invalid STIX bundle format

```json
{
  "detail": "Invalid STIX bundle: missing 'type' field"
}
```

- **422 Unprocessable Entity**: ADM validation failed

```json
{
  "detail": "ADM validation failed",
  "errors": [
    "attack-pattern missing kill_chain_phases",
    "Invalid external_reference format"
  ]
}
```

### Processing Notes

1. **Duplicate Handling**: Objects with same ID are updated if `modified` timestamp is newer
2. **Provenance Tracking**: All objects are stamped with source metadata
3. **Vector Generation**: Embeddings are generated for searchable text fields
4. **Graph Updates**: Neo4j nodes and relationships are created/updated atomically
5. **Index Updates**: OpenSearch indices are updated in batch for performance