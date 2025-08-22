# Sprint 7 Extension: Sigma Rules Integration Complete

## Date: 2025-08-22

## Summary
Successfully implemented Sigma rule integration as first-class, versioned artifacts linked to MITRE Analytics via reference-based relationships. The system now supports ingestion, validation, linking, search, and coverage analysis of Sigma detection rules.

## Completed Components

### Phase 1: Data Model & Storage ✅

#### 1. Sigma Rule Validator (`bandjacks/llm/sigma_validator.py`)
- **Features:**
  - YAML schema validation using pySigma
  - License allowlist enforcement (MIT, Apache-2.0, DRL, CC licenses)
  - Metadata extraction (title, status, tags, logsource)
  - ATT&CK technique extraction from tags
  - Platform detection from logsource
  - SHA256 hash generation for content integrity
  - Stable rule_id generation: `repo:path@commit_sha`

#### 2. Neo4j Schema Extensions (`bandjacks/loaders/neo4j_ddl.py`)
- **New Constraints:**
  - `SigmaRule` with unique `rule_id`
  - `SigmaFeedback` with unique `feedback_id`
- **New Indexes:**
  - Performance indexes on status, severity, platforms, logsource fields
  - Fulltext search index on title, description, tags
- **New Relationships:**
  - `(:Analytic)-[:IMPLEMENTED_BY {source, confidence}]->(:SigmaRule)`
  - `(:SigmaRule)-[:TARGETS_LOG_SOURCE {keys}]->(:LogSource)`
  - `(:SigmaRule)-[:DETECTS]->(:AttackPattern)` (derived from tags)

#### 3. Sigma Loader (`bandjacks/loaders/sigma_loader.py`)
- **Ingestion Sources:**
  - Git repository (planned)
  - ZIP archive download
  - Direct rule list
- **Features:**
  - Rule validation and normalization
  - Blob storage for YAML content
  - Automatic relationship creation
  - Link management to Analytics
  - External reference updates

### Phase 2: API Endpoints ✅

#### 1. Sigma Management (`bandjacks/services/api/routes/sigma.py`)
- **POST /v1/sigma/ingest** - Ingest Sigma rules from various sources
  - Validates YAML and license
  - Creates nodes with full provenance
  - Returns detailed ingestion summary
  
- **GET /v1/sigma/rules/{rule_id}** - Get rule details
  - Returns metadata, relationships, linked analytics
  
- **POST /v1/sigma/rules/search** - Search Sigma rules
  - Text search via fulltext index
  - Filter by technique, platform, status, severity
  - Returns ranked results

#### 2. Analytics Integration (`bandjacks/services/api/routes/detections.py`)
- **POST /v1/detections/analytics/{id}/sigma** - Link Sigma rules
  - Creates IMPLEMENTED_BY relationships
  - Configurable confidence scores
  - Updates external_references
  
- **DELETE /v1/detections/analytics/{id}/sigma/{rule_id}** - Unlink rules
  - Removes relationships cleanly
  
- **GET /v1/detections/analytics/{id}** - Enhanced with Sigma
  - Returns linked Sigma rules in response
  - Includes confidence scores

### Phase 3: Coverage Analytics ✅

#### Enhanced Coverage (`bandjacks/services/api/routes/coverage.py`)
- **GET /v1/coverage/technique/{technique_id}** now includes:
  - `sigma_rules_total` - Count of Sigma rules for technique
  - `sigma_rules_by_platform` - Platform breakdown
  - `missing_logsource_permutations_from_sigma` - Gap analysis

## Neo4j Data Model

### SigmaRule Node
```cypher
(:SigmaRule {
  rule_id: "sigmahq:rules/windows/process_creation/proc_creation_win_susp_svchost.yml@abc123",
  title: "Suspicious Svchost Process",
  status: "stable",  // stable|test|experimental|deprecated
  severity: "high",  // informational|low|medium|high|critical
  description: "...",
  author: "...",
  license: "MIT",
  tags: ["attack.t1055", "attack.defense_evasion"],
  attack_techniques: ["T1055"],
  platforms: ["windows"],
  logsource_product: "windows",
  logsource_service: "sysmon",
  logsource_category: "process_creation",
  keys: ["EventID", "Image", "CommandLine"],
  references: ["https://..."],
  false_positives: ["Legitimate svchost"],
  repo_url: "https://github.com/SigmaHQ/sigma",
  path: "rules/windows/process_creation/...",
  commit_sha: "abc123...",
  sha256_yaml: "def456...",
  blob_uri: "s3://sigma-rules/abc123/rule.yml",
  ingested_at: "2025-08-22T10:00:00Z"
})
```

### Relationships
```cypher
// Analytics implementation
(:Analytic)-[:IMPLEMENTED_BY {
  source: "sigma",
  confidence: 85,
  created: datetime(),
  updated: datetime()
}]->(:SigmaRule)

// Log source targeting
(:SigmaRule)-[:TARGETS_LOG_SOURCE {
  keys: ["EventID", "Image"],
  matched_on: "product"
}]->(:LogSource)

// Technique detection (derived)
(:SigmaRule)-[:DETECTS {
  source: "sigma_tag",
  created: datetime()
}]->(:AttackPattern)
```

## API Examples

### Ingest Sigma Rules
```bash
curl -X POST "http://localhost:8001/v1/sigma/ingest" \
  -H "Content-Type: application/json" \
  -d '{
    "zip_url": "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip",
    "link": [
      {
        "analytic_id": "x-mitre-analytic--001",
        "rule_id": "sigmahq:rules/windows/process_creation/proc_creation_win_susp_svchost.yml@abc123"
      }
    ]
  }'
```

**Response:**
```json
{
  "success": true,
  "inserted": 150,
  "updated": 20,
  "rejected": [
    {
      "rule": "rules/deprecated/old_rule.yml",
      "errors": ["Invalid YAML structure"]
    }
  ],
  "warnings": [],
  "linked_analytics": 1,
  "trace_id": "tr-xyz123"
}
```

### Link Sigma to Analytic
```bash
curl -X POST "http://localhost:8001/v1/detections/analytics/x-mitre-analytic--001/sigma" \
  -H "Content-Type: application/json" \
  -d '{
    "rule_ids": [
      "sigmahq:rules/windows/process_creation/proc_creation_win_susp_svchost.yml@abc123",
      "sigmahq:rules/windows/process_access/proc_access_win_lsass_memdump.yml@def456"
    ],
    "confidence": 90
  }'
```

### Get Analytic with Sigma Rules
```bash
curl "http://localhost:8001/v1/detections/analytics/x-mitre-analytic--001"
```

**Response includes:**
```json
{
  "stix_id": "x-mitre-analytic--001",
  "name": "Process Memory Access Detection",
  "sigma_rules": [
    {
      "rule_id": "sigmahq:rules/windows/...",
      "title": "LSASS Memory Dump",
      "status": "stable",
      "confidence": 90
    }
  ]
}
```

### Search Sigma Rules
```bash
curl -X POST "http://localhost:8001/v1/sigma/rules/search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "lsass memory",
    "technique": "T1003",
    "platform": "windows",
    "status": "stable",
    "limit": 10
  }'
```

### Get Coverage with Sigma
```bash
curl "http://localhost:8001/v1/coverage/technique/T1003"
```

**Response includes:**
```json
{
  "technique_id": "T1003",
  "technique_name": "OS Credential Dumping",
  "sigma_rules_total": 25,
  "sigma_rules_by_platform": {
    "windows": 20,
    "linux": 5
  },
  "missing_logsource_permutations_from_sigma": [
    "sigma:aws",
    "sigma:azure"
  ]
}
```

## Key Features Delivered

### 1. Reference-Based Architecture
- Sigma rules are **not embedded** in STIX objects
- Clean separation of concerns
- Analytics maintain pointers via `external_references`
- Graph relationships for efficient queries

### 2. Version Control
- Every rule tracked with `commit_sha`
- Content integrity via `sha256_yaml`
- Blob storage for original YAML
- Drift detection capability

### 3. License Compliance
- Configurable allowlist (MIT, Apache, DRL, CC)
- Validation at ingestion time
- Warnings for non-compliant licenses
- Attribution preserved in metadata

### 4. Coverage Enhancement
- Sigma rules counted in coverage metrics
- Platform-specific analysis
- Log source gap detection
- Integration with existing coverage APIs

### 5. Search & Discovery
- Fulltext search on title, description, tags
- Technique-based filtering
- Platform and severity filters
- Status-based queries (stable, experimental)

## Benefits

### For Analysts
- Access to community detection content
- Link best-of-breed Sigma rules to analytics
- Coverage visibility across rule sources
- Confidence scoring for implementations

### For Detection Engineers
- Reuse existing Sigma content
- Track rule versions and updates
- Validate against log source availability
- Identify coverage gaps

### For Security Teams
- Leverage SigmaHQ repository
- Maintain provenance and attribution
- Ensure license compliance
- Enable drift detection

## Testing Recommendations

### Unit Tests
```python
def test_sigma_validation():
    validator = SigmaValidator()
    yaml_content = """
    title: Test Rule
    status: stable
    logsource:
        product: windows
        service: sysmon
    detection:
        selection:
            EventID: 1
        condition: selection
    """
    is_valid, data, errors = validator.validate_rule(yaml_content)
    assert is_valid
    assert data["title"] == "Test Rule"

def test_sigma_linking():
    # Test linking Sigma rules to Analytics
    result = loader.link_sigma_to_analytic(
        analytic_id="test-001",
        rule_ids=["sigma-001"],
        confidence=85
    )
    assert result["linked"] == 1
```

### Integration Tests
- E2E ingestion from ZIP archive
- Link rules and verify in analytic retrieval
- Search by technique and platform
- Coverage calculation with Sigma rules

## Metrics & Monitoring

### Key Metrics
- `sigma_rules_ingested_total` - Total rules ingested
- `sigma_rules_rejected_total{reason}` - Rejected rules by reason
- `analytics_linked_to_sigma_total` - Analytics with Sigma implementations
- `sigma_search_latency_ms_p95` - Search performance

### Monitoring Queries
```cypher
// Most linked Sigma rules
MATCH (sr:SigmaRule)<-[:IMPLEMENTED_BY]-(a:Analytic)
RETURN sr.title, count(a) as usage_count
ORDER BY usage_count DESC

// Platform coverage
MATCH (sr:SigmaRule)
UNWIND sr.platforms as platform
RETURN platform, count(sr) as rule_count
ORDER BY rule_count DESC

// License distribution
MATCH (sr:SigmaRule)
RETURN sr.license, count(sr) as count
ORDER BY count DESC
```

## Next Steps (Optional)

### Phase 4: Feedback System
- Add `POST /v1/feedback/sigma/{rule_id}` endpoint
- Track effectiveness scores
- Monitor false positive rates

### Phase 5: Background Sync
- Implement periodic git pull
- Diff based on commit_sha
- Update changed rules
- Notification on drift

### OpenSearch Integration
- Create `bandjacks_sigma-v1` index
- Generate embeddings for semantic search
- Include in TTX search results

## Conclusion

The Sprint 7 Sigma extension successfully delivers:
- ✅ First-class Sigma rule entities
- ✅ Reference-based linking to Analytics
- ✅ Version control and provenance
- ✅ License compliance enforcement
- ✅ Integration with coverage analytics
- ✅ Search and discovery capabilities

The implementation maintains clean separation between STIX objects and Sigma rules while providing practical detection operations through the knowledge graph.