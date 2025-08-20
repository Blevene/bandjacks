# Search API Endpoints

The search endpoints provide text-to-technique mapping and entity search capabilities using vector similarity and graph queries.

## POST /search/ttx

Search for ATT&CK techniques matching natural language text using vector similarity.

### Request

```http
POST /v1/search/ttx
Content-Type: application/json
```

```json
{
  "text": "The attacker sent emails with malicious PDF attachments to executives",
  "kb_types": ["attack-pattern", "intrusion-set"],
  "top_k": 5
}
```

### Parameters

- **text** (required): Natural language text to search for
  - Min length: 10 characters
  - Max length: 5000 characters
- **kb_types** (optional): Filter results by STIX object types
  - Default: `["attack-pattern"]`
  - Options: `"attack-pattern"`, `"intrusion-set"`, `"malware"`, `"tool"`, `"course-of-action"`
- **top_k** (optional): Maximum number of results to return
  - Default: `5`
  - Range: 1-20
  

### Response

```json
{
  "query": "The attacker sent emails with malicious PDF attachments to executives",
  "results": [
    {
      "stix_id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
      "type": "attack-pattern",
      "name": "Spearphishing Attachment",
      "confidence": 0.92,
      "score": 0.876,
      "external_id": "T1566.001",
      "description": "Adversaries may send spearphishing emails with a malicious attachment...",
      "kill_chain_phases": ["initial-access"],
      "is_subtechnique": true,
      "parent_technique": "T1566",
      "platforms": ["Windows", "macOS", "Linux"],
      "highlights": [
        "emails with malicious",
        "PDF attachments",
        "targeted executives"
      ]
    },
    {
      "stix_id": "attack-pattern--2b742742-28c3-4e1b-bab7-8350d6300fa7",
      "type": "attack-pattern",
      "name": "Spearphishing Link",
      "confidence": 0.78,
      "score": 0.743,
      "external_id": "T1566.002",
      "description": "Adversaries may send spearphishing emails with a malicious link...",
      "kill_chain_phases": ["initial-access"],
      "is_subtechnique": true,
      "parent_technique": "T1566",
      "platforms": ["Windows", "macOS", "Linux"]
    },
    {
      "stix_id": "attack-pattern--a62a8db3-d4e6-4e3f-a8dd-78f60e2a9d0e",
      "type": "attack-pattern",
      "name": "Phishing",
      "confidence": 0.71,
      "score": 0.689,
      "external_id": "T1566",
      "description": "Adversaries may send phishing messages to gain access...",
      "kill_chain_phases": ["initial-access"],
      "is_subtechnique": false,
      "platforms": ["Windows", "macOS", "Linux", "SaaS", "Office 365"]
    }
  ],
  "metadata": {
    "total_matches": 3,
    "search_time_ms": 142,
    "embedding_model": "sentence-transformers/all-MiniLM-L6-v2",
    "index": "bandjacks_attack_nodes-v1"
  }
}
```

### Fields in Response

- **stix_id**: STIX 2.1 identifier
- **type**: STIX object type
- **name**: Technique or entity name
- **confidence**: Normalized confidence score (0.0-1.0)
- **score**: Raw similarity score from vector search
- **external_id**: ATT&CK ID (e.g., T1566.001)
- **description**: Full description (if include_descriptions=true)
- **kill_chain_phases**: Tactics associated with technique
- **is_subtechnique**: Whether this is a sub-technique
- **parent_technique**: Parent technique ID (for sub-techniques)
- **platforms**: Applicable platforms
- **highlights**: Key phrases that matched (when available)

### Example Usage

```bash
# Basic search for techniques
curl -X POST http://localhost:8000/v1/search/ttx \
  -H "Content-Type: application/json" \
  -d '{
    "text": "ransomware encryption of files"
  }'

# Search with filters and more results
curl -X POST http://localhost:8000/v1/search/ttx \
  -H "Content-Type: application/json" \
  -d '{
    "text": "APT29 credential dumping LSASS",
    "kb_types": ["attack-pattern", "intrusion-set"],
    "top_k": 10
  }'

# Search for specific tools
curl -X POST http://localhost:8000/v1/search/ttx \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Cobalt Strike beacon",
    "kb_types": ["tool", "malware"],
    "top_k": 3
  }'
```

### Search Algorithm

1. **Text Processing**: Query text is cleaned and normalized
2. **Embedding Generation**: Text is converted to vector using sentence-transformers
3. **KNN Search**: OpenSearch performs k-nearest neighbor search
4. **Re-ranking**: Results are re-ranked based on:
   - Vector similarity score
   - Exact phrase matches
   - Technique popularity/prevalence
   - Recency of technique updates
5. **Filtering**: Results below confidence threshold are removed
6. **Enhancement**: Additional metadata fetched from Neo4j

### Performance Characteristics

- P50 latency: ~100ms
- P95 latency: ~300ms
- P99 latency: ~500ms
- Scales to millions of techniques
- Cached embeddings for common queries

### Error Responses

- **400 Bad Request**: Invalid query parameters

```json
{
  "detail": "Query text too short: minimum 10 characters required"
}
```

- **503 Service Unavailable**: OpenSearch not available

```json
{
  "detail": "Search service temporarily unavailable"
}
```

### Advanced Features

#### Phrase Matching

The search engine recognizes 150+ technique-specific phrases:

- "spearphishing" → T1566.001, T1566.002
- "credential dumping" → T1003
- "living off the land" → T1218
- "lateral movement" → Multiple techniques in TA0008

#### Context Enhancement

When searching for groups or malware, related techniques are boosted:

```json
{
  "text": "Lazarus group activities",
  "kb_types": ["intrusion-set", "attack-pattern"]
}
```

Returns Lazarus (G0032) plus techniques commonly used by Lazarus.

#### Multi-language Support

The vector model supports multiple languages:

```json
{
  "text": "El atacante utilizó phishing dirigido",
  "top_k": 3
}
```

### Integration with LLM

This endpoint is used by the LLM tool-calling system:

```python
# LLM tool definition
{
  "type": "function",
  "function": {
    "name": "vector_search_ttx",
    "description": "Search for ATT&CK techniques matching text",
    "parameters": {
      "type": "object",
      "properties": {
        "query_text": {"type": "string"},
        "kb_types": {"type": "array", "items": {"type": "string"}},
        "top_k": {"type": "integer"}
      },
      "required": ["query_text"]
    }
  }
}
```