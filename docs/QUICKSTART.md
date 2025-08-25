# Bandjacks Quick Start Guide

Get up and running with Bandjacks in 5 minutes.

## Prerequisites

- Python 3.11+
- Docker and Docker Compose
- 8GB RAM minimum
- OpenAI API key or Google API key (for LLM features)

## Installation

### 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/your-org/bandjacks.git
cd bandjacks

# Install dependencies with uv
pip install uv
uv sync

# Copy environment template
cp .env.example .env
```

### 2. Configure Environment

Edit `.env` file with your settings:

```bash
# Required for LLM features
OPENAI_API_KEY=sk-...
# OR
GOOGLE_API_KEY=...

# Database connections (defaults work with Docker)
NEO4J_URI=bolt://localhost:7687
NEO4J_PASSWORD=your-secure-password
OPENSEARCH_URL=http://localhost:9200
```

### 3. Start Services

```bash
# Start Neo4j and OpenSearch
docker-compose up -d

# Wait for services to be ready (about 30 seconds)
sleep 30

# Start the API server
uv run uvicorn bandjacks.services.api.main:app --reload
```

The API will be available at `http://localhost:8000`

## First Steps

### 1. Load ATT&CK Data

Load the latest MITRE ATT&CK framework:

```bash
curl -X POST http://localhost:8000/v1/stix/load/attack \
  -H "Content-Type: application/json" \
  -d '{
    "collection": "enterprise-attack",
    "version": "latest"
  }'
```

This takes 3-5 minutes and loads:
- 600+ techniques and sub-techniques
- 140+ threat groups
- 700+ software tools
- 300+ mitigations

### 2. Test Search

Search for techniques by description:

```bash
curl -X POST http://localhost:8000/v1/search/ttx \
  -H "Content-Type: application/json" \
  -d '{
    "query_text": "ransomware encrypting files",
    "top_k": 3
  }'
```

Expected output:
```json
{
  "results": [
    {
      "name": "Data Encrypted for Impact",
      "external_id": "T1486",
      "confidence": 0.92
    }
  ]
}
```

### 3. Extract TTPs from Text

Analyze a threat report (async extraction runs recommended):

```bash
# Start async run
curl -s -X POST http://localhost:8000/v1/extract/runs \
  -H "Content-Type: application/json" \
  -d '{
    "method": "agentic_v2",
    "content": "APT29 uses spearphishing emails with malicious PDF attachments. They establish persistence using scheduled tasks and registry keys.",
    "title": "Sample Report",
    "config": {"top_k": 5, "min_quotes": 2}
  }'

# Then poll status and fetch result with the returned run_id
```

Returns mapped techniques:
- T1566.001 - Spearphishing Attachment
- T1053.005 - Scheduled Task
- T1547.001 - Registry Run Keys

### 4. Generate AttackFlow Models

Create co-occurrence models showing how threat actors use techniques together:

```bash
# Generate flow for APT29 (Cozy Bear)
curl -X POST http://localhost:8000/v1/flows/build \
  -H "Content-Type: application/json" \
  -d '{
    "intrusion_set_id": "intrusion-set--899ce53f-13a0-479b-a0e4-67d46e241542"
  }'
```

Expected output:
```json
{
  "flow_id": "flow--abc123...",
  "name": "Techniques used by APT29",
  "steps": 67,
  "edges": 84,
  "flow_type": "co-occurrence"
}
```

**Bulk Generation** - Generate flows for all threat actors:

```bash
# Generate flows for all 165+ intrusion sets
uv run python scripts/build_intrusion_flows_simple.py

# Monitor progress in real-time
watch 'curl -s "http://localhost:7687" | grep -o "AttackFlow.*count.*[0-9]*"'
```

This creates **co-occurrence models** (not sequential) because intrusion sets don't have inherent sequence information. The system connects techniques that are commonly used together within the same tactics or across adjacent kill chain phases.

## Common Workflows

### Analyze a PDF Report

```bash
# Extract text locally, then start async extraction
python - <<'PY'
from pathlib import Path
import pdfplumber, requests
pdf = Path("samples/reports/new-darkcloud-stealer-infection-chain.pdf")
parts = []
with pdfplumber.open(pdf) as doc:
    for p in doc.pages:
        t = p.extract_text() or ""
        if t: parts.append(t)
text = "\n\n".join(parts)
resp = requests.post("http://localhost:8000/v1/extract/runs", json={
  "method": "agentic_v2",
  "content": text,
  "title": "Darkcloud Stealer",
  "config": {"top_k": 5, "disable_discovery": true, "min_quotes": 2}
})
print(resp.json())
PY
```

### Review and Validate Mappings

```bash
# Accept a proposed mapping
curl -X POST http://localhost:8000/v1/review/mapping \
  -H "Content-Type: application/json" \
  -d '{
    "source_id": "apt-report-2024",
    "object_id": "attack-pattern--7e33a43e-e34b-40ec-89da-36c9bb2cacd5",
    "decision": "accept",
    "confidence_override": 95,
    "note": "Verified by analyst"
  }'
```

### Use LLM Extraction

```bash
# Extract with GPT-5
curl -X POST http://localhost:8000/v1/llm/extract \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Lazarus group deploys ransomware after lateral movement using RDP"
  }'
```

### Generate STIX Bundle

```bash
# Convert extraction to STIX
curl -X POST http://localhost:8000/v1/llm/to-stix \
  -H "Content-Type: application/json" \
  -d '{
    "llm_output": {
      "claims": [...]
    },
    "source_metadata": {
      "source_id": "report-123"
    }
  }'
```

## API Documentation

- **API Explorer**: http://localhost:8000/docs
- **Full Documentation**: [API Reference](./api/README.md)

## Extraction Engines

Bandjacks offers three extraction engines:

| Engine | Speed | Accuracy | Best For |
|--------|-------|----------|----------|
| **vector** | Fast (~200ms) | Good | High-volume processing |
| **llm** | Slower (~2s) | Excellent | Detailed analysis |
| **hybrid** | Medium (~1.5s) | Best | Critical documents |

Choose based on your needs:
- Use `vector` for real-time processing
- Use `llm` for comprehensive extraction with rationales
- Use `hybrid` for highest accuracy

## Monitoring

### Check Service Health

```bash
# Neo4j
curl http://localhost:7474

# OpenSearch
curl http://localhost:9200/_cluster/health

# API
curl http://localhost:8000/health
```

### View Logs

```bash
# API logs
tail -f bandjacks.log

# Neo4j logs
docker logs bandjacks-neo4j

# OpenSearch logs
docker logs bandjacks-opensearch
```

## Troubleshooting

### Services Won't Start

```bash
# Check Docker status
docker ps

# Restart services
docker-compose down
docker-compose up -d

# Check ports aren't in use
lsof -i :8000  # API
lsof -i :7687  # Neo4j
lsof -i :9200  # OpenSearch
```

### Import Errors

```bash
# Reinstall dependencies
uv sync --refresh

# Check Python version
python --version  # Should be 3.11+
```

### LLM Not Working

1. Check API key in `.env`
2. Verify network connectivity
3. Try backup model:
   ```bash
   # Use Gemini instead of GPT-5
   curl -X POST http://localhost:8000/v1/llm/extract \
     -d '{"text": "...", "model": "gemini-2.5-flash"}'
   ```

## Next Steps

1. **Load Custom Data**: Import your own STIX bundles
2. **Configure Extraction**: Adjust chunking and confidence thresholds
3. **Set Up Review Pipeline**: Implement analyst workflow
4. **Integrate with Tools**: Connect to your SIEM/SOAR
5. **Monitor Performance**: Set up metrics and alerting

## Getting Help

- **Documentation**: [Full Docs](./README.md)
- **API Reference**: [API Docs](./api/README.md)
- **Issues**: [GitHub Issues](https://github.com/anthropics/claude-code/issues)

## Sample Data

Try these example texts for testing:

### Spearphishing Campaign
```
The threat actors sent targeted emails to executives containing 
malicious Excel documents. When opened, the documents execute 
PowerShell scripts that establish persistence via scheduled tasks.
```

### Ransomware Attack
```
After gaining initial access through RDP brute force, the attackers 
deployed Cobalt Strike beacons for command and control. They then 
used Mimikatz to harvest credentials before encrypting files.
```

### APT Activity
```
APT28 conducted reconnaissance using open-source intelligence 
gathering before launching watering hole attacks against defense 
contractors. They maintained persistence using WMI event subscriptions.
```

## AttackFlow Generation

### What are AttackFlow Models?

AttackFlow models represent how threat actors use MITRE ATT&CK techniques together. Bandjacks creates **co-occurrence models** that show relationships between techniques without implying false temporal ordering.

### Single Flow Generation

Generate a flow for a specific threat actor:

```bash
# Get the STIX ID for a group (e.g., APT28)
curl -s "http://localhost:8000/v1/search/groups?name=APT28" | jq '.results[0].stix_id'

# Generate the AttackFlow
curl -X POST http://localhost:8000/v1/flows/build \
  -H "Content-Type: application/json" \
  -d '{
    "intrusion_set_id": "intrusion-set--bef4c620-0787-42a8-a96d-b7eb6e85917c"
  }'
```

### Bulk Flow Generation

Generate flows for all threat actors at once:

```bash
# Run the bulk generation script
uv run python scripts/build_intrusion_flows_simple.py

# Optional: Limit to first 10 for testing
uv run python scripts/build_intrusion_flows_simple.py --limit 10

# Force regeneration of existing flows
uv run python scripts/build_intrusion_flows_simple.py --force
```

**Progress Monitoring**: The script handles rate limiting and provides real-time progress:

```
[1/165] Processing Kimsuky (103 techniques)...
  ✓ success - flow: flow--587a05ae-2ee6..., 103 steps, 107 edges

[2/165] Processing Lazarus Group (92 techniques)...
  ✓ success - flow: flow--108821a9-1069..., 92 steps, 96 edges

[20/165] Processing FIN7 (53 techniques)...
  [Rate limit pause - waiting 25 seconds...]
```

### Verifying Generated Flows

Check what flows have been created:

```bash
# Count total flows
curl -s "http://localhost:8000/v1/graph/query" \
  -H "Content-Type: application/json" \
  -d '{"query": "MATCH (f:AttackFlow) RETURN count(f) as total"}' \
  | jq '.results[0].total'

# List top 10 flows by technique count
curl -s "http://localhost:8000/v1/graph/query" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "MATCH (f:AttackFlow)-[:CONTAINS_EPISODE]->(e:AttackEpisode)-[:CONTAINS]->(a:AttackAction) RETURN f.attributed_group_name as group, count(a) as techniques ORDER BY techniques DESC LIMIT 10"
  }' | jq '.results'
```

### Exploring Flow Details

Get detailed information about a specific flow:

```bash
# Get flow details
FLOW_ID="flow--587a05ae-2ee6-480c-9727-f455d44b2587"
curl "http://localhost:8000/v1/flows/$FLOW_ID" | jq '{
  name: .name,
  techniques: .steps | length,
  edges: .edges | length,
  tactics: [.steps[].tactics[]] | unique
}'
```

### Co-occurrence Model Details

The system creates **co-occurrence edges** rather than sequential flows because:

1. **Intrusion sets lack sequence information** - We know APT28 uses T1566.001 and T1059.001, but not in what order
2. **Techniques cluster by tactic** - Most connections are within kill chain tactics (e.g., multiple persistence techniques)
3. **Cross-tactic patterns** - Some edges connect adjacent tactics (initial-access → execution → persistence)

**Edge Types Created**:
- **Intra-tactic**: Full mesh for small groups (<5 techniques), hub-spoke for large groups
- **Cross-tactic**: Connect techniques across adjacent kill chain phases
- **Probability weights**: 0.3 for same-tactic, 0.4 for cross-tactic patterns

### Troubleshooting Flow Generation

**Rate Limiting**: The script automatically handles API rate limits with 25-second pauses every 20 requests.

**Memory Issues**: For very large datasets, the script processes one intrusion set at a time to avoid memory problems.

**Failed Flows**: Check the log output for specific error messages:

```bash
# If a flow fails, check the API logs
tail -f bandjacks.log | grep "Error persisting flow"

# Retry failed flows manually
curl -X POST http://localhost:8000/v1/flows/build \
  -H "Content-Type: application/json" \
  -d '{"intrusion_set_id": "FAILED_GROUP_ID"}'
```

**Performance**: Generation takes ~1-3 seconds per intrusion set, with automatic skipping of existing flows.

### Using AttackFlow Data

Query the generated flows for analysis:

```bash
# Find flows with the most cross-tactic edges
curl -s "http://localhost:8000/v1/graph/query" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "MATCH (f:AttackFlow)-[:CONTAINS_EPISODE]->(e)-[:CONTAINS]->(a1)-[n:NEXT {edge_type: \"co-occurrence\"}]->(a2) WHERE n.rationale CONTAINS \"cross-tactic\" RETURN f.attributed_group_name, count(n) as cross_tactic_edges ORDER BY cross_tactic_edges DESC LIMIT 5"
  }'

# Get techniques commonly used together
curl -s "http://localhost:8000/v1/graph/query" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "MATCH (a1:AttackAction)-[n:NEXT]->(a2:AttackAction) WHERE n.probability > 0.3 RETURN a1.attack_pattern_ref, a2.attack_pattern_ref, n.probability, n.rationale ORDER BY n.probability DESC LIMIT 10"
  }'
```

## Performance Tips

1. **Batch Operations**: Process multiple documents in parallel
2. **Use Caching**: Results are cached for 15 minutes
3. **Optimize Chunking**: Larger chunks = better context but slower
4. **Choose Right Engine**: Match engine to your accuracy/speed needs
5. **Index Management**: Periodically optimize OpenSearch indices
6. **AttackFlow Generation**: Use bulk script for efficiency, monitor rate limits