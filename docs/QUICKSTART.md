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

Analyze a threat report:

```bash
curl -X POST "http://localhost:8000/v1/mapper/propose?engine=hybrid" \
  -H "Content-Type: application/json" \
  -d '{
    "source_id": "test-001",
    "source_type": "txt",
    "inline_text": "APT29 uses spearphishing emails with malicious PDF attachments. They establish persistence using scheduled tasks and registry keys."
  }'
```

Returns mapped techniques:
- T1566.001 - Spearphishing Attachment
- T1053.005 - Scheduled Task
- T1547.001 - Registry Run Keys

## Common Workflows

### Analyze a PDF Report

```bash
# Extract and map techniques from PDF
curl -X POST "http://localhost:8000/v1/mapper/propose?engine=llm" \
  -H "Content-Type: application/json" \
  -d '{
    "source_id": "apt-report-2024",
    "source_type": "pdf",
    "url": "https://example.com/threat-report.pdf"
  }'
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

## Performance Tips

1. **Batch Operations**: Process multiple documents in parallel
2. **Use Caching**: Results are cached for 15 minutes
3. **Optimize Chunking**: Larger chunks = better context but slower
4. **Choose Right Engine**: Match engine to your accuracy/speed needs
5. **Index Management**: Periodically optimize OpenSearch indices