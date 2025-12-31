# Bandjacks CLI Quick Start Guide

## New Features Summary

### ✅ What's Been Added

1. **Export Functionality for Analytics** - Export co-occurrence data and bundles to CSV/JSON
2. **Neo4j Storage for Batch Extraction** - Store extracted reports as AttackEpisode nodes
3. **Integrated Workflows** - End-to-end pipelines combining extraction and analytics

---

## Quick Examples

### 1. Export Analytics to CSV/JSON

```bash
# Export global co-occurrence to CSV
bandjacks analytics global --format csv --output cooccurrence.csv

# Export to JSON with metadata
bandjacks analytics global --format json --output cooccurrence.json

# Export technique bundles
bandjacks analytics bundles --format csv --output bundles.csv
```

### 2. Batch Extract with Neo4j Storage

```bash
# Process reports and store in Neo4j for analytics
python -m bandjacks.cli.batch_extract --store-in-neo4j ./reports/

# With custom Neo4j connection
python -m bandjacks.cli.batch_extract \
  --store-in-neo4j \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-password mypassword \
  ./reports/

# Auto-approve high-confidence results (no manual review)
python -m bandjacks.cli.batch_extract \
  --store-in-neo4j \
  --auto-approve \
  --auto-approve-threshold 0.80 \
  ./reports/

# Skip entity extraction (techniques only, faster)
python -m bandjacks.cli.batch_extract \
  --store-in-neo4j \
  --skip-entity-extraction \
  --auto-approve \
  ./reports/

# Upsert full attack flows with NEXT edges (for flow-based analytics)
python -m bandjacks.cli.batch_extract \
  --store-in-neo4j \
  --auto-approve \
  --upsert-flows \
  ./reports/

# Full integration: Store in both Neo4j and OpenSearch (UI-accessible)
python -m bandjacks.cli.batch_extract \
  --store-in-neo4j \
  --auto-approve \
  --upsert-flows \
  --opensearch-url http://localhost:9200 \
  ./reports/
```

### 3. End-to-End Workflows

```bash
# Process reports → Store in Neo4j → Run analytics → Export results
bandjacks workflow process-reports ./reports/ \
  --analyze \
  --export-dir ./results/

# Export all analytics data
bandjacks workflow bulk-export --export-dir ./analytics_export/
```

---

## Auto-Approve Features (NEW)

### What is Auto-Approve?

Auto-approve automatically validates high-confidence technique extractions, skipping manual review for trusted results. This is ideal for:
- **Bulk processing** of large report archives
- **Trusted sources** with consistent quality
- **Automated pipelines** requiring immediate analytics

### How It Works

1. **Confidence Calculation**: Average confidence across all extracted techniques
2. **Threshold Check**: Compare against `--auto-approve-threshold` (default: 0.80)
3. **Direct Storage**: Auto-approved techniques get full Neo4j relationships immediately
4. **Immediate Analytics**: Data available for co-occurrence analysis without review

### Auto-Approve Flags

```bash
--auto-approve                    # Enable auto-approval
--auto-approve-threshold FLOAT    # Confidence threshold (0.0-1.0, default: 0.80)
--skip-entity-extraction          # Skip entities, techniques only (faster)
```

### Auto-Approve Examples

#### Example 1: High-Confidence Auto-Approve
```bash
# Only auto-approve techniques with 85%+ confidence
python -m bandjacks.cli.batch_extract \
  --store-in-neo4j \
  --auto-approve \
  --auto-approve-threshold 0.85 \
  ./reports/
```

#### Example 2: Fast Bulk Processing with Flows
```bash
# Skip entities, auto-approve 75%+, upsert flows, use 8 workers
python -m bandjacks.cli.batch_extract \
  --store-in-neo4j \
  --skip-entity-extraction \
  --auto-approve \
  --auto-approve-threshold 0.75 \
  --upsert-flows \
  --workers 8 \
  ./reports/
```

#### Example 3: Conservative Auto-Approval
```bash
# Very high threshold (90%+) for maximum quality
python -m bandjacks.cli.batch_extract \
  --store-in-neo4j \
  --auto-approve \
  --auto-approve-threshold 0.90 \
  ./reports/
```

### What Gets Created in Neo4j

**Without Auto-Approve** (default):
```
AttackEpisode → CONTAINS → AttackAction
                            (pending review)
```

**With Auto-Approve**:
```
AttackEpisode → CONTAINS → AttackAction → USES → AttackPattern
                            (auto_approved=true)
```

**With Auto-Approve + Upsert Flows**:
```
AttackEpisode → CONTAINS → AttackAction → USES → AttackPattern
                ↓           ↓ NEXT (p=0.7)
                flow_id     AttackAction → USES → AttackPattern
                            ↓ NEXT (p=0.6)
                            AttackAction → USES → AttackPattern
```

Auto-approved data is **immediately available** for:
- Co-occurrence analysis (`bandjacks analytics global`)
- Technique bundles (`bandjacks analytics bundles`)
- Actor profiling (`bandjacks analytics actor`)
- Attack flow analytics (with `--upsert-flows`)

## Complete Workflow Example

### Goal: Process 50 threat reports and analyze co-occurrence patterns

```bash
# Step 1: Extract techniques from all reports and store in Neo4j
python -m bandjacks.cli.batch_extract \
  --store-in-neo4j \
  --workers 5 \
  ./threat_reports/

# Step 2: Export global co-occurrence analysis
bandjacks analytics global \
  --limit 500 \
  --format csv \
  --output global_cooccurrence.csv

# Step 3: Export technique bundles
bandjacks analytics bundles \
  --min-support 3 \
  --format json \
  --output technique_bundles.json

# Step 4: Analyze specific actor (if known)
bandjacks analytics actor intrusion-set--<uuid> \
  --format json \
  --output actor_analysis.json
```

### Or Use Auto-Approve for Faster Processing:

```bash
# Auto-approve high-confidence extractions with flow upsert (no manual review)
python -m bandjacks.cli.batch_extract \
  --store-in-neo4j \
  --skip-entity-extraction \
  --auto-approve \
  --auto-approve-threshold 0.80 \
  --upsert-flows \
  --workers 8 \
  ./threat_reports/

# Immediately run analytics (data is already approved with flows!)
bandjacks analytics global --format csv --output results.csv
```

### Or Use the Integrated Workflow:

```bash
# All in one command!
bandjacks workflow process-reports ./threat_reports/ \
  --workers 5 \
  --analyze \
  --export-dir ./threat_analysis/
```

---

## Analytics Export Formats

### CSV Format
- Ideal for Excel, data analysis tools
- Headers included for all metrics
- Technique names resolved automatically

### JSON Format
- Structured data with metadata
- Includes analysis parameters
- Programmatic access friendly

### Example CSV Output (cooccurrence.csv):
```csv
Technique_A,Name_A,Technique_B,Name_B,Co-occurrence_Count,Confidence_A_to_B,Lift,NPMI,Jaccard
attack-pattern--123,Phishing,attack-pattern--456,Command and Scripting,15,0.75,3.2,0.68,0.45
```

### Example JSON Output (bundles.json):
```json
{
  "metadata": {
    "export_timestamp": "2025-01-28T10:30:00Z",
    "total_bundles": 25,
    "min_support": 3
  },
  "bundles": [
    {
      "techniques": ["attack-pattern--123", "attack-pattern--456", "attack-pattern--789"],
      "support": 12,
      "confidence": 0.85,
      "lift": 4.2,
      "tactics": ["initial-access", "execution", "persistence"]
    }
  ]
}
```

---

## Command Reference

### Analytics Commands with Export

```bash
# Global co-occurrence metrics
bandjacks analytics global [OPTIONS]
  --format [table|csv|json]    # Output format (default: table)
  --output PATH                # Output file path (required for csv/json)
  --limit INT                  # Maximum pairs to export (default: 50)
  --min-support INT            # Minimum episode support (default: 2)

# Technique bundles
bandjacks analytics bundles [OPTIONS]
  --format [table|csv|json]
  --output PATH
  --min-support INT            # Minimum bundle support (default: 3)
  --min-size INT              # Minimum techniques per bundle (default: 3)
  --max-size INT              # Maximum techniques per bundle (default: 5)
  --actor TEXT                # Filter by intrusion set ID

# Actor-specific analysis
bandjacks analytics actor INTRUSION_SET_ID [OPTIONS]
  --format [table|csv|json]
  --output PATH
  --min-support INT
```

### Batch Extraction with Storage

```bash
python -m bandjacks.cli.batch_extract [PATHS] [OPTIONS]
  --store-in-neo4j            # Store results in Neo4j as AttackEpisode nodes
  --neo4j-uri TEXT            # Neo4j URI (default: from env NEO4J_URI)
  --neo4j-user TEXT           # Neo4j username (default: from env NEO4J_USER)
  --neo4j-password TEXT       # Neo4j password (default: from env NEO4J_PASSWORD)
  --workers INT               # Parallel workers (default: 3)
  --api                       # Use API instead of direct Python

  # Auto-Approve Flags (NEW)
  --skip-entity-extraction    # Skip entity extraction (techniques only, faster)
  --auto-approve              # Auto-approve high-confidence results
  --auto-approve-threshold    # Confidence threshold for auto-approval (default: 0.80)
  --upsert-flows              # Upsert full attack flow structure with NEXT edges

  # OpenSearch Storage Flags (NEW)
  --opensearch-url TEXT       # OpenSearch URL (default: from env OPENSEARCH_URL)
  --opensearch-user TEXT      # OpenSearch username (optional)
  --opensearch-password TEXT  # OpenSearch password (optional)
```

### Workflow Commands

```bash
# Process reports end-to-end
bandjacks workflow process-reports REPORT_DIR [OPTIONS]
  --workers INT               # Parallel workers (default: 3)
  --analyze                   # Run analytics after extraction
  --export-dir PATH          # Export analytics to directory
  --api                       # Use API for extraction

# Bulk export all analytics
bandjacks workflow bulk-export [OPTIONS]
  --export-dir PATH          # Export directory (required)
```

---

## OpenSearch Integration (NEW)

### What Gets Stored in OpenSearch

When `--opensearch-url` is provided, batch-extracted reports are stored in OpenSearch with:

- **Full Report Text**: Original document content for search
- **Text Chunks**: Chunked content with embeddings for semantic search
- **Extraction Results**: All techniques, entities, and flows
- **Review Status**: Auto-approved or pending review
- **UI Accessibility**: Reports visible and searchable in the UI

### Benefits of OpenSearch Storage

1. **UI Integration**: Reports appear in the web UI for viewing and review
2. **Search Capability**: Full-text and semantic search across reports
3. **Audit Trail**: Complete record of all batch-processed reports
4. **Future Review**: Can manually review auto-approved reports if needed
5. **Analytics**: Reports included in dashboard statistics and metrics

### Example: Full Emulation of UI Path

```bash
# CLI with OpenSearch = Same as UI upload
python -m bandjacks.cli.batch_extract \
  --store-in-neo4j \
  --auto-approve \
  --upsert-flows \
  --opensearch-url http://localhost:9200 \
  ./reports/
```

After processing, reports are:
- ✅ Stored in OpenSearch (searchable, viewable in UI)
- ✅ Techniques upserted to Neo4j (immediately available for analytics)
- ✅ Attack flows created in Neo4j (with NEXT edges)
- ✅ Auto-approved (no manual review needed)

## Environment Variables

Set these for easier CLI usage:

```bash
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=your_password
export OPENSEARCH_URL=http://localhost:9200
export OPENSEARCH_USER=admin         # Optional
export OPENSEARCH_PASSWORD=password  # Optional
```

---

## Tips & Best Practices

### 1. **Start with Neo4j Storage**
Always use `--store-in-neo4j` when batch processing so you can run analytics immediately:

```bash
python -m bandjacks.cli.batch_extract --store-in-neo4j ./reports/
```

### 2. **Export Large Datasets**
For comprehensive analysis, use high limits and export to files:

```bash
bandjacks analytics global --limit 1000 --format csv --output large_analysis.csv
```

### 3. **Use Workflows for Automation**
The workflow commands handle all the complexity:

```bash
# One command does everything
bandjacks workflow process-reports ./reports/ --analyze --export-dir ./results/
```

### 4. **Chain Commands for Complex Analysis**
```bash
# Extract and store
python -m bandjacks.cli.batch_extract --store-in-neo4j ./reports/

# Then run multiple analytics
bandjacks analytics global --format csv --output global.csv
bandjacks analytics bundles --format csv --output bundles.csv
bandjacks workflow bulk-export --export-dir ./complete_analysis/
```

---

## Next Steps

After extraction and analysis, you can:

1. **Import CSV into Excel/Pandas** for further analysis
2. **Use JSON data programmatically** in your own tools
3. **Visualize co-occurrence networks** using graph tools
4. **Track technique evolution** by comparing exports over time

---

## Troubleshooting

### "Neo4j storage failed"
- Check Neo4j is running: `neo4j status`
- Verify credentials in environment variables
- Ensure AttackPattern nodes exist (load ATT&CK data first)

### "No co-occurrence pairs found"
- Ensure reports were stored with `--store-in-neo4j`
- Check AttackEpisode nodes exist: `MATCH (e:AttackEpisode) RETURN count(e)`
- Try lowering `--min-support` threshold

### "Export file already exists"
- Output files will be overwritten
- Use timestamped filenames: `--output results_$(date +%Y%m%d).csv`

---

## Support

For more information:
- Full documentation: `docs/CLI_MODERNIZATION_PLAN.md`
- Examples: See `bandjacks/cli/` for working code
- Issues: https://github.com/anthropics/bandjacks/issues
