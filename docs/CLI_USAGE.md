# Bandjacks CLI Documentation

The Bandjacks CLI provides a comprehensive command-line interface for cyber threat intelligence operations, including search, analysis, review workflows, and system administration.

## Installation

The CLI is included with the main Bandjacks package:

```bash
# Install dependencies
uv sync

# Verify installation
python -m bandjacks.cli.main --help
```

## Configuration

The CLI reads configuration from environment variables:

```bash
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=password
export OPENSEARCH_URL=http://localhost:9200
export OS_INDEX_NODES=bandjacks_attack_nodes-v1
```

## Command Reference

### Global Options

```bash
python -m bandjacks.cli.main [--debug/--no-debug] COMMAND
```

- `--debug`: Enable debug output for troubleshooting

### Query Commands

#### Natural Language Search

Search for threat intelligence using natural language queries with hybrid vector and graph search.

```bash
python -m bandjacks.cli.main query search "SEARCH_QUERY" [OPTIONS]
```

**Options:**
- `--top-k INTEGER` (default: 10): Number of results to return
- `--entity-type TEXT`: Filter by entity type (attack-pattern, intrusion-set, software)
- `--no-context`: Skip graph context enrichment

**Examples:**

```bash
# Basic search
python -m bandjacks.cli.main query search "lateral movement techniques"

# Search with filters
python -m bandjacks.cli.main query search "ransomware groups" --entity-type intrusion-set --top-k 5

# Search without graph context (faster)
python -m bandjacks.cli.main query search "credential theft" --no-context
```

**Output:**
- Ranked results with fusion scores
- Entity types and names
- Preview of descriptions
- Graph context showing relationships (unless --no-context)

#### Graph Exploration

Explore the knowledge graph around a specific technique or entity.

```bash
python -m bandjacks.cli.main query graph TECHNIQUE_ID [OPTIONS]
```

**Options:**
- `--depth INTEGER` (default: 2): Graph traversal depth

**Examples:**

```bash
# Explore around a technique
python -m bandjacks.cli.main query graph "attack-pattern--3ccef7ae-cb5e-48f6-8302-897105fbf55c"

# Deeper exploration
python -m bandjacks.cli.main query graph "T1003.001" --depth 3
```

**Output:**
- Nodes grouped by distance from center
- Node types and relationships
- STIX IDs for reference

### Review Queue Commands

#### View Review Queue

Display candidate nodes pending review from extraction operations.

```bash
python -m bandjacks.cli.main review queue [OPTIONS]
```

**Options:**
- `--status TEXT`: Filter by status (pending, under_review, auto_approved, approved, rejected)
- `--limit INTEGER` (default: 20): Maximum items to display

**Examples:**

```bash
# View all pending candidates
python -m bandjacks.cli.main review queue --status pending

# View recently auto-approved items
python -m bandjacks.cli.main review queue --status auto_approved --limit 10
```

**Output:**
- Queue statistics (total, pending, auto-approved)
- Table of candidates with ID, type, name, confidence, status

#### Approve Candidate

Approve a candidate node and optionally merge it to the main knowledge graph.

```bash
python -m bandjacks.cli.main review approve CANDIDATE_ID [OPTIONS]
```

**Options:**
- `--reviewer TEXT` (default: 'cli-user'): Reviewer identifier
- `--merge/--no-merge` (default: merge): Whether to merge to main graph

**Examples:**

```bash
# Approve and merge
python -m bandjacks.cli.main review approve "candidate--abc123"

# Approve without merging
python -m bandjacks.cli.main review approve "candidate--xyz789" --no-merge

# Approve with custom reviewer
python -m bandjacks.cli.main review approve "candidate--def456" --reviewer "analyst-1"
```

#### Reject Candidate

Reject a candidate with a reason.

```bash
python -m bandjacks.cli.main review reject CANDIDATE_ID --reason TEXT [OPTIONS]
```

**Options:**
- `--reviewer TEXT` (default: 'cli-user'): Reviewer identifier
- `--reason TEXT` (required): Rejection reason

**Examples:**

```bash
# Reject with reason
python -m bandjacks.cli.main review reject "candidate--bad123" --reason "Duplicate entity"

# Reject with detailed reason
python -m bandjacks.cli.main review reject "candidate--wrong456" \
  --reason "Low confidence extraction with incorrect technique mapping"
```

### Document Extraction

#### Extract CTI from Document

Process documents to extract cyber threat intelligence entities.

```bash
python -m bandjacks.cli.main extract document FILE_PATH [OPTIONS]
```

**Options:**
- `--confidence-threshold FLOAT` (default: 80.0): Auto-approval threshold
- `--show-evidence`: Display extraction evidence

**Examples:**

```bash
# Basic extraction
python -m bandjacks.cli.main extract document reports/apt28.pdf

# Extract with evidence
python -m bandjacks.cli.main extract document reports/ransomware.txt --show-evidence

# Set high auto-approval threshold
python -m bandjacks.cli.main extract document reports/incident.md --confidence-threshold 95
```

**Output:**
- Number of entities extracted
- Entity types and names
- Confidence scores
- Evidence citations (if --show-evidence)
- Relationships discovered

### Administrative Commands

#### System Health Check

Check the health status of all system components.

```bash
python -m bandjacks.cli.main admin health
```

**Output:**
- Neo4j connection status
- OpenSearch connection status
- Redis cache status
- Service availability

**Example:**

```bash
$ python -m bandjacks.cli.main admin health

System Health Status:

  ✓ neo4j: Online
  ✓ opensearch: Online
  ✓ Redis: Online
```

#### Database Optimization

Run database optimization including index creation and query analysis.

```bash
python -m bandjacks.cli.main admin optimize
```

**Output:**
- Index creation results
- Query optimization recommendations
- Performance improvement suggestions

**Example:**

```bash
$ python -m bandjacks.cli.main admin optimize

Index Creation Results:
  ✓ AttackPattern_stix_id
  ✓ AttackPattern_name
  ✓ IntrusionSet_stix_id
  ...

Optimization Recommendations:
  • [high] Consider adding composite index on relationship patterns
  • [medium] Consider partitioning AttackPattern nodes (count: 12543)
```

#### Cache Statistics

View Redis cache performance statistics.

```bash
python -m bandjacks.cli.main admin cache-stats
```

**Output:**
- Cache hit rate
- Total hits/misses
- Memory usage
- Commands processed

**Example:**

```bash
$ python -m bandjacks.cli.main admin cache-stats

Cache Statistics
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Metric              Value
────────────────────────────────
Hit Rate            85.43%
Total Hits          12,543
Total Misses        2,145
Memory Used         45.2MB
Commands Processed  14,688
```

#### Clear Cache

Clear cache entries to force fresh queries.

```bash
python -m bandjacks.cli.main admin cache-clear [OPTIONS]
```

**Options:**
- `--pattern TEXT`: Pattern to match for selective clearing

**Examples:**

```bash
# Clear all cache
python -m bandjacks.cli.main admin cache-clear

# Clear specific pattern
python -m bandjacks.cli.main admin cache-clear --pattern "lateral"
```

## Advanced Usage

### Scripting and Automation

The CLI can be used in scripts for automation:

```bash
#!/bin/bash
# Auto-approve high-confidence candidates

for candidate in $(python -m bandjacks.cli.main review queue --status pending --limit 100 | grep "candidate--" | cut -d' ' -f1); do
    confidence=$(python -m bandjacks.cli.main review queue | grep $candidate | awk '{print $4}')
    if [ "$confidence" -gt "90" ]; then
        python -m bandjacks.cli.main review approve $candidate
    fi
done
```

### Output Formats

The CLI uses rich terminal formatting by default. For machine-readable output in scripts:

```bash
# Disable rich formatting
NO_COLOR=1 python -m bandjacks.cli.main query search "malware"

# Pipe to other tools
python -m bandjacks.cli.main review queue | grep pending | wc -l
```

### Performance Tips

1. **Use --no-context for faster searches** when graph relationships aren't needed
2. **Leverage caching** - repeated queries will be faster
3. **Run optimization regularly** to maintain index performance
4. **Monitor cache stats** to tune TTL values

### Troubleshooting

#### Debug Mode

Enable debug output to see detailed operation information:

```bash
python -m bandjacks.cli.main --debug query search "test"
```

#### Connection Issues

If services are unavailable, check with health command:

```bash
python -m bandjacks.cli.main admin health
```

#### Cache Issues

Clear cache if seeing stale results:

```bash
python -m bandjacks.cli.main admin cache-clear
```

## Examples by Use Case

### Analyst Workflow

```bash
# 1. Search for relevant techniques
python -m bandjacks.cli.main query search "spearphishing for credentials"

# 2. Explore relationships
python -m bandjacks.cli.main query graph "T1566.001" --depth 2

# 3. Review extraction queue
python -m bandjacks.cli.main review queue --status pending

# 4. Approve high-confidence extractions
python -m bandjacks.cli.main review approve "candidate--abc123"
```

### Batch Processing

```bash
# Process multiple reports
for report in reports/*.txt; do
    python -m bandjacks.cli.main extract document "$report" --confidence-threshold 85
done

# Review and approve in batch
python -m bandjacks.cli.main review queue --status auto_approved
```

### System Maintenance

```bash
# Daily maintenance routine
python -m bandjacks.cli.main admin health
python -m bandjacks.cli.main admin optimize
python -m bandjacks.cli.main admin cache-stats

# Weekly cache clear
python -m bandjacks.cli.main admin cache-clear
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NEO4J_URI` | Neo4j connection URI | `bolt://localhost:7687` |
| `NEO4J_USER` | Neo4j username | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j password | `password` |
| `OPENSEARCH_URL` | OpenSearch URL | `http://localhost:9200` |
| `OS_INDEX_NODES` | OpenSearch index name | `bandjacks_attack_nodes-v1` |
| `REDIS_URL` | Redis cache URL | `redis://localhost:6379` |
| `NO_COLOR` | Disable colored output | `false` |

## Command Shortcuts

For frequent use, create aliases:

```bash
# Add to ~/.bashrc or ~/.zshrc
alias bj="python -m bandjacks.cli.main"
alias bjsearch="python -m bandjacks.cli.main query search"
alias bjqueue="python -m bandjacks.cli.main review queue"
alias bjhealth="python -m bandjacks.cli.main admin health"

# Usage
bjsearch "lateral movement"
bjqueue --status pending
bjhealth
```