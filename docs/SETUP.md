# Bandjacks Environment Setup

Complete guide for setting up Bandjacks development and production environments.

## System Requirements

### Minimum Requirements
- **CPU**: 4 cores
- **RAM**: 8GB
- **Storage**: 20GB free space
- **OS**: Linux, macOS, or Windows with WSL2

### Recommended Requirements
- **CPU**: 8+ cores
- **RAM**: 16GB
- **Storage**: 50GB SSD
- **OS**: Ubuntu 22.04 LTS or macOS 13+

## Software Dependencies

### Core Requirements

#### Python
```bash
# Install Python 3.11+
# macOS
brew install python@3.11

# Ubuntu/Debian
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip

# Verify installation
python3.11 --version
```

#### UV Package Manager
```bash
# Install uv
pip install uv

# Or using pipx (recommended)
pipx install uv

# Verify installation
uv --version
```

#### Docker & Docker Compose
```bash
# macOS
brew install docker docker-compose

# Ubuntu/Debian
sudo apt install docker.io docker-compose

# Add user to docker group (Linux)
sudo usermod -aG docker $USER
newgrp docker

# Verify installation
docker --version
docker-compose --version
```

## Environment Configuration

### 1. Create Configuration File

```bash
# Copy template
cp .env.example .env

# Edit with your settings
nano .env
```

### 2. Required Environment Variables

```bash
# === API Configuration ===
API_PREFIX=/v1
API_TITLE=Bandjacks API

# === ATT&CK Configuration ===
ATTACK_INDEX_URL=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json
ATTACK_COLLECTION=enterprise-attack
ATTACK_VERSION=latest

# === Neo4j Configuration ===
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your-secure-password-here  # CHANGE THIS!

# === OpenSearch Configuration ===
OPENSEARCH_URL=http://localhost:9200
OS_INDEX_NODES=bandjacks_attack_nodes-v1

# === ADM Validation ===
ADM_MODE=schema  # or "sidecar" for external validator
ADM_SPEC_MIN=3.3.0

# === LLM Configuration (Required for LLM features) ===
# Option 1: OpenAI
OPENAI_API_KEY=sk-proj-...  # Your OpenAI API key
OPENAI_MODEL=gpt-5  # Model to use

# Option 2: Google
GOOGLE_API_KEY=...  # Your Google API key
GOOGLE_MODEL=gemini-2.5-flash  # Model to use

# === Optional: LiteLLM Proxy ===
LITELLM_BASE_URL=http://localhost:4000
LITELLM_API_KEY=
LITELLM_MODEL=gpt-4o-mini
LITELLM_TIMEOUT_MS=30000
LITELLM_TEMPERATURE=0.2
LITELLM_MAX_TOKENS=800
```

### 3. Sensitive Data Management

**Never commit `.env` to version control!**

```bash
# Ensure .env is in .gitignore
echo ".env" >> .gitignore

# For production, use environment variables or secrets manager
export OPENAI_API_KEY="sk-proj-..."
export NEO4J_PASSWORD="secure-password"
```

## Database Setup

### Neo4j Setup

#### Option 1: Docker (Recommended)
```bash
# Start Neo4j
docker-compose up -d neo4j

# Wait for startup
sleep 30

# Verify connection
curl http://localhost:7474
```

#### Option 2: Local Installation
```bash
# macOS
brew install neo4j

# Start service
neo4j start

# Set initial password
cypher-shell -u neo4j -p neo4j
> ALTER USER neo4j SET PASSWORD 'your-secure-password';
```

#### Neo4j Configuration
Edit `neo4j.conf`:
```
# Memory settings (adjust based on available RAM)
dbms.memory.heap.initial_size=2g
dbms.memory.heap.max_size=4g
dbms.memory.pagecache.size=2g

# Performance
dbms.threads.worker_count=8
dbms.connector.bolt.thread_pool_max_size=400
```

### OpenSearch Setup

#### Option 1: Docker (Recommended)
```bash
# Start OpenSearch
docker-compose up -d opensearch

# Wait for startup
sleep 45

# Verify cluster health
curl http://localhost:9200/_cluster/health?pretty
```

#### Option 2: Local Installation
```bash
# Download OpenSearch
wget https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.0/opensearch-2.11.0-linux-x64.tar.gz
tar -xzf opensearch-2.11.0-linux-x64.tar.gz
cd opensearch-2.11.0

# Start with security disabled for development
./bin/opensearch -Eplugins.security.disabled=true
```

#### OpenSearch Configuration
Edit `opensearch.yml`:
```yaml
# Cluster settings
cluster.name: bandjacks-cluster
node.name: node-1

# Memory settings
indices.memory.index_buffer_size: 30%
indices.queries.cache.size: 15%

# KNN settings for vector search
knn.memory.circuit_breaker.limit: 50%
knn.algo_param.index_thread_qty: 4
```

## Python Environment Setup

### 1. Create Virtual Environment

```bash
# Using uv (recommended)
uv venv

# Activate environment
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows
```

### 2. Install Dependencies

```bash
# Install all dependencies
uv sync

# Or install specific groups
uv sync --group dev  # Development dependencies
uv sync --group test  # Testing dependencies
```

### 3. Verify Installation

```bash
# Check installed packages
uv pip list

# Run tests
uv run pytest tests/

# Check code quality
uv run ruff check .
uv run mypy .
```

## Service Configuration

### API Server Configuration

Create `config.yaml` for advanced settings:

```yaml
# API Settings
api:
  workers: 4
  timeout: 60
  max_request_size: 10MB
  cors_origins:
    - "http://localhost:3000"
    - "https://app.example.com"

# Logging
logging:
  level: INFO
  format: json
  file: /var/log/bandjacks/api.log

# Cache Settings
cache:
  ttl: 900  # 15 minutes
  max_size: 1000

# Rate Limiting
rate_limit:
  enabled: true
  requests_per_minute: 60
  burst: 100
```

### Docker Compose Configuration

Full `docker-compose.yml`:

```yaml
version: '3.8'

services:
  neo4j:
    image: neo4j:5.15
    container_name: bandjacks-neo4j
    ports:
      - "7474:7474"  # HTTP
      - "7687:7687"  # Bolt
    environment:
      - NEO4J_AUTH=neo4j/${NEO4J_PASSWORD}
      - NEO4J_PLUGINS=["apoc", "graph-data-science"]
      - NEO4J_dbms_memory_heap_max__size=4G
      - NEO4J_dbms_memory_pagecache_size=2G
    volumes:
      - neo4j_data:/data
      - neo4j_logs:/logs

  opensearch:
    image: opensearchproject/opensearch:2.11.0
    container_name: bandjacks-opensearch
    ports:
      - "9200:9200"
      - "9600:9600"
    environment:
      - discovery.type=single-node
      - plugins.security.disabled=true  # For development only!
      - OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g
    volumes:
      - opensearch_data:/usr/share/opensearch/data

  api:
    build: .
    container_name: bandjacks-api
    ports:
      - "8000:8000"
    environment:
      - NEO4J_URI=bolt://neo4j:7687
      - OPENSEARCH_URL=http://opensearch:9200
    env_file:
      - .env
    depends_on:
      - neo4j
      - opensearch
    volumes:
      - ./bandjacks:/app/bandjacks
      - ./data:/app/data

volumes:
  neo4j_data:
  neo4j_logs:
  opensearch_data:
```

## Production Setup

### Security Hardening

1. **Enable OpenSearch Security**
```bash
# Generate certificates
./opensearch-2.11.0/plugins/opensearch-security/tools/install_demo_configuration.sh

# Update .env
OPENSEARCH_URL=https://localhost:9200
OPENSEARCH_USER=admin
OPENSEARCH_PASSWORD=secure-password
```

2. **Configure Neo4j SSL**
```bash
# Generate certificates
neo4j-admin certificates generate --self-signed

# Update neo4j.conf
dbms.ssl.policy.bolt.enabled=true
dbms.ssl.policy.bolt.base_directory=certificates/bolt
```

3. **API Authentication**
```python
# Add to settings.py
API_KEY_HEADER = "X-API-Key"
REQUIRE_API_KEY = True
ALLOWED_API_KEYS = ["key1", "key2"]  # Load from secure storage
```

### Performance Tuning

1. **System Limits**
```bash
# /etc/security/limits.conf
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
```

2. **Kernel Parameters**
```bash
# /etc/sysctl.conf
vm.max_map_count=262144
fs.file-max=65536
net.core.somaxconn=1024
```

3. **Process Management**
```bash
# Use systemd service
sudo cp bandjacks.service /etc/systemd/system/
sudo systemctl enable bandjacks
sudo systemctl start bandjacks
```

### Monitoring Setup

1. **Prometheus Metrics**
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'bandjacks'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
```

2. **Logging**
```python
# logging.conf
[loggers]
keys=root,bandjacks

[handlers]
keys=console,file,syslog

[formatters]
keys=json,detailed
```

3. **Health Checks**
```bash
# Health check script
#!/bin/bash
curl -f http://localhost:8000/health || exit 1
curl -f http://localhost:7474 || exit 1
curl -f http://localhost:9200/_cluster/health || exit 1
```

## Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Find process using port
lsof -i :8000
# Kill process
kill -9 <PID>
```

#### Memory Issues
```bash
# Increase Docker memory
docker system prune -a
# Edit Docker Desktop settings to increase memory
```

#### Permission Denied
```bash
# Fix permissions
sudo chown -R $USER:$USER .
chmod -R 755 bandjacks/
```

#### SSL Certificate Issues
```bash
# Disable SSL verification (development only)
export PYTHONHTTPSVERIFY=0
export CURL_CA_BUNDLE=""
```

### Debug Mode

Enable debug logging:
```bash
# Set in .env
LOG_LEVEL=DEBUG
DEBUG=true

# Or via command line
LOG_LEVEL=DEBUG uv run uvicorn bandjacks.services.api.main:app --reload --log-level debug
```

## Development Tools

### IDE Setup

#### VS Code
```json
// .vscode/settings.json
{
  "python.defaultInterpreter": ".venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.ruffEnabled": true,
  "python.formatting.provider": "black",
  "python.testing.pytestEnabled": true
}
```

#### PyCharm
1. Set Project Interpreter to `.venv/bin/python`
2. Enable Ruff inspections
3. Configure pytest as test runner

### Pre-commit Hooks

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

`.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.1.6
    hooks:
      - id: ruff
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.7.1
    hooks:
      - id: mypy
```

## Next Steps

1. **Load ATT&CK Data**: See [Quick Start](./QUICKSTART.md)
2. **Run Tests**: `uv run pytest tests/`
3. **Start Development**: `uv run uvicorn bandjacks.services.api.main:app --reload`
4. **Read API Docs**: http://localhost:8000/docs
5. **Configure LLM**: Add API keys to `.env`

## Support

- **Documentation**: [Main Docs](./README.md)
- **Issues**: [GitHub Issues](https://github.com/anthropics/claude-code/issues)
- **Community**: Join our Discord/Slack