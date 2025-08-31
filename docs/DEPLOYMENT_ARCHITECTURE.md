# Bandjacks Deployment Architecture

## Table of Contents
1. [Overview](#overview)
2. [Development Environment](#development-environment)
3. [Production Architecture](#production-architecture)
4. [Container Strategy](#container-strategy)
5. [Infrastructure as Code](#infrastructure-as-code)
6. [CI/CD Pipeline](#cicd-pipeline)
7. [Monitoring & Observability](#monitoring--observability)
8. [Security Deployment](#security-deployment)
9. [Scaling Strategies](#scaling-strategies)
10. [Disaster Recovery](#disaster-recovery)

## Overview

The Bandjacks deployment architecture is designed for **flexibility**, **scalability**, and **operational excellence**. The system supports multiple deployment patterns from single-machine development to distributed production clusters.

### **Deployment Targets**
- **Development**: Local development with Docker Compose
- **Staging**: Cloud-based staging environment
- **Production**: Kubernetes-based production cluster
- **Edge**: Lightweight deployments for specific use cases

### **Key Design Principles**
- **Infrastructure as Code**: All infrastructure defined declaratively
- **Immutable Infrastructure**: Container-based deployments
- **Zero-Downtime Deployments**: Blue-green and rolling updates
- **Observability First**: Comprehensive monitoring and logging
- **Security by Default**: Security controls at every layer

## Development Environment

### **Local Development Stack**

```
Developer Workstation
├── Host OS (macOS/Linux/Windows)
├── Docker Desktop
├── Development Tools
│   ├── VS Code / IDE
│   ├── Git
│   ├── UV (Python package manager)
│   └── Node.js / npm
└── Local Services (Docker Compose)
    ├── Neo4j (7687/7474)
    ├── OpenSearch (9200)
    ├── OpenSearch Dashboards (5601)
    └── Redis (6379, optional)
```

#### **Docker Compose Configuration (`infra/docker-compose.yml`)**

```yaml
version: '3.8'

services:
  neo4j:
    image: neo4j:5-community
    container_name: bandjacks-neo4j
    ports:
      - "7474:7474"  # HTTP
      - "7687:7687"  # Bolt
    environment:
      - NEO4J_AUTH=neo4j/password
      - NEO4J_PLUGINS=["apoc", "n10s"]
      - NEO4J_dbms_security_procedures_unrestricted=apoc.*,n10s.*
      - NEO4J_dbms_security_procedures_allowlist=apoc.*,n10s.*
      - NEO4J_dbms_memory_heap_initial_size=512m
      - NEO4J_dbms_memory_heap_max_size=2g
    volumes:
      - neo4j_data:/data
      - neo4j_logs:/logs
    healthcheck:
      test: ["CMD", "cypher-shell", "--username", "neo4j", "--password", "password", "RETURN 1"]
      interval: 30s
      timeout: 10s
      retries: 5

  opensearch:
    image: opensearchproject/opensearch:2.11.0
    container_name: bandjacks-opensearch
    environment:
      - discovery.type=single-node
      - OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g
      - DISABLE_SECURITY_PLUGIN=true  # Development only
      - bootstrap.memory_lock=true
    ports:
      - "9200:9200"
      - "9600:9600"  # Performance analyzer
    volumes:
      - opensearch_data:/usr/share/opensearch/data
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9200/_cluster/health"]
      interval: 30s
      timeout: 10s
      retries: 5

  opensearch-dashboards:
    image: opensearchproject/opensearch-dashboards:2.11.0
    container_name: bandjacks-dashboards
    ports:
      - "5601:5601"
    environment:
      - OPENSEARCH_HOSTS=http://opensearch:9200
      - DISABLE_SECURITY_DASHBOARDS_PLUGIN=true
    depends_on:
      opensearch:
        condition: service_healthy

  redis:
    image: redis:7-alpine
    container_name: bandjacks-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 5

volumes:
  neo4j_data:
  neo4j_logs:
  opensearch_data:
  redis_data:

networks:
  default:
    name: bandjacks-network
```

#### **Development Startup Script**

```bash
#!/bin/bash
# scripts/dev-setup.sh

set -e

echo "🚀 Starting Bandjacks Development Environment"

# Start infrastructure services
echo "📦 Starting infrastructure services..."
docker-compose -f infra/docker-compose.yml up -d

# Wait for services to be healthy
echo "⏳ Waiting for services to be ready..."
docker-compose -f infra/docker-compose.yml ps

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
cd bandjacks
uv sync
cd ..

# Install frontend dependencies
echo "⚛️  Installing frontend dependencies..."
cd ui
npm install
cd ..

# Initialize databases
echo "💾 Initializing databases..."
cd bandjacks
uv run python -c "
from bandjacks.loaders.neo4j_ddl import ensure_ddl
from bandjacks.loaders.opensearch_index import ensure_attack_nodes_index, ensure_attack_flows_index
from bandjacks.services.api.settings import settings

# Create Neo4j constraints and indexes
ensure_ddl(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)

# Create OpenSearch indices
ensure_attack_nodes_index(settings.opensearch_url, settings.os_index_nodes)
ensure_attack_flows_index(settings.opensearch_url)

print('✅ Database initialization complete')
"
cd ..

echo "🎉 Development environment ready!"
echo ""
echo "Services available at:"
echo "  • Neo4j Browser:     http://localhost:7474"
echo "  • OpenSearch:        http://localhost:9200"
echo "  • Kibana Dashboards: http://localhost:5601" 
echo ""
echo "To start the application:"
echo "  • Backend:  cd bandjacks && uv run uvicorn bandjacks.services.api.main:app --reload --host 0.0.0.0 --port 8000"
echo "  • Frontend: cd ui && npm run dev"
```

#### **VS Code Development Configuration**

```json
// .vscode/settings.json
{
  "python.defaultInterpreterPath": "./.venv/bin/python",
  "python.terminal.activateEnvironment": true,
  "python.linting.enabled": true,
  "python.linting.ruffEnabled": true,
  "python.formatting.provider": "ruff",
  "python.testing.pytestEnabled": true,
  "python.testing.unittestEnabled": false,
  "python.testing.pytestArgs": ["tests"],
  "typescript.preferences.includePackageJsonAutoImports": "on",
  "eslint.workingDirectories": ["ui"],
  "files.associations": {
    "*.md": "markdown"
  },
  "markdown.preview.breaks": true
}
```

```json
// .vscode/launch.json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Python: FastAPI",
      "type": "python",
      "request": "launch",
      "program": "-m",
      "args": ["uvicorn", "bandjacks.services.api.main:app", "--reload", "--host", "0.0.0.0", "--port", "8000"],
      "console": "integratedTerminal",
      "cwd": "${workspaceFolder}/bandjacks",
      "env": {
        "LOG_LEVEL": "DEBUG"
      }
    },
    {
      "name": "Python: Pytest",
      "type": "python", 
      "request": "launch",
      "module": "pytest",
      "args": ["tests/", "-v"],
      "console": "integratedTerminal",
      "cwd": "${workspaceFolder}/bandjacks"
    }
  ]
}
```

## Production Architecture

### **Cloud-Native Production Stack**

```
┌─────────────────────────────────────────────────────────────────┐
│                      Load Balancer                             │
│                   (AWS ALB / GCP LB)                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Kubernetes Cluster                           │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                  Application Tier                          ││
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐││
│  │  │   UI Service     │  │  API Service     │  │  Worker Service  ││
│  │  │  (Next.js)       │  │  (FastAPI)       │  │  (Background)    ││
│  │  │  Replicas: 3     │  │  Replicas: 5     │  │  Replicas: 2     ││
│  │  │  Port: 3000      │  │  Port: 8000      │  │  Port: N/A       ││
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘││
│  └─────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   Data Tier                                ││
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐││
│  │  │   Neo4j          │  │   OpenSearch     │  │     Redis        ││
│  │  │   Cluster        │  │   Cluster        │  │   Cluster        ││
│  │  │   (StatefulSet)  │  │   (StatefulSet)  │  │   (Deployment)   ││
│  │  │   Replicas: 3    │  │   Replicas: 3    │  │   Replicas: 3    ││
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘││
│  └─────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                Infrastructure Services                     ││
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐││
│  │  │   Monitoring     │  │   Logging        │  │   Service Mesh   ││
│  │  │   (Prometheus)   │  │   (ELK Stack)    │  │   (Istio)        ││
│  │  └──────────────────┘  └──────────────────┘  └──────────────────┘││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────────┐
│                   External Services                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐│
│  │   Object Storage │  │   Secret Mgmt    │  │   DNS / CDN      ││
│  │   (S3 / GCS)     │  │   (Vault)        │  │   (Route53)      ││
│  └──────────────────┘  └──────────────────┘  └──────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

#### **Kubernetes Manifests**

##### **Namespace Configuration**
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: bandjacks
  labels:
    name: bandjacks
    environment: production
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: bandjacks-quota
  namespace: bandjacks
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 32Gi
    limits.cpu: "20" 
    limits.memory: 64Gi
    pods: "50"
    persistentvolumeclaims: "10"
```

##### **API Service Deployment**
```yaml
# k8s/api-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bandjacks-api
  namespace: bandjacks
  labels:
    app: bandjacks-api
    component: backend
spec:
  replicas: 5
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 2
      maxUnavailable: 1
  selector:
    matchLabels:
      app: bandjacks-api
  template:
    metadata:
      labels:
        app: bandjacks-api
        component: backend
    spec:
      serviceAccountName: bandjacks-api
      containers:
      - name: api
        image: bandjacks/api:latest
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 8000
        env:
        - name: NEO4J_URI
          value: "bolt://neo4j-service:7687"
        - name: OPENSEARCH_URL
          value: "http://opensearch-service:9200"
        - name: REDIS_URL
          value: "redis://redis-service:6379"
        - name: LOG_LEVEL
          value: "INFO"
        - name: WORKERS
          value: "4"
        envFrom:
        - secretRef:
            name: bandjacks-secrets
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 15
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
      volumes:
      - name: tmp-volume
        emptyDir:
          sizeLimit: 1Gi
      nodeSelector:
        node-type: compute
      tolerations:
      - key: "compute-only"
        operator: "Equal"
        value: "true"
        effect: "NoSchedule"
---
apiVersion: v1
kind: Service
metadata:
  name: bandjacks-api-service
  namespace: bandjacks
spec:
  selector:
    app: bandjacks-api
  ports:
  - port: 80
    targetPort: 8000
    protocol: TCP
  type: ClusterIP
```

##### **Neo4j StatefulSet**
```yaml
# k8s/neo4j-statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: neo4j
  namespace: bandjacks
spec:
  serviceName: neo4j-service
  replicas: 3
  selector:
    matchLabels:
      app: neo4j
  template:
    metadata:
      labels:
        app: neo4j
    spec:
      containers:
      - name: neo4j
        image: neo4j:5-enterprise
        ports:
        - containerPort: 7474
        - containerPort: 7687
        env:
        - name: NEO4J_AUTH
          valueFrom:
            secretKeyRef:
              name: neo4j-secrets
              key: auth
        - name: NEO4J_PLUGINS
          value: '["apoc", "n10s"]'
        - name: NEO4J_dbms_mode
          value: "CORE"
        - name: NEO4J_causal__clustering_initial__discovery__members
          value: "neo4j-0.neo4j-service:5000,neo4j-1.neo4j-service:5000,neo4j-2.neo4j-service:5000"
        - name: NEO4J_dbms_memory_heap_initial__size
          value: "2g"
        - name: NEO4J_dbms_memory_heap_max__size
          value: "4g"
        - name: NEO4J_dbms_memory_pagecache_size
          value: "2g"
        resources:
          requests:
            memory: "4Gi"
            cpu: "1000m"
          limits:
            memory: "8Gi"
            cpu: "2000m"
        volumeMounts:
        - name: neo4j-data
          mountPath: /data
        - name: neo4j-logs
          mountPath: /logs
        livenessProbe:
          tcpSocket:
            port: 7687
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          tcpSocket:
            port: 7687
          initialDelaySeconds: 30
          periodSeconds: 10
  volumeClaimTemplates:
  - metadata:
      name: neo4j-data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 100Gi
      storageClassName: fast-ssd
  - metadata:
      name: neo4j-logs
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 20Gi
      storageClassName: standard
---
apiVersion: v1
kind: Service
metadata:
  name: neo4j-service
  namespace: bandjacks
spec:
  clusterIP: None
  selector:
    app: neo4j
  ports:
  - port: 7474
    name: http
  - port: 7687
    name: bolt
  - port: 5000
    name: discovery
```

##### **Ingress Configuration**
```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: bandjacks-ingress
  namespace: bandjacks
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "50m"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  tls:
  - hosts:
    - api.bandjacks.io
    - app.bandjacks.io
    secretName: bandjacks-tls
  rules:
  - host: api.bandjacks.io
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: bandjacks-api-service
            port:
              number: 80
  - host: app.bandjacks.io
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: bandjacks-ui-service
            port:
              number: 80
```

## Container Strategy

### **Multi-Stage Docker Builds**

#### **API Container**
```dockerfile
# bandjacks/Dockerfile
FROM python:3.11-slim as base

# System dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install UV
RUN pip install uv

WORKDIR /app

# Dependencies stage
FROM base as deps
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# Development stage  
FROM deps as dev
RUN uv sync --frozen
COPY . .
CMD ["uv", "run", "uvicorn", "bandjacks.services.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Production stage
FROM base as prod
COPY --from=deps /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app
USER appuser

COPY --chown=appuser:appuser . .

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000
CMD ["uvicorn", "bandjacks.services.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

#### **UI Container**
```dockerfile
# ui/Dockerfile
FROM node:18-alpine as base
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Dependencies stage
FROM base as deps
COPY package.json package-lock.json ./
RUN npm ci --only=production && npm cache clean --force

# Builder stage
FROM base as builder
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production stage
FROM base as runner
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/public ./public

# Set correct permissions for prerendered cache
RUN mkdir .next
RUN chown nextjs:nodejs .next

COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000
ENV PORT 3000
ENV HOSTNAME "0.0.0.0"

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

CMD ["node", "server.js"]
```

### **Container Registry Strategy**

```bash
# Build and tag images
docker build -f bandjacks/Dockerfile -t bandjacks/api:v1.0.0 bandjacks/
docker build -f ui/Dockerfile -t bandjacks/ui:v1.0.0 ui/

# Tag for different environments
docker tag bandjacks/api:v1.0.0 bandjacks/api:latest
docker tag bandjacks/api:v1.0.0 bandjacks/api:staging

# Push to registry
docker push bandjacks/api:v1.0.0
docker push bandjacks/api:latest
docker push bandjacks/ui:v1.0.0
docker push bandjacks/ui:latest
```

## Infrastructure as Code

### **Terraform Configuration**

#### **AWS Infrastructure**
```hcl
# terraform/aws/main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  backend "s3" {
    bucket = "bandjacks-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-west-2"
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "bandjacks"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# EKS Cluster
module "eks" {
  source = "terraform-aws-modules/eks/aws"
  
  cluster_name    = "bandjacks-${var.environment}"
  cluster_version = "1.28"
  
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  
  cluster_endpoint_public_access = true
  cluster_endpoint_private_access = true
  
  node_groups = {
    compute = {
      desired_capacity = 3
      max_capacity     = 10
      min_capacity     = 3
      
      instance_types = ["m5.xlarge"]
      k8s_labels = {
        Environment = var.environment
        NodeType    = "compute"
      }
      
      additional_tags = {
        "kubernetes.io/cluster/bandjacks-${var.environment}" = "owned"
      }
    }
    
    data = {
      desired_capacity = 3
      max_capacity     = 5
      min_capacity     = 3
      
      instance_types = ["r5.2xlarge"]
      k8s_labels = {
        Environment = var.environment
        NodeType    = "data"
      }
      
      k8s_taints = [{
        key    = "data-only"
        value  = "true"
        effect = "NO_SCHEDULE"
      }]
    }
  }
}

# RDS for metadata (optional)
resource "aws_db_instance" "metadata" {
  identifier = "bandjacks-metadata-${var.environment}"
  
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.r5.large"
  
  allocated_storage     = 100
  max_allocated_storage = 1000
  storage_type          = "gp2"
  storage_encrypted     = true
  
  db_name  = "bandjacks_metadata"
  username = "bandjacks"
  password = random_password.db_password.result
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = var.environment != "prod"
  
  tags = {
    Name = "bandjacks-metadata-${var.environment}"
  }
}

# S3 Buckets
resource "aws_s3_bucket" "reports" {
  bucket = "bandjacks-reports-${var.environment}-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "reports" {
  bucket = aws_s3_bucket.reports.id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
```

#### **Helm Charts**
```yaml
# helm/bandjacks/Chart.yaml
apiVersion: v2
name: bandjacks
description: Cyber Threat Defense World Modeling System
type: application
version: 1.0.0
appVersion: "1.0.0"

dependencies:
- name: neo4j
  version: "5.0.0"
  repository: https://helm.neo4j.com/neo4j
  condition: neo4j.enabled
- name: opensearch
  version: "2.11.0" 
  repository: https://opensearch-project.github.io/helm-charts/
  condition: opensearch.enabled
- name: redis
  version: "17.0.0"
  repository: https://charts.bitnami.com/bitnami
  condition: redis.enabled
```

```yaml
# helm/bandjacks/values.yaml
global:
  environment: production
  domain: bandjacks.io

api:
  image:
    repository: bandjacks/api
    tag: v1.0.0
    pullPolicy: IfNotPresent
  
  replicas: 5
  
  resources:
    requests:
      memory: 1Gi
      cpu: 500m
    limits:
      memory: 2Gi
      cpu: 1000m
  
  env:
    LOG_LEVEL: INFO
    WORKERS: 4
  
  service:
    type: ClusterIP
    port: 80
    targetPort: 8000

ui:
  image:
    repository: bandjacks/ui
    tag: v1.0.0
    pullPolicy: IfNotPresent
  
  replicas: 3
  
  resources:
    requests:
      memory: 256Mi
      cpu: 100m
    limits:
      memory: 512Mi
      cpu: 500m

neo4j:
  enabled: true
  neo4j:
    edition: enterprise
    acceptLicenseAgreement: "yes"
  
  core:
    numberOfServers: 3
  
  volumes:
    data:
      mode: volume
      volume:
        size: 100Gi
        storageClassName: fast-ssd

opensearch:
  enabled: true
  
  replicas: 3
  minimumMasterNodes: 2
  
  resources:
    requests:
      memory: 2Gi
      cpu: 1000m
    limits:
      memory: 4Gi 
      cpu: 2000m
  
  persistence:
    enabled: true
    size: 100Gi
    storageClass: fast-ssd

redis:
  enabled: true
  architecture: replication
  
  auth:
    enabled: true
    password: "" # Generated automatically
  
  master:
    persistence:
      enabled: true
      size: 8Gi
  
  replica:
    replicaCount: 2
    persistence:
      enabled: true
      size: 8Gi

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  
  hosts:
  - host: api.bandjacks.io
    paths:
    - path: /
      pathType: Prefix
      service: bandjacks-api
  - host: app.bandjacks.io
    paths:
    - path: /
      pathType: Prefix
      service: bandjacks-ui
  
  tls:
  - secretName: bandjacks-tls
    hosts:
    - api.bandjacks.io
    - app.bandjacks.io
```

## CI/CD Pipeline

### **GitHub Actions Workflow**

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]
    tags: ['v*']
  pull_request:
    branches: [main]

env:
  REGISTRY: ghcr.io
  API_IMAGE_NAME: ${{ github.repository }}/api
  UI_IMAGE_NAME: ${{ github.repository }}/ui

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      neo4j:
        image: neo4j:5-community
        env:
          NEO4J_AUTH: neo4j/password
        ports:
          - 7687:7687
        options: >-
          --health-cmd "cypher-shell --username neo4j --password password 'RETURN 1'"
          --health-interval 30s
          --health-timeout 10s
          --health-retries 5
      
      opensearch:
        image: opensearchproject/opensearch:2.11.0
        env:
          discovery.type: single-node
          DISABLE_SECURITY_PLUGIN: true
        ports:
          - 9200:9200
        options: >-
          --health-cmd "curl -f http://localhost:9200/_cluster/health"
          --health-interval 30s
          --health-timeout 10s
          --health-retries 5
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Install UV
      uses: astral-sh/setup-uv@v1
      with:
        version: "latest"
    
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        cd bandjacks
        uv sync
    
    - name: Run tests
      run: |
        cd bandjacks
        uv run pytest tests/ -v --cov=bandjacks --cov-report=xml
      env:
        NEO4J_URI: bolt://localhost:7687
        OPENSEARCH_URL: http://localhost:9200
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: bandjacks/coverage.xml

  test-ui:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'
        cache-dependency-path: ui/package-lock.json
    
    - name: Install dependencies
      run: |
        cd ui
        npm ci
    
    - name: Run tests
      run: |
        cd ui
        npm run test:ci
    
    - name: Build
      run: |
        cd ui
        npm run build

  build:
    needs: [test, test-ui]
    runs-on: ubuntu-latest
    if: github.event_name == 'push'
    
    permissions:
      contents: read
      packages: write
    
    outputs:
      api-image: ${{ steps.meta-api.outputs.tags }}
      ui-image: ${{ steps.meta-ui.outputs.tags }}
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3
    
    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Extract metadata (API)
      id: meta-api
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.API_IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=semver,pattern={{version}}
          type=semver,pattern={{major}}.{{minor}}
    
    - name: Build and push API image
      uses: docker/build-push-action@v5
      with:
        context: bandjacks
        file: bandjacks/Dockerfile
        target: prod
        push: true
        tags: ${{ steps.meta-api.outputs.tags }}
        labels: ${{ steps.meta-api.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
    
    - name: Extract metadata (UI)
      id: meta-ui
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.UI_IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=semver,pattern={{version}}
          type=semver,pattern={{major}}.{{minor}}
    
    - name: Build and push UI image
      uses: docker/build-push-action@v5
      with:
        context: ui
        file: ui/Dockerfile
        push: true
        tags: ${{ steps.meta-ui.outputs.tags }}
        labels: ${{ steps.meta-ui.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max

  deploy-staging:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: staging
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: us-west-2
    
    - name: Update kubeconfig
      run: |
        aws eks update-kubeconfig --region us-west-2 --name bandjacks-staging
    
    - name: Deploy with Helm
      run: |
        helm upgrade --install bandjacks ./helm/bandjacks \
          --namespace bandjacks \
          --create-namespace \
          --values ./helm/bandjacks/values-staging.yaml \
          --set api.image.tag=${{ github.sha }} \
          --set ui.image.tag=${{ github.sha }} \
          --wait --timeout=10m

  deploy-production:
    needs: [build, deploy-staging]
    runs-on: ubuntu-latest
    if: startsWith(github.ref, 'refs/tags/v')
    environment: production
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: us-west-2
    
    - name: Update kubeconfig
      run: |
        aws eks update-kubeconfig --region us-west-2 --name bandjacks-prod
    
    - name: Deploy with Helm
      run: |
        helm upgrade --install bandjacks ./helm/bandjacks \
          --namespace bandjacks \
          --create-namespace \
          --values ./helm/bandjacks/values-production.yaml \
          --set api.image.tag=${{ github.ref_name }} \
          --set ui.image.tag=${{ github.ref_name }} \
          --wait --timeout=15m
    
    - name: Run smoke tests
      run: |
        kubectl wait --for=condition=ready pod -l app=bandjacks-api -n bandjacks --timeout=300s
        kubectl wait --for=condition=ready pod -l app=bandjacks-ui -n bandjacks --timeout=300s
        
        # Run health checks
        API_ENDPOINT=$(kubectl get ingress bandjacks-ingress -n bandjacks -o jsonpath='{.spec.rules[0].host}')
        curl -f "https://${API_ENDPOINT}/health"
        
        UI_ENDPOINT=$(kubectl get ingress bandjacks-ingress -n bandjacks -o jsonpath='{.spec.rules[1].host}')
        curl -f "https://${UI_ENDPOINT}/"
```

## Monitoring & Observability

### **Prometheus Configuration**

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "bandjacks-rules.yml"

scrape_configs:
  - job_name: 'bandjacks-api'
    kubernetes_sd_configs:
    - role: endpoints
      namespaces:
        names:
        - bandjacks
    relabel_configs:
    - source_labels: [__meta_kubernetes_service_name]
      action: keep
      regex: bandjacks-api-service
    - source_labels: [__meta_kubernetes_endpoint_port_name]
      action: keep
      regex: http

  - job_name: 'neo4j'
    kubernetes_sd_configs:
    - role: endpoints
      namespaces:
        names:
        - bandjacks
    relabel_configs:
    - source_labels: [__meta_kubernetes_service_name]
      action: keep
      regex: neo4j-service
    - source_labels: [__meta_kubernetes_endpoint_port_name]
      action: keep
      regex: http

  - job_name: 'opensearch'
    kubernetes_sd_configs:
    - role: endpoints
      namespaces:
        names:
        - bandjacks
    relabel_configs:
    - source_labels: [__meta_kubernetes_service_name]
      action: keep
      regex: opensearch-service

alertmanager:
  alertmanagers:
  - static_configs:
    - targets:
      - alertmanager:9093
```

### **Alert Rules**

```yaml
# monitoring/bandjacks-rules.yml
groups:
- name: bandjacks-api
  rules:
  - alert: BandjacksAPIDown
    expr: up{job="bandjacks-api"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Bandjacks API is down"
      description: "Bandjacks API has been down for more than 1 minute."

  - alert: BandjacksAPIHighLatency
    expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job="bandjacks-api"}[5m])) > 1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Bandjacks API high latency"
      description: "95th percentile latency is {{ $value }}s"

  - alert: BandjacksAPIHighErrorRate
    expr: rate(http_requests_total{job="bandjacks-api",status=~"5.."}[5m]) / rate(http_requests_total{job="bandjacks-api"}[5m]) > 0.05
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Bandjacks API high error rate"
      description: "Error rate is {{ $value | humanizePercentage }}"

- name: bandjacks-data
  rules:
  - alert: Neo4jDown
    expr: up{job="neo4j"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Neo4j database is down"
      description: "Neo4j has been down for more than 1 minute."

  - alert: OpenSearchDown
    expr: up{job="opensearch"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "OpenSearch is down"
      description: "OpenSearch has been down for more than 1 minute."

  - alert: Neo4jHighMemoryUsage
    expr: (neo4j_database_heap_used_bytes / neo4j_database_heap_max_bytes) > 0.9
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Neo4j high memory usage"
      description: "Memory usage is {{ $value | humanizePercentage }}"
```

### **Grafana Dashboards**

```json
{
  "dashboard": {
    "title": "Bandjacks System Overview",
    "panels": [
      {
        "title": "API Request Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(rate(http_requests_total{job=\"bandjacks-api\"}[5m]))",
            "legendFormat": "Requests/sec"
          }
        ]
      },
      {
        "title": "API Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(http_request_duration_seconds_bucket{job=\"bandjacks-api\"}[5m]))",
            "legendFormat": "50th percentile"
          },
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{job=\"bandjacks-api\"}[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Database Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "neo4j_database_pool_total_size",
            "legendFormat": "Neo4j Pool Size"
          },
          {
            "expr": "opensearch_thread_pool_search_active",
            "legendFormat": "OpenSearch Active Threads"
          }
        ]
      },
      {
        "title": "Extraction Pipeline Metrics",
        "type": "table",
        "targets": [
          {
            "expr": "bandjacks_extractions_total",
            "legendFormat": "Total Extractions"
          },
          {
            "expr": "bandjacks_techniques_extracted_total",
            "legendFormat": "Techniques Extracted"
          },
          {
            "expr": "bandjacks_extraction_duration_seconds",
            "legendFormat": "Avg Duration"
          }
        ]
      }
    ]
  }
}
```

## Security Deployment

### **Network Security**

```yaml
# k8s/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: bandjacks-network-policy
  namespace: bandjacks
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8000  # API
    - protocol: TCP  
      port: 3000  # UI
  
  - from:
    - podSelector:
        matchLabels:
          app: bandjacks-api
    - podSelector:
        matchLabels:
          app: neo4j
    - podSelector:
        matchLabels:
          app: opensearch
    ports:
    - protocol: TCP
      port: 7687  # Neo4j Bolt
    - protocol: TCP
      port: 9200  # OpenSearch
    - protocol: TCP
      port: 6379  # Redis
  
  egress:
  - to: []  # Allow all egress (restrict in production)
    ports:
    - protocol: TCP
      port: 443  # HTTPS
    - protocol: TCP
      port: 53   # DNS
    - protocol: UDP
      port: 53   # DNS
```

### **Pod Security Standards**

```yaml
# k8s/pod-security-policy.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: bandjacks
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### **Secret Management**

```yaml
# k8s/sealed-secrets.yaml
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: bandjacks-secrets
  namespace: bandjacks
spec:
  encryptedData:
    NEO4J_PASSWORD: AgBy3i4OJSWK+PiTySYZZA9rO3xvI7zWGYHFK...
    OPENSEARCH_PASSWORD: AgBy3i4OJSWK+PiTySYZZA9rO3xvI7zWGYHFK...
    GOOGLE_API_KEY: AgBy3i4OJSWK+PiTySYZZA9rO3xvI7zWGYHFK...
    OPENAI_API_KEY: AgBy3i4OJSWK+PiTySYZZA9rO3xvI7zWGYHFK...
  template:
    metadata:
      name: bandjacks-secrets
      namespace: bandjacks
    type: Opaque
```

### **RBAC Configuration**

```yaml
# k8s/rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: bandjacks-api
  namespace: bandjacks
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bandjacks-api-role
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bandjacks-api-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: bandjacks-api-role
subjects:
- kind: ServiceAccount
  name: bandjacks-api
  namespace: bandjacks
```

## Scaling Strategies

### **Horizontal Pod Autoscaler**

```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: bandjacks-api-hpa
  namespace: bandjacks
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: bandjacks-api
  minReplicas: 5
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "30"
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
```

### **Vertical Pod Autoscaler**

```yaml
# k8s/vpa.yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: bandjacks-api-vpa
  namespace: bandjacks
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: bandjacks-api
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: api
      maxAllowed:
        cpu: 2
        memory: 4Gi
      minAllowed:
        cpu: 100m
        memory: 128Mi
      controlledResources: ["cpu", "memory"]
```

### **Cluster Autoscaler**

```yaml
# k8s/cluster-autoscaler.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cluster-autoscaler
  namespace: kube-system
spec:
  template:
    spec:
      containers:
      - image: k8s.gcr.io/autoscaling/cluster-autoscaler:v1.21.0
        name: cluster-autoscaler
        command:
        - ./cluster-autoscaler
        - --v=4
        - --stderrthreshold=info
        - --cloud-provider=aws
        - --skip-nodes-with-local-storage=false
        - --expander=least-waste
        - --node-group-auto-discovery=asg:tag=k8s.io/cluster-autoscaler/enabled,k8s.io/cluster-autoscaler/bandjacks-prod
        - --balance-similar-node-groups
        - --scale-down-enabled=true
        - --scale-down-delay-after-add=10m
        - --scale-down-unneeded-time=10m
        - --scale-down-utilization-threshold=0.5
```

## Disaster Recovery

### **Backup Strategy**

```bash
#!/bin/bash
# scripts/backup.sh

set -e

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
S3_BUCKET="bandjacks-backups-prod"

echo "🔄 Starting backup process - $BACKUP_DATE"

# Backup Neo4j
echo "💾 Backing up Neo4j..."
kubectl exec -n bandjacks neo4j-0 -- neo4j-admin database dump \
    --database=neo4j --to-path=/tmp/backup.dump

kubectl cp bandjacks/neo4j-0:/tmp/backup.dump \
    ./neo4j-backup-$BACKUP_DATE.dump

aws s3 cp ./neo4j-backup-$BACKUP_DATE.dump \
    s3://$S3_BUCKET/neo4j/neo4j-backup-$BACKUP_DATE.dump

# Backup OpenSearch
echo "🔍 Backing up OpenSearch..."
curl -X PUT "opensearch-service.bandjacks.svc.cluster.local:9200/_snapshot/s3-backups/snapshot-$BACKUP_DATE" \
    -H 'Content-Type: application/json' \
    -d '{"indices": "bandjacks_*", "ignore_unavailable": true}'

# Backup configuration
echo "⚙️  Backing up configuration..."
kubectl get all -n bandjacks -o yaml > k8s-config-$BACKUP_DATE.yaml
aws s3 cp ./k8s-config-$BACKUP_DATE.yaml \
    s3://$S3_BUCKET/config/k8s-config-$BACKUP_DATE.yaml

# Cleanup local files
rm -f ./neo4j-backup-$BACKUP_DATE.dump
rm -f ./k8s-config-$BACKUP_DATE.yaml

echo "✅ Backup completed - $BACKUP_DATE"
```

### **Recovery Procedure**

```bash
#!/bin/bash
# scripts/recovery.sh

set -e

BACKUP_DATE=${1:-latest}
S3_BUCKET="bandjacks-backups-prod"

echo "🔄 Starting recovery process - $BACKUP_DATE"

# Stop applications
echo "🛑 Stopping applications..."
kubectl scale deployment bandjacks-api --replicas=0 -n bandjacks
kubectl scale deployment bandjacks-ui --replicas=0 -n bandjacks

# Restore Neo4j
echo "💾 Restoring Neo4j..."
aws s3 cp s3://$S3_BUCKET/neo4j/neo4j-backup-$BACKUP_DATE.dump \
    ./neo4j-backup-$BACKUP_DATE.dump

kubectl cp ./neo4j-backup-$BACKUP_DATE.dump \
    bandjacks/neo4j-0:/tmp/restore.dump

kubectl exec -n bandjacks neo4j-0 -- neo4j-admin database load \
    --from-path=/tmp/restore.dump --overwrite-destination=true

# Restore OpenSearch  
echo "🔍 Restoring OpenSearch..."
curl -X POST "opensearch-service.bandjacks.svc.cluster.local:9200/_snapshot/s3-backups/snapshot-$BACKUP_DATE/_restore" \
    -H 'Content-Type: application/json' \
    -d '{"indices": "bandjacks_*", "ignore_unavailable": true}'

# Wait for recovery
echo "⏳ Waiting for data recovery..."
sleep 60

# Restart applications
echo "🚀 Restarting applications..."
kubectl scale deployment bandjacks-api --replicas=5 -n bandjacks
kubectl scale deployment bandjacks-ui --replicas=3 -n bandjacks

# Wait for pods to be ready
kubectl wait --for=condition=ready pod -l app=bandjacks-api -n bandjacks --timeout=300s
kubectl wait --for=condition=ready pod -l app=bandjacks-ui -n bandjacks --timeout=300s

# Health check
echo "🏥 Running health checks..."
API_HEALTH=$(kubectl exec -n bandjacks deployment/bandjacks-api -- curl -f http://localhost:8000/health)
if [[ "$API_HEALTH" == *"healthy"* ]]; then
    echo "✅ API health check passed"
else
    echo "❌ API health check failed"
    exit 1
fi

echo "✅ Recovery completed successfully"
```

## Conclusion

The Bandjacks deployment architecture provides **comprehensive support** for all deployment scenarios from development to production. Key strengths:

**Flexibility:**
- Multiple deployment patterns (local, cloud, edge)
- Container-first approach with Docker and Kubernetes
- Infrastructure as Code for reproducible deployments

**Scalability:**
- Horizontal and vertical pod autoscaling
- Cluster-level auto-scaling
- Performance-optimized resource allocation

**Reliability:**
- Comprehensive monitoring and alerting
- Automated backup and recovery procedures
- Zero-downtime deployment strategies

**Security:**
- Network policies and pod security standards
- Secret management with sealed secrets
- RBAC and service account configuration

The system successfully delivers **enterprise-grade deployment capabilities** while maintaining **developer productivity** and **operational excellence**.