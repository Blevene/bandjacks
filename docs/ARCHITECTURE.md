# Bandjacks System Architecture

## Table of Contents
1. [System Overview](#system-overview)
2. [High-Level Architecture](#high-level-architecture)
3. [Technology Stack](#technology-stack)
4. [Core Components](#core-components)
5. [Design Principles](#design-principles)
6. [Data Flow](#data-flow)
7. [Scalability & Performance](#scalability--performance)
8. [Security Architecture](#security-architecture)
9. [Deployment Topology](#deployment-topology)
10. [Future Evolution](#future-evolution)

## System Overview

Bandjacks is a **Cyber Threat Defense World Modeling System** designed to transform unstructured threat intelligence reports into validated, structured knowledge graphs. The system combines advanced natural language processing, vector search, and human-in-the-loop validation to create comprehensive threat intelligence models.

### **Primary Capabilities**
- **Intelligence Ingestion**: Extract structured data from PDFs, text, and URLs
- **ATT&CK Mapping**: Map threat behaviors to MITRE ATT&CK framework
- **Attack Flow Generation**: Create temporal sequences of threat activities
- **Knowledge Graph**: Build comprehensive threat actor, malware, and technique relationships
- **Review & Validation**: Human analyst review and refinement of extractions
- **Defense Integration**: D3FEND ontology integration for defensive recommendations

### **Target Users**
- **Threat Intelligence Analysts**: Review and validate automated extractions
- **Security Researchers**: Explore threat patterns and relationships
- **Defense Teams**: Identify defensive gaps and recommendations
- **API Consumers**: Integrate threat intelligence into security tools

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Layer                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐│
│  │   Web UI         │  │   CLI Tools      │  │  API Clients     ││
│  │  (Next.js/React) │  │  (Python CLI)    │  │  (External)      ││
│  │  Port 3000       │  │  Batch Processing│  │  HTTP/REST       ││
│  └──────────────────┘  └──────────────────┘  └──────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
┌─────────────────────────────────────────────────────────────────┐
│                      API Gateway Layer                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────────┐│
│  │              FastAPI Application                             ││
│  │                   Port 8000                                  ││
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐ ││
│  │  │ Middleware  │ │   Router    │ │      Workers            │ ││
│  │  │ - CORS      │ │ 30+ Modules │ │ - Async Processing      │ ││
│  │  │ - Auth      │ │ - Reports   │ │ - Job Queue             │ ││
│  │  │ - Rate Limit│ │ - Review    │ │ - Background Tasks      │ ││
│  │  └─────────────┘ └─────────────┘ └─────────────────────────┘ ││
│  └──────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
┌─────────────────────────────────────────────────────────────────┐
│                    Processing Layer                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐│
│  │  LLM Pipeline    │  │  Vector Search   │  │ Attack Flow Gen  ││
│  │                  │  │                  │  │                  ││
│  │ ┌──────────────┐ │  │ ┌──────────────┐ │  │ ┌──────────────┐ ││
│  │ │SpanFinder    │ │  │ │OpenSearch KNN│ │  │ │Flow Builder  │ ││
│  │ │BatchRetriever│ │  │ │Embeddings    │ │  │ │LLM Synthesis │ ││
│  │ │BatchMapper   │ │  │ │Similarity    │ │  │ │Probabilistic │ ││
│  │ │Consolidator  │ │  │ │Search        │ │  │ │Edges         │ ││
│  │ └──────────────┘ │  │ └──────────────┘ │  │ └──────────────┘ ││
│  └──────────────────┘  └──────────────────┘  └──────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
┌─────────────────────────────────────────────────────────────────┐
│                      Data Layer                                │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐│
│  │     Neo4j        │  │    OpenSearch    │  │    File Store    ││
│  │  Port 7687/7474  │  │   Port 9200      │  │                  ││
│  │                  │  │                  │  │                  ││
│  │ ┌──────────────┐ │  │ ┌──────────────┐ │  │ ┌──────────────┐ ││
│  │ │Graph Database│ │  │ │Vector Store  │ │  │ │PDF Storage   │ ││
│  │ │STIX 2.1 Data │ │  │ │Report Index  │ │  │ │Temp Files    │ ││
│  │ │ATT&CK Nodes  │ │  │ │Embeddings    │ │  │ │Upload Buffer │ ││
│  │ │Relationships │ │  │ │Search Index  │ │  │ └──────────────┘ ││
│  │ └──────────────┘ │  │ └──────────────┘ │  │                  ││
│  └──────────────────┘  └──────────────────┘  └──────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Technology Stack

### **Backend Technologies**
| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **API Framework** | FastAPI | 0.116.1+ | High-performance async REST API |
| **Language** | Python | 3.11+ | Core application language |
| **Package Manager** | UV | Latest | Fast Python dependency management |
| **LLM Integration** | LiteLLM | 1.0.0+ | Multi-provider LLM abstraction |
| **Primary LLM** | Google Gemini | 2.5-flash | Main extraction model |
| **Fallback LLM** | OpenAI GPT-4o | Latest | Backup extraction model |
| **Vector Search** | OpenSearch | 2.11.0 | Vector embeddings and search |
| **Graph Database** | Neo4j | 5.x | Knowledge graph storage |
| **Embeddings** | Sentence-Transformers | 5.1.0+ | Text-to-vector encoding |
| **PDF Processing** | PDFPlumber | 0.11.7+ | High-quality text extraction |

### **Frontend Technologies**
| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Framework** | Next.js | 15.5.0 | React-based web framework |
| **Language** | TypeScript | 5.x | Type-safe JavaScript |
| **UI Library** | React | 19.1.0 | Component framework |
| **Styling** | Tailwind CSS | 4.x | Utility-first CSS |
| **Components** | Radix UI | Latest | Accessible UI components |
| **State Management** | TanStack Query | 5.85.5+ | Server state management |
| **API Client** | OpenAPI-TS | 7.9.1+ | Type-safe API client generation |
| **Visualization** | React Flow | 11.11.4+ | Graph visualization |
| **Charts** | Recharts | 3.1.2+ | Data visualization |

### **Infrastructure Technologies**
| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Containerization** | Docker | Latest | Service containerization |
| **Orchestration** | Docker Compose | Latest | Multi-service deployment |
| **Process Manager** | Uvicorn | 0.35.0+ | ASGI server with workers |
| **Caching** | Redis | 6.4.0+ | Response caching (optional) |
| **Monitoring** | Structured Logging | Built-in | Application observability |

## Core Components

### **1. API Gateway (FastAPI Application)**

**Responsibilities:**
- HTTP request routing and validation
- Authentication and authorization
- Rate limiting and CORS handling
- Request/response transformation
- API documentation generation

**Key Features:**
- **30+ Route Modules**: Organized by functional domain
- **OpenAPI 3.0**: Auto-generated documentation
- **Async Processing**: Non-blocking I/O operations
- **Middleware Stack**: Pluggable request/response processing
- **Worker Pool**: 4-worker configuration for concurrency

### **2. LLM Processing Pipeline**

**Agent Architecture:**
```
Text Input → SpanFinderAgent → BatchRetrieverAgent → BatchMapperAgent → ConsolidatorAgent → Structured Output
```

**Components:**
- **SpanFinder**: Pattern-based technique detection
- **BatchRetriever**: Vector similarity search
- **BatchMapper**: LLM verification and extraction
- **Consolidator**: Deduplication and evidence merging

**Capabilities:**
- **Multi-Model Support**: Gemini primary, GPT-4 fallback
- **Chunked Processing**: Handles large documents (15KB+)
- **Batch Operations**: Efficient API usage
- **Evidence Tracking**: Source text provenance

### **3. Knowledge Graph (Neo4j)**

**Schema Design:**
- **STIX 2.1 Compliant**: Standards-based threat intelligence
- **MITRE ATT&CK**: Complete technique and tactic coverage
- **Attack Flows**: Temporal sequences with probabilities
- **Entity Relationships**: Threat actors, malware, campaigns

**Performance Characteristics:**
- **Graph Traversal**: Optimized for relationship queries
- **Bulk Import**: Efficient STIX bundle loading
- **Index Strategy**: Property-based query optimization

### **4. Vector Search (OpenSearch)**

**Index Strategy:**
```
bandjacks_attack_nodes-v1     # ATT&CK technique embeddings
bandjacks_reports             # Report storage and search
bandjacks_flows               # Attack flow sequences
```

**Vector Configuration:**
- **Dimensions**: 768 (sentence-transformers)
- **Algorithm**: HNSW for fast approximate search
- **Similarity**: Cosine similarity
- **Performance**: <300ms P95 for top-10 results

### **5. Review System (Unified Interface)**

**Architecture Pattern:**
- **Universal Data Model**: Single `ReviewableItem` interface
- **Atomic Operations**: All decisions in single transaction
- **Evidence-Based**: Direct links to source text
- **Progressive Enhancement**: Keyboard shortcuts and bulk operations

**Component Stack:**
```
Review Page → Unified Review Component → Item Cards → Decision Collection → API Submission
```

## Design Principles

### **1. Evidence-Based Architecture**
- **Provenance Tracking**: Every extraction linked to source text
- **Line References**: Precise source location tracking
- **Confidence Scoring**: Probabilistic assessment of extractions
- **Human Validation**: Analyst review of all automated decisions

### **2. Scalable Processing**
- **Async-First Design**: Non-blocking operations throughout
- **Chunked Processing**: Large document handling without timeouts
- **Batch Operations**: Efficient LLM API usage
- **Caching Strategy**: Reduce redundant computations

### **3. Standards Compliance**
- **STIX 2.1**: Industry-standard threat intelligence format
- **MITRE ATT&CK**: Official technique taxonomy
- **ADM Validation**: ATT&CK Data Model compliance
- **OpenAPI 3.0**: Standardized API documentation

### **4. Human-Centric Design**
- **Review-First Workflow**: Human validation of AI extractions
- **Progressive Disclosure**: Information revealed as needed
- **Keyboard Navigation**: Efficient analyst workflows
- **Error Recovery**: Graceful handling of edge cases

### **5. Defensive Security Focus**
- **No IOC Management**: Focus on behaviors, not indicators
- **Threat-Centric**: Analysis of adversary techniques
- **Defense Integration**: D3FEND ontology mapping
- **Gap Analysis**: Coverage assessment and recommendations

## Data Flow

### **1. Report Ingestion Flow**
```
PDF/Text Upload → Size Check → Sync/Async Routing → Text Extraction → Chunking → Processing Pipeline
```

### **2. Extraction Pipeline Flow**
```
Text Chunks → Span Detection → Vector Retrieval → LLM Mapping → Evidence Consolidation → STIX Generation
```

### **3. Review Process Flow**
```
Extraction Results → Review Interface → Analyst Decisions → Atomic Update → Graph Creation → Report Completion
```

### **4. Search and Retrieval Flow**
```
User Query → Vector Encoding → Similarity Search → Graph Traversal → Result Ranking → Response Assembly
```

## Scalability & Performance

### **Performance Targets**
| Operation | Target | Current |
|-----------|--------|---------|
| Document Processing | <60s for 15KB PDF | ~30-45s |
| Vector Search | <300ms P95 | ~150ms |
| Review Submission | <5s | ~3s |
| Graph Traversal | <1s for 3-hop | ~500ms |
| API Response | <100ms median | ~75ms |

### **Scaling Strategies**

**Horizontal Scaling:**
- **Stateless API**: Multiple FastAPI instances
- **Worker Pools**: Parallel document processing
- **Database Sharding**: Partition by data type
- **CDN Integration**: Static asset distribution

**Vertical Scaling:**
- **Memory Optimization**: Efficient data structures
- **CPU Utilization**: Multi-core processing
- **I/O Optimization**: Async operations
- **Cache Strategy**: Multiple cache layers

**Bottleneck Analysis:**
- **LLM API Calls**: Primary constraint (~80% of processing time)
- **Vector Similarity**: Secondary constraint (~15% of processing time)
- **Database Writes**: Minimal constraint (~5% of processing time)

## Security Architecture

### **Authentication & Authorization**
- **JWT Tokens**: Stateless authentication (planned)
- **OIDC Integration**: Enterprise identity provider support
- **Role-Based Access**: Analyst, admin, read-only roles
- **API Key Management**: Service-to-service authentication

### **Data Protection**
- **Input Validation**: Pydantic schema validation
- **SQL Injection**: Parameterized queries only
- **XSS Prevention**: Content Security Policy
- **File Upload**: Size limits and type validation

### **Network Security**
- **HTTPS Only**: TLS encryption for all traffic
- **CORS Policy**: Restricted origin access
- **Rate Limiting**: DoS protection
- **Internal Communication**: Service mesh patterns

### **Audit & Compliance**
- **Action Logging**: Comprehensive audit trail
- **Data Retention**: Configurable retention policies
- **Privacy Controls**: Data anonymization options
- **Export Controls**: STIX-compliant data export

## Deployment Topology

### **Development Environment**
```
Developer Machine
├── UI (npm run dev) → localhost:3000
├── API (uvicorn) → localhost:8000
├── Neo4j (docker) → localhost:7687/7474
├── OpenSearch (docker) → localhost:9200
└── Dashboards (docker) → localhost:5601
```

### **Production Environment (Recommended)**
```
Load Balancer
├── UI Cluster (Next.js)
│   ├── Static Assets → CDN
│   └── API Proxy → Backend
├── API Cluster (FastAPI)
│   ├── Multiple Workers
│   ├── Health Checks
│   └── Auto Scaling
├── Data Tier
│   ├── Neo4j Cluster (Primary/Replica)
│   ├── OpenSearch Cluster (3+ nodes)
│   └── Redis Cluster (Caching)
└── Monitoring
    ├── Logs → ELK Stack
    ├── Metrics → Prometheus
    └── Alerts → PagerDuty
```

### **Deployment Patterns**
- **Blue-Green**: Zero-downtime deployments
- **Rolling Updates**: Gradual service updates
- **Feature Flags**: Progressive feature rollout
- **Circuit Breakers**: Fault tolerance patterns

## Future Evolution

### **Short-Term Enhancements (3-6 months)**
- **Advanced Analytics**: Coverage gap analysis
- **ML Integration**: Improved extraction accuracy
- **Performance Optimization**: Sub-second search responses
- **Enhanced Review**: Collaborative review workflows

### **Medium-Term Evolution (6-12 months)**
- **Multi-Tenant Architecture**: Organization isolation
- **Real-Time Processing**: Streaming data ingestion
- **Advanced Visualization**: Interactive graph exploration
- **API Versioning**: Backward-compatible evolution

### **Long-Term Vision (1-2 years)**
- **Federated Learning**: Cross-organization model training
- **Automated Decision Making**: High-confidence auto-approval
- **Threat Hunting**: Proactive threat discovery
- **Integration Ecosystem**: Broad security tool integration

### **Technology Evolution**
- **Cloud-Native**: Kubernetes orchestration
- **Microservices**: Service decomposition
- **Event Sourcing**: Audit-first architecture
- **GraphQL**: Flexible API evolution

## Architectural Decision Records

### **ADR-001: FastAPI over Django**
**Decision**: Use FastAPI for API framework
**Rationale**: Superior async performance, automatic OpenAPI generation, modern Python features
**Trade-offs**: Smaller ecosystem vs. Django's maturity

### **ADR-002: Neo4j over PostgreSQL**
**Decision**: Use Neo4j for primary data storage
**Rationale**: Natural graph relationships, optimized traversal, STIX compatibility
**Trade-offs**: Higher complexity vs. relational familiarity

### **ADR-003: Next.js over SPA Framework**
**Decision**: Use Next.js for frontend
**Rationale**: SSR capabilities, API integration, TypeScript support
**Trade-offs**: Framework lock-in vs. flexibility

### **ADR-004: OpenSearch over Elasticsearch**
**Decision**: Use OpenSearch for vector search
**Rationale**: Open source, cost-effective, feature parity
**Trade-offs**: Smaller community vs. Elasticsearch ecosystem

## Conclusion

The Bandjacks architecture is designed for **scalability**, **maintainability**, and **extensibility**. The system successfully balances **automation efficiency** with **human expertise**, creating a robust platform for threat intelligence analysis.

Key architectural strengths:
- **Modular Design**: Clear separation of concerns
- **Standards Compliance**: Industry-standard formats and protocols
- **Evidence-Based**: Transparent and auditable processing
- **Human-Centric**: Optimized for analyst workflows
- **Performance-Oriented**: Sub-second response times for critical operations

The architecture supports the system's primary goal: transforming unstructured threat intelligence into actionable, validated knowledge while maintaining human oversight and quality assurance.