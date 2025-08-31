# Bandjacks Backend Architecture

## Table of Contents
1. [Overview](#overview)
2. [FastAPI Application Structure](#fastapi-application-structure)
3. [Route Organization](#route-organization)
4. [LLM Processing Pipeline](#llm-processing-pipeline)
5. [Data Access Layer](#data-access-layer)
6. [Middleware Stack](#middleware-stack)
7. [Async Job Processing](#async-job-processing)
8. [Configuration Management](#configuration-management)
9. [Error Handling](#error-handling)
10. [Performance Optimization](#performance-optimization)

## Overview

The Bandjacks backend is built on **FastAPI**, a modern Python web framework designed for high-performance API development. The architecture follows a **layered approach** with clear separation of concerns across presentation, business logic, and data access layers.

### **Key Design Patterns**
- **Dependency Injection**: FastAPI's built-in DI for database connections and services
- **Repository Pattern**: Abstracted data access through store classes
- **Agent Pattern**: Specialized processing agents for different tasks
- **Factory Pattern**: Configuration and client creation
- **Observer Pattern**: Event-driven job processing

### **Technology Stack**
- **Framework**: FastAPI 0.116.1+ with Pydantic 2.5+ validation
- **Language**: Python 3.11+ with modern async/await patterns
- **Package Management**: UV for fast dependency resolution
- **LLM Integration**: LiteLLM for multi-provider abstraction
- **Database Drivers**: Neo4j Python driver, OpenSearch-py client
- **Processing**: Tenacity for retry logic, AIOLimiter for rate limiting

## FastAPI Application Structure

### **Application Bootstrap (`main.py`)**

```python
# Application Lifecycle
app = FastAPI(
    title="Bandjacks API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Middleware Stack (order matters)
app.add_middleware(ErrorHandlerMiddleware)      # Global error handling
app.add_middleware(RateLimitMiddleware)         # Rate limiting
app.add_middleware(JWTAuthMiddleware)           # Authentication  
app.add_middleware(TracingMiddleware)           # Request tracing
app.add_middleware(CORSMiddleware)              # Cross-origin requests

# Startup/Shutdown Events
@app.on_event("startup")
async def startup():
    ensure_ddl()                    # Neo4j schema
    ensure_opensearch_indices()     # OpenSearch indices
    start_job_processor()           # Background jobs

@app.on_event("shutdown")  
async def shutdown():
    stop_job_processor()            # Graceful shutdown
```

### **Directory Structure**
```
bandjacks/
├── services/
│   └── api/
│       ├── main.py                 # FastAPI app and configuration
│       ├── settings.py             # Environment-based configuration
│       ├── deps.py                 # Dependency injection setup
│       ├── middleware/             # Custom middleware
│       │   ├── auth.py            # JWT authentication
│       │   ├── rate_limit.py      # Rate limiting
│       │   ├── error_handler.py   # Global error handling
│       │   └── tracing.py         # Request tracing
│       ├── routes/                # API endpoint modules
│       └── job_processor.py       # Async job management
├── llm/                           # LLM processing pipeline
├── store/                         # Data access layer
├── loaders/                       # Database initialization
├── core/                          # Business logic
└── monitoring/                    # Observability
```

### **Dependency Injection Setup (`deps.py`)**

```python
# Database Dependencies
def get_neo4j_session() -> Session:
    """Neo4j session with automatic cleanup."""
    driver = get_neo4j_driver()
    session = driver.session()
    try:
        yield session
    finally:
        session.close()

def get_opensearch_client() -> OpenSearch:
    """OpenSearch client singleton."""
    return OpenSearch(
        hosts=[settings.opensearch_url],
        http_auth=(settings.opensearch_user, settings.opensearch_password),
        use_ssl=False,
        verify_certs=False
    )

# Service Dependencies
def get_llm_client() -> LLMClient:
    """LLM client with fallback configuration."""
    return LLMClient(
        primary_model="gemini-2.5-flash",
        fallback_model="gpt-4o-mini",
        cache_enabled=True
    )
```

## Route Organization

The API is organized into **30+ route modules**, each handling a specific functional domain:

### **Core API Routes**

| Module | Purpose | Key Endpoints | Dependencies |
|--------|---------|---------------|--------------|
| **catalog** | ATT&CK release management | `/catalog/attack/releases` | Neo4j |
| **stix_loader** | STIX bundle ingestion | `/stix/load/attack` | Neo4j, OpenSearch |
| **search** | Vector and text search | `/search/ttx` | OpenSearch |
| **reports** | Report ingestion/processing | `/reports/ingest*` | All systems |
| **unified_review** | Review decision submission | `/reports/{id}/unified-review` | All systems |

### **Analysis & Intelligence Routes**

| Module | Purpose | Key Endpoints | Dependencies |
|--------|---------|---------------|--------------|
| **extract** | Document extraction | `/extract/pdf` | LLM Pipeline |
| **mapper** | Text-to-ATT&CK mapping | `/mapper/text-to-techniques` | LLM, OpenSearch |
| **flows** | Attack flow generation | `/flows/build` | LLM, Neo4j |
| **sequence** | Attack sequence analysis | `/sequence/propose` | LLM, Neo4j |
| **attackflow** | STIX Attack Flow export | `/attackflow/export` | Neo4j |

### **Review & Feedback Routes**

| Module | Purpose | Key Endpoints | Dependencies |
|--------|---------|---------------|--------------|
| **review** | Legacy review decisions | `/review/mapping` | Neo4j |
| **entity_review** | Entity-specific review | `/entity-review/submit` | Neo4j, OpenSearch |
| **review_queue** | Candidate queue management | `/review-queue/candidates` | Neo4j |
| **candidates** | Review candidate workflow | `/candidates/submit` | Neo4j |
| **feedback** | User feedback collection | `/feedback/submit` | OpenSearch |

### **Analytics & Monitoring Routes**

| Module | Purpose | Key Endpoints | Dependencies |
|--------|---------|---------------|--------------|
| **analytics** | Coverage and gap analysis | `/analytics/coverage` | Neo4j |
| **provenance** | Object lineage tracking | `/provenance/trace` | Neo4j |
| **compliance** | ADM validation metrics | `/compliance/report` | Neo4j |
| **ml_metrics** | Model performance tracking | `/ml-metrics/accuracy` | OpenSearch |
| **drift** | Data drift detection | `/drift/detection` | All systems |

### **Route Module Template**

Each route module follows a consistent structure:

```python
# routes/example.py
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional

# Router configuration
router = APIRouter(prefix="/example", tags=["example"])

# Request/Response models
class ExampleRequest(BaseModel):
    field1: str
    field2: Optional[int] = None
    
class ExampleResponse(BaseModel):
    success: bool
    data: dict

# Endpoint implementation
@router.post("/process", response_model=ExampleResponse)
async def process_example(
    request: ExampleRequest,
    neo4j_session: Session = Depends(get_neo4j_session),
    os_client: OpenSearch = Depends(get_opensearch_client)
):
    """Process example with proper error handling."""
    try:
        # Business logic
        result = await process_business_logic(request)
        
        # Data persistence
        store_results(neo4j_session, result)
        
        return ExampleResponse(success=True, data=result)
        
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Processing failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
```

## LLM Processing Pipeline

The LLM pipeline is the core of the system's intelligence extraction capabilities, implemented as a series of specialized agents.

### **Pipeline Architecture**

```
Text Input → SpanFinderAgent → BatchRetrieverAgent → BatchMapperAgent → ConsolidatorAgent → Structured Output
     ↓              ↓                    ↓                   ↓                   ↓
  Chunking    Pattern Detection    Vector Search      LLM Verification    Deduplication
```

### **Agent Implementation**

#### **1. SpanFinderAgent (`llm/agents_v2.py`)**

**Purpose**: Identify potential technique indicators in text

```python
class SpanFinderAgent:
    def __init__(self):
        self.tactic_patterns = {
            'reconnaissance': [r'scann\w+', r'enum\w+', r'reconnaiss\w+'],
            'initial_access': [r'phish\w+', r'exploit\w+', r'deliver\w+'],
            'execution': [r'execut\w+', r'run\w+', r'launch\w+'],
            # ... more tactic patterns
        }
        
    async def find_spans(self, text: str, max_spans: int = 20) -> List[TechniqueSpan]:
        """Find technique-relevant text spans."""
        spans = []
        
        # Pattern-based detection
        for tactic, patterns in self.tactic_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    spans.append(TechniqueSpan(
                        text=match.group(),
                        start=match.start(),
                        end=match.end(),
                        tactic=tactic,
                        confidence=0.7
                    ))
        
        # Explicit technique ID detection
        technique_pattern = r'T\d{4}(?:\.\d{3})?'
        for match in re.finditer(technique_pattern, text):
            spans.append(TechniqueSpan(
                text=match.group(),
                start=match.start(),
                end=match.end(),
                technique_id=match.group(),
                confidence=0.95
            ))
            
        return spans[:max_spans]
```

#### **2. BatchRetrieverAgent (`llm/batch_retriever.py`)**

**Purpose**: Vector similarity search for candidate techniques

```python
class BatchRetrieverAgent:
    def __init__(self, os_client: OpenSearch):
        self.client = os_client
        self.index_name = "bandjacks_attack_nodes-v1"
        
    async def retrieve_candidates(
        self, 
        spans: List[TechniqueSpan], 
        top_k: int = 10
    ) -> Dict[str, List[AttackTechnique]]:
        """Retrieve candidate techniques for each span."""
        
        # Batch embed all span texts
        embeddings = await self.embed_texts([span.text for span in spans])
        
        # Batch search
        candidates = {}
        for span, embedding in zip(spans, embeddings):
            query = {
                "knn": {
                    "embedding": {
                        "vector": embedding,
                        "k": top_k
                    }
                },
                "_source": ["name", "description", "external_id", "kill_chain_phases"]
            }
            
            result = self.client.search(index=self.index_name, body=query)
            candidates[span.id] = [
                AttackTechnique(**hit["_source"]) 
                for hit in result["hits"]["hits"]
            ]
            
        return candidates
```

#### **3. BatchMapperAgent (`llm/mapper_optimized.py`)**

**Purpose**: LLM-based verification and final technique mapping

```python
class BatchMapperAgent:
    def __init__(self, llm_client: LLMClient):
        self.client = llm_client
        
    async def map_spans_to_techniques(
        self,
        spans: List[TechniqueSpan],
        candidates: Dict[str, List[AttackTechnique]],
        context: str
    ) -> List[TechniqueClaim]:
        """Use LLM to map spans to final techniques."""
        
        # Construct batch prompt
        prompt = self._build_batch_prompt(spans, candidates, context)
        
        # Single LLM call for all spans
        response = await self.client.complete(
            prompt=prompt,
            model="gemini-2.5-flash",
            temperature=0.1,
            max_tokens=2000
        )
        
        # Parse structured response
        claims = self._parse_llm_response(response, spans)
        
        return [claim for claim in claims if claim.confidence >= 0.5]
        
    def _build_batch_prompt(self, spans, candidates, context) -> str:
        """Build optimized batch processing prompt."""
        return f"""
        Analyze the following text spans and determine which MITRE ATT&CK techniques they represent:

        CONTEXT: {context[:500]}...

        SPANS AND CANDIDATES:
        {self._format_spans_and_candidates(spans, candidates)}

        For each span, provide:
        1. technique_id (from candidates or "NONE")
        2. confidence (0-100)
        3. reasoning (brief explanation)

        Format as JSON array.
        """
```

#### **4. ConsolidatorAgent (`llm/agents_v2.py`)**

**Purpose**: Deduplicate and merge technique claims

```python
class ConsolidatorAgent:
    def __init__(self):
        self.similarity_threshold = 0.8
        
    async def consolidate_claims(
        self, 
        claims: List[TechniqueClaim]
    ) -> List[TechniqueClaim]:
        """Merge duplicate technique claims."""
        
        # Group by technique ID
        technique_groups = {}
        for claim in claims:
            tid = claim.external_id
            if tid not in technique_groups:
                technique_groups[tid] = []
            technique_groups[tid].append(claim)
        
        consolidated = []
        for technique_id, group in technique_groups.items():
            if len(group) == 1:
                consolidated.append(group[0])
            else:
                # Merge multiple claims for same technique
                merged_claim = self._merge_claims(group)
                consolidated.append(merged_claim)
                
        return consolidated
        
    def _merge_claims(self, claims: List[TechniqueClaim]) -> TechniqueClaim:
        """Merge multiple claims for the same technique."""
        base_claim = claims[0]
        
        # Combine evidence
        all_quotes = []
        all_line_refs = []
        for claim in claims:
            all_quotes.extend(claim.quotes)
            all_line_refs.extend(claim.line_refs)
            
        # Average confidence
        avg_confidence = sum(c.confidence for c in claims) / len(claims)
        
        return TechniqueClaim(
            external_id=base_claim.external_id,
            name=base_claim.name,
            quotes=list(set(all_quotes)),
            line_refs=sorted(set(all_line_refs)),
            confidence=avg_confidence,
            source="consolidated"
        )
```

### **Pipeline Orchestration (`llm/extraction_pipeline.py`)**

```python
class ExtractionPipeline:
    def __init__(self):
        self.span_finder = SpanFinderAgent()
        self.retriever = BatchRetrieverAgent(get_opensearch_client())
        self.mapper = BatchMapperAgent(get_llm_client())
        self.consolidator = ConsolidatorAgent()
        
    async def extract_techniques(
        self, 
        text: str, 
        config: ExtractionConfig
    ) -> ExtractionResult:
        """Run complete extraction pipeline."""
        
        start_time = time.time()
        
        # Stage 1: Find potential technique spans
        logger.info("Starting span detection")
        spans = await self.span_finder.find_spans(
            text, 
            max_spans=config.max_spans
        )
        
        if not spans:
            return ExtractionResult(claims=[], metrics={})
            
        # Stage 2: Retrieve candidate techniques
        logger.info(f"Retrieving candidates for {len(spans)} spans")
        candidates = await self.retriever.retrieve_candidates(spans)
        
        # Stage 3: LLM verification and mapping
        logger.info("Starting LLM mapping")
        claims = await self.mapper.map_spans_to_techniques(
            spans, candidates, text
        )
        
        # Stage 4: Consolidate duplicate claims
        logger.info("Consolidating claims")
        final_claims = await self.consolidator.consolidate_claims(claims)
        
        # Calculate metrics
        metrics = {
            "extraction_time_ms": int((time.time() - start_time) * 1000),
            "spans_found": len(spans),
            "candidates_retrieved": sum(len(c) for c in candidates.values()),
            "claims_mapped": len(claims),
            "claims_consolidated": len(final_claims),
            "llm_calls": 1  # Batch processing
        }
        
        logger.info(f"Extraction complete: {len(final_claims)} techniques found")
        
        return ExtractionResult(
            claims=final_claims,
            metrics=metrics,
            spans=spans
        )
```

## Data Access Layer

The data access layer provides abstracted interfaces to the underlying storage systems.

### **Store Pattern Implementation**

#### **OpenSearch Report Store (`store/opensearch_report_store.py`)**

```python
class OpenSearchReportStore:
    def __init__(self, client: OpenSearch):
        self.client = client
        self.index_name = "bandjacks_reports"
        
    async def save_report(self, report: ReportDocument) -> str:
        """Save report with auto-generated ID."""
        doc_id = f"report--{uuid.uuid4()}"
        
        document = {
            "report_id": doc_id,
            "name": report.name,
            "content": report.content,
            "extraction": report.extraction.dict() if report.extraction else None,
            "status": report.status,
            "created": datetime.utcnow().isoformat(),
            "modified": datetime.utcnow().isoformat()
        }
        
        response = self.client.index(
            index=self.index_name,
            id=doc_id,
            body=document
        )
        
        return doc_id
        
    async def get_report(self, report_id: str) -> Optional[dict]:
        """Retrieve report by ID."""
        try:
            response = self.client.get(
                index=self.index_name,
                id=report_id
            )
            return response["_source"]
        except NotFoundError:
            return None
            
    async def update_report_status(
        self, 
        report_id: str, 
        status: str, 
        extraction_data: dict = None
    ):
        """Update report status and extraction data."""
        update_doc = {
            "doc": {
                "status": status,
                "modified": datetime.utcnow().isoformat()
            }
        }
        
        if extraction_data:
            update_doc["doc"]["extraction"] = extraction_data
            
        self.client.update(
            index=self.index_name,
            id=report_id,
            body=update_doc
        )
```

#### **Neo4j Graph Operations**

```python
class Neo4jGraphStore:
    def __init__(self, session: Session):
        self.session = session
        
    def create_attack_episode(
        self, 
        episode_id: str, 
        source_report: str, 
        actions: List[AttackAction]
    ):
        """Create attack episode with actions."""
        
        # Create episode node
        self.session.run("""
            MERGE (e:AttackEpisode {episode_id: $episode_id})
            SET e.source_ref = $source_report,
                e.created = datetime(),
                e.action_count = $action_count
        """, 
        episode_id=episode_id,
        source_report=source_report,
        action_count=len(actions)
        )
        
        # Create action nodes and relationships
        for i, action in enumerate(actions):
            self.session.run("""
                MATCH (e:AttackEpisode {episode_id: $episode_id})
                MERGE (a:AttackAction {action_id: $action_id})
                SET a.name = $name,
                    a.technique_ref = $technique_ref,
                    a.order = $order,
                    a.confidence = $confidence
                MERGE (e)-[:CONTAINS]->(a)
            """,
            episode_id=episode_id,
            action_id=action.action_id,
            name=action.name,
            technique_ref=action.technique_ref,
            order=i + 1,
            confidence=action.confidence
            )
            
        # Create NEXT relationships
        for i in range(len(actions) - 1):
            current_action = actions[i]
            next_action = actions[i + 1]
            probability = self._calculate_probability(current_action, next_action)
            
            self.session.run("""
                MATCH (a1:AttackAction {action_id: $action1_id})
                MATCH (a2:AttackAction {action_id: $action2_id})
                MERGE (a1)-[r:NEXT]->(a2)
                SET r.probability = $probability,
                    r.created = datetime()
            """,
            action1_id=current_action.action_id,
            action2_id=next_action.action_id,
            probability=probability
            )
```

## Middleware Stack

### **Error Handling Middleware (`middleware/error_handler.py`)**

```python
class ErrorHandlerMiddleware:
    def __init__(self, app):
        self.app = app
        
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
            
        try:
            await self.app(scope, receive, send)
        except HTTPException:
            # Let FastAPI handle HTTP exceptions
            raise
        except ValidationError as e:
            # Handle Pydantic validation errors
            response = JSONResponse(
                status_code=422,
                content={
                    "detail": "Validation error",
                    "errors": e.errors()
                }
            )
            await response(scope, receive, send)
        except Exception as e:
            # Handle unexpected errors
            logger.error(f"Unhandled exception: {e}", exc_info=True)
            response = JSONResponse(
                status_code=500,
                content={
                    "detail": "Internal server error",
                    "trace_id": get_trace_id()
                }
            )
            await response(scope, receive, send)
```

### **Rate Limiting Middleware (`middleware/rate_limit.py`)**

```python
class RateLimitMiddleware:
    def __init__(self, app, default_limit: int = 100):
        self.app = app
        self.limiter = AsyncLimiter(default_limit, 60)  # per minute
        
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
            
        client_id = self._get_client_id(scope)
        
        try:
            await self.limiter.acquire()
            await self.app(scope, receive, send)
        except RateLimitExceeded:
            response = JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": 60
                },
                headers={"Retry-After": "60"}
            )
            await response(scope, receive, send)
```

## Async Job Processing

### **Job Processor (`job_processor.py`)**

```python
class JobProcessor:
    def __init__(self):
        self.jobs: Dict[str, JobStatus] = {}
        self.worker_pool = asyncio.Queue(maxsize=4)
        self.running = False
        
    async def start(self):
        """Start background job processing."""
        self.running = True
        
        # Start worker tasks
        for i in range(4):
            task = asyncio.create_task(self._worker())
            await self.worker_pool.put(task)
            
    async def submit_job(
        self, 
        job_type: str, 
        job_data: dict
    ) -> str:
        """Submit async job for processing."""
        job_id = f"job-{uuid.uuid4()}"
        
        job_status = JobStatus(
            job_id=job_id,
            job_type=job_type,
            status="queued",
            created_at=datetime.utcnow(),
            data=job_data
        )
        
        self.jobs[job_id] = job_status
        
        # Add to processing queue
        await self._queue_job(job_status)
        
        return job_id
        
    async def _worker(self):
        """Background worker for job processing."""
        while self.running:
            try:
                job = await self._get_next_job()
                if job:
                    await self._process_job(job)
            except Exception as e:
                logger.error(f"Worker error: {e}")
            await asyncio.sleep(1)
            
    async def _process_job(self, job: JobStatus):
        """Process individual job."""
        job.status = "processing"
        job.started_at = datetime.utcnow()
        
        try:
            if job.job_type == "report_extraction":
                result = await self._process_report_extraction(job.data)
            elif job.job_type == "attack_flow_generation":
                result = await self._process_attack_flow(job.data)
            else:
                raise ValueError(f"Unknown job type: {job.job_type}")
                
            job.status = "completed"
            job.result = result
            job.completed_at = datetime.utcnow()
            
        except Exception as e:
            job.status = "failed"
            job.error = str(e)
            job.completed_at = datetime.utcnow()
            logger.error(f"Job {job.job_id} failed: {e}")
```

## Configuration Management

### **Settings (`settings.py`)**

```python
class Settings(BaseSettings):
    """Environment-based configuration."""
    
    # API Configuration
    api_prefix: str = "/v1"
    api_title: str = "Bandjacks API"
    
    # Database Configuration
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "neo4j"
    
    opensearch_url: str = "http://localhost:9200"
    opensearch_user: str = "admin"
    opensearch_password: str = "admin"
    
    # LLM Configuration  
    primary_llm: str = "gemini"
    google_api_key: str = ""
    openai_api_key: str = ""
    
    # Feature Flags
    enable_auth: bool = False
    rate_limit_enabled: bool = True
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8"
    )

settings = Settings()
```

## Error Handling

### **Exception Hierarchy**

```python
# Custom exceptions
class BandjacksException(Exception):
    """Base exception for Bandjacks."""
    pass

class ExtractionException(BandjacksException):
    """Extraction pipeline errors."""
    pass

class LLMException(BandjacksException):
    """LLM service errors."""
    pass

class ValidationException(BandjacksException):
    """Data validation errors."""
    pass

class StorageException(BandjacksException):
    """Database/storage errors."""
    pass
```

### **Error Response Format**

```python
class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None
    trace_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
# Usage in endpoints
@router.post("/example")
async def example_endpoint():
    try:
        # Business logic
        pass
    except ValidationException as e:
        raise HTTPException(
            status_code=400,
            detail=ErrorResponse(
                detail=str(e),
                error_code="VALIDATION_ERROR"
            ).dict()
        )
```

## Performance Optimization

### **Connection Pooling**

```python
# Neo4j connection pool
neo4j_driver = GraphDatabase.driver(
    settings.neo4j_uri,
    auth=(settings.neo4j_user, settings.neo4j_password),
    max_connection_lifetime=3600,
    max_connection_pool_size=50,
    connection_acquisition_timeout=60
)

# OpenSearch connection pool  
opensearch_client = OpenSearch(
    hosts=[settings.opensearch_url],
    http_auth=(settings.opensearch_user, settings.opensearch_password),
    use_ssl=False,
    verify_certs=False,
    connection_pool_size=20,
    timeout=30
)
```

### **Caching Strategy**

```python
from functools import lru_cache
import asyncio

# In-memory caching for frequently accessed data
@lru_cache(maxsize=1000)
def get_attack_technique(technique_id: str) -> Optional[AttackTechnique]:
    """Cache ATT&CK technique lookups."""
    pass

# Async cache for LLM responses
class AsyncLRUCache:
    def __init__(self, maxsize: int = 100):
        self.cache = {}
        self.maxsize = maxsize
        
    async def get_or_compute(self, key: str, compute_func):
        if key in self.cache:
            return self.cache[key]
            
        result = await compute_func()
        
        if len(self.cache) >= self.maxsize:
            # Remove oldest entry
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            
        self.cache[key] = result
        return result

llm_cache = AsyncLRUCache(maxsize=500)
```

### **Batch Processing Optimization**

```python
async def batch_process_items(items: List[Any], batch_size: int = 10):
    """Process items in batches to avoid overwhelming services."""
    results = []
    
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        batch_results = await asyncio.gather(*[
            process_item(item) for item in batch
        ])
        results.extend(batch_results)
        
        # Brief pause between batches
        await asyncio.sleep(0.1)
        
    return results
```

## Monitoring and Observability

### **Structured Logging**

```python
import logging
import json
from datetime import datetime

class StructuredLogger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        
    def info(self, message: str, **kwargs):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": "INFO",
            "message": message,
            "service": "bandjacks-api",
            **kwargs
        }
        self.logger.info(json.dumps(log_entry))
        
    def error(self, message: str, error: Exception = None, **kwargs):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": "ERROR",
            "message": message,
            "service": "bandjacks-api",
            **kwargs
        }
        
        if error:
            log_entry["error_type"] = type(error).__name__
            log_entry["error_message"] = str(error)
            
        self.logger.error(json.dumps(log_entry))
```

### **Performance Metrics**

```python
import time
from contextlib import asynccontextmanager

@asynccontextmanager
async def track_performance(operation: str):
    """Track operation performance."""
    start_time = time.time()
    try:
        yield
    finally:
        duration = time.time() - start_time
        logger.info(
            f"Performance metric",
            operation=operation,
            duration_ms=int(duration * 1000)
        )

# Usage
async def some_operation():
    async with track_performance("llm_extraction"):
        result = await llm_client.extract(text)
    return result
```

## Conclusion

The Bandjacks backend architecture provides a **robust, scalable foundation** for cyber threat intelligence processing. Key architectural strengths:

- **Modular Design**: Clear separation between API, business logic, and data layers
- **Async-First**: Non-blocking operations for high concurrency
- **Agent-Based Processing**: Specialized components for different tasks  
- **Standards Compliance**: STIX 2.1 and MITRE ATT&CK integration
- **Observability**: Comprehensive logging and error handling
- **Performance-Oriented**: Caching, connection pooling, and batch processing

The system successfully handles the complexity of threat intelligence extraction while maintaining **developer productivity** and **operational reliability**.