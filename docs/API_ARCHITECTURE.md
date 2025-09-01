# Bandjacks API Architecture

## Table of Contents
1. [Overview](#overview)
2. [API Design Principles](#api-design-principles)
3. [REST API Structure](#rest-api-structure)
4. [Route Organization](#route-organization)
5. [Authentication & Authorization](#authentication--authorization)
6. [Request/Response Patterns](#requestresponse-patterns)
7. [Error Handling](#error-handling)
8. [Rate Limiting](#rate-limiting)
9. [API Versioning](#api-versioning)
10. [Documentation & Testing](#documentation--testing)

## Overview

The Bandjacks API is built with **FastAPI** and follows **RESTful principles** while providing specialized endpoints for cyber threat intelligence operations. The API serves as the primary interface between the frontend application, external integrations, and the underlying data processing systems.

### **Key Characteristics**
- **RESTful Design**: Resource-based URLs with standard HTTP methods
- **OpenAPI 3.0 Compliant**: Auto-generated documentation and client SDKs
- **Async-First**: Non-blocking operations for high concurrency
- **Type-Safe**: Full Pydantic validation for requests and responses
- **Standards-Based**: STIX 2.1 and MITRE ATT&CK integration

### **API Metrics**
- **30+ Route Modules**: Organized by functional domain
- **100+ Endpoints**: Comprehensive CTI operations coverage
- **Sub-second Response**: <100ms median response time
- **High Availability**: 99.9% uptime SLA target

## API Design Principles

### **1. Resource-Oriented Design**
```
/v1/reports                    # Collection of reports
/v1/reports/{id}              # Specific report
/v1/reports/{id}/review       # Review sub-resource
/v1/reports/{id}/flows        # Flow sub-resource
```

### **2. HTTP Method Semantics**
```
GET     /v1/reports           # List reports
POST    /v1/reports           # Create report
GET     /v1/reports/{id}      # Get specific report
PUT     /v1/reports/{id}      # Update entire report
PATCH   /v1/reports/{id}      # Partial update
DELETE  /v1/reports/{id}      # Delete report
```

### **3. Consistent Response Structure**
```json
{
  "success": true,
  "data": { /* resource data */ },
  "metadata": {
    "timestamp": "2025-08-31T10:00:00Z",
    "version": "1.0.0",
    "request_id": "req-123"
  },
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 156,
    "has_next": true
  }
}
```

### **4. Error Response Format**
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input parameters",
    "details": [
      {
        "field": "confidence",
        "message": "Value must be between 0 and 100"
      }
    ],
    "trace_id": "trace-abc123"
  }
}
```

## REST API Structure

### **Base URL Structure**
```
Production:  https://api.bandjacks.io/v1
Staging:     https://staging-api.bandjacks.io/v1  
Development: http://localhost:8000/v1
```

### **Resource Hierarchy**
```
/v1/
├── catalog/                  # ATT&CK catalog management
│   └── attack/
│       └── releases         # Available ATT&CK releases
├── stix/                    # STIX data operations
│   ├── load/
│   │   └── attack          # Load ATT&CK data
│   └── bundles             # STIX bundle operations
├── search/                  # Search operations
│   ├── ttx                 # Text-to-technique search
│   └── flows               # Attack flow search
├── reports/                 # Report management
│   ├── ingest              # Synchronous ingestion
│   ├── ingest_async        # Asynchronous ingestion
│   ├── jobs/               # Job status tracking
│   └── {id}/               # Report-specific operations
│       ├── review          # Legacy review interface
│       ├── unified-review  # Unified review system
│       └── flows           # Attack flow visualization
├── query/                   # Natural language queries
├── graph/                   # Graph traversal operations
├── flows/                   # Attack flow generation
├── defense/                 # Defensive recommendations
├── analytics/               # Coverage and gap analysis
└── admin/                   # Administrative operations
```

## Route Organization

### **Core Data Management Routes**

#### **Catalog Routes (`/v1/catalog/`)**
```python
GET  /catalog/attack/releases
# List available MITRE ATT&CK releases
# Response: Array of release metadata

GET  /catalog/attack/releases/{collection}
# Get specific collection details
# Response: Collection metadata with techniques count

POST /catalog/attack/releases/{collection}/refresh
# Refresh collection from upstream
# Response: Refresh job details
```

#### **STIX Loader Routes (`/v1/stix/`)**
```python
POST /stix/load/attack
# Load ATT&CK release into system
# Params: collection, version, adm_strict
# Response: Load job status

POST /stix/bundles
# Import custom STIX bundles  
# Params: strict validation flag
# Response: Import results with validation errors

GET  /stix/bundles/{bundle_id}
# Retrieve imported bundle
# Response: STIX bundle object
```

### **Search & Discovery Routes**

#### **Search Routes (`/v1/search/`)**
```python
POST /search/ttx
# Text-to-ATT&CK technique search
# Request: { "text": "spearphishing email", "top_k": 10 }
# Response: Array of candidate techniques with scores

POST /search/flows
# Find similar attack flows
# Request: { "techniques": ["T1566.001", "T1059.001"], "similarity_threshold": 0.8 }
# Response: Array of matching flows with similarity scores

POST /search/entities
# Search for threat entities
# Request: { "query": "APT29", "entity_types": ["threat-actor"] }
# Response: Array of matching entities
```

#### **Query Routes (`/v1/query/`)**
```python  
POST /query/natural-language
# Natural language query interface
# Request: { "query": "What techniques does APT29 use for initial access?" }
# Response: Structured query results with explanations

POST /query/graph
# Cypher-like graph queries
# Request: { "query": "MATCH (ta:ThreatActor)-[:USES]->(t:Technique) RETURN ta.name, t.name" }
# Response: Graph query results
```

### **Processing & Analysis Routes**

#### **Extract Routes (`/v1/extract/`)**
```python
POST /extract/pdf
# Extract techniques from PDF document
# Request: Multipart file upload
# Response: Extraction results with techniques and confidence

POST /extract/text  
# Extract techniques from text
# Request: { "text": "...", "config": { "confidence_threshold": 50 } }
# Response: Extraction results

POST /extract/url
# Extract techniques from URL content  
# Request: { "url": "https://...", "config": {} }
# Response: Extraction job ID for async processing
```

#### **Flow Routes (`/v1/flows/`)**
```python
POST /flows/build
# Generate attack flow from techniques
# Request: { "techniques": [...], "source_id": "report-123" }
# Response: Generated attack flow with sequence

GET  /flows/{flow_id}
# Retrieve attack flow details
# Response: Flow object with steps and edges

POST /flows/{flow_id}/export
# Export flow to STIX format
# Response: STIX Attack Flow object

GET  /flows/{flow_id}/similar
# Find flows similar to given flow
# Response: Array of similar flows with scores
```

### **Review & Feedback Routes**

#### **Unified Review Routes (`/v1/reports/{id}/`)**
```python
POST /reports/{id}/unified-review
# Submit comprehensive review decisions
# Request: {
#   "reviewer_id": "user-123",
#   "decisions": [
#     {
#       "item_id": "entity-malware-0",
#       "action": "approve",
#       "timestamp": "2025-08-31T10:00:00Z"
#     }
#   ],
#   "global_notes": "Review completed",
#   "review_timestamp": "2025-08-31T10:05:00Z"
# }
# Response: {
#   "success": true,
#   "items_reviewed": 25,
#   "items_approved": 18,
#   "items_rejected": 4,
#   "items_edited": 3
# }

GET  /reports/{id}/review-status
# Get review progress status
# Response: Review statistics and completion percentage
```

#### **Legacy Review Routes (`/v1/review/`)**
```python
POST /review/mapping
# Submit technique mapping decisions
# Request: Array of mapping decisions
# Response: Update confirmation

POST /review/flowedge  
# Review attack flow edge decisions
# Request: Edge validation results
# Response: Flow update status
```

### **Analytics & Monitoring Routes**

#### **Analytics Routes (`/v1/analytics/`)**
```python
GET  /analytics/coverage
# Get technique coverage analysis
# Params: tactics, platforms, data_sources
# Response: Coverage statistics and gaps

GET  /analytics/statistics
# System performance statistics
# Response: Processing metrics and system health

POST /analytics/gaps
# Identify coverage gaps
# Request: { "scope": "enterprise", "tactics": ["initial-access"] }
# Response: Gap analysis with recommendations
```

#### **Provenance Routes (`/v1/provenance/`)**  
```python
GET  /provenance/trace/{object_id}
# Trace object lineage and sources
# Response: Provenance chain with timestamps

POST /provenance/validate
# Validate data integrity
# Request: Object IDs to validate
# Response: Integrity check results
```

## Authentication & Authorization

### **Authentication Strategies**

#### **Development Mode**
```python
# No authentication required
@app.middleware("http")
async def dev_mode_middleware(request: Request, call_next):
    # Allow all requests in development
    response = await call_next(request)
    return response
```

#### **JWT Authentication (Production)**
```python
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer
import jwt

security = HTTPBearer()

async def get_current_user(token: str = Depends(security)):
    """Extract and validate JWT token."""
    try:
        payload = jwt.decode(
            token.credentials, 
            settings.jwt_secret, 
            algorithms=[settings.jwt_algorithm]
        )
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return User(id=user_id, **payload)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
```

### **Authorization Patterns**

#### **Role-Based Access Control**
```python
from enum import Enum
from functools import wraps

class Role(Enum):
    ADMIN = "admin"
    ANALYST = "analyst" 
    REVIEWER = "reviewer"
    READ_ONLY = "read_only"

def require_role(required_role: Role):
    """Decorator to enforce role-based access."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, user: User = Depends(get_current_user), **kwargs):
            if user.role not in get_authorized_roles(required_role):
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return await func(*args, user=user, **kwargs)
        return wrapper
    return decorator

# Usage example
@router.post("/admin/reset-system")
@require_role(Role.ADMIN)
async def reset_system(user: User = Depends()):
    """Administrative system reset."""
    pass
```

#### **Resource-Based Permissions**
```python
async def check_report_access(report_id: str, user: User, action: str):
    """Check if user can perform action on report."""
    report = await get_report(report_id)
    
    if action == "read":
        # All authenticated users can read
        return True
    elif action == "review":
        # Only reviewers and above
        return user.role in [Role.REVIEWER, Role.ANALYST, Role.ADMIN]
    elif action == "delete":
        # Only admin or report owner
        return user.role == Role.ADMIN or report.created_by == user.id
    
    return False
```

### **API Key Authentication**
```python
async def verify_api_key(api_key: str = Header(None)):
    """Verify API key for service-to-service calls."""
    if not api_key:
        raise HTTPException(status_code=401, detail="API key required")
    
    # Hash and compare with stored keys
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    if key_hash not in settings.valid_api_keys:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    return ServiceAccount(api_key=key_hash)
```

## Request/Response Patterns

### **Request Validation**

#### **Pydantic Models**
```python
from pydantic import BaseModel, Field, validator
from typing import List, Optional
from datetime import datetime

class TechniqueExtractionRequest(BaseModel):
    """Request model for technique extraction."""
    
    text: str = Field(..., min_length=10, max_length=100000)
    confidence_threshold: float = Field(50.0, ge=0, le=100)
    max_techniques: int = Field(20, ge=1, le=100)
    include_evidence: bool = Field(True)
    config: Optional[dict] = Field(default_factory=dict)
    
    @validator('text')
    def validate_text_content(cls, v):
        if not v.strip():
            raise ValueError('Text cannot be empty')
        return v.strip()
    
    @validator('config')
    def validate_config(cls, v):
        allowed_keys = {'chunk_size', 'max_chunks', 'use_batch_mapper'}
        if not set(v.keys()).issubset(allowed_keys):
            raise ValueError(f'Config keys must be subset of {allowed_keys}')
        return v

class TechniqueExtractionResponse(BaseModel):
    """Response model for technique extraction."""
    
    success: bool
    techniques_count: int
    claims: List[TechniqueClaim]
    confidence_avg: float
    extraction_time_ms: int
    metadata: dict
    
    class Config:
        schema_extra = {
            "example": {
                "success": True,
                "techniques_count": 5,
                "claims": [
                    {
                        "external_id": "T1566.001",
                        "name": "Spearphishing Attachment",
                        "confidence": 92.0,
                        "quotes": ["malicious email attachments"],
                        "line_refs": [45, 46]
                    }
                ],
                "confidence_avg": 87.5,
                "extraction_time_ms": 2340,
                "metadata": {
                    "chunks_processed": 3,
                    "llm_calls": 1
                }
            }
        }
```

#### **Custom Validators**
```python
def validate_technique_id(technique_id: str) -> str:
    """Validate MITRE ATT&CK technique ID format."""
    import re
    pattern = r'^T\d{4}(?:\.\d{3})?$'
    if not re.match(pattern, technique_id):
        raise ValueError(f'Invalid technique ID format: {technique_id}')
    return technique_id

def validate_stix_id(stix_id: str) -> str:
    """Validate STIX ID format."""
    if not stix_id.count('--') == 1:
        raise ValueError('STIX ID must contain exactly one double dash')
    
    object_type, uuid_part = stix_id.split('--')
    if object_type not in VALID_STIX_TYPES:
        raise ValueError(f'Invalid STIX object type: {object_type}')
    
    # Validate UUID format
    try:
        import uuid
        uuid.UUID(uuid_part)
    except ValueError:
        raise ValueError('Invalid UUID in STIX ID')
    
    return stix_id
```

### **Response Formatting**

#### **Success Response Builder**
```python
def build_success_response(
    data: Any,
    message: str = "Success",
    metadata: dict = None,
    pagination: dict = None
) -> dict:
    """Build standardized success response."""
    response = {
        "success": True,
        "data": data,
        "message": message,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "version": settings.api_version,
            **(metadata or {})
        }
    }
    
    if pagination:
        response["pagination"] = pagination
    
    return response
```

#### **Pagination Pattern**
```python
from fastapi import Query

async def paginate_results(
    query_func,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100)
) -> dict:
    """Standard pagination implementation."""
    
    offset = (page - 1) * limit
    
    # Get total count
    total = await count_func()
    
    # Get page results
    results = await query_func(offset=offset, limit=limit)
    
    return build_success_response(
        data=results,
        pagination={
            "page": page,
            "limit": limit,
            "total": total,
            "pages": math.ceil(total / limit),
            "has_next": offset + limit < total,
            "has_prev": page > 1
        }
    )
```

### **File Upload Handling**
```python
from fastapi import UploadFile, File, Form
from typing import Optional

@router.post("/reports/upload")
async def upload_report(
    file: UploadFile = File(...),
    name: Optional[str] = Form(None),
    config: Optional[str] = Form(None)  # JSON string
):
    """Handle file upload with validation."""
    
    # Validate file type
    if file.content_type not in ['application/pdf', 'text/plain']:
        raise HTTPException(
            status_code=400, 
            detail="Only PDF and text files are supported"
        )
    
    # Validate file size
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(
            status_code=400,
            detail="File size exceeds 10MB limit"
        )
    
    # Parse config if provided
    extraction_config = {}
    if config:
        try:
            extraction_config = json.loads(config)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=400,
                detail="Invalid JSON in config parameter"
            )
    
    # Route to sync or async processing
    if len(content) > 5000:  # 5KB threshold
        # Async processing
        job_id = await process_file_async(content, name, extraction_config)
        return {"job_id": job_id, "status": "queued"}
    else:
        # Sync processing
        result = await process_file_sync(content, name, extraction_config)
        return build_success_response(result)
```

## Error Handling

### **Exception Hierarchy**
```python
class BandjacksException(Exception):
    """Base exception for all Bandjacks errors."""
    
    def __init__(self, message: str, code: str = None, details: dict = None):
        self.message = message
        self.code = code or self.__class__.__name__.upper()
        self.details = details or {}
        super().__init__(message)

class ValidationException(BandjacksException):
    """Request validation errors."""
    pass

class ProcessingException(BandjacksException):
    """Data processing errors."""
    pass

class ExternalServiceException(BandjacksException):
    """External service integration errors."""
    pass

class NotFoundError(BandjacksException):
    """Resource not found errors."""
    pass

class PermissionError(BandjacksException):
    """Authorization errors."""
    pass
```

### **Global Exception Handler**
```python
from fastapi import Request
from fastapi.responses import JSONResponse
import traceback
import logging

logger = logging.getLogger(__name__)

@app.exception_handler(BandjacksException)
async def bandjacks_exception_handler(request: Request, exc: BandjacksException):
    """Handle custom Bandjacks exceptions."""
    
    status_code = 400
    if isinstance(exc, NotFoundError):
        status_code = 404
    elif isinstance(exc, PermissionError):
        status_code = 403
    elif isinstance(exc, ExternalServiceException):
        status_code = 502
    
    error_response = {
        "success": False,
        "error": {
            "code": exc.code,
            "message": exc.message,
            "details": exc.details,
            "trace_id": getattr(request.state, 'trace_id', None)
        }
    }
    
    # Log error details
    logger.error(
        f"API Error: {exc.code}",
        extra={
            "trace_id": getattr(request.state, 'trace_id', None),
            "path": str(request.url),
            "method": request.method,
            "details": exc.details
        }
    )
    
    return JSONResponse(
        status_code=status_code,
        content=error_response
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    
    trace_id = getattr(request.state, 'trace_id', 'unknown')
    
    # Log full traceback for debugging
    logger.error(
        f"Unhandled exception: {str(exc)}",
        extra={
            "trace_id": trace_id,
            "path": str(request.url),
            "method": request.method,
            "traceback": traceback.format_exc()
        }
    )
    
    # Return generic error to client
    error_response = {
        "success": False,
        "error": {
            "code": "INTERNAL_ERROR",
            "message": "An unexpected error occurred",
            "trace_id": trace_id
        }
    }
    
    return JSONResponse(
        status_code=500,
        content=error_response
    )
```

### **Validation Error Handling**
```python
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle Pydantic validation errors."""
    
    error_details = []
    for error in exc.errors():
        error_details.append({
            "field": ".".join(str(loc) for loc in error["loc"][1:]),  # Skip 'body'
            "message": error["msg"],
            "type": error["type"],
            "input": error.get("input")
        })
    
    error_response = {
        "success": False,
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Request validation failed",
            "details": error_details,
            "trace_id": getattr(request.state, 'trace_id', None)
        }
    }
    
    return JSONResponse(
        status_code=422,
        content=error_response
    )
```

## Rate Limiting

### **Rate Limiting Implementation**
```python
from aiolimiter import AsyncLimiter
from fastapi import HTTPException
import hashlib

class RateLimiter:
    """Flexible rate limiting implementation."""
    
    def __init__(self):
        self.limiters = {}
        self.default_limiter = AsyncLimiter(100, 60)  # 100 requests per minute
    
    def get_client_id(self, request: Request) -> str:
        """Extract client identifier from request."""
        
        # Try API key first
        api_key = request.headers.get('x-api-key')
        if api_key:
            return f"api_key:{hashlib.sha256(api_key.encode()).hexdigest()[:8]}"
        
        # Try JWT token
        auth_header = request.headers.get('authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                payload = jwt.decode(token, options={"verify_signature": False})
                return f"user:{payload.get('sub', 'unknown')}"
            except:
                pass
        
        # Fall back to IP address
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            client_ip = forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.client.host
        
        return f"ip:{client_ip}"
    
    def get_limiter(self, client_id: str, endpoint: str) -> AsyncLimiter:
        """Get rate limiter for specific client and endpoint."""
        
        # Different limits for different endpoints
        limits = {
            'extract': (10, 60),    # 10 extractions per minute
            'search': (50, 60),     # 50 searches per minute  
            'upload': (5, 60),      # 5 uploads per minute
            'default': (100, 60)    # 100 requests per minute
        }
        
        endpoint_type = 'default'
        if '/extract/' in endpoint:
            endpoint_type = 'extract'
        elif '/search/' in endpoint:
            endpoint_type = 'search'
        elif '/upload' in endpoint:
            endpoint_type = 'upload'
        
        limiter_key = f"{client_id}:{endpoint_type}"
        
        if limiter_key not in self.limiters:
            rate, period = limits[endpoint_type]
            self.limiters[limiter_key] = AsyncLimiter(rate, period)
        
        return self.limiters[limiter_key]

rate_limiter = RateLimiter()

@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    """Apply rate limiting to all requests."""
    
    if not settings.rate_limit_enabled:
        return await call_next(request)
    
    client_id = rate_limiter.get_client_id(request)
    endpoint = str(request.url.path)
    limiter = rate_limiter.get_limiter(client_id, endpoint)
    
    try:
        await limiter.acquire()
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers['X-RateLimit-Limit'] = str(limiter.max_rate)
        response.headers['X-RateLimit-Remaining'] = str(limiter.max_rate - limiter.current_level)
        response.headers['X-RateLimit-Reset'] = str(int(limiter.next_reset_time))
        
        return response
        
    except Exception as e:
        # Rate limit exceeded
        error_response = {
            "success": False,
            "error": {
                "code": "RATE_LIMIT_EXCEEDED",
                "message": "Rate limit exceeded",
                "retry_after": 60
            }
        }
        
        return JSONResponse(
            status_code=429,
            content=error_response,
            headers={
                "Retry-After": "60",
                "X-RateLimit-Limit": str(limiter.max_rate),
                "X-RateLimit-Remaining": "0"
            }
        )
```

## API Versioning

### **URL Path Versioning**
```python
from fastapi import APIRouter

# V1 API (current)
v1_router = APIRouter(prefix="/v1")

@v1_router.get("/reports")
async def get_reports_v1():
    """V1 implementation with basic fields."""
    return {"reports": [...]}

# V2 API (future)
v2_router = APIRouter(prefix="/v2")

@v2_router.get("/reports")
async def get_reports_v2():
    """V2 implementation with enhanced fields."""
    return {
        "reports": [...],
        "metadata": {...},
        "enhancements": "V2 features"
    }

app.include_router(v1_router)
app.include_router(v2_router)
```

### **Header-Based Versioning**
```python
from fastapi import Header

@router.get("/reports")
async def get_reports(api_version: str = Header("1.0", alias="API-Version")):
    """Version-aware endpoint implementation."""
    
    if api_version.startswith("2."):
        return await get_reports_v2()
    elif api_version.startswith("1."):
        return await get_reports_v1()
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported API version: {api_version}"
        )
```

### **Backward Compatibility**
```python
class ReportResponseV1(BaseModel):
    """V1 response format."""
    id: str
    name: str
    status: str
    created: datetime

class ReportResponseV2(ReportResponseV1):
    """V2 response format with additional fields."""
    metadata: dict
    extraction_stats: dict
    review_status: Optional[str]
    
    # Backward compatibility method
    def to_v1(self) -> ReportResponseV1:
        """Convert V2 response to V1 format."""
        return ReportResponseV1(
            id=self.id,
            name=self.name, 
            status=self.status,
            created=self.created
        )
```

## Documentation & Testing

### **OpenAPI Documentation**

#### **Enhanced Endpoint Documentation**
```python
@router.post(
    "/extract/techniques",
    response_model=TechniqueExtractionResponse,
    summary="Extract MITRE ATT&CK Techniques",
    description="""
    Extract MITRE ATT&CK techniques from text using advanced NLP and LLM processing.
    
    The extraction process involves:
    1. Text preprocessing and chunking
    2. Pattern-based technique detection
    3. Vector similarity search for candidates
    4. LLM verification and confidence scoring
    5. Evidence consolidation and deduplication
    
    **Processing Time**: Typically 2-5 seconds for documents under 10KB.
    
    **Confidence Scoring**: All techniques include confidence scores (0-100).
    Recommended threshold is 50 for production use.
    
    **Evidence Tracking**: Each technique includes quotes from source text
    with line number references for validation.
    """,
    responses={
        200: {
            "description": "Successful extraction",
            "model": TechniqueExtractionResponse
        },
        400: {
            "description": "Invalid input",
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Text length must be between 10 and 100,000 characters"
                        }
                    }
                }
            }
        },
        429: {
            "description": "Rate limit exceeded",
            "headers": {
                "Retry-After": {
                    "description": "Seconds to wait before retrying",
                    "schema": {"type": "integer"}
                }
            }
        }
    },
    tags=["extraction"],
    operation_id="extractTechniques"
)
async def extract_techniques(request: TechniqueExtractionRequest):
    """Implementation..."""
    pass
```

### **API Testing Strategy**

#### **Unit Tests for Endpoints**
```python
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

@pytest.fixture
def test_client():
    """Test client fixture."""
    return TestClient(app)

@pytest.fixture
def sample_extraction_request():
    """Sample extraction request."""
    return {
        "text": "APT29 uses spearphishing emails with malicious attachments to gain initial access to target networks.",
        "confidence_threshold": 50.0,
        "max_techniques": 10,
        "include_evidence": True
    }

def test_extract_techniques_success(test_client, sample_extraction_request):
    """Test successful technique extraction."""
    
    with patch('bandjacks.llm.extraction_pipeline.extract_techniques') as mock_extract:
        mock_extract.return_value = ExtractionResult(
            claims=[
                TechniqueClaim(
                    external_id="T1566.001",
                    name="Spearphishing Attachment",
                    confidence=92.0,
                    quotes=["malicious attachments"],
                    line_refs=[1]
                )
            ],
            metrics={"extraction_time_ms": 2340}
        )
        
        response = test_client.post(
            "/v1/extract/techniques",
            json=sample_extraction_request
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] == True
        assert data["techniques_count"] == 1
        assert len(data["claims"]) == 1
        assert data["claims"][0]["external_id"] == "T1566.001"

def test_extract_techniques_validation_error(test_client):
    """Test validation error handling."""
    
    response = test_client.post(
        "/v1/extract/techniques",
        json={"text": ""}  # Empty text should fail validation
    )
    
    assert response.status_code == 422
    data = response.json()
    assert data["success"] == False
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "text" in str(data["error"]["details"])

def test_extract_techniques_processing_error(test_client, sample_extraction_request):
    """Test processing error handling."""
    
    with patch('bandjacks.llm.extraction_pipeline.extract_techniques') as mock_extract:
        mock_extract.side_effect = ProcessingException("LLM service unavailable")
        
        response = test_client.post(
            "/v1/extract/techniques", 
            json=sample_extraction_request
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] == False
        assert data["error"]["code"] == "PROCESSING_EXCEPTION"

@pytest.mark.asyncio
async def test_rate_limiting(test_client):
    """Test rate limiting functionality."""
    
    # Make requests rapidly to trigger rate limit
    responses = []
    for i in range(15):  # Exceed the limit of 10/minute for extract endpoints
        response = test_client.post(
            "/v1/extract/techniques",
            json={"text": f"Test text {i}"}
        )
        responses.append(response)
    
    # Should have some 429 responses
    rate_limited = [r for r in responses if r.status_code == 429]
    assert len(rate_limited) > 0
    
    # Check rate limit headers
    for response in responses[:5]:  # Check first few successful responses
        if response.status_code == 200:
            assert "X-RateLimit-Limit" in response.headers
            assert "X-RateLimit-Remaining" in response.headers
```

#### **Integration Tests**
```python
@pytest.mark.integration
class TestExtractionIntegration:
    """Integration tests with real services."""
    
    @pytest.fixture(autouse=True)
    async def setup_services(self):
        """Setup test services."""
        # Start test Neo4j and OpenSearch containers
        await self.start_test_services()
        yield
        await self.cleanup_test_services()
    
    async def test_end_to_end_extraction(self):
        """Test complete extraction pipeline."""
        
        # Upload a test report
        with open("tests/data/sample_report.pdf", "rb") as f:
            response = test_client.post(
                "/v1/reports/upload",
                files={"file": ("test.pdf", f, "application/pdf")}
            )
        
        assert response.status_code == 200
        report_id = response.json()["data"]["report_id"]
        
        # Wait for extraction to complete
        await asyncio.sleep(5)
        
        # Verify extraction results
        response = test_client.get(f"/v1/reports/{report_id}")
        assert response.status_code == 200
        
        report_data = response.json()["data"]
        assert report_data["status"] == "extracted"
        assert len(report_data["extraction"]["claims"]) > 0
        
        # Submit review
        review_data = {
            "reviewer_id": "test-user",
            "decisions": [
                {
                    "item_id": "technique-0",
                    "action": "approve",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            ],
            "review_timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        response = test_client.post(
            f"/v1/reports/{report_id}/unified-review",
            json=review_data
        )
        
        assert response.status_code == 200
        assert response.json()["success"] == True
```

### **API Documentation Generation**

#### **Custom OpenAPI Schema**
```python
def custom_openapi():
    """Generate custom OpenAPI schema."""
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="Bandjacks API",
        version="1.0.0",
        description="""
        ## Cyber Threat Defense World Modeling API
        
        The Bandjacks API provides comprehensive cyber threat intelligence operations including:
        
        - **Document Processing**: Extract techniques from threat reports
        - **Attack Flow Generation**: Model threat actor behavior sequences
        - **Review Workflows**: Human-in-the-loop validation
        - **Search & Discovery**: Find similar threats and techniques
        - **Analytics**: Coverage analysis and gap identification
        
        ### Authentication
        
        Development: No authentication required
        Production: JWT Bearer token or API Key
        
        ### Rate Limits
        
        - General endpoints: 100 requests/minute
        - Extraction endpoints: 10 requests/minute  
        - Upload endpoints: 5 requests/minute
        
        ### Support
        
        For support and documentation, visit: https://docs.bandjacks.io
        """,
        routes=app.routes,
        servers=[
            {"url": "https://api.bandjacks.io", "description": "Production"},
            {"url": "https://staging-api.bandjacks.io", "description": "Staging"},
            {"url": "http://localhost:8000", "description": "Development"}
        ]
    )
    
    # Add custom extensions
    openapi_schema["info"]["x-logo"] = {
        "url": "https://bandjacks.io/logo.png"
    }
    
    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        },
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key"
        }
    }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
```

## Conclusion

The Bandjacks API architecture provides a **comprehensive, scalable, and maintainable** foundation for cyber threat intelligence operations. Key architectural strengths:

**Design Excellence:**
- RESTful principles with consistent patterns
- OpenAPI 3.0 compliance for auto-documentation  
- Type-safe validation with Pydantic models
- Comprehensive error handling and logging

**Security & Performance:**
- Flexible authentication and authorization
- Intelligent rate limiting by endpoint type
- Robust validation and input sanitization
- Sub-second response times for most operations

**Developer Experience:**
- Auto-generated client SDKs
- Comprehensive API documentation
- Extensive test coverage
- Clear versioning strategy

**Operational Excellence:**
- Detailed monitoring and observability
- Graceful error handling and recovery
- Performance optimization and caching
- Production-ready deployment patterns

The API successfully balances **feature richness** with **operational simplicity**, providing a robust platform for both **internal applications** and **external integrations** in the cyber threat intelligence domain.