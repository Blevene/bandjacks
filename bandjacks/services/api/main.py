"""Main FastAPI application."""

import os
import logging
import logging.config
import logging.handlers
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from bandjacks.services.api.settings import settings

# Configure logging before anything else
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FILE = os.getenv('LOG_FILE', 'extraction_pipeline.log')

LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'detailed': {
            'format': '%(asctime)s [%(processName)s:%(threadName)s] %(name)s %(levelname)s: %(message)s'
        },
        'simple': {
            'format': '%(levelname)s: %(message)s'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'level': LOG_LEVEL,
            'formatter': 'detailed',
            'stream': 'ext://sys.stdout'
        },
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',  # Always capture DEBUG in file
            'formatter': 'detailed',
            'filename': LOG_FILE,
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5
        }
    },
    'loggers': {
        'bandjacks.llm': {
            'level': 'DEBUG',
            'handlers': ['console', 'file'],
            'propagate': False
        },
        'bandjacks.services.api': {
            'level': 'DEBUG' if LOG_LEVEL == 'DEBUG' else 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False
        },
        'bandjacks.llm.client': {
            'level': 'DEBUG',
            'handlers': ['console', 'file'],
            'propagate': False
        },
        'bandjacks.llm.chunked_extractor': {
            'level': 'DEBUG',
            'handlers': ['console', 'file'],
            'propagate': False
        }
    },
    'root': {
        'level': LOG_LEVEL,
        'handlers': ['console']
    }
}

logging.config.dictConfig(LOGGING_CONFIG)
from bandjacks.services.api.routes import catalog, stix_loader, search, mapper, review, query, graph, feedback, review_queue, flows, defense, candidates, simulation, analytics, provenance, drift, attackflow, detections, coverage, compliance, ml_metrics, notifications, sigma, reports, sequence, simulate, analyze, entity_review, unified_review, actors
from bandjacks.services.api.middleware import TracingMiddleware
from bandjacks.services.api.middleware.error_handler import ErrorHandlerMiddleware
from bandjacks.services.api.middleware.auth import JWTAuthMiddleware
from bandjacks.services.api.middleware.rate_limit import RateLimitMiddleware
from bandjacks.services.api.job_processor import get_job_processor
from bandjacks.loaders.neo4j_ddl import ensure_ddl
from bandjacks.loaders.opensearch_index import ensure_attack_nodes_index, ensure_attack_flows_index, OpenSearchIndexManager
from bandjacks.loaders.edge_embeddings import ensure_attack_edges_index
from bandjacks.llm.cache import get_cache_stats, clear_cache
from bandjacks.monitoring.compliance_metrics import get_compliance_report, get_compliance_metrics
from bandjacks.services.technique_cache import technique_cache
from bandjacks.services.actor_cache import actor_cache

logger = logging.getLogger(__name__)
logger.info(f"Logging configured: level={LOG_LEVEL}, file={LOG_FILE}")

app = FastAPI(
    title="Bandjacks API",
    description="""
    ## Cyber Threat Defense World Modeling API
    
    Bandjacks provides comprehensive cyber threat intelligence operations including:
    
    - **ATT&CK Data Management**: Load and manage MITRE ATT&CK releases
    - **Natural Language Search**: Hybrid vector and graph search for CTI
    - **Graph Exploration**: Traverse and analyze threat relationships
    - **Document Extraction**: Extract CTI entities from documents using LLMs
    - **Review Workflows**: Human-in-the-loop validation and feedback
    - **Defense Recommendations**: D3FEND integration (coming in Sprint 4)
    
    ### Key Features
    
    - STIX 2.1 compliant data model
    - ADM (ATT&CK Data Model) validation
    - Hybrid search with vector embeddings and graph patterns
    - LLM-powered extraction with evidence grounding
    - Review queue for candidate validation
    - Performance optimized with caching and connection pooling
    
    ### Authentication
    
    Currently no authentication required (development mode).
    Production deployments should implement appropriate authentication.
    
    ### Rate Limiting
    
    No rate limiting currently implemented.
    Production deployments should add rate limiting.
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    servers=[
        {"url": "http://localhost:8000", "description": "Development server"},
        {"url": "https://api.bandjacks.io", "description": "Production server (future)"}
    ]
)

# Add middleware (order matters - error handler should be first to catch all errors)
app.add_middleware(ErrorHandlerMiddleware)

# Add rate limiting if enabled
if settings.rate_limit_enabled:
    app.add_middleware(RateLimitMiddleware)
    logger.info("Rate limiting enabled")

# Add authentication if enabled
if settings.enable_auth:
    app.add_middleware(JWTAuthMiddleware)
    logger.info(f"Authentication enabled with issuer: {settings.oidc_issuer or 'local'}")

# Add tracing (should be after auth to capture user info)
app.add_middleware(TracingMiddleware)

# Add CORS middleware for frontend development (outermost to ensure headers on all responses/preflights)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:3002",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:3002",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    # ensure infra bits exist
    try:
        ensure_ddl(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
    except Exception as e:
        print(f"[startup] Neo4j DDL ensure failed: {e}")
    
    # Load technique cache after Neo4j is ready
    try:
        techniques_loaded = technique_cache.load_from_neo4j(
            settings.neo4j_uri, 
            settings.neo4j_user, 
            settings.neo4j_password
        )
        logger.info(f"TechniqueCache initialized with {techniques_loaded} techniques")
    except Exception as e:
        logger.error(f"Failed to load technique cache: {e}")
        # Continue startup even if cache fails - will fall back to direct queries
    # Load actor cache for lookups/search
    try:
        actors_loaded = actor_cache.load_from_neo4j(
            settings.neo4j_uri,
            settings.neo4j_user,
            settings.neo4j_password,
        )
        logger.info(f"ActorCache initialized with {actors_loaded} actors")
    except Exception as e:
        logger.error(f"Failed to load actor cache: {e}")
    
    try:
        ensure_attack_nodes_index(settings.opensearch_url, settings.os_index_nodes)
        ensure_attack_edges_index(settings.opensearch_url)
        ensure_attack_flows_index(settings.opensearch_url)
        
        # Initialize reports index
        from opensearchpy import OpenSearch
        os_client = OpenSearch(
            hosts=[settings.opensearch_url],
            http_auth=(settings.opensearch_user, settings.opensearch_password),
            use_ssl=False,
            verify_certs=False
        )
        index_manager = OpenSearchIndexManager(os_client)
        index_manager.create_reports_index()
    except Exception as e:
        print(f"[startup] OpenSearch index ensure failed: {e}")
    
    # Start the job processor for async report processing
    try:
        job_processor = get_job_processor()
        await job_processor.start()
        logger.info("Job processor started successfully")
    except Exception as e:
        logger.error(f"Failed to start job processor: {e}")

@app.on_event("shutdown")
async def shutdown():
    # Stop the job processor gracefully
    try:
        job_processor = get_job_processor()
        await job_processor.stop()
        logger.info("Job processor stopped successfully")
    except Exception as e:
        logger.error(f"Failed to stop job processor: {e}")

# Configure API tags for better organization
tags_metadata = [
    {
        "name": "catalog",
        "description": "ATT&CK catalog and release management",
    },
    {
        "name": "stix",
        "description": "STIX data loading and validation",
    },
    {
        "name": "search",
        "description": "Vector and text-based search operations",
    },
    {
        "name": "query",
        "description": "Natural language query and hybrid search",
    },
    {
        "name": "graph",
        "description": "Graph traversal and exploration",
    },
    {
        "name": "extract",
        "description": "Document extraction and CTI entity recognition",
    },
    {
        "name": "feedback",
        "description": "User feedback collection and management",
    },
    {
        "name": "review_queue",
        "description": "Candidate review queue management",
    },
    {
        "name": "mapper",
        "description": "Text to ATT&CK technique mapping",
    },
    {
        "name": "review",
        "description": "Review decisions and workflows",
    },
    {
        "name": "flows",
        "description": "Attack flow generation, retrieval, and search",
    },
    {
        "name": "defense",
        "description": "D3FEND defense overlay and recommendations",
    },
    {
        "name": "candidates",
        "description": "Candidate attack pattern review workflow",
    },
    {
        "name": "simulation",
        "description": "Attack path simulation and prediction",
    },
    {
        "name": "analytics",
        "description": "Coverage analytics and gap analysis",
    },
    {
        "name": "provenance",
        "description": "Object provenance and lineage tracking",
    },
    {
        "name": "drift",
        "description": "Drift detection and monitoring for data quality and model performance",
    },
    {
        "name": "attackflow",
        "description": "Attack Flow 2.0 ingestion, export, and interoperability",
    },
    {
        "name": "detections",
        "description": "Detection strategies, analytics, and log sources management",
    },
    {
        "name": "coverage",
        "description": "Technique coverage analysis across detections, mitigations, and D3FEND",
    },
    {
        "name": "compliance",
        "description": "Compliance metrics and reporting for ADM validation and review processes",
    },
    {
        "name": "ml-metrics",
        "description": "Machine learning model performance metrics and monitoring",
    },
    {
        "name": "sigma",
        "description": "Sigma rule management and integration with analytics",
    },
    {
        "name": "reports",
        "description": "Report ingestion with extraction and campaign creation",
    }
]

app.openapi_tags = tags_metadata

app.include_router(catalog.router, prefix=settings.api_prefix)
app.include_router(stix_loader.router, prefix=settings.api_prefix)
app.include_router(search.router, prefix=settings.api_prefix)
app.include_router(mapper.router, prefix=settings.api_prefix)
app.include_router(review.router, prefix=settings.api_prefix)
app.include_router(query.router, prefix=settings.api_prefix)
app.include_router(graph.router, prefix=settings.api_prefix)
app.include_router(feedback.router, prefix=settings.api_prefix)
app.include_router(review_queue.router, prefix=settings.api_prefix)
app.include_router(flows.router, prefix=settings.api_prefix)
app.include_router(defense.router, prefix=settings.api_prefix)
app.include_router(candidates.router, prefix=settings.api_prefix)
app.include_router(simulation.router, prefix=settings.api_prefix)
app.include_router(simulate.router, prefix=settings.api_prefix)
app.include_router(analyze.router, prefix=settings.api_prefix)
app.include_router(analytics.router, prefix=settings.api_prefix)
app.include_router(provenance.router, prefix=settings.api_prefix)
app.include_router(drift.router, prefix=settings.api_prefix)
app.include_router(attackflow.router, prefix=settings.api_prefix)
app.include_router(detections.router, prefix=settings.api_prefix)
app.include_router(coverage.router, prefix=settings.api_prefix)
app.include_router(compliance.router, prefix=settings.api_prefix)
app.include_router(ml_metrics.router, prefix=settings.api_prefix)
app.include_router(notifications.router, prefix=settings.api_prefix)
app.include_router(sigma.router, prefix=settings.api_prefix)
app.include_router(reports.router, prefix=settings.api_prefix)
app.include_router(entity_review.router, prefix=settings.api_prefix)
app.include_router(unified_review.router, prefix=settings.api_prefix)
app.include_router(sequence.router, prefix=settings.api_prefix)
app.include_router(actors.router, prefix=settings.api_prefix)

# Cache management endpoints
@app.get("/v1/cache/stats", tags=["monitoring"])
async def get_cache_statistics():
    """Get LLM cache statistics."""
    return get_cache_stats()

@app.post("/v1/cache/clear", tags=["monitoring"])
async def clear_llm_cache():
    """Clear the LLM response cache."""
    clear_cache()
    return {"message": "Cache cleared successfully"}

# Legacy compliance endpoints removed - use /v1/compliance/* routes instead