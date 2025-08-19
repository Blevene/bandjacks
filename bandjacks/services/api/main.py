"""Main FastAPI application."""

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from bandjacks.services.api.settings import settings
from bandjacks.services.api.routes import catalog, stix_loader, search, mapper, review, llm, extract, query, graph, feedback, review_queue, flows, defense, candidates, simulation, analytics, provenance, drift
from bandjacks.services.api.middleware import TracingMiddleware
from bandjacks.loaders.neo4j_ddl import ensure_ddl
from bandjacks.loaders.opensearch_index import ensure_attack_nodes_index, ensure_attack_flows_index
from bandjacks.loaders.edge_embeddings import ensure_attack_edges_index

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

# Add tracing middleware
app.add_middleware(TracingMiddleware)

@app.on_event("startup")
def startup():
    # ensure infra bits exist
    try:
        ensure_ddl(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
    except Exception as e:
        print(f"[startup] Neo4j DDL ensure failed: {e}")
    try:
        ensure_attack_nodes_index(settings.opensearch_url, settings.os_index_nodes)
        ensure_attack_edges_index(settings.opensearch_url)
        ensure_attack_flows_index(settings.opensearch_url)
    except Exception as e:
        print(f"[startup] OpenSearch index ensure failed: {e}")

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
    }
]

app.openapi_tags = tags_metadata

app.include_router(catalog.router, prefix=settings.api_prefix)
app.include_router(stix_loader.router, prefix=settings.api_prefix)
app.include_router(search.router, prefix=settings.api_prefix)
app.include_router(mapper.router, prefix=settings.api_prefix)
app.include_router(review.router, prefix=settings.api_prefix)
app.include_router(llm.router, prefix=settings.api_prefix)
app.include_router(extract.router, prefix=settings.api_prefix)
app.include_router(query.router, prefix=settings.api_prefix)
app.include_router(graph.router, prefix=settings.api_prefix)
app.include_router(feedback.router, prefix=settings.api_prefix)
app.include_router(review_queue.router, prefix=settings.api_prefix)
app.include_router(flows.router, prefix=settings.api_prefix)
app.include_router(defense.router, prefix=settings.api_prefix)
app.include_router(candidates.router, prefix=settings.api_prefix)
app.include_router(simulation.router, prefix=settings.api_prefix)
app.include_router(analytics.router, prefix=settings.api_prefix)
app.include_router(provenance.router, prefix=settings.api_prefix)
app.include_router(drift.router, prefix=settings.api_prefix)