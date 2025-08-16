"""Main FastAPI application."""

from fastapi import FastAPI
from .settings import settings
from .routes import catalog, stix_loader
from ...loaders.neo4j_ddl import ensure_ddl
from ...loaders.opensearch_index import ensure_attack_nodes_index

app = FastAPI(title=settings.api_title, version="1.0.0")

@app.on_event("startup")
def startup():
    # ensure infra bits exist
    try:
        ensure_ddl(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)
    except Exception as e:
        print(f"[startup] Neo4j DDL ensure failed: {e}")
    try:
        ensure_attack_nodes_index(settings.opensearch_url, settings.os_index_nodes)
    except Exception as e:
        print(f"[startup] OpenSearch index ensure failed: {e}")

app.include_router(catalog.router, prefix=settings.api_prefix)
app.include_router(stix_loader.router, prefix=settings.api_prefix)