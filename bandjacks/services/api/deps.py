"""Dependency injection for FastAPI."""

from typing import Generator
from neo4j import GraphDatabase, Session
from opensearchpy import OpenSearch
from .settings import settings


def get_neo4j_session() -> Generator[Session, None, None]:
    """Get Neo4j session dependency."""
    if not settings.neo4j_password:
        raise ValueError(
            "NEO4J_PASSWORD environment variable is required. "
            "Please set it in your .env file or environment variables."
        )
    driver = GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password)
    )
    with driver.session() as session:
        yield session
    driver.close()


def get_opensearch_client() -> OpenSearch:
    """Get OpenSearch client dependency."""
    # OpenSearch may work without password if security is disabled
    # Only use http_auth if password is provided
    auth = None
    if settings.opensearch_password:
        auth = (settings.opensearch_user, settings.opensearch_password)
    
    return OpenSearch(
        hosts=[settings.opensearch_url],
        http_auth=auth,
        use_ssl=False,
        verify_certs=False
    )