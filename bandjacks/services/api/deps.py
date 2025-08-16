"""Dependency injection for FastAPI."""

from typing import Generator
from neo4j import GraphDatabase, Session
from opensearchpy import OpenSearch
from .settings import settings


def get_neo4j_session() -> Generator[Session, None, None]:
    """Get Neo4j session dependency."""
    driver = GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_user, settings.neo4j_password)
    )
    with driver.session() as session:
        yield session
    driver.close()


def get_opensearch_client() -> OpenSearch:
    """Get OpenSearch client dependency."""
    return OpenSearch(
        hosts=[settings.opensearch_url],
        http_auth=(settings.opensearch_user, settings.opensearch_password),
        use_ssl=False,
        verify_certs=False
    )