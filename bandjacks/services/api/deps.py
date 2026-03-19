"""FastAPI dependency injection for database connections."""

import logging
from typing import Generator
from neo4j import Session
from opensearchpy import OpenSearch
from bandjacks.core.connection_pool import Neo4jPool
from .settings import settings

logger = logging.getLogger(__name__)

_neo4j_pool: Neo4jPool | None = None
_opensearch_client: OpenSearch | None = None


def get_neo4j_driver():
    """Get or create the shared Neo4j driver singleton (via connection pool).

    Returns the underlying Neo4j Driver instance from the pool so that
    existing callers (``driver.session()``) keep working unchanged.
    """
    global _neo4j_pool
    if _neo4j_pool is None:
        if not settings.neo4j_password:
            raise ValueError(
                "NEO4J_PASSWORD environment variable is required. "
                "Please set it in your .env file or environment variables."
            )
        _neo4j_pool = Neo4jPool(
            uri=settings.neo4j_uri,
            user=settings.neo4j_user,
            password=settings.neo4j_password,
            max_connection_pool_size=50,
            max_connection_lifetime=3600,
            connection_acquisition_timeout=60,
        )
        logger.info(f"Created Neo4j connection pool for {settings.neo4j_uri}")
    return _neo4j_pool.driver


def get_neo4j_session() -> Generator[Session, None, None]:
    """Yield a Neo4j session from the shared driver."""
    driver = get_neo4j_driver()
    session = driver.session()
    try:
        yield session
    finally:
        session.close()


def get_opensearch_client() -> OpenSearch:
    """Get or create the shared OpenSearch client singleton."""
    global _opensearch_client
    if _opensearch_client is None:
        # OpenSearch may work without password if security is disabled
        # Only use http_auth if password is provided
        auth = None
        if settings.opensearch_password:
            auth = (settings.opensearch_user, settings.opensearch_password)

        _opensearch_client = OpenSearch(
            hosts=[settings.opensearch_url],
            http_auth=auth,
            use_ssl=False,
            verify_certs=False,
        )
        logger.info(f"Created OpenSearch client for {settings.opensearch_url}")
    return _opensearch_client


def close_connections():
    """Close all database connections. Call during shutdown."""
    global _neo4j_pool, _opensearch_client
    if _neo4j_pool:
        _neo4j_pool.close()
        _neo4j_pool = None
        logger.info("Neo4j connection pool closed")
    if _opensearch_client:
        _opensearch_client.close()
        _opensearch_client = None
        logger.info("OpenSearch client closed")
