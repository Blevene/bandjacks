"""Connection pooling for database connections."""

from typing import Optional, Dict, Any
from contextlib import contextmanager
from neo4j import GraphDatabase, Driver
from opensearchpy import OpenSearch, ConnectionPool as OSConnectionPool
import threading


class Neo4jPool:
    """Connection pool manager for Neo4j."""
    
    def __init__(
        self,
        uri: str,
        user: str,
        password: str,
        max_connection_lifetime: int = 3600,
        max_connection_pool_size: int = 50,
        connection_acquisition_timeout: int = 60
    ):
        """
        Initialize Neo4j connection pool.
        
        Args:
            uri: Neo4j URI
            user: Username
            password: Password
            max_connection_lifetime: Max lifetime in seconds
            max_connection_pool_size: Max pool size
            connection_acquisition_timeout: Timeout in seconds
        """
        self.driver = GraphDatabase.driver(
            uri,
            auth=(user, password),
            max_connection_lifetime=max_connection_lifetime,
            max_connection_pool_size=max_connection_pool_size,
            connection_acquisition_timeout=connection_acquisition_timeout
        )
        self._lock = threading.Lock()
    
    @contextmanager
    def get_session(self):
        """Get a Neo4j session from pool."""
        session = self.driver.session()
        try:
            yield session
        finally:
            session.close()
    
    def execute_read(self, query: str, params: Optional[Dict[str, Any]] = None):
        """Execute read query."""
        with self.get_session() as session:
            return session.read_transaction(
                lambda tx: list(tx.run(query, params or {}))
            )
    
    def execute_write(self, query: str, params: Optional[Dict[str, Any]] = None):
        """Execute write query."""
        with self.get_session() as session:
            return session.write_transaction(
                lambda tx: list(tx.run(query, params or {}))
            )
    
    def close(self):
        """Close the driver."""
        if self.driver:
            self.driver.close()
    
    def verify_connectivity(self) -> bool:
        """Verify connection is alive."""
        try:
            self.driver.verify_connectivity()
            return True
        except Exception:
            return False


class OpenSearchPool:
    """Connection pool manager for OpenSearch."""
    
    def __init__(
        self,
        hosts: list,
        timeout: int = 30,
        max_retries: int = 3,
        retry_on_timeout: bool = True,
        maxsize: int = 25
    ):
        """
        Initialize OpenSearch connection pool.
        
        Args:
            hosts: List of hosts
            timeout: Request timeout
            max_retries: Max retry attempts
            retry_on_timeout: Whether to retry on timeout
            maxsize: Max connections per node
        """
        self.client = OpenSearch(
            hosts=hosts,
            timeout=timeout,
            max_retries=max_retries,
            retry_on_timeout=retry_on_timeout,
            maxsize=maxsize,
            block=True  # Block when pool is full
        )
        self._lock = threading.Lock()
    
    def search(
        self,
        index: str,
        body: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """Execute search query."""
        return self.client.search(index=index, body=body, **kwargs)
    
    def index(
        self,
        index: str,
        body: Dict[str, Any],
        id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Index a document."""
        return self.client.index(index=index, body=body, id=id, **kwargs)
    
    def bulk(
        self,
        body: list,
        index: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Bulk index documents."""
        return self.client.bulk(body=body, index=index, **kwargs)
    
    def delete(
        self,
        index: str,
        id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Delete a document."""
        return self.client.delete(index=index, id=id, **kwargs)
    
    def ping(self) -> bool:
        """Check if cluster is up."""
        try:
            return self.client.ping()
        except Exception:
            return False
    
    def close(self):
        """Close connections."""
        if self.client:
            self.client.close()


class ConnectionManager:
    """Manages all database connection pools."""
    
    def __init__(self):
        """Initialize connection manager."""
        self.neo4j_pool: Optional[Neo4jPool] = None
        self.opensearch_pool: Optional[OpenSearchPool] = None
        self._lock = threading.Lock()
    
    def init_neo4j(
        self,
        uri: str,
        user: str,
        password: str,
        **kwargs
    ) -> Neo4jPool:
        """
        Initialize Neo4j connection pool.
        
        Args:
            uri: Neo4j URI
            user: Username
            password: Password
            **kwargs: Additional pool configuration
            
        Returns:
            Neo4j pool instance
        """
        with self._lock:
            if self.neo4j_pool is None:
                self.neo4j_pool = Neo4jPool(uri, user, password, **kwargs)
            return self.neo4j_pool
    
    def init_opensearch(
        self,
        hosts: list,
        **kwargs
    ) -> OpenSearchPool:
        """
        Initialize OpenSearch connection pool.
        
        Args:
            hosts: List of hosts
            **kwargs: Additional pool configuration
            
        Returns:
            OpenSearch pool instance
        """
        with self._lock:
            if self.opensearch_pool is None:
                self.opensearch_pool = OpenSearchPool(hosts, **kwargs)
            return self.opensearch_pool
    
    def get_neo4j(self) -> Optional[Neo4jPool]:
        """Get Neo4j pool if initialized."""
        return self.neo4j_pool
    
    def get_opensearch(self) -> Optional[OpenSearchPool]:
        """Get OpenSearch pool if initialized."""
        return self.opensearch_pool
    
    def health_check(self) -> Dict[str, bool]:
        """Check health of all connections."""
        health = {}
        
        if self.neo4j_pool:
            health["neo4j"] = self.neo4j_pool.verify_connectivity()
        
        if self.opensearch_pool:
            health["opensearch"] = self.opensearch_pool.ping()
        
        return health
    
    def close_all(self):
        """Close all connection pools."""
        if self.neo4j_pool:
            self.neo4j_pool.close()
            self.neo4j_pool = None
        
        if self.opensearch_pool:
            self.opensearch_pool.close()
            self.opensearch_pool = None


# Global connection manager
_connection_manager = None


def get_connection_manager() -> ConnectionManager:
    """Get global connection manager instance."""
    global _connection_manager
    
    if _connection_manager is None:
        _connection_manager = ConnectionManager()
    
    return _connection_manager