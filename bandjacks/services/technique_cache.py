"""
Global cache for MITRE ATT&CK technique lookups.

Provides O(1) lookups for technique names and metadata by external_id.
Loaded once at startup from Neo4j to avoid repeated database queries.

The TechniqueCache is a thread-safe singleton that loads all AttackPattern
nodes from Neo4j at API startup. This eliminates the need for database
queries during extraction and review operations, significantly improving
performance and ensuring consistent technique naming across the application.

Usage:
    from bandjacks.services.technique_cache import technique_cache
    
    # Get technique metadata
    tech = technique_cache.get("T1557")
    if tech:
        print(f"{tech['external_id']}: {tech['name']}")
        # Output: T1557: Adversary-in-the-Middle
    
    # Get just the name
    name = technique_cache.get_name("T1059.001")
    # Returns: "Command and Scripting Interpreter: PowerShell"
    
    # Check if technique exists
    if technique_cache.contains("T1234"):
        print("Technique found")

Architecture:
    - Singleton pattern ensures single instance across workers
    - Thread-safe operations with internal locking
    - Loaded once at startup, typically ~1376 techniques
    - Falls back gracefully if cache fails to load

Performance:
    - O(1) lookups after initial load
    - Eliminates 100-500 database queries per extraction
    - Startup load time: ~0.1-0.5 seconds
    - Memory usage: ~2-5 MB for full ATT&CK dataset
"""

import logging
import threading
import time
from typing import Dict, Any, Optional
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


class TechniqueCache:
    """
    Singleton cache for ATT&CK technique metadata.
    
    Provides fast O(1) lookups by external_id (e.g., T1557, T1059.001).
    Thread-safe implementation for use across multiple workers.
    """
    
    _instance = None
    _lock = threading.Lock()
    _cache: Dict[str, Dict[str, Any]] = {}
    _loaded = False
    
    def __new__(cls):
        """Ensure singleton pattern."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def load_from_neo4j(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str) -> int:
        """
        Load all AttackPattern nodes from Neo4j into cache.
        
        Args:
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            
        Returns:
            Number of techniques loaded
        """
        if self._loaded:
            logger.info("TechniqueCache already loaded, skipping reload")
            return len(self._cache)
        
        start_time = time.time()
        logger.info("Loading technique cache from Neo4j...")
        
        try:
            driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
            
            with driver.session() as session:
                # Query all AttackPattern nodes with their tactics
                result = session.run("""
                    MATCH (ap:AttackPattern)
                    WHERE ap.external_id IS NOT NULL
                    OPTIONAL MATCH (ap)-[:HAS_TACTIC]->(t:Tactic)
                    WITH ap, collect(DISTINCT t.shortname) as tactics
                    RETURN
                        ap.external_id as external_id,
                        ap.stix_id as stix_id,
                        ap.name as name,
                        ap.description as description,
                        ap.x_mitre_is_subtechnique as is_subtechnique,
                        ap.x_mitre_platforms as platforms,
                        ap.revoked as revoked,
                        ap.x_mitre_deprecated as deprecated,
                        tactics
                    ORDER BY ap.external_id
                """)
                
                count = 0
                with self._lock:
                    self._cache.clear()
                    
                    for record in result:
                        external_id = record["external_id"]
                        
                        # Store technique metadata
                        self._cache[external_id] = {
                            "external_id": external_id,
                            "stix_id": record["stix_id"],
                            "name": record["name"],
                            "description": record["description"],
                            "is_subtechnique": record["is_subtechnique"] or False,
                            "platforms": record["platforms"] or [],
                            "tactics": record["tactics"] or [],
                            "tactic": record["tactics"][0] if record["tactics"] else None,  # Primary tactic
                            "revoked": record["revoked"] or False,
                            "deprecated": record["deprecated"] or False,
                        }
                        count += 1
                    
                    self._loaded = True
            
            driver.close()
            
            elapsed = time.time() - start_time
            logger.info(f"Loaded {count} techniques into cache in {elapsed:.2f} seconds")
            
            # Log sample entries for verification
            if count > 0:
                samples = list(self._cache.keys())[:5]
                for ext_id in samples:
                    tech = self._cache[ext_id]
                    logger.debug(f"  {ext_id}: {tech['name']}")
            
            return count
            
        except Exception as e:
            logger.error(f"Failed to load technique cache: {e}")
            # Don't mark as loaded if there was an error
            self._loaded = False
            raise
    
    def get(self, external_id: str) -> Optional[Dict[str, Any]]:
        """
        Get technique metadata by external_id.
        
        Args:
            external_id: ATT&CK external ID (e.g., T1557, T1059.001)
            
        Returns:
            Dict with technique metadata or None if not found
        """
        return self._cache.get(external_id)
    
    def get_name(self, external_id: str) -> Optional[str]:
        """
        Get just the technique name by external_id.
        
        Args:
            external_id: ATT&CK external ID
            
        Returns:
            Technique name or None if not found
        """
        tech = self._cache.get(external_id)
        return tech["name"] if tech else None
    
    def contains(self, external_id: str) -> bool:
        """Check if a technique is in the cache."""
        return external_id in self._cache
    
    def size(self) -> int:
        """Get the number of techniques in cache."""
        return len(self._cache)
    
    def is_loaded(self) -> bool:
        """Check if cache has been loaded."""
        return self._loaded
    
    def clear(self):
        """Clear the cache (mainly for testing)."""
        with self._lock:
            self._cache.clear()
            self._loaded = False
            logger.info("TechniqueCache cleared")
    
    def get_all_external_ids(self) -> list:
        """Get all cached external IDs (for debugging/testing)."""
        return list(self._cache.keys())


# Global singleton instance
technique_cache = TechniqueCache()