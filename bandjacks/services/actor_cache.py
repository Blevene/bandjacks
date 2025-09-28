"""Global cache for IntrusionSet (actors) to support fast lookups/search.

Loaded at API startup from Neo4j and used by search/lookup endpoints
to avoid per-keystroke DB hits.
"""

import logging
import threading
from typing import Dict, Any, List, Optional
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)


class ActorCache:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        # id -> { id, name, aliases }
        self._by_id: Dict[str, Dict[str, Any]] = {}
        # lowercased name and aliases for search
        self._records: List[Dict[str, Any]] = []
        self._loaded: bool = False
        self._load_lock = threading.Lock()

    def load_from_neo4j(self, uri: str, user: str, password: str) -> int:
        if self._loaded:
            return len(self._by_id)
        with self._load_lock:
            if self._loaded:
                return len(self._by_id)
            logger.info("Loading ActorCache from Neo4j...")
            driver = GraphDatabase.driver(uri, auth=(user, password))
            try:
                with driver.session() as session:
                    result = session.run(
                        """
                        MATCH (g:IntrusionSet)
                        RETURN g.stix_id as id, g.name as name, coalesce(g.aliases, []) as aliases
                        """
                    )
                    count = 0
                    self._by_id.clear()
                    self._records.clear()
                    for rec in result:
                        rid = rec["id"]
                        name = rec["name"] or ""
                        aliases = rec["aliases"] or []
                        self._by_id[rid] = {"id": rid, "name": name, "aliases": aliases}
                        self._records.append(
                            {
                                "id": rid,
                                "name": name,
                                "name_l": name.lower(),
                                "aliases": aliases,
                                "aliases_l": [str(a or "").lower() for a in aliases],
                            }
                        )
                        count += 1
                self._loaded = True
                logger.info(f"ActorCache loaded {count} actors")
                return count
            finally:
                driver.close()

    def is_loaded(self) -> bool:
        return self._loaded

    def get(self, actor_id: str) -> Optional[Dict[str, Any]]:
        return self._by_id.get(actor_id)

    def search(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        q = (query or "").lower().strip()
        if not q:
            return []
        results: List[Dict[str, Any]] = []
        for rec in self._records:
            if q in rec["name_l"] or any(q in a for a in rec["aliases_l"]):
                results.append({"id": rec["id"], "name": rec["name"], "aliases": rec["aliases"]})
                if len(results) >= limit:
                    break
        return results


actor_cache = ActorCache()


