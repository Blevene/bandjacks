"""Hybrid search implementation combining vector and graph queries."""

from typing import List, Dict, Any, Optional, Tuple
from opensearchpy import OpenSearch
from neo4j import GraphDatabase
import numpy as np
from bandjacks.loaders.embedder import encode
from bandjacks.loaders.technique_phrases import TECHNIQUE_PHRASES
from bandjacks.core.cache import get_query_cache
from bandjacks.core.connection_pool import get_connection_manager


class HybridSearcher:
    """Combines vector search and graph queries for comprehensive results."""
    
    def __init__(
        self,
        opensearch_url: str,
        opensearch_index: str,
        neo4j_uri: str,
        neo4j_user: str,
        neo4j_password: str,
        enable_cache: bool = True
    ):
        """
        Initialize hybrid searcher with connections.
        
        Args:
            opensearch_url: OpenSearch connection URL
            opensearch_index: Index name for vector search
            neo4j_uri: Neo4j connection URI
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
            enable_cache: Whether to enable result caching
        """
        # Use connection pooling
        conn_manager = get_connection_manager()
        
        # Initialize pools if not already done
        self.neo4j_pool = conn_manager.init_neo4j(
            neo4j_uri, neo4j_user, neo4j_password
        )
        self.os_pool = conn_manager.init_opensearch([opensearch_url])
        
        self.os_index = opensearch_index
        
        # Initialize cache
        self.cache = get_query_cache() if enable_cache else None
        
        # For backwards compatibility
        self.neo4j_driver = self.neo4j_pool.driver
        self.os_client = self.os_pool.client
    
    def search(
        self,
        query: str,
        top_k: int = 20,
        filters: Optional[Dict[str, Any]] = None,
        include_graph_context: bool = True,
        fusion_weights: Optional[Dict[str, float]] = None
    ) -> List[Dict[str, Any]]:
        """
        Perform hybrid search combining vector and graph results.
        
        Args:
            query: Natural language query
            top_k: Number of results to return
            filters: Optional filters (entity_type, confidence_min, etc.)
            include_graph_context: Whether to enrich with graph neighbors
            fusion_weights: Weights for result fusion (default: vector=0.6, graph=0.4)
            
        Returns:
            List of ranked results with scores and context
        """
        if not fusion_weights:
            fusion_weights = {"vector": 0.6, "graph": 0.4}
        
        # Check cache first
        if self.cache:
            cached_results = self.cache.get_search_results(query, filters, top_k)
            if cached_results is not None:
                return cached_results
        
        # 1. Query expansion
        expanded_query = self._expand_query(query)
        
        # 2. Vector search
        vector_results = self._vector_search(
            expanded_query,
            top_k * 2,  # Get more for fusion
            filters
        )
        
        # 3. Graph pattern search
        graph_results = self._graph_search(
            query,
            expanded_query,
            top_k * 2,
            filters
        )
        
        # 4. Reciprocal rank fusion
        fused_results = self._reciprocal_rank_fusion(
            vector_results,
            graph_results,
            fusion_weights,
            top_k
        )
        
        # 5. Enrich with graph context if requested
        if include_graph_context:
            fused_results = self._enrich_with_context(fused_results)
        
        # Cache results
        if self.cache:
            self.cache.set_search_results(query, fused_results, filters, top_k)
        
        return fused_results
    
    def _expand_query(self, query: str) -> str:
        """
        Expand query with synonyms and related terms.
        
        Args:
            query: Original query text
            
        Returns:
            Expanded query string
        """
        query_lower = query.lower()
        expansions = [query]
        
        # Check for technique phrases
        for phrase, details in TECHNIQUE_PHRASES.items():
            if phrase in query_lower:
                # Add technique name if we have it
                if "technique" in details:
                    expansions.append(details["technique"])
                # Add related terms
                if "related" in details:
                    expansions.extend(details["related"])
        
        # Common synonyms in cyber threat domain
        synonyms = {
            "apt": ["advanced persistent threat", "threat actor", "group"],
            "c2": ["command and control", "c&c", "cnc"],
            "creds": ["credentials", "passwords", "authentication"],
            "lateral": ["lateral movement", "pivoting", "spread"],
            "persist": ["persistence", "maintain access", "backdoor"],
            "exfil": ["exfiltration", "data theft", "steal data"]
        }
        
        for term, syns in synonyms.items():
            if term in query_lower:
                expansions.extend(syns)
        
        # Remove duplicates and join
        expanded = " ".join(list(dict.fromkeys(expansions)))
        return expanded
    
    def _vector_search(
        self,
        query: str,
        top_k: int,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Perform vector search in OpenSearch.
        
        Args:
            query: Query text (possibly expanded)
            top_k: Number of results
            filters: Optional filters
            
        Returns:
            List of vector search results
        """
        query_vector = encode(query)
        if query_vector is None:
            return []
        
        # Build query
        body = {
            "size": top_k,
            "query": {
                "knn": {
                    "embedding": {
                        "vector": query_vector,
                        "k": top_k
                    }
                }
            },
            "_source": ["id", "kb_type", "attack_version", "text", "revoked"]
        }
        
        # Add filters if provided
        if filters:
            filter_clauses = []
            
            if "entity_type" in filters:
                filter_clauses.append({
                    "term": {"kb_type": filters["entity_type"]}
                })
            
            if "exclude_revoked" in filters and filters["exclude_revoked"]:
                filter_clauses.append({
                    "term": {"revoked": False}
                })
            
            if filter_clauses:
                body["query"] = {
                    "bool": {
                        "must": [body["query"]],
                        "filter": filter_clauses
                    }
                }
        
        # Execute search
        response = self.os_client.search(index=self.os_index, body=body)
        
        results = []
        for i, hit in enumerate(response["hits"]["hits"]):
            src = hit["_source"]
            text_preview = (src.get("text", "") or "")[:200]
            
            results.append({
                "stix_id": src.get("id"),
                "type": src.get("kb_type"),
                "score": hit.get("_score", 0.0),
                "rank": i + 1,
                "source": "vector",
                "name": text_preview.split("\n")[0] if text_preview else "Unknown",
                "preview": text_preview
            })
        
        return results
    
    def _graph_search(
        self,
        original_query: str,
        expanded_query: str,
        top_k: int,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Perform graph-based search using Neo4j.
        
        Args:
            original_query: Original query text
            expanded_query: Expanded query with synonyms
            top_k: Number of results
            filters: Optional filters
            
        Returns:
            List of graph search results
        """
        results = []
        
        with self.neo4j_driver.session() as session:
            # Search for techniques by name/description
            technique_query = """
                MATCH (n:AttackPattern)
                WHERE toLower(n.name) CONTAINS toLower($query)
                   OR toLower(n.description) CONTAINS toLower($query)
                   OR ANY(phrase IN $phrases WHERE toLower(n.name) CONTAINS phrase)
                OPTIONAL MATCH (n)-[:HAS_TACTIC]->(t:Tactic)
                RETURN n.stix_id as id, n.name as name, n.description as desc,
                       n.type as type, collect(t.name) as tactics
                LIMIT $limit
            """
            
            # Extract key phrases from expanded query
            phrases = [p.strip() for p in expanded_query.lower().split() 
                      if len(p.strip()) > 3][:5]
            
            result = session.run(
                technique_query,
                query=original_query,
                phrases=phrases,
                limit=top_k
            )
            
            for i, record in enumerate(result):
                results.append({
                    "stix_id": record["id"],
                    "type": record["type"] or "attack-pattern",
                    "score": 1.0 / (i + 1),  # Reciprocal rank
                    "rank": i + 1,
                    "source": "graph",
                    "name": record["name"],
                    "preview": record["desc"][:200] if record["desc"] else "",
                    "tactics": record["tactics"]
                })
            
            # Search for groups/software by name
            entity_query = """
                MATCH (n)
                WHERE (n:IntrusionSet OR n:Software)
                  AND (toLower(n.name) CONTAINS toLower($query)
                       OR ANY(alias IN n.aliases WHERE toLower(alias) CONTAINS toLower($query)))
                OPTIONAL MATCH (n)-[:USES]->(t:AttackPattern)
                RETURN n.stix_id as id, n.name as name, n.type as type,
                       n.description as desc, count(t) as technique_count
                LIMIT $limit
            """
            
            result = session.run(
                entity_query,
                query=original_query,
                limit=top_k
            )
            
            for i, record in enumerate(result):
                results.append({
                    "stix_id": record["id"],
                    "type": record["type"],
                    "score": 0.8 / (i + 1),  # Slightly lower weight
                    "rank": i + 1,
                    "source": "graph",
                    "name": record["name"],
                    "preview": record["desc"][:200] if record["desc"] else "",
                    "technique_count": record["technique_count"]
                })
        
        return results
    
    def _reciprocal_rank_fusion(
        self,
        vector_results: List[Dict[str, Any]],
        graph_results: List[Dict[str, Any]],
        weights: Dict[str, float],
        top_k: int
    ) -> List[Dict[str, Any]]:
        """
        Fuse results using reciprocal rank fusion.
        
        Args:
            vector_results: Results from vector search
            graph_results: Results from graph search
            weights: Weight for each source
            top_k: Number of final results
            
        Returns:
            Fused and ranked results
        """
        # Create score map
        fusion_scores = {}
        
        # Constant for RRF (typically 60)
        k = 60
        
        # Process vector results
        for result in vector_results:
            stix_id = result["stix_id"]
            if stix_id:
                rank = result["rank"]
                rrf_score = 1.0 / (k + rank)
                fusion_scores[stix_id] = fusion_scores.get(stix_id, 0) + \
                    (rrf_score * weights["vector"])
                
                # Store the best result data
                if stix_id not in fusion_scores or "data" not in fusion_scores:
                    fusion_scores[stix_id] = {
                        "score": fusion_scores.get(stix_id, 0),
                        "data": result
                    }
        
        # Process graph results
        for result in graph_results:
            stix_id = result["stix_id"]
            if stix_id:
                rank = result["rank"]
                rrf_score = 1.0 / (k + rank)
                
                if stix_id in fusion_scores and isinstance(fusion_scores[stix_id], dict):
                    fusion_scores[stix_id]["score"] += rrf_score * weights["graph"]
                    # Merge data, preferring graph data for certain fields
                    fusion_scores[stix_id]["data"]["tactics"] = result.get("tactics", [])
                    fusion_scores[stix_id]["data"]["technique_count"] = result.get("technique_count", 0)
                else:
                    fusion_scores[stix_id] = {
                        "score": rrf_score * weights["graph"],
                        "data": result
                    }
        
        # Sort by fusion score
        sorted_results = sorted(
            fusion_scores.items(),
            key=lambda x: x[1]["score"] if isinstance(x[1], dict) else 0,
            reverse=True
        )[:top_k]
        
        # Format final results
        final_results = []
        for i, (stix_id, item) in enumerate(sorted_results):
            if isinstance(item, dict) and "data" in item:
                result = item["data"].copy()
                result["fusion_score"] = item["score"]
                result["fusion_rank"] = i + 1
                final_results.append(result)
        
        return final_results
    
    def _enrich_with_context(
        self,
        results: List[Dict[str, Any]],
        max_neighbors: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Enrich results with graph context (neighbors, relationships).
        
        Args:
            results: Search results to enrich
            max_neighbors: Maximum neighbors to include
            
        Returns:
            Enriched results with graph context
        """
        with self.neo4j_driver.session() as session:
            for result in results:
                stix_id = result.get("stix_id")
                if not stix_id:
                    continue
                
                # Get neighbors and relationships
                context_query = """
                    MATCH (n {stix_id: $stix_id})
                    OPTIONAL MATCH (n)-[r:USES|MITIGATES|HAS_TACTIC]-(neighbor)
                    WHERE neighbor.revoked = false OR neighbor.revoked IS NULL
                    RETURN type(r) as rel_type, 
                           neighbor.stix_id as neighbor_id,
                           neighbor.name as neighbor_name,
                           neighbor.type as neighbor_type,
                           startNode(r).stix_id = $stix_id as outgoing
                    LIMIT $limit
                """
                
                context_result = session.run(
                    context_query,
                    stix_id=stix_id,
                    limit=max_neighbors
                )
                
                neighbors = []
                relationships = []
                
                for record in context_result:
                    if record["neighbor_id"]:
                        neighbors.append({
                            "id": record["neighbor_id"],
                            "name": record["neighbor_name"],
                            "type": record["neighbor_type"]
                        })
                        
                        relationships.append({
                            "type": record["rel_type"],
                            "direction": "outgoing" if record["outgoing"] else "incoming",
                            "target": record["neighbor_id"]
                        })
                
                result["graph_context"] = {
                    "neighbors": neighbors,
                    "relationships": relationships,
                    "neighbor_count": len(neighbors)
                }
        
        return results
    
    def close(self):
        """Close connections."""
        if self.neo4j_driver:
            self.neo4j_driver.close()