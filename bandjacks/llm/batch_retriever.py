"""Batch retriever agent for efficient OpenSearch queries."""

import logging
from typing import Dict, Any, List
from opensearchpy import OpenSearch
from bandjacks.llm.memory import WorkingMemory
from bandjacks.loaders.embedder import batch_encode
from bandjacks.llm.tools import graph_lookup
import os

logger = logging.getLogger(__name__)

# Connection pooling - reuse client across calls
_opensearch_client = None

def get_opensearch_client(url: str = None, timeout: int = 30) -> OpenSearch:
    """Get or create a singleton OpenSearch client."""
    global _opensearch_client
    if _opensearch_client is None:
        from bandjacks.services.api.settings import settings
        os_url = url or settings.opensearch_url
        _opensearch_client = OpenSearch(os_url, timeout=timeout)
    return _opensearch_client


class BatchRetrieverAgent:
    """Retrieve technique candidates for all spans in a single batch operation."""
    
    def run(self, mem: WorkingMemory, config: Dict[str, Any]) -> None:
        """Process all spans in a batch for efficiency.
        
        Args:
            mem: Working memory with spans to process
            config: Configuration with top_k parameter
        """
        logger.info(f"[BatchRetrieverAgent] Starting with {len(mem.spans)} spans")
        print(f"[BatchRetrieverAgent] Starting with {len(mem.spans)} spans")
        if not mem.spans:
            logger.info("[BatchRetrieverAgent] No spans to process")
            print("[BatchRetrieverAgent] No spans to process")
            return
            
        top_k = int(config.get("top_k", 8))
        
        # Apply lexical hints to all span texts
        span_texts = [self._hinted_query(span["text"]) for span in mem.spans]
        
        logger.info(f"[BatchRetriever] Processing {len(span_texts)} spans in batch")
        print(f"[BatchRetriever] Processing {len(span_texts)} spans in batch")
        
        # Batch encode all texts at once
        import time
        start_time = time.time()
        vectors = batch_encode(span_texts)
        encode_time = time.time() - start_time
        logger.info(f"[BatchRetriever] Batch encoding took {encode_time:.2f}s for {len(span_texts)} texts")
        print(f"[BatchRetriever] Batch encoding took {encode_time:.2f}s for {len(span_texts)} texts")
        
        # Get OpenSearch client
        from bandjacks.services.api.settings import settings
        client = get_opensearch_client()
        
        # Build multi-search request
        msearch_body = []
        valid_indices = []
        
        for i, vec in enumerate(vectors):
            if vec is None:
                continue
            valid_indices.append(i)
            
            # Add index specification
            msearch_body.append({"index": settings.os_index_nodes})
            
            # Add search query
            msearch_body.append({
                "size": max(top_k, 20),  # Fetch extra for filtering
                "query": {
                    "knn": {
                        "embedding": {
                            "vector": vec,
                            "k": max(top_k, 20)
                        }
                    }
                },
                "_source": ["id", "stix_id", "external_id", "name", "kb_type", "attack_version", "text"]
            })
        
        if not msearch_body:
            print("[BatchRetriever] No valid vectors to search")
            return
            
        try:
            # Execute batch search
            search_start = time.time()
            response = client.msearch(body=msearch_body)
            search_time = time.time() - search_start
            logger.info(f"[BatchRetriever] msearch took {search_time:.2f}s for {len(valid_indices)} queries")
            print(f"[BatchRetriever] msearch took {search_time:.2f}s for {len(valid_indices)} queries")
            
            # Process results
            for idx, i in enumerate(valid_indices):
                if idx >= len(response["responses"]):
                    continue
                    
                search_result = response["responses"][idx]
                if "error" in search_result:
                    print(f"[BatchRetriever] Error for span {i}: {search_result['error']}")
                    continue
                
                # Initialize candidates list for this span
                mem.candidates.setdefault(i, [])
                seen = {c.get("external_id") for c in mem.candidates[i]}
                
                # Filter to AttackPattern types and add candidates
                added = 0
                for hit in search_result.get("hits", {}).get("hits", []):
                    src = hit["_source"]
                    
                    # Filter by kb_type
                    if src.get("kb_type") != "AttackPattern":
                        continue
                        
                    ext_id = src.get("external_id") or src.get("id")
                    if not ext_id or ext_id in seen:
                        continue
                    
                    # Look up metadata if needed
                    stix_id = src.get("stix_id") or src.get("id", "")
                    meta = mem.graph_cache.get(ext_id)
                    if not meta and stix_id:
                        meta = graph_lookup(stix_id)
                        if isinstance(meta, dict):
                            mem.graph_cache[ext_id] = meta
                    
                    # Extract name from text field or metadata
                    name = src.get("name", "")
                    if not name and src.get("text"):
                        # First line of text often contains the name
                        name = src["text"].split("\n", 1)[0]
                    if not name and meta:
                        name = meta.get("name", "")
                    
                    mem.candidates[i].append({
                        "external_id": ext_id,
                        "name": name,
                        "score": hit.get("_score", 0.0),
                        "stix_id": stix_id,
                        "source": "batch_retriever"
                    })
                    
                    added += 1
                    if added >= top_k:
                        break
                        
            print(f"[BatchRetriever] Added candidates for {len(valid_indices)} spans")
            
        except Exception as e:
            print(f"[BatchRetriever] Error in batch search: {e}")
            # Fallback to sequential retriever
            print("[BatchRetriever] Falling back to sequential retrieval")
            from bandjacks.llm.agents_v2 import RetrieverAgent
            RetrieverAgent().run(mem, config)
    
    def _hinted_query(self, text: str) -> str:
        """Add lexical hints to improve search relevance."""
        # Simplified hint list for common attack terms
        LEX = [
            "phish", "spear", "inject", "persist", "escalat", "evad",
            "credential", "lateral", "exfiltrat", "command", "control",
            "ransom", "encrypt", "backdoor", "rootkit", "malware"
        ]
        
        lower = text.lower()
        hits = [h for h in LEX if h in lower]
        return f"{text}\nHINTS: {', '.join(hits)}" if hits else text