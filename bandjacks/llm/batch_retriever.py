"""Batch retriever agent for efficient OpenSearch queries."""

import logging
from typing import Dict, Any, List, Optional, Tuple
from functools import lru_cache
import hashlib
from opensearchpy import OpenSearch
from bandjacks.llm.memory import WorkingMemory
from bandjacks.loaders.embedder import batch_encode
from bandjacks.llm.tools import graph_lookup
import os

logger = logging.getLogger(__name__)

# Connection pooling - reuse client across calls
_opensearch_client = None

# Cache for embedding results - shared across all BatchRetrieverAgent instances
_embedding_cache = {}
_cache_hits = 0
_cache_misses = 0

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
        global _cache_hits, _cache_misses
        
        logger.info(f"[BatchRetrieverAgent] Starting with {len(mem.spans)} spans")
        logger.debug(f"[BatchRetrieverAgent] Starting with {len(mem.spans)} spans")
        if not mem.spans:
            logger.info("[BatchRetrieverAgent] No spans to process")
            logger.debug("[BatchRetrieverAgent] No spans to process")
            return
            
        top_k = int(config.get("top_k", 8))
        use_cache = config.get("use_embedding_cache", True)
        
        # Apply lexical hints to all span texts
        span_texts = [self._hinted_query(span["text"]) for span in mem.spans]
        
        # Deduplicate span texts before encoding
        unique_texts, text_to_indices = self._deduplicate_texts(span_texts)
        logger.info(f"[BatchRetriever] Deduplication: {len(span_texts)} spans → {len(unique_texts)} unique texts")
        
        # Separate cached vs uncached texts
        vectors_to_encode = []
        cached_vectors = {}
        
        if use_cache:
            for i, text in enumerate(unique_texts):
                text_hash = self._get_text_hash(text)
                if text_hash in _embedding_cache:
                    cached_vectors[i] = _embedding_cache[text_hash]
                    _cache_hits += 1
                else:
                    vectors_to_encode.append((i, text))
                    _cache_misses += 1
            
            logger.info(f"[BatchRetriever] Cache stats: {_cache_hits} hits, {_cache_misses} misses")
        else:
            vectors_to_encode = [(i, text) for i, text in enumerate(unique_texts)]
        
        # Batch encode only uncached texts
        import time
        vectors = [None] * len(unique_texts)
        
        if vectors_to_encode:
            texts_to_encode = [text for _, text in vectors_to_encode]
            start_time = time.time()
            encoded_vectors = batch_encode(texts_to_encode)
            encode_time = time.time() - start_time
            logger.info(f"[BatchRetriever] Batch encoding took {encode_time:.2f}s for {len(texts_to_encode)} unique texts")
            
            # Place encoded vectors and update cache
            for (idx, text), vec in zip(vectors_to_encode, encoded_vectors):
                vectors[idx] = vec
                if use_cache and vec is not None:
                    text_hash = self._get_text_hash(text)
                    _embedding_cache[text_hash] = vec
        
        # Add cached vectors
        for idx, vec in cached_vectors.items():
            vectors[idx] = vec
        
        # Get OpenSearch client
        from bandjacks.services.api.settings import settings
        client = get_opensearch_client()
        
        # Build multi-search request for unique vectors only
        msearch_body = []
        unique_to_search_idx = {}  # Maps unique text index to search result index
        search_idx = 0
        
        for unique_idx, vec in enumerate(vectors):
            if vec is None:
                continue
            unique_to_search_idx[unique_idx] = search_idx
            search_idx += 1
            
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
            logger.debug("[BatchRetriever] No valid vectors to search")
            return
            
        try:
            # Execute batch search
            search_start = time.time()
            response = client.msearch(body=msearch_body)
            search_time = time.time() - search_start
            logger.info(f"[BatchRetriever] msearch took {search_time:.2f}s for {len(unique_to_search_idx)} queries")
            logger.debug(f"[BatchRetriever] msearch took {search_time:.2f}s for {len(unique_to_search_idx)} queries")
            
            # Process results and map back to original span indices
            unique_candidates = {}
            for unique_idx, search_idx in unique_to_search_idx.items():
                if search_idx >= len(response["responses"]):
                    continue
                    
                search_result = response["responses"][search_idx]
                if "error" in search_result:
                    logger.debug(f"[BatchRetriever] Error for unique text {unique_idx}: {search_result['error']}")
                    continue
                
                # Store candidates for this unique text
                unique_candidates[unique_idx] = []
                seen = set()  # Track seen external_ids to avoid duplicates
                
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
                    seen.add(ext_id)  # Mark as seen
                    
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
                    
                    unique_candidates[unique_idx].append({
                        "external_id": ext_id,
                        "name": name,
                        "score": hit.get("_score", 0.0),
                        "stix_id": stix_id,
                        "source": "batch_retriever"
                    })
                    
                    added += 1
                    if added >= top_k:
                        break
            
            # Map candidates from unique texts back to original span indices
            for span_idx, unique_idx in enumerate(text_to_indices):
                if unique_idx in unique_candidates:
                    mem.candidates.setdefault(span_idx, [])
                    mem.candidates[span_idx].extend(unique_candidates[unique_idx])
                        
            logger.debug(f"[BatchRetriever] Added candidates for {len(mem.candidates)} spans from {len(unique_candidates)} unique searches")
            
        except Exception as e:
            logger.debug(f"[BatchRetriever] Error in batch search: {e}")
            # Fallback to sequential retriever
            logger.debug("[BatchRetriever] Falling back to sequential retrieval")
            from bandjacks.llm.agents_v2 import RetrieverAgent
            RetrieverAgent().run(mem, config)
    
    def _deduplicate_texts(self, texts: List[str]) -> Tuple[List[str], List[int]]:
        """
        Deduplicate texts while tracking original indices.
        
        Args:
            texts: List of potentially duplicate texts
            
        Returns:
            Tuple of (unique_texts, text_to_unique_idx)
            where text_to_unique_idx[i] gives the unique text index for original text i
        """
        unique_texts = []
        text_to_unique = {}
        text_to_indices = []
        
        for text in texts:
            if text not in text_to_unique:
                text_to_unique[text] = len(unique_texts)
                unique_texts.append(text)
            text_to_indices.append(text_to_unique[text])
        
        return unique_texts, text_to_indices
    
    def _get_text_hash(self, text: str) -> str:
        """
        Generate a hash for text to use as cache key.
        
        Args:
            text: Text to hash
            
        Returns:
            Hash string for the text
        """
        return hashlib.md5(text.encode('utf-8')).hexdigest()
    
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