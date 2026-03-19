"""Search functionality for nodes using KNN vectors."""

from typing import List, Optional
from opensearchpy import OpenSearch
from bandjacks.loaders.embedder import encode

def ttx_search(os_url: str, index: str, text: str, top_k: int = 10):
    """
    Search for techniques similar to input text using KNN.
    
    Args:
        os_url: OpenSearch URL
        index: Index name to search
        text: Query text
        top_k: Number of results to return
        
    Returns:
        List of matching techniques with scores
    """
    client = OpenSearch(os_url, timeout=30)
    qvec = encode(text)
    
    if qvec is None:
        return []
    
    body = {
        "size": top_k,
        "query": {
            "knn": {
                "embedding": {
                    "vector": qvec,
                    "k": top_k
                }
            }
        },
        "_source": ["id", "kb_type", "attack_version", "text"]
    }
    
    resp = client.search(index=index, body=body)
    out = []
    
    for hit in resp["hits"]["hits"]:
        src = hit["_source"]
        out.append({
            "stix_id": src.get("id"),
            "kb_type": src.get("kb_type"),
            "attack_version": src.get("attack_version"),
            "score": hit.get("_score", 0.0),
            "name_or_snippet": (src.get("text") or "").split("\n", 1)[0]
        })
    
    return out


def ttx_search_kb(os_url: str, index: str, text: str, top_k: int = 10, kb_types: Optional[List[str]] = None, client: Optional[OpenSearch] = None):
    """
    Search for nodes similar to input text using KNN with optional kb_type filtering.

    Args:
        os_url: OpenSearch URL
        index: Index name to search
        text: Query text
        top_k: Number of results to return
        kb_types: Optional list of kb_types to filter (e.g., ['AttackPattern', 'IntrusionSet'])
        client: Optional pre-existing OpenSearch client to reuse (avoids creating a new one per call)

    Returns:
        List of matching nodes with scores, filtered by kb_type if specified
    """
    if client is None:
        client = OpenSearch(os_url, timeout=30)
    qvec = encode(text)
    
    if qvec is None:
        return []
    
    # Fetch extra results to allow for filtering
    fetch_size = max(top_k, 20) if not kb_types else max(top_k * 2, 30)
    
    body = {
        "size": fetch_size,
        "query": {
            "knn": {
                "embedding": {
                    "vector": qvec,
                    "k": fetch_size
                }
            }
        },
        "_source": ["id", "kb_type", "attack_version", "text", "name", "external_id"]  # Include name and external_id
    }
    
    resp = client.search(index=index, body=body)
    out = []
    
    for hit in resp.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        
        # Filter by kb_types if specified
        if kb_types and src.get("kb_type") not in kb_types:
            continue
            
        out.append({
            "stix_id": src.get("id"),
            "kb_type": src.get("kb_type"),
            "attack_version": src.get("attack_version"),
            "score": hit.get("_score", 0.0),
            "name": src.get("name"),  # Include actual name if available
            "external_id": src.get("external_id"),  # Include T-number
            "name_or_snippet": src.get("name") or (src.get("text") or "").split("\n", 1)[0]
        })
        
        # Stop when we have enough results
        if len(out) >= top_k:
            break
    
    return out