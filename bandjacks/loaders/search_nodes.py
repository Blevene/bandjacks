"""Search functionality for nodes using KNN vectors."""

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