"""Edge embeddings functionality for relationship indexing."""

from opensearchpy import OpenSearch
from bandjacks.loaders.embedder import encode


def ensure_attack_edges_index(os_url: str, index: str = "bandjacks_attack_edges-v1"):
    """Ensure the attack edges index exists in OpenSearch."""
    client = OpenSearch(hosts=[os_url], timeout=30, use_ssl=False, verify_certs=False)
    
    if client.indices.exists(index=index):
        print(f"Index {index} already exists")
        return
    
    mapping = {
        "settings": {"index": {"knn": True}},
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "edge_type": {"type": "keyword"},   # USES, MITIGATES
                "source_id": {"type": "keyword"},
                "target_id": {"type": "keyword"},
                "attack_version": {"type": "keyword"},
                "text": {"type": "text"},
                "embedding": {"type": "knn_vector", "dimension": 768}
            }
        }
    }
    
    client.indices.create(index=index, body=mapping)
    print(f"Created index: {index}")


def upsert_edge_doc(os_url: str, index: str, doc: dict):
    """Upsert an edge document to OpenSearch."""
    client = OpenSearch(hosts=[os_url], timeout=30, use_ssl=False, verify_certs=False)
    client.index(index=index, id=doc["id"], body=doc)


def bulk_upsert_edge_docs(os_url: str, index: str, docs: list[dict]):
    """Bulk upsert edge documents to OpenSearch.

    Args:
        os_url: OpenSearch URL
        index: Target index name
        docs: List of edge dicts with 'id', 'embedding', etc.
    """
    if not docs:
        return

    client = OpenSearch(hosts=[os_url], timeout=60, use_ssl=False, verify_certs=False)

    body = []
    for doc in docs:
        body.append({"index": {"_index": index, "_id": doc["id"]}})
        body.append(doc)

    resp = client.bulk(body=body)
    if resp.get("errors"):
        failed = [item for item in resp["items"] if item.get("index", {}).get("error")]
        print(f"[bulk-edge] {len(failed)}/{len(docs)} failed: {failed[:3]}")
    else:
        print(f"[bulk-edge] indexed {len(docs)} docs to {index}")