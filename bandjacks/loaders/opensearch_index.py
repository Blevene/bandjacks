"""OpenSearch index management."""

from opensearchpy import OpenSearch
from typing import Dict, Any


class OpenSearchIndexManager:
    """Manages OpenSearch indexes and mappings."""
    
    def __init__(self, client: OpenSearch):
        self.client = client
    
    def create_attack_pattern_index(self):
        """Create index for attack patterns with KNN vectors."""
        index_name = "attack_patterns"
        
        if self.client.indices.exists(index=index_name):
            print(f"Index {index_name} already exists")
            return
        
        mapping = {
            "settings": {
                "index": {
                    "knn": True,
                    "knn.algo_param.ef_search": 100
                }
            },
            "mappings": {
                "properties": {
                    "stix_id": {"type": "keyword"},
                    "name": {"type": "text"},
                    "description": {"type": "text"},
                    "tactics": {"type": "keyword"},
                    "platforms": {"type": "keyword"},
                    "is_subtechnique": {"type": "boolean"},
                    "created": {"type": "date"},
                    "modified": {"type": "date"},
                    "embedding": {
                        "type": "knn_vector",
                        "dimension": 768,
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "nmslib",
                            "parameters": {
                                "ef_construction": 128,
                                "m": 24
                            }
                        }
                    }
                }
            }
        }
        
        self.client.indices.create(index=index_name, body=mapping)
        print(f"Created index: {index_name}")
    
    def create_attack_flow_index(self):
        """Create index for attack flows."""
        index_name = "attack_flows"
        
        if self.client.indices.exists(index=index_name):
            print(f"Index {index_name} already exists")
            return
        
        mapping = {
            "mappings": {
                "properties": {
                    "flow_id": {"type": "keyword"},
                    "source_id": {"type": "keyword"},
                    "created": {"type": "date"},
                    "episodes": {
                        "type": "nested",
                        "properties": {
                            "episode_id": {"type": "keyword"},
                            "actions": {"type": "keyword"},
                            "tactics": {"type": "keyword"},
                            "timestamp": {"type": "date"}
                        }
                    },
                    "flow_embedding": {
                        "type": "knn_vector",
                        "dimension": 768,
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "nmslib"
                        }
                    }
                }
            }
        }
        
        self.client.indices.create(index=index_name, body=mapping)
        print(f"Created index: {index_name}")
    
    def create_review_queue_index(self):
        """Create index for review queue."""
        index_name = "review_queue"
        
        if self.client.indices.exists(index=index_name):
            print(f"Index {index_name} already exists")
            return
        
        mapping = {
            "mappings": {
                "properties": {
                    "review_id": {"type": "keyword"},
                    "type": {"type": "keyword"},
                    "source_text": {"type": "text"},
                    "proposed_mapping": {"type": "keyword"},
                    "confidence": {"type": "float"},
                    "created": {"type": "date"},
                    "status": {"type": "keyword"},
                    "decision": {"type": "keyword"},
                    "reviewed_by": {"type": "keyword"},
                    "reviewed_at": {"type": "date"}
                }
            }
        }
        
        self.client.indices.create(index=index_name, body=mapping)
        print(f"Created index: {index_name}")
    
    def create_detection_strategies_index(self):
        """Create index for detection strategies."""
        index_name = "detection_strategies"
        
        if self.client.indices.exists(index=index_name):
            print(f"Index {index_name} already exists")
            return
        
        mapping = {
            "settings": {
                "index": {
                    "knn": True,
                    "knn.algo_param.ef_search": 100
                }
            },
            "mappings": {
                "properties": {
                    "stix_id": {"type": "keyword"},
                    "name": {"type": "text"},
                    "description": {"type": "text"},
                    "det_id": {"type": "keyword"},
                    "x_mitre_version": {"type": "keyword"},
                    "x_mitre_domains": {"type": "keyword"},
                    "revoked": {"type": "boolean"},
                    "x_mitre_deprecated": {"type": "boolean"},
                    "created": {"type": "date"},
                    "modified": {"type": "date"},
                    "strategy_embedding": {
                        "type": "knn_vector",
                        "dimension": 768,
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "nmslib",
                            "parameters": {
                                "ef_construction": 128,
                                "m": 24
                            }
                        }
                    }
                }
            }
        }
        
        self.client.indices.create(index=index_name, body=mapping)
        print(f"Created index: {index_name}")
    
    def create_analytics_index(self):
        """Create index for analytics."""
        index_name = "analytics"
        
        if self.client.indices.exists(index=index_name):
            print(f"Index {index_name} already exists")
            return
        
        mapping = {
            "settings": {
                "index": {
                    "knn": True,
                    "knn.algo_param.ef_search": 100
                }
            },
            "mappings": {
                "properties": {
                    "stix_id": {"type": "keyword"},
                    "name": {"type": "text"},
                    "description": {"type": "text"},
                    "platforms": {"type": "keyword"},
                    "x_mitre_detects": {"type": "text"},
                    "x_mitre_mutable_elements": {"type": "keyword"},
                    "revoked": {"type": "boolean"},
                    "x_mitre_deprecated": {"type": "boolean"},
                    "created": {"type": "date"},
                    "modified": {"type": "date"},
                    "analytic_embedding": {
                        "type": "knn_vector",
                        "dimension": 768,
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "nmslib",
                            "parameters": {
                                "ef_construction": 128,
                                "m": 24
                            }
                        }
                    }
                }
            }
        }
        
        self.client.indices.create(index=index_name, body=mapping)
        print(f"Created index: {index_name}")
    
    def create_log_sources_index(self):
        """Create index for log sources."""
        index_name = "log_sources"
        
        if self.client.indices.exists(index=index_name):
            print(f"Index {index_name} already exists")
            return
        
        mapping = {
            "settings": {
                "index": {
                    "knn": True,
                    "knn.algo_param.ef_search": 100
                }
            },
            "mappings": {
                "properties": {
                    "stix_id": {"type": "keyword"},
                    "name": {"type": "text"},
                    "description": {"type": "text"},
                    "x_mitre_log_source_permutations": {"type": "nested"},
                    "created": {"type": "date"},
                    "modified": {"type": "date"},
                    "log_source_embedding": {
                        "type": "knn_vector",
                        "dimension": 768,
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "nmslib",
                            "parameters": {
                                "ef_construction": 128,
                                "m": 24
                            }
                        }
                    }
                }
            }
        }
        
        self.client.indices.create(index=index_name, body=mapping)
        print(f"Created index: {index_name}")
    
    def create_reports_index(self):
        """Create index for ingested reports with review data."""
        index_name = "bandjacks_reports"
        
        if self.client.indices.exists(index=index_name):
            print(f"Index {index_name} already exists")
            return
        
        mapping = {
            "settings": {
                "index": {
                    "knn": True,
                    "knn.algo_param.ef_search": 100
                }
            },
            "mappings": {
                "properties": {
                    # Report identification
                    "report_id": {"type": "keyword"},
                    "job_id": {"type": "keyword"},
                    "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "description": {"type": "text"},
                    
                    # Full text content
                    "raw_text": {"type": "text", "index": True},  # Full report text for search
                    "text_chunks": {  # Array of text chunks for retrieval
                        "type": "nested",
                        "properties": {
                            "chunk_id": {"type": "integer"},
                            "text": {"type": "text"},
                            "start_idx": {"type": "integer"},
                            "end_idx": {"type": "integer"}
                        }
                    },
                    
                    # Embeddings for semantic search
                    "text_embedding": {  # Full document embedding
                        "type": "knn_vector",
                        "dimension": 768,
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "nmslib",
                            "parameters": {
                                "ef_construction": 128,
                                "m": 24
                            }
                        }
                    },
                    "chunk_embeddings": {  # Array of chunk embeddings
                        "type": "nested",
                        "properties": {
                            "chunk_id": {"type": "integer"},
                            "embedding": {
                                "type": "knn_vector",
                                "dimension": 768,
                                "method": {
                                    "name": "hnsw",
                                    "space_type": "cosinesimil",
                                    "engine": "nmslib",
                                    "parameters": {
                                        "ef_construction": 128,
                                        "m": 24
                                    }
                                }
                            }
                        }
                    },
                    
                    # Timestamps
                    "created": {"type": "date"},
                    "modified": {"type": "date"},
                    "published": {"type": "date"},
                    "ingested_at": {"type": "date"},
                    
                    # Status tracking
                    "status": {"type": "keyword"},  # pending_review, reviewed, approved
                    "extraction_status": {"type": "keyword"},  # pending, processing, completed, failed
                    
                    # Extraction results
                    "extraction": {
                        "type": "object",
                        "properties": {
                            "techniques_count": {"type": "integer"},
                            "claims_count": {"type": "integer"},
                            "confidence_avg": {"type": "float"},
                            "metrics": {"type": "object", "enabled": False},  # Store as unindexed JSON
                            "bundle": {"type": "object", "enabled": False},  # STIX bundle stored as JSON
                            "claims": {"type": "object", "enabled": False}  # Claims stored as JSON
                        }
                    },
                    
                    # Review data
                    "review": {
                        "type": "object",
                        "properties": {
                            "reviewer_id": {"type": "keyword"},
                            "reviewed_at": {"type": "date"},
                            "approved_count": {"type": "integer"},
                            "rejected_count": {"type": "integer"},
                            "edited_count": {"type": "integer"},
                            "decisions": {"type": "object", "enabled": False},  # Store as unindexed JSON
                            "notes": {"type": "text"}
                        }
                    },
                    
                    # Approval data
                    "approval": {
                        "type": "object",
                        "properties": {
                            "approver_id": {"type": "keyword"},
                            "approved_at": {"type": "date"},
                            "upserted": {"type": "boolean"},
                            "upserted_at": {"type": "date"}
                        }
                    },
                    
                    # Campaign and flow associations
                    "campaign": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "keyword"},
                            "name": {"type": "text"},
                            "provisional": {"type": "boolean"}
                        }
                    },
                    "flow": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "keyword"},
                            "generated": {"type": "boolean"},
                            "generated_at": {"type": "date"},
                            "episode_type": {"type": "keyword"},
                            "actions_count": {"type": "integer"},
                            "edges_count": {"type": "integer"},
                            "flow_type": {"type": "keyword"}
                        }
                    },
                    
                    # Attribution information
                    "attribution": {
                        "type": "object",
                        "properties": {
                            "intrusion_sets": {"type": "keyword"},  # Array of intrusion set STIX IDs
                            "malware": {"type": "keyword"},  # Array of malware/tool STIX IDs
                            "confidence": {"type": "float"},
                            "notes": {"type": "text"},
                            "updated_at": {"type": "date"}
                        }
                    },
                    
                    # Source information
                    "source": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "keyword"},  # file, url, inline
                            "filename": {"type": "text"},
                            "url": {"type": "keyword"},
                            "content_size": {"type": "long"}
                        }
                    },
                    
                    # For search
                    "techniques": {"type": "keyword"},  # Array of technique IDs
                    "actors": {"type": "keyword"},  # Array of actor names
                    "software": {"type": "keyword"}  # Array of software names
                }
            }
        }
        
        self.client.indices.create(index=index_name, body=mapping)
        print(f"Created index: {index_name}")
    
    def initialize_indexes(self):
        """Initialize all required indexes."""
        self.create_attack_pattern_index()
        self.create_attack_flow_index()
        self.create_review_queue_index()
        self.create_detection_strategies_index()
        self.create_analytics_index()
        self.create_log_sources_index()
        self.create_reports_index()
        print("OpenSearch indexes initialized successfully")


def ensure_attack_nodes_index(opensearch_url: str, index_name: str):
    """Ensure the attack nodes index exists in OpenSearch."""
    client = OpenSearch(
        hosts=[opensearch_url],
        use_ssl=False,
        verify_certs=False
    )
    
    if client.indices.exists(index=index_name):
        print(f"Index {index_name} already exists")
        return
    
    mapping = {
        "settings": {
            "index": {
                "knn": True,
                "knn.algo_param.ef_search": 100
            }
        },
        "mappings": {
            "properties": {
                "id": {"type": "keyword"},
                "kb_type": {"type": "keyword"},
                "attack_version": {"type": "keyword"},
                "revoked": {"type": "boolean"},
                "external_id": {"type": "keyword"},  # T-number, M-number, etc.
                "name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},  # Name for display
                "text": {"type": "text"},
                "embedding": {
                    "type": "knn_vector",
                    "dimension": 768,
                    "method": {
                        "name": "hnsw",
                        "space_type": "cosinesimil",
                        "engine": "nmslib",
                        "parameters": {
                            "ef_construction": 128,
                            "m": 24
                        }
                    }
                }
            }
        }
    }
    
    client.indices.create(index=index_name, body=mapping)
    print(f"Created index: {index_name}")


def upsert_node_embedding(os_url: str, index: str, doc: Dict[str, Any]):
    """Upsert a document with embeddings to OpenSearch."""
    client = OpenSearch(
        hosts=[os_url],
        use_ssl=False,
        verify_certs=False
    )
    
    client.index(
        index=index,
        id=doc.get("id"),
        body=doc
    )


def ensure_attack_flows_index(opensearch_url: str):
    """Ensure the attack flows index exists in OpenSearch."""
    client = OpenSearch(
        hosts=[opensearch_url],
        use_ssl=False,
        verify_certs=False
    )
    
    index_name = "attack_flows"
    
    if client.indices.exists(index=index_name):
        print(f"Index {index_name} already exists")
        return
    
    mapping = {
        "settings": {
            "index": {
                "knn": True,
                "knn.algo_param.ef_search": 100
            }
        },
        "mappings": {
            "properties": {
                "flow_id": {"type": "keyword"},
                "episode_id": {"type": "keyword"},
                "name": {"type": "text"},
                "source_id": {"type": "keyword"},
                "created": {"type": "date"},
                "flow_text": {"type": "text"},  # Full flow text, no truncation
                "steps_count": {"type": "integer"},
                "avg_confidence": {"type": "float"},
                "llm_synthesized": {"type": "boolean"},
                "tactics": {"type": "keyword"},
                "techniques": {"type": "keyword"},
                "flow_embedding": {
                    "type": "knn_vector",
                    "dimension": 768,
                    "method": {
                        "name": "hnsw",
                        "space_type": "cosinesimil",
                        "engine": "nmslib",
                        "parameters": {
                            "ef_construction": 128,
                            "m": 24
                        }
                    }
                }
            }
        }
    }
    
    client.indices.create(index=index_name, body=mapping)
    print(f"Created index: {index_name}")


def upsert_flow_embedding(os_url: str, index: str, doc: Dict[str, Any]):
    """Upsert a flow document with embeddings to OpenSearch."""
    client = OpenSearch(
        hosts=[os_url],
        use_ssl=False,
        verify_certs=False
    )
    
    client.index(
        index=index,
        id=doc.get("flow_id"),
        body=doc
    )