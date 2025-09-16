"""Application settings and configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    api_prefix: str = "/v1"
    api_title: str = "Bandjacks API"

    attack_index_url: str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "neo4j"

    opensearch_url: str = "http://localhost:9200"
    opensearch_user: str = "admin"
    opensearch_password: str = "admin"
    os_index_nodes: str = "bandjacks_attack_nodes-v1"

    adm_mode: str = "schema"   # "sidecar" | "schema"
    adm_base_url: str = "http://localhost:8080"
    adm_spec_min: str = "3.3.0"
    
    # LiteLLM configuration
    litellm_base_url: str = "http://localhost:4000"
    litellm_api_key: str = ""
    litellm_model: str = "gpt-4o-mini"
    litellm_timeout_ms: int = 30000
    litellm_temperature: float = 1.0
    litellm_max_tokens: int = 800
    
    # API Keys for LLM services (loaded from environment)
    openai_api_key: str = ""
    google_api_key: str = ""
    openai_model: str = "gpt-5"  # OpenAI model (backup)
    google_model: str = "gemini-2.5-flash"  # Primary Google model
    primary_llm: str = "gemini"  # Use Gemini as primary
    
    # Authentication settings
    enable_auth: bool = False  # Feature flag for JWT/OIDC
    oidc_issuer: str = ""  # OIDC issuer URL
    oidc_audience: str = "bandjacks-api"  # Expected audience
    jwt_algorithm: str = "RS256"  # JWT algorithm
    jwt_secret: str = ""  # Must be set via environment variable JWT_SECRET
    require_auth_for_reads: bool = False  # Require auth for GET requests
    
    # Redis settings for job queue and distributed locking
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str = ""
    redis_lock_timeout: int = 600  # 10 minutes max lock time
    redis_heartbeat_interval: int = 30  # Worker heartbeat every 30s
    
    # Job processing settings
    job_claim_ttl: int = 300  # 5 minutes to process a job before it's reclaimed
    job_heartbeat_ttl: int = 60  # Heartbeat expires after 60s
    worker_id_prefix: str = "worker"  # Prefix for worker IDs
    
    # Rate limiting settings
    rate_limit_enabled: bool = True  # Enable rate limiting
    default_rate_limit: int = 100  # Requests per minute
    rate_limit_window: int = 60  # Window size in seconds
    burst_allowance: float = 1.5  # Burst multiplier
    
    # Progressive Accumulation and Early Termination Settings
    enable_early_termination: bool = True
    early_termination_threshold: float = 100.0
    min_techniques_for_termination: int = 40
    confidence_boost: float = 5.0
    max_context_hints: int = 10
    
    # Mapper Batch Size Settings
    mapper_batch_size: int = 20  # Default batch size for BatchMapperAgent
    max_mapper_batch_size: int = 25  # Maximum allowed batch size
    
    # Vector Search Cache Settings
    vector_cache_enabled: bool = True  # Enable vector search caching
    vector_cache_max_size: int = 5000  # Maximum cache entries (LRU eviction)
    vector_cache_ttl: int = 3600  # Cache TTL in seconds (1 hour)
    vector_result_cache_enabled: bool = True  # Cache full search results
    vector_cache_redis_enabled: bool = True  # Use Redis for shared cache
    
    # Extraction Pipeline Configuration
    use_optimized_extractor: bool = True  # Use optimized chunked extractor
    chunk_size: int = 4000  # Size of text chunks for processing
    max_chunks: int = 30  # Maximum number of chunks to process
    chunk_overlap: int = 200  # Overlap between chunks
    
    # Batch Processing Configuration
    parallel_workers: int = 4  # Number of parallel workers for chunk processing
    batch_encoding_size: int = 100  # Max texts to encode in one batch
    opensearch_batch_size: int = 50  # Max queries per OpenSearch msearch
    
    # Entity Extraction Configuration
    use_entity_claims: bool = True  # Use claim-based entity extraction
    entity_single_pass_limit: int = 30000  # Max text size for single-pass entity extraction
    entity_window_size: int = 30000  # Window size for progressive entity extraction
    entity_overlap_size: int = 5000  # Overlap for entity extraction windows
    
    # Span Detection Configuration  
    span_detection_threshold: int = 30000  # Threshold for global vs windowed span detection
    span_window_size: int = 30000  # Window size for span detection
    span_overlap_size: int = 5000  # Overlap for span detection windows
    
    # Quality Improvement Configuration
    enable_sentence_evidence: bool = True  # Extract complete sentences as evidence
    context_sentences: int = 1  # Number of context sentences around evidence
    
    # Semantic Deduplication Configuration
    enable_semantic_dedup: bool = True  # Use embedding-based deduplication
    semantic_dedup_threshold: float = 0.85  # Similarity threshold for techniques/evidence
    entity_dedup_threshold: float = 0.90  # Higher threshold for entities (avoid false merges)
    deduplicate_techniques: bool = True  # Deduplicate similar techniques
    deduplicate_entities: bool = True  # Deduplicate similar entities (APT29/Cozy Bear)
    
    # Performance Monitoring
    enable_performance_logging: bool = True  # Log performance metrics
    log_batch_statistics: bool = True  # Log batch processing statistics

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()