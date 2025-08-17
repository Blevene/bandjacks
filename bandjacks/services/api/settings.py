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

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()