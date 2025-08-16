"""Application settings and configuration."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    api_prefix: str = "/v1"
    api_title: str = "Bandjacks API"

    attack_index_url: str = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""

    opensearch_url: str = "http://localhost:9200"
    os_index_nodes: str = "bandjacks_attack_nodes-v1"

    adm_mode: str = "schema"   # "sidecar" | "schema"
    adm_base_url: str = "http://localhost:8080"
    adm_spec_min: str = "3.3.0"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()