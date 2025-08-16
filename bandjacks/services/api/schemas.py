"""Pydantic schemas for API requests and responses."""

from typing import Any, List, Optional, Dict
from pydantic import BaseModel, Field

class VersionRef(BaseModel):
    version: str
    url: str
    modified: Optional[str] = None

class CatalogItem(BaseModel):
    name: str
    key: str
    versions: List[VersionRef]

class UpsertProvenance(BaseModel):
    collection: str
    version: str
    modified: Optional[str] = None
    url: str
    adm_spec: Optional[str] = None
    adm_sha: Optional[str] = None

class UpsertResult(BaseModel):
    inserted: int = 0
    updated: int = 0
    rejected: List[Dict[str, Any]] = Field(default_factory=list)
    provenance: UpsertProvenance
    trace_id: Optional[str] = None