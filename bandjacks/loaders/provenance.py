"""Provenance tracking for loaded data."""

from bandjacks.services.api.schemas import UpsertProvenance

def make_provenance(collection: str, version: str, modified: str | None, url: str, adm_spec: str | None, adm_sha: str | None) -> UpsertProvenance:
    return UpsertProvenance(collection=collection, version=version, modified=modified, url=url, adm_spec=adm_spec, adm_sha=adm_sha)