"""STIX loading routes."""

from fastapi import APIRouter, HTTPException, Query
from bandjacks.services.api.settings import settings
from bandjacks.services.api.schemas import UpsertResult
from bandjacks.loaders.attack_upsert import resolve_bundle, fetch_bundle, adm_validate, upsert_to_graph_and_vectors
from bandjacks.loaders.provenance import make_provenance

router = APIRouter(tags=["stix"])

@router.post("/stix/load/attack", response_model=UpsertResult)
async def load_attack_collection(
    collection: str = Query(..., pattern="^(enterprise-attack|mobile-attack|ics-attack)$"),
    version: str | None = Query(None, description="e.g., 17.1 or 'latest'"),
    adm_strict: bool = Query(True),
    force: bool = Query(False),
):
    try:
        url, resolved_version, modified = resolve_bundle(settings.attack_index_url, collection, version)
        bundle = fetch_bundle(url)

        ok, rejected, adm_sha = adm_validate(bundle, adm_strict, settings.adm_mode, settings.adm_spec_min)
        if not ok and adm_strict:
            return UpsertResult(
                inserted=0, updated=0, rejected=rejected,
                provenance=make_provenance(collection, resolved_version, modified, url, settings.adm_spec_min, adm_sha)
            )

        inserted, updated = upsert_to_graph_and_vectors(
            bundle=bundle, collection=collection, version=resolved_version,
            neo4j_uri=settings.neo4j_uri, neo4j_user=settings.neo4j_user, neo4j_password=settings.neo4j_password,
            os_url=settings.opensearch_url, os_index=settings.os_index_nodes
        )

        return UpsertResult(
            inserted=inserted, updated=updated, rejected=rejected,
            provenance=make_provenance(collection, resolved_version, modified, url, settings.adm_spec_min, adm_sha)
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Load failed: {e}")