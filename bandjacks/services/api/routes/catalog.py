"""Catalog routes for ATT&CK releases."""

from fastapi import APIRouter, HTTPException
from bandjacks.services.api.settings import settings
from bandjacks.loaders.attack_catalog import fetch_catalog
from bandjacks.services.api.schemas import CatalogItem, VersionRef

router = APIRouter(tags=["catalog"])

@router.get("/catalog/attack/releases", response_model=list[CatalogItem])
async def get_attack_releases():
    try:
        cat = fetch_catalog(settings.attack_index_url)
        return [
            CatalogItem(
                name=c.name,
                key=c.key,
                versions=[VersionRef(version=v.version, url=v.url, modified=v.modified) for v in c.versions]
            )
            for c in cat.values()
        ]
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch catalog: {e}")