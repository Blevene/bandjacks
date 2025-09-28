"""Actor (IntrusionSet) lookup endpoints.

Provides lightweight APIs to resolve actors by STIX ID and to search by
name/alias. Separated from reports routes for better organization.
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field
from typing import List, Optional
from neo4j import Session

from bandjacks.services.api.deps import get_neo4j_session
from bandjacks.services.actor_cache import actor_cache


router = APIRouter(prefix="/actors", tags=["actors"])


class Actor(BaseModel):
    id: str = Field(..., description="Intrusion set STIX ID")
    name: Optional[str] = None
    aliases: List[str] = Field(default_factory=list)


@router.get("/{actor_id}", response_model=Actor)
async def get_actor_by_id(actor_id: str, neo4j_session: Session = Depends(get_neo4j_session)) -> Actor:
    """Resolve intrusion set details by STIX ID."""
    # Try cache first
    cached = actor_cache.get(actor_id)
    if cached:
        return Actor(id=cached["id"], name=cached.get("name"), aliases=cached.get("aliases") or [])

    query = """
        MATCH (g:IntrusionSet {stix_id: $id})
        RETURN g.stix_id as id, g.name as name, coalesce(g.aliases, []) as aliases
        LIMIT 1
    """
    rec = neo4j_session.run(query, id=actor_id).single()
    if not rec:
        raise HTTPException(status_code=404, detail={
            "error": "ActorNotFound",
            "message": f"Intrusion set {actor_id} not found",
        })
    return Actor(id=rec["id"], name=rec["name"], aliases=rec["aliases"] or [])


class ActorSearchResponse(BaseModel):
    query: str
    results: List[Actor]
    total: int


@router.get("/search", response_model=ActorSearchResponse)
async def search_actors(query: str = Query(..., min_length=2), neo4j_session: Session = Depends(get_neo4j_session)) -> ActorSearchResponse:
    """Search intrusion sets by name or alias."""
    # Use cache if available; fall back to DB
    cached_results = actor_cache.search(query, limit=20)
    if cached_results:
        results = [Actor(id=r["id"], name=r.get("name"), aliases=r.get("aliases") or []) for r in cached_results]
        return ActorSearchResponse(query=query, results=results, total=len(results))

    cypher = """
        MATCH (g:IntrusionSet)
        WHERE toLower(g.name) CONTAINS toLower($query)
           OR ANY(alias IN g.aliases WHERE toLower(alias) CONTAINS toLower($query))
        RETURN g.stix_id as id, g.name as name, coalesce(g.aliases, []) as aliases
        LIMIT 20
    """
    results = [Actor(id=rec["id"], name=rec["name"], aliases=rec["aliases"] or []) for rec in neo4j_session.run(cypher, query=query)]
    return ActorSearchResponse(query=query, results=results, total=len(results))


