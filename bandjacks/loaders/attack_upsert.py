"""ATT&CK data upserter for Neo4j and OpenSearch."""

import httpx
import orjson
from typing import Tuple
from neo4j import GraphDatabase
from .attack_catalog import fetch_catalog
from .opensearch_index import upsert_node_embedding

def resolve_bundle(index_url: str, collection: str, version: str | None) -> Tuple[str,str|None,str|None]:
    cat = fetch_catalog(index_url)
    if collection not in cat: raise ValueError(f"Unknown collection: {collection}")
    versions = cat[collection].versions
    if not versions: raise ValueError(f"No versions for {collection}")
    if version in (None, "", "latest"):
        v = versions[0]
    else:
        v = next((x for x in versions if x.version == version), None)
        if not v: raise ValueError(f"Version {version} not found for {collection}")
    return v.url, v.version, v.modified

def fetch_bundle(url: str) -> dict:
    r = httpx.get(url, timeout=60)
    r.raise_for_status()
    return r.json()

def adm_validate(bundle: dict, strict: bool, adm_mode: str, adm_spec_min: str) -> tuple[bool, list[dict], str | None]:
    # Sprint-1: permissive; wire ADM in Sprint-2
    return True, [], None

def _ap_text(obj: dict, tactic_names: list[str]) -> str:
    name = obj.get("name","")
    desc = obj.get("description","")
    det  = obj.get("x_mitre_detection","")
    platforms = ", ".join(obj.get("x_mitre_platforms",[]) or obj.get("x_mitre_platforms",""))
    return f"{name}\n{desc}\nDetection: {det}\nTactics: {', '.join(tactic_names)}\nPlatforms: {platforms}"

def upsert_to_graph_and_vectors(
    bundle: dict, collection: str, version: str,
    neo4j_uri: str, neo4j_user: str, neo4j_password: str,
    os_url: str, os_index: str
) -> tuple[int,int]:
    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
    inserted = updated = 0

    # pre-collect tactics by shortname for quick lookups
    tactics = {o["id"]: o for o in bundle["objects"] if o.get("type") == "x-mitre-tactic" or o.get("type")=="tactic"}
    with driver.session() as s:
        for obj in bundle.get("objects", []):
            t = obj.get("type")
            if t == "attack-pattern":
                stix_id = obj["id"]
                x_is_sub = obj.get("x_mitre_is_subtechnique", False)
                name = obj.get("name","")
                desc = obj.get("description","")
                revoked = obj.get("revoked", False)
                modified = obj.get("modified","")
                # tactics via kill_chain_phases
                tactic_names = []
                for kp in obj.get("kill_chain_phases", []) or []:
                    if kp.get("kill_chain_name") == "mitre-attack":
                        # kp.phase_name is the tactic shortname
                        tactic_names.append(kp.get("phase_name"))
                res = s.run(
                    """
                    MERGE (ap:AttackPattern {stix_id:$stix_id})
                    ON CREATE SET ap.name=$name, ap.description=$desc, ap.revoked=$revoked,
                                  ap.x_mitre_is_subtechnique=$x_is_sub, ap.created_ts=timestamp()
                    ON MATCH  SET ap.name=$name, ap.description=$desc, ap.revoked=$revoked,
                                  ap.x_mitre_is_subtechnique=$x_is_sub, ap.updated_ts=timestamp()
                    SET ap.type='attack-pattern', ap.modified=$modified,
                        ap.source_collection=$collection, ap.source_version=$version
                    RETURN ap, ap.updated_ts IS NOT NULL AS was_update
                    """,
                    stix_id=stix_id, name=name, desc=desc, revoked=revoked, x_is_sub=x_is_sub,
                    modified=modified, collection=collection, version=version
                )
                rec = res.single()
                if rec and rec["was_update"]:
                    updated += 1
                else:
                    inserted += 1

                # link to tactics
                for short in tactic_names:
                    s.run(
                        """
                        MERGE (ta:Tactic {shortname:$short})
                        ON CREATE SET ta.name=$short, ta.type='tactic', ta.created_ts=timestamp()
                        MERGE (ap:AttackPattern {stix_id:$stix_id})
                        MERGE (ap)-[:HAS_TACTIC]->(ta)
                        """,
                        short=short, stix_id=stix_id
                    )

                # upsert embedding doc (placeholder text assembler)
                try:
                    upsert_node_embedding(
                        os_url=os_url, index=os_index,
                        doc={
                            "id": stix_id,
                            "kb_type": "AttackPattern",
                            "attack_version": version,
                            "revoked": revoked,
                            "text": _ap_text(obj, tactic_names),
                            # "embedding": [...]  # add real vector when you wire a model
                        }
                    )
                except Exception as e:
                    print(f"[embedding] skip {stix_id}: {e}")

            elif t == "relationship":
                rtype = obj.get("relationship_type")
                src = obj.get("source_ref")
                tgt = obj.get("target_ref")
                if not (rtype and src and tgt):  # minimal guard
                    continue
                if rtype == "uses":
                    s.run(
                        """
                        MERGE (s {stix_id:$src})
                        MERGE (t {stix_id:$tgt})
                        SET s.type = coalesce(s.type, split($src, '--')[0]), t.type = coalesce(t.type, split($tgt,'--')[0])
                        MERGE (s)-[:USES]->(t)
                        """,
                        src=src, tgt=tgt
                    )
            # (Extend with IntrusionSet/Software/Mitigation upserts as needed)

    driver.close()
    return inserted, updated