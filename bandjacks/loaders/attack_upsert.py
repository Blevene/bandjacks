"""ATT&CK data upserter for Neo4j and OpenSearch."""

import httpx
import orjson
from typing import Tuple
from neo4j import GraphDatabase
from .attack_catalog import fetch_catalog
from .opensearch_index import upsert_node_embedding
from .embedder import encode

# ATT&CK object type constants
AP = "attack-pattern"
INTRUSION_SET = "intrusion-set"
SOFTWARE_TYPES = {"tool", "malware", "software"}  # ATT&CK 'software' is umbrella
MITIGATION = "course-of-action"  # ATT&CK Mitigations are STIX COA
RELATIONSHIP = "relationship"

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
    if not strict:
        return True, [], None
    rejected = []
    objs = bundle.get("objects", [])
    for o in objs:
        t = o.get("type")
        if not t:
            rejected.append({"id": o.get("id"), "type": None, "reason": "missing type"})
            continue
        if t == RELATIONSHIP:
            if not o.get("relationship_type") or not o.get("source_ref") or not o.get("target_ref"):
                rejected.append({"id": o.get("id"), "type": t, "reason": "relationship missing required fields"})
        # you can add more: validate x_mitre fields exist when present, etc.
    ok = len(rejected) == 0
    return ok, rejected, None

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
    
    objs = bundle.get("objects", [])
    
    # Pre-collect tactics (ATT&CK has 'x-mitre-tactic' or 'tactic' in some exports)
    tactics_by_short = {}
    for o in objs:
        if o.get("type") in ("x-mitre-tactic", "tactic"):
            short = o.get("x_mitre_shortname") or o.get("name")
            if short:
                tactics_by_short[short] = o
    
    with driver.session() as s:
        # 1) AttackPattern nodes
        aps = [o for o in objs if o.get("type") == AP]
        for obj in aps:
            stix_id = obj["id"]
            name = obj.get("name","")
            desc = obj.get("description","")
            revoked = obj.get("revoked", False)
            modified = obj.get("modified","")
            x_is_sub = obj.get("x_mitre_is_subtechnique", False)
            
            res = s.run(
                """
                MERGE (n:AttackPattern {stix_id:$stix_id})
                ON CREATE SET n.created_ts=timestamp()
                SET n.type='attack-pattern', n.name=$name, n.description=$desc, n.revoked=$revoked,
                    n.x_mitre_is_subtechnique=$x_is_sub, n.modified=$modified,
                    n.source_collection=$collection, n.source_version=$version
                RETURN n.created_ts IS NOT NULL AS created
                """,
                stix_id=stix_id, name=name, desc=desc, revoked=revoked, x_is_sub=x_is_sub,
                modified=modified, collection=collection, version=version
            )
            if res.single()["created"]:
                inserted += 1
            else:
                updated += 1
            
            # HAS_TACTIC edges from kill_chain_phases
            tactic_names = []
            for kp in obj.get("kill_chain_phases", []) or []:
                if kp.get("kill_chain_name") == "mitre-attack":
                    short = kp.get("phase_name")
                    if not short: 
                        continue
                    tactic_names.append(short)
                    s.run(
                        """
                        MERGE (t:Tactic {shortname:$short})
                        ON CREATE SET t.name=$short, t.type='tactic', t.created_ts=timestamp()
                        WITH t
                        MATCH (ap:AttackPattern {stix_id:$stix_id})
                        MERGE (ap)-[:HAS_TACTIC]->(t)
                        """,
                        short=short, stix_id=stix_id
                    )
            
            # upsert node embedding with real vectors
            txt = _ap_text(obj, tactic_names)
            try:
                vec = encode(txt)
                if vec is not None and len(vec) == 768:  # Ensure we have a valid 768-dim vector
                    upsert_node_embedding(
                        os_url=os_url, index=os_index,
                        doc={
                            "id": stix_id,
                            "kb_type": "AttackPattern",
                            "attack_version": version,
                            "revoked": revoked,
                            "text": txt,
                            "embedding": vec
                        }
                    )
                else:
                    print(f"[embedding] skipping {stix_id}: invalid vector (got {type(vec)} with length {len(vec) if vec else 'None'})")
            except Exception as e:
                print(f"[embedding] error generating vector for {stix_id}: {e}")
        
        # 2) IntrusionSet nodes (Groups)
        groups = [o for o in objs if o.get("type") == INTRUSION_SET]
        for obj in groups:
            res = s.run(
                """
                MERGE (g:IntrusionSet {stix_id:$id})
                ON CREATE SET g.created_ts=timestamp()
                SET g.type='intrusion-set', g.name=$name, g.description=$desc, g.revoked=$revoked,
                    g.modified=$modified, g.source_collection=$collection, g.source_version=$version
                RETURN g.created_ts IS NOT NULL AS created
                """,
                id=obj["id"], name=obj.get("name",""), desc=obj.get("description",""),
                revoked=obj.get("revoked", False), modified=obj.get("modified",""),
                collection=collection, version=version
            )
            # track counts roughly (MERGE doesn't tell created easily here)
            # optional: query exists; for sprint-1 ok to skip precise counts
        
        # 3) Software (Tool/Malware/Software umbrella)
        software = [o for o in objs if o.get("type") in SOFTWARE_TYPES]
        for obj in software:
            s.run(
                """
                MERGE (sw:Software {stix_id:$id})
                ON CREATE SET sw.created_ts=timestamp()
                SET sw.type=$type, sw.name=$name, sw.description=$desc, sw.revoked=$revoked,
                    sw.modified=$modified, sw.source_collection=$collection, sw.source_version=$version
                """,
                id=obj["id"], type=obj.get("type"), name=obj.get("name",""), desc=obj.get("description",""),
                revoked=obj.get("revoked", False), modified=obj.get("modified",""),
                collection=collection, version=version
            )
        
        # 4) Mitigations (course-of-action)
        mitigs = [o for o in objs if o.get("type") == MITIGATION]
        for obj in mitigs:
            s.run(
                """
                MERGE (m:Mitigation {stix_id:$id})
                ON CREATE SET m.created_ts=timestamp()
                SET m.type='mitigation', m.name=$name, m.description=$desc, m.revoked=$revoked,
                    m.modified=$modified, m.source_collection=$collection, m.source_version=$version
                """,
                id=obj["id"], name=obj.get("name",""), desc=obj.get("description",""),
                revoked=obj.get("revoked", False), modified=obj.get("modified",""),
                collection=collection, version=version
            )
        
        # Relationships (USES, MITIGATES, IMPLIES)
        rels = [o for o in objs if o.get("type") == RELATIONSHIP]
        for r in rels:
            rtype = r.get("relationship_type")
            src = r.get("source_ref")
            tgt = r.get("target_ref")
            if not (rtype and src and tgt):
                continue
            
            if rtype == "uses":
                s.run(
                    """
                    MERGE (s {stix_id:$src}) ON CREATE SET s.type=split($src,'--')[0]
                    MERGE (t {stix_id:$tgt}) ON CREATE SET t.type=split($tgt,'--')[0]
                    MERGE (s)-[:USES]->(t)
                    """,
                    src=src, tgt=tgt
                )
            
            elif rtype == "mitigates":
                s.run(
                    """
                    MATCH (m:Mitigation {stix_id:$src})
                    MATCH (ap:AttackPattern {stix_id:$tgt})
                    MERGE (m)-[:MITIGATES]->(ap)
                    """,
                    src=src, tgt=tgt
                )
            
            # IMPLIES_TECHNIQUE is our derived edge from Software→Technique (optional)
            elif rtype in ("uses-against", "delivers", "drops"):  # rare; keep for future
                pass

    driver.close()
    return inserted, updated