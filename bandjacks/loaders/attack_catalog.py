"""ATT&CK catalog loader for managing releases."""

import re
import httpx
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class VersionRef:
    version: str
    url: str
    modified: str | None

@dataclass
class Collection:
    name: str
    key: str
    versions: List[VersionRef]

def _norm_key(name: str) -> str:
    n = name.lower()
    if "enterprise" in n: return "enterprise-attack"
    if "mobile"    in n: return "mobile-attack"
    if "ics"       in n: return "ics-attack"
    return re.sub(r"[^a-z0-9]+", "-", n)

def _ver_key(v: str) -> tuple[int,int]:
    m = re.match(r"^(\d+)(?:\.(\d+))?$", v)
    return (int(m.group(1)), int(m.group(2) or 0)) if m else (-1,-1)

def fetch_catalog(index_url: str) -> Dict[str, Collection]:
    r = httpx.get(index_url, timeout=30)
    r.raise_for_status()
    data = r.json()
    out: Dict[str, Collection] = {}
    for coll in data.get("collections", []):
        key = _norm_key(coll.get("name",""))
        vers = [VersionRef(v["version"], v["url"], v.get("modified")) for v in coll.get("versions",[])]
        vers.sort(key=lambda x: _ver_key(x.version), reverse=True)
        out[key] = Collection(name=coll.get("name",""), key=key, versions=vers)
    return out