# Bandjacks — Architecture v1.0


---

## 0) Executive Summary

This system models adversary **behaviors (TTPs)** using MITRE ATT\&CK STIX 2.1 as the canonical schema, integrates **D3FEND** for defensive mappings, and continuously learns by converting processed intelligence into **ordered Attack Flows**. It is a **hybrid graph + vector** architecture with strict **ATT\&CK Data Model (ADM)** validation and **release pinning** via the official ATT\&CK `index.json` catalog.

> **Design stance:** TTP‑centric. Indicators of Compromise (IOCs) are out of scope except when needed for contextual linkage to TTPs.

---

## 1) Goals & Non‑Goals

### Goals

* Represent adversary behaviors in a **queryable, versioned** knowledge base aligned to **STIX 2.1** and **ADM**.
* Generate **Attack Flows** (ordered steps with confidence) from real reports and telemetry‑like inputs.
* Overlay **D3FEND** to recommend countermeasures and sensing **artifacts** per flow step.
* Support **hybrid retrieval**: fast graph traversal + semantic vector search over nodes, edges, and flows.
* Continuously improve via **analyst feedback** and lightweight **active learning**.

### Non‑Goals (v1)

* IOC management, enrichment, or case management.
* Real‑time enforcement or automated blocking.
* Full SOC console; we ship a minimal review UI/API only.

---

## 2) Key Architectural Decisions (KADs)

1. **ATT\&CK release pinning via `index.json`**: The loader enumerates collections and versions from the upstream catalog; loads **latest or pinned** versions. Provenance is stamped on every node/edge.
2. **ADM‑gated ingest**: All bundles (official or user‑authored) must validate against the **ATT\&CK Data Model** (spec version X.Y.Z). Two modes:

   * **A. Sidecar service (Node/TS)** using ADM directly.
   * **B. JSON‑Schema export** from ADM validated in Python.
3. **Dual model representation**: Maintain **RDF/OWL** (for semantics & validation) and a **property graph** (Neo4j) for operational analytics; bridge via neosemantics (n10s).
4. **Vector fusion**: Per‑node, per‑edge, and per‑flow embeddings stored in a vector index (OpenSearch KNN). Retrieval seeds the IE/mapper; vectors accelerate similarity over flows.
5. **Attack Flow as first‑class**: Flows are materialized in STIX (extension) and as a graph substructure (`AttackEpisode`, `AttackAction`, `:NEXT {p}`) for simulation.
6. **D3FEND overlay**: Materialize `COUNTERS` edges from ATT\&CK Mitigations → D3FEND techniques, plus **Digital Artifacts** for placement of sensors/controls.
7. **TTP‑only scope**: Techniques/sub‑techniques, tactics, intrusion sets (groups), software (tools/malware), mitigations, data sources/components.

---

## 3) System Context

* **Producers**: Intelligence reports (PDF/blog/markdown), structured JSON/CSV feeds, official ATT\&CK releases, D3FEND ontology.
* **Consumers**: TI analysts (review/curate), detection engineers (coverage, countermeasures), threat hunters (sequence prediction, similar flows).

---

## 4) Logical Architecture

```mermaid
graph LR
  subgraph Sources
    A1[Reports\nPDF/Blog/Markdown]
    A2[Structured Feeds\nJSON/CSV]
    A3[ATT&CK Releases\nindex.json]
    A4[D3FEND Ontology\nOWL/TTL/JSON-LD]
  end

  subgraph Ingestion & Mapping
    B1[Parser/Normalizer]
    B2[Vector Retriever\n(TTP candidates)]
    B3[IE & Linker\n(entities + relations)]
    B4[STIX Mapper\n(SDO/SRO bundles)]
    B5[ADM Validator\n(sidecar or schema)]
    B6[STIX Loader\n(release pinning)]
  end

  subgraph Knowledge Layer
    C1[(Neo4j Property Graph)]
    C2[(RDF/OWL via n10s)]
    C3[(Vector Store\nOpenSearch KNN)]
    C4[(Blob Store\nBundles/Docs)]
  end

  subgraph World Model
    D1[Attack Flow Builder\n(episodes & NEXT{p})]
    D2[D3FEND Overlay\n(COUNTERS + artifacts)]
    D3[Simulation/Prediction\n(next step, minimal cuts)]
    D4[Coverage & Gap Analytics]
  end

  subgraph Feedback & Ops
    E1[Review API/UI]
    E2[Active Learning Queue]
    E3[Model Refresh Jobs]
    E4[Observability & RBAC]
  end

  A1-->B1-->B2-->B3-->B4-->B5
  A2-->B1
  A3-->B6-->B5
  A4-->C2
  B5-->C1
  B5-->C3
  B4-->C4
  C2<-->C1
  C1-->D1-->D2-->D3-->D4
  D1-->C1
  D1-->C3
  D2-->C1
  E1-->B4
  E1-->D1
  E1-->E2-->E3-->B3
  C1-->E1
  C3-->E1
```

---

## 5) Deployment View

```mermaid
graph TB
  subgraph API Layer (FastAPI, uv)
    S1[/catalog/]
    S2[/stix-loader/]
    S3[/mapper/]
    S4[/graph/]
    S5[/vectors/]
    S6[/flows/]
    S7[/defense/]
    S8[/feedback/]
    S9[/sim/]
  end

  subgraph Sidecar (Option A)
    V1[[adm-validate (Node/TS)]]
  end

  subgraph Data Stores
    DB1[(Neo4j)]
    DB2[(OpenSearch)]
    DB3[(Blob: S3-compatible)]
  end

  subgraph Integration
    Q1{{Queue/Topic\n(bundles, corrections)}}
    M1[(Prometheus/Grafana)]
    A1[(OIDC/JWT Provider)]
  end

  S2--fetch releases->S1
  S2--validate->V1
  S3--validate->V1
  S2--upsert->DB1
  S2--embed->S5
  S5--index->DB2
  S3--upsert->DB1
  S6--read/write->DB1
  S6--embeddings->DB2
  S7--read D3FEND->DB1
  S8-.decisions.->Q1
  S9--read->DB1
  S9--read->DB2
  API Layer--auth-->A1
  API Layer--metrics-->M1
  API Layer--store->DB3
```

**Option B (pure Python):** replace `adm-validate` with JSON‑Schema generated at build time from ADM and validated in Python.

---

## 6) Data Model (Property Graph Projection)

### Node Labels

* `AttackPattern` (techniques & sub‑techniques; `x_mitre_is_subtechnique`)
* `Tactic`
* `IntrusionSet` (groups)
* `Software` (tools/malware; keep original type)
* `Mitigation`
* `DataSource`, `DataComponent`
* `AttackEpisode`, `AttackAction` (operational)
* `D3fendTechnique`, `DigitalArtifact` (defense overlay)

### Edge Types

* `USES` (e.g., Group → Technique | Software → Technique)
* `HAS_TACTIC` (Technique → Tactic via kill\_chain\_phases)
* `MITIGATES` (Mitigation → Technique)
* `IMPLIES_TECHNIQUE` (Software → Technique)
* `OF_TACTIC` (Technique → Tactic explicit link)
* `NEXT {p}` (AttackAction → AttackAction with probability)
* `COUNTERS` (D3fendTechnique → Technique or AttackAction)

### Core Properties (all nodes)

* `stix_id`, `type`, `name`, `description`, `created`, `modified`, `revoked`, `confidence`
* `x_mitre_*` fields (domains, platforms, version, detection, etc.)
* `source`: `{collection, version, modified, url, adm_spec, adm_sha}`

---

## 7) Vector Strategy

* **Node embeddings**: concatenate curated fields (`name`, `description`, `x_mitre_detection`, `tactics`, `platforms`)
* **Edge embeddings**: templated relation strings (e.g., “IntrusionSet X uses T1059 on Windows via powershell.exe …”)
* **Flow embeddings**: a single text for ordered steps; used for similarity and retrieval of historical episodes.
* **Indices**: `attack_nodes‑v1` and `attack_flows‑v1` (OpenSearch KNN). Keys: `kb_type`, `attack_version`.

---

## 8) Processing Pipelines

### 8.1 ATT\&CK & D3FEND Load

1. `GET /catalog/attack/releases` → resolve collection/version
2. Download bundle → **ADM validate** (`strict=true` default)
3. Upsert to graph (idempotent, version‑aware) + create/update embeddings
4. Persist raw bundle to blob store; stamp provenance on all created/updated entities

### 8.2 Report Ingest → STIX Mapping

1. Parse/normalize (PDF/HTML/MD/JSON/CSV)
2. Vector‑seeded retrieval for candidate TTPs
3. IE & linking (entities, `uses`/`indicates`/`mitigates`)
4. Build STIX SDO/SRO bundle → **ADM validate** → upsert graph & vectors
5. Queue low‑confidence items to **review** and **active learning**

### 8.3 Attack Flow Build

1. Group observations by episode (time window + entity overlap)
2. Order and merge; score `NEXT` edges (temporal + transition frequency + text cues)
3. Emit STIX Attack Flow bundle + project to graph (`AttackEpisode`, `AttackAction`, `NEXT {p}`)
4. Create flow embedding; enable **similar flow search**

### 8.4 D3FEND Overlay & Simulation

* Map ATT\&CK Mitigations → D3FEND techniques; attach `COUNTERS` and **artifact** hints per action
* Simulate next steps with historical transition priors and recency; compute **minimal‑cut** defensive sets

---

## 9) Public Interfaces (OpenAPI‑first)

* `GET /v1/catalog/attack/releases` — list collections/versions/URLs
* `POST /v1/stix/load/attack?collection=&version=&adm_strict=true` — ingest a pinned or latest release
* `POST /v1/stix/bundles?strict=true` — ingest validated bundles (TTP‑only scope)
* `POST /v1/flows/build?source_id=` — build an Attack Flow from observations
* `GET /v1/flows/{flow_id}` — fetch flow steps & `NEXT` edges
* `GET /v1/defense/overlay/{flow_id}` — D3FEND techniques & artifacts per step
* `POST /v1/search/ttx` — text → ATT\&CK technique candidates
* `POST /v1/search/flows` — flow/text → similar flows
* `POST /v1/review/mapping` / `POST /v1/review/flowedge` — analyst decisions

**Common response enrichment:** `trace_id`, `provenance`, `warnings[]`, `rejected[]` (for partial success).

---

## 10) Persistence & Indexing

### Neo4j

* **Constraints**: unique `stix_id`; composite `(type, stix_id)`
* **Indexes**: `(AttackPattern {revoked:false})`, `(IntrusionSet)`, `(Software)`
* **Write policy**: create new versions when `modified` changes; never downgrade unless `force=true`

### OpenSearch

* `attack_nodes‑v1` (KNN on `embedding`) — filter on `kb_type`, `attack_version`, `revoked=false`
* `attack_flows‑v1` (KNN) — flow embeddings; metadata includes tactic mix, domains, platforms

### Blob Store

* Raw ATT\&CK bundles, user bundles, Attack Flow bundles (for audit/export)

---

## 11) Versioning & Provenance

* **ATT\&CK**: `{collection, version, modified, source_url}` recorded on all entities
* **ADM**: `{adm_spec, adm_sha}` recorded per ingest run
* **Policy**: `409 Conflict` on attempted downgrade; `?force=true` overrides with audit log

---

## 12) Security, Markings, and RBAC

* **AuthN**: OIDC/JWT; service‑to‑service tokens for internal calls
* **AuthZ**: role scopes (analyst, engineer, admin); per‑route guards
* **Markings**: honor STIX marking definitions (e.g., TLP); propagate to derived objects; enforce on read APIs

---

## 13) Observability & SLOs

* **Metrics**: `bundles_ingested`, `objects_updated`, `objects_rejected`, `/search` latency P95, `flow_build_success`, `next_step_hit_rate`
* **Tracing**: OpenTelemetry spans across services; `trace_id` surfaced in responses and error payloads
* **Logging**: structured JSON with provenance snapshot per ingest
* **SLOs** (dev targets):

  * ATT\&CK+D3FEND baseline load ≤ 5m
  * `/search/ttx` P95 ≤ 300ms for `top_k ≤ 10`
  * ≥ 99.5% monthly API availability (non‑prod baseline)

---

## 14) Failure Modes & Backpressure

* **Upstream unavailability**: cache `index.json` for 6h; S3 cache for bundles (etag‑keyed)
* **Validation failures**: surface `rejected[]` with reasons; do not partial‑write invalid objects
* **Graph contention**: batch writes; retry with exponential backoff; idempotent upserts keyed by `stix_id`
* **Vector lag**: write‑behind indexing with retry; stale reads acceptable for ≤ N minutes

---

## 15) Scaling & Capacity

* Horizontal scale for API layer (stateless FastAPI); sticky sessions not required
* Neo4j sized for ≥ 5M nodes / 20M edges; periodic compaction; read replicas for heavy query workloads
* OpenSearch shards by `kb_type` and/or `attack_version`; refresh tuned for ingest bursts

---

## 16) Configuration (env)

```
ATTACK_INDEX_URL=.../attack-stix-data/master/index.json
ATTACK_COLLECTION=enterprise-attack
ATTACK_VERSION=latest

ADM_MODE=sidecar|schema
ADM_BASE_URL=http://adm-validate:8080
ADM_SPEC_MIN=3.3.0

NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=...

OPENSEARCH_URL=http://opensearch:9200
BLOB_BASE=s3://world-model/
```

---

## 17) Technology Choices

* **Language/Runtime**: Python (FastAPI) managed with **uv**; optional Node (ADM sidecar)
* **Graph**: Neo4j + **neosemantics (n10s)** for RDF interchange
* **Vector**: OpenSearch KNN (pluggable interface for Milvus/Qdrant)
* **Orchestration**: lightweight jobs (cron/queue) for retraining and re‑embedding

---

## 18) Risks & Mitigations

* **Schema drift vs ADM** → pin ADM spec; nightly check; fail‑fast validation
* **ATT\&CK release churn** → provenance + delta loaders; re‑embed only changed nodes
* **Ambiguous mapping** → retrieval‑assisted linking + analyst review + active learning
* **Confidence inflation** → calibrated scores; require review for high‑impact links and edges

---

## 19) Roadmap Hooks (Beyond v1)

* Integrate **Analytic** and **Detection Strategy** objects to drive detection design
* Managed TAXII server mirroring curated collections for partner consumption
* Graph ML over flows (e.g., sequence models) and counterfactual simulation

---

## 20) Appendix A — Neo4j DDL (Constraints/Indexes)

```
CREATE CONSTRAINT stix_id_unique IF NOT EXISTS
FOR (n) REQUIRE n.stix_id IS UNIQUE;

CREATE INDEX ap_revoked_false IF NOT EXISTS
FOR (n:AttackPattern) ON (n.revoked);

CREATE INDEX node_type IF NOT EXISTS
FOR (n) ON (n.type);
```

---

## 21) Appendix B — OpenSearch Index Hints

* `attack_nodes‑v1`: KNN vector field, doc fields: `id`, `kb_type`, `attack_version`, `revoked`, `text`, `embedding`
* `attack_flows‑v1`: KNN vector field, doc fields: `flow_id`, `text`, `embedding`, `tactics[]`, `platforms[]`

---

## 22) Glossary

* **ADM** — ATT\&CK Data Model (published schemas for ATT\&CK content)
* **TTPs** — Tactics, Techniques, and Procedures
* **Attack Flow** — STIX extension to model ordered adversary steps
* **D3FEND** — MITRE ontology for defensive techniques and artifacts
* **Provenance** — recorded source metadata for reproducibility
