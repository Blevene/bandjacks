# Bandjacks Data Model (LLM Context Pack)

> Purpose: describe node/relationship types, fields, constraints, and semantics so downstream systems (incl. LLMs) can **understand, reason over, and generate** valid objects and edges.
> Foundations: **STIX 2.1**, **MITRE ATT\&CK**, **ADM Detection** (Detection Strategy / Analytic / Log Source), **D3FEND**, **ATT\&CK Flow 2.0**.

---

## 0. Global conventions

* **All SDO/SRO** must include `spec_version: "2.1"` (ATT\&CK Flow objects use their own 2.0 schema).
* **IDs:** Use native STIX IDs where applicable (e.g., `attack-pattern--...`) and keep **ATT\&CK external IDs** (e.g., `T1059.001`) in `external_references[].external_id` and in a fast field `external_id`.
* **Domains:** Track `{domain, collection, version}` (e.g., `enterprise-attack v18.1`) in `source`.
* **Status:** Preserve `revoked`, `x_mitre_deprecated`. Default queries **exclude** these unless explicitly included.
* **Markings/Provenance:** Preserve `created_by_ref`, `object_marking_refs`, `granular_markings`, and an `x_bj_provenance` block (loader, timestamps, evidence refs).
* **Temporal:** Prefer ISO-8601 strings; edges that reflect observations may carry `first_seen`/`last_seen`.
* **Cardinality:** Listed below as *typical*; the graph can support many↔many unless stated otherwise.

---

## 1. Node (Entity) Types

| Label                           | STIX Type                    | Key Fields                                                                                                                                                                                          | Notes                                                                |                                                              |
| ------------------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------ |
| **AttackPattern**               | `attack-pattern`             | `stix_id`, `name`, `external_id` (e.g., `T1059.001`), `x_mitre_is_subtechnique`, `x_mitre_platforms[]`, `kill_chain_phases[]`, `revoked`, `x_mitre_deprecated`, `source{domain,collection,version}` | Technique/Sub-technique. Attach tactic links & parent hierarchy.     |                                                              |
| **Tactic**                      | `x-mitre-tactic`             | `stix_id`, `name`, `x_mitre_shortname`, `external_references[]`, `source`                                                                                                                           | ATT\&CK tactic SDO (not just kill chain text).                       |                                                              |
| **CourseOfAction** (Mitigation) | `course-of-action`           | `stix_id`, `name`, `description`, `external_references[]`, `source`                                                                                                                                 | Mitigations in ATT\&CK.                                              |                                                              |
| **IntrusionSet**                | `intrusion-set`              | `stix_id`, `name`, `aliases[]`, `goals[]`, `resource_level?`, `primary_motivation?`, `source`                                                                                                       | The actor/group cluster.                                             |                                                              |
| **Software**                    | `tool` or `malware`          | `stix_id`, `name`, `labels[]`, `aliases[]`, `description`, \`software\_type: "tool"                                                                                                                 | "malware"`, `source\`                                                | ATT\&CK collapses tool/malware into “Software” conceptually. |
| **Campaign**                    | `campaign`                   | `stix_id`, `name`, `description`, `first_seen?`, `last_seen?`, `aliases[]?`, `revoked?`, `x_mitre_deprecated?`, `source`                                                                            | Use when an operation window is supported by evidence.               |                                                              |
| **Identity**                    | `identity`                   | `stix_id`, `name`, `identity_class`, `sectors[]?`, `country?`, `source`                                                                                                                             | Organizations/people/sectors (for targeting).                        |                                                              |
| **Location**                    | `location`                   | `stix_id`, `name`, `region?`, `country?`, `city?`, `source`                                                                                                                                         | Geo targets/scopes.                                                  |                                                              |
| **Infrastructure**              | `infrastructure`             | `stix_id`, `name`, `infrastructure_types[]`, `source`                                                                                                                                               | Optional targeting context.                                          |                                                              |
| **Report**                      | `report`                     | `stix_id`, `name`, `published`, `object_refs[]`, `source`                                                                                                                                           | Evidence container; do **not** equate report to campaign by default. |                                                              |
| **Sighting**                    | `sighting`                   | `stix_id`, `first_seen?`, `last_seen?`, `count?`, `where_sighted_refs?`, `sighting_of_ref`                                                                                                          | Observation records.                                                 |                                                              |
| **DetectionStrategy**           | `x-mitre-detection-strategy` | `stix_id`, `name`, `description`, `x_mitre_attack_spec_version`, `x_mitre_analytics[] (refs)`, `revoked?`, `x_mitre_deprecated?`, `source`                                                          | Behavioral detection blueprint.                                      |                                                              |
| **Analytic**                    | `x-mitre-analytic`           | `stix_id`, `name`, `platforms[]`, `x_mitre_detects` (text), `x_mitre_log_sources[] (refs+keys)`, `x_mitre_mutable_elements[]`, `source`                                                             | Platform/telemetry-specific detection.                               |                                                              |
| **LogSource**                   | `x-mitre-log-source`         | `stix_id`, `name`, `x_mitre_log_source_permutations[]`                                                                                                                                              | Canonical telemetry descriptors (e.g., “Sysmon EID 10”).             |                                                              |
| **DefensiveTechnique**          | (D3FEND)                     | `id` (d3f\:ID), `name`, `iri`, `description`                                                                                                                                                        | From D3FEND ontology.                                                |                                                              |
| **AttackFlow**                  | `attack-flow` (AF 2.0)       | `id`, `name`, `description`, `created`, `modified`, `raw_json_ref`                                                                                                                                  | Flow container (stored in parallel to STIX graph).                   |                                                              |
| **Action** (AF step)            | `action` (AF 2.0)            | `id`, `name`, `corresponds_to` (AttackPattern `stix_id`), `properties?`                                                                                                                             | Atomic step in a flow.                                               |                                                              |
| **Condition/Operator** (AF)     | `condition` / `operator`     | `id`, `expr?`, `type`                                                                                                                                                                               | Predicates/branching in flows.                                       |                                                              |

> All nodes include `x_bj_provenance` (source URI, loader version, timestamps) and retain `created_by_ref`, `object_marking_refs`, `granular_markings` where supplied.

---

## 2. Relationship Types

| Edge                  | From → To                                                        | Meaning                                   | Typical Cardinality | Key Props / Rules                                     |
| --------------------- | ---------------------------------------------------------------- | ----------------------------------------- | ------------------- | ----------------------------------------------------- |
| **USES**              | IntrusionSet → Software                                          | Actor employs tool/malware                | many→many           | Optional `confidence`, `first_seen/last_seen`         |
| **USES**              | Software → AttackPattern                                         | Tool/malware implements/enables technique | many→many           | —                                                     |
| **HAS\_TACTIC**       | AttackPattern → Tactic                                           | Technique’s mapped tactic                 | many→1              | Mirror `kill_chain_phases` and tactic SDO             |
| **SUBTECHNIQUE\_OF**  | AttackPattern(sub) → AttackPattern(parent)                       | Technique hierarchy                       | many→1              | Derived from ATT\&CK IDs or `x_mitre_is_subtechnique` |
| **MITIGATES**         | CourseOfAction → AttackPattern                                   | Mitigation counters behavior              | many→many           | —                                                     |
| **ATTRIBUTED\_TO**    | Campaign → IntrusionSet                                          | Operational attribution                   | many→many           | `confidence`, `first_seen/last_seen?`                 |
| **USES**              | Campaign → Software / AttackPattern                              | Capabilities/behaviors in campaign        | many→many           | Time-bounded optional                                 |
| **TARGETS**           | Campaign → Identity / Location / Infrastructure                  | Intended/affected targets                 | many→many           | Optional `sector`, `geo_scope`                        |
| **DESCRIBES**         | Report → Campaign/IntrusionSet/Software/AttackPattern/AttackFlow | Evidence linkage                          | many→many           | —                                                     |
| **OF**                | Sighting → Campaign/Software/AttackPattern                       | Observation record                        | many→1              | `first_seen/last_seen`, `count`                       |
| **DETECTS**           | DetectionStrategy → AttackPattern                                | Strategy detects technique                | many→many           | Store `attack_spec_version`                           |
| **HAS\_ANALYTIC**     | DetectionStrategy → Analytic                                     | Strategy realization                      | 1→many              | Derived from SDO array                                |
| **USES\_LOG\_SOURCE** | Analytic → LogSource                                             | Telemetry dependency                      | many→many           | `keys: string[]` (e.g., `["Sysmon:EID=10"]`)          |
| **COUNTERS**          | DefensiveTechnique → AttackPattern                               | D3FEND defensive countermeasure           | many→many           | —                                                     |
| **HAS\_FLOW**         | Campaign → AttackFlow                                            | Flow instance bound to campaign           | many→many           | `{version, created_ts}`                               |
| **HAS\_STEP**         | AttackFlow → Action/Condition                                    | Membership in flow                        | 1→many              | —                                                     |
| **NEXT**              | Action → Action                                                  | Execution order                           | many→many           | Optional `{order, probability?}`                      |
| **REQUIRES**          | Action → Condition                                               | Precondition/guard                        | many→many           | —                                                     |
| **CORRESPONDS\_TO**   | Action → AttackPattern                                           | Bind AF action to canonical technique     | many→1              | ATT\&CK alignment                                     |

**Validation hints (ingest):**

* Only allow legal SRO pairings per STIX/ATT\&CK (e.g., `detects` from Strategy→AttackPattern).
* Reject unknown or cross-type invalid relationships, return explicit `rejected[]` entries.

---

## 3. Status, Versioning, and Namespaces

* **Revoked/Deprecated:** preserve and filter by default.
* **Provisional:** Bandjacks may mark nodes `x_bj_status: "provisional"` (e.g., auto-campaigns). Exclude from default analyst views; support merge/promotion.
* **Release lineage:** stamp `source.domain`, `source.collection`, `source.version` on each object for multi-release reasoning.
* **ADM (Detection) spec version:** capture `x_mitre_attack_spec_version` on DetectionStrategy and on its `DETECTS` edges.

---

## 4. Example: Minimal end-to-end subgraph (JSON)

```json
{
  "nodes": [
    {"label":"IntrusionSet","stix_id":"intrusion-set--apt29","name":"APT29"},
    {"label":"Software","stix_id":"tool--cobalt-strike","name":"Cobalt Strike","software_type":"tool"},
    {"label":"AttackPattern","stix_id":"attack-pattern--t1059.001","name":"PowerShell","external_id":"T1059.001"},
    {"label":"DetectionStrategy","stix_id":"x-mitre-detection-strategy--det-lsass","name":"LSASS Access Strategy","x_mitre_attack_spec_version":"3.3.0"},
    {"label":"Analytic","stix_id":"x-mitre-analytic--win-lsass-openprocess","name":"Win LSASS OpenProcess","x_mitre_detects":"Detect OpenProcess on lsass.exe","platforms":["Windows"]},
    {"label":"LogSource","stix_id":"x-mitre-log-source--sysmon","name":"Sysmon","x_mitre_log_source_permutations":[{"name":"Sysmon Event","channel":"Microsoft-Windows-Sysmon/Operational"}]},
    {"label":"DefensiveTechnique","id":"d3f:process-access-monitoring","name":"Process Access Monitoring"},
    {"label":"Campaign","stix_id":"campaign--2019-apt29","name":"APT29 Fall 2019","first_seen":"2019-10-01T00:00:00Z","last_seen":"2019-11-30T00:00:00Z"},
    {"label":"AttackFlow","id":"attack-flow--af-2019","name":"Observed Flow"},
    {"label":"Action","id":"action--ps1","name":"Execute PowerShell"}
  ],
  "edges": [
    {"type":"USES","from":"intrusion-set--apt29","to":"tool--cobalt-strike"},
    {"type":"USES","from":"tool--cobalt-strike","to":"attack-pattern--t1059.001"},
    {"type":"DETECTS","from":"x-mitre-detection-strategy--det-lsass","to":"attack-pattern--t1059.001","attack_spec_version":"3.3.0"},
    {"type":"HAS_ANALYTIC","from":"x-mitre-detection-strategy--det-lsass","to":"x-mitre-analytic--win-lsass-openprocess"},
    {"type":"USES_LOG_SOURCE","from":"x-mitre-analytic--win-lsass-openprocess","to":"x-mitre-log-source--sysmon","keys":["EID=10"]},
    {"type":"COUNTERS","from":"d3f:process-access-monitoring","to":"attack-pattern--t1059.001"},
    {"type":"HAS_FLOW","from":"campaign--2019-apt29","to":"attack-flow--af-2019","version":"1"},
    {"type":"HAS_STEP","from":"attack-flow--af-2019","to":"action--ps1"},
    {"type":"CORRESPONDS_TO","from":"action--ps1","to":"attack-pattern--t1059.001"}
  ]
}
```

---

## 5. LLM Guidance (Reasoning Rules)

When asked to propose or map objects/edges:

1. **Prefer existing ATT\&CK IDs** (never invent). If unknown, propose **Bandjacks candidate** with `x_bj_status:"proposed"` (human review required).
2. **Don’t assume a campaign** just because a report exists. Create/merge a Campaign only if rubric is met (time-bounded, scope, attribution, multi-step). Otherwise: link `Report → DESCRIBES →` observed entities and (optionally) produce **unsequenced Attack Flow**.
3. **Sequencing:** only create `NEXT` edges if explicit or strongly implied ordering exists; otherwise model **parallel actions**.
4. **Detection layer:** `DETECTS` edges originate **only** from `DetectionStrategy` and terminate at `AttackPattern`. `HAS_ANALYTIC` and `USES_LOG_SOURCE` are derived from ADM SDO properties.
5. **Sub-techniques:** ensure `SUBTECHNIQUE_OF` links and correct tactic mapping (`HAS_TACTIC`).
6. **Status filtering:** default outputs exclude `revoked`/`deprecated`/`provisional` unless explicitly requested.
7. **Provenance:** attach evidence spans (when available) and source references in `x_bj_provenance`.

---

## 6. Minimal Mermaid Diagram (paste into docs)

```mermaid
flowchart LR
  subgraph Actors
    IS[IntrusionSet]
    CA[Campaign]
  end
  subgraph Behaviors
    AP[AttackPattern]
    APp[AttackPattern (Parent)]
    TAC[Tactic]
    COA[Mitigation]
  end
  subgraph Software
    SW[Software]
  end
  subgraph Detection
    DS[DetectionStrategy]
    AN[Analytic]
    LS[LogSource]
  end
  subgraph D3FEND
    DT[DefensiveTechnique]
  end
  subgraph AttackFlow
    AF[AttackFlow]
    ACT1[Action]
    ACT2[Action]
    COND[Condition]
  end

  IS -- USES --> SW
  SW -- USES --> AP
  AP -- HAS_TACTIC --> TAC
  AP -. SUBTECHNIQUE_OF .-> APp
  COA -- MITIGATES --> AP

  CA -- ATTRIBUTED_TO --> IS
  CA -- USES --> SW
  CA -- USES --> AP

  DS -- DETECTS --> AP
  DS -- HAS_ANALYTIC --> AN
  AN -- USES_LOG_SOURCE --> LS

  DT -- COUNTERS --> AP

  CA -- HAS_FLOW --> AF
  AF -- HAS_STEP --> ACT1
  AF -- HAS_STEP --> ACT2
  ACT1 -- NEXT --> ACT2
  ACT1 -- REQUIRES --> COND
  ACT1 -- CORRESPONDS_TO --> AP
  ACT2 -- CORRESPONDS_TO --> AP
```

---

## 7. Validation Rules (quick list)

* Reject ingest objects missing `spec_version: "2.1"` (except AF JSON which uses AF 2.0).
* Validate SRO pairings: `uses`, `mitigates`, `detects`, `attributed-to`, `targets`, `describes`, `sighting`.
* Derive and enforce `SUBTECHNIQUE_OF` when `x_mitre_is_subtechnique=true` or external\_id pattern `T####.###`.
* Default query scope excludes `revoked`/`x_mitre_deprecated`.
* For detection: require Strategy has ≥1 Analytic; Analytic has ≥1 LogSource and ≥1 Mutable Element; LogSource has ≥1 permutation.
* Attack Flow ingest/export must validate against **attack-flow-schema-2.0.0**.

---

## 8. Query Patterns (Neo4j Cypher Cheats)

```cypher
// Group → Software → Technique
MATCH (i:IntrusionSet)-[:USES]->(s:Software)-[:USES]->(ap:AttackPattern)
RETURN i.name, s.name, ap.external_id LIMIT 20;

// Technique coverage (Detection + D3FEND)
MATCH (ap:AttackPattern {external_id:$tid})
OPTIONAL MATCH (ds:DetectionStrategy)-[:DETECTS]->(ap)
OPTIONAL MATCH (ds)-[:HAS_ANALYTIC]->(an:Analytic)-[:USES_LOG_SOURCE]->(ls:LogSource)
OPTIONAL MATCH (dt:DefensiveTechnique)-[:COUNTERS]->(ap)
RETURN ap, collect(DISTINCT ds) AS strategies, collect(DISTINCT an) AS analytics,
       collect(DISTINCT ls) AS log_sources, collect(DISTINCT dt) AS defenses;

// Campaign subgraph (time windowed)
MATCH (c:Campaign {stix_id:$cid})
OPTIONAL MATCH (c)-[u:USES]->(ap:AttackPattern)
WHERE ($from IS NULL OR u.first_seen >= $from) AND ($to IS NULL OR u.last_seen <= $to)
OPTIONAL MATCH (c)-[:HAS_FLOW]->(af:AttackFlow)-[:HAS_STEP]->(a:Action)-[:CORRESPONDS_TO]->(ap2:AttackPattern)
RETURN c, collect(DISTINCT ap) + collect(DISTINCT ap2) AS techniques, af, a;
``
