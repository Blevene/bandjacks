# Bandjacks Product Requirements Document

**Title:** Adversary World Model System with ATT\&CK STIX 2.1, D3FEND Integration, and Adaptive Attack Flow Generation
**Version:** Draft
**Author:** \[Brandon Levene]
**Date:** \[2025-08-15]
**Last Update:** \[2025-08-15]

---

## 1. Overview

The system models adversary behavior using MITRE ATT\&CK STIX 2.1 as the primary schema, integrates MITRE D3FEND for defensive mappings, and generates **Attack Flow** sequences from real-world threat intelligence. It operates as a **hybrid graph + vector** platform to enable retrieval, reasoning, simulation, and adaptation from continuous intelligence inputs.

---

## 2. Goals & Objectives

* **Model adversary behavior** in a structured, queryable format compliant with STIX 2.1.
* **Integrate defense mappings** from D3FEND to link attacks to countermeasures and artifacts.
* **Automate attack flow creation** from processed threat intelligence.
* **Enable simulation** of potential attacker courses of action and defensive impacts.
* **Continuously adapt** using feedback loops from analyst review and new data.

---

## 3. Scope

### In Scope

* Ingestion of **ATT\&CK STIX 2.1** (via TAXII) and **D3FEND ontology**.
* Parsing of unstructured (PDF, blog, markdown) and structured (JSON, CSV) intelligence reports.
* Natural language and pattern-based extraction of entities, techniques, tools, and relationships.
* Transformation of extracted data into **STIX SDO/SRO** objects.
* Attack Flow generation following the STIX 2.1 extension for ordered behavior.
* Vector embedding of nodes, edges, and flows for hybrid search.
* Feedback mechanisms for analyst review and iterative model improvement.

### Out of Scope (v1)

* Real-time intrusion detection or automated enforcement actions.
* Native UI for broad operational SOC integration (analyst review UI will be minimal).
* Proprietary data source connectors beyond common file/API ingestion.

---

## 4. Functional Requirements

### 4.1 Data Ingestion & Normalization

**Inputs:**

* MITRE ATT\&CK STIX 2.1 (Enterprise, Mobile, ICS collections).
* MITRE D3FEND OWL ontology and mapping tables.
* Threat intelligence in unstructured and structured formats.

**Processes:**

* Parse and extract text from PDFs, HTML/blogs, markdown.
* Normalize indicators (T-IDs, CVEs, IPs, domains).
* Tokenize, clean, and segment for downstream extraction.

**Outputs:**

* Cleaned, structured text blocks and metadata for extraction and mapping.

---

### 4.2 Entity & Relation Extraction

* Identify entities: threat actors, intrusion sets, malware, tools, infrastructure, data components.
* Detect ATT\&CK techniques/tactics via ID match, keyword match, and semantic similarity.
* Extract relationships (`uses`, `targets`, `delivers`, `indicates`, `mitigates`).
* Score relationships with confidence values.

---

### 4.3 Knowledge Graph Integration

* Store ATT\&CK and D3FEND objects as nodes with properties:

  * `id`, `name`, `description`, `type`, `created`, `modified`, `revoked`, `confidence`.
* Store relationships as typed edges with direction, STIX relationship type, and provenance.
* Maintain both RDF/OWL and property graph representations.
* Materialize `COUNTERS` relationships from D3FEND to ATT\&CK techniques.

---

### 4.4 Vector Indexing

* Generate embeddings for:

  * Nodes (descriptions, aliases, detection guidance).
  * Edges (relation summaries).
  * Attack Flows (ordered step text).
* Store embeddings in vector database (e.g., OpenSearch KNN) keyed to graph IDs.

---

### 4.5 Attack Flow Generation

* Group observations into “episodes” based on shared entities and time windows.
* Order events by time; merge duplicates and handle concurrency.
* Create `attack-action` objects for each step with references to ATT\&CK IDs.
* Link steps with `next` relationships and conditional branches as applicable.
* Output valid STIX 2.1 Attack Flow JSON and ingest into graph.

---

### 4.6 Analyst Feedback Loop

* Display proposed objects, relationships, and flows with scores.
* Allow accept / edit / reject actions.
* Log decisions with rationale.
* Use decisions to retrain extraction, linking, and sequencing models.

---

### 4.7 Simulation & Query

* Query graph for likely next techniques given current episode context.
* Overlay D3FEND controls to determine defensive choke points.
* Compute coverage gaps by tactic, platform, or artifact.

---

## 5. User Journeys

### 5.1 Threat Intelligence Analyst

1. Upload or connect a new report.
2. System parses, extracts, and generates candidate STIX objects and Attack Flow.
3. Analyst reviews in UI:

   * Confirms or edits mappings to ATT\&CK.
   * Adjusts flow sequencing if needed.
4. System updates graph, vector store, and model weights.

**Outcome:** Verified, structured representation of the report’s adversary behavior integrated into the world model.

---

### 5.2 Detection Engineer

1. Search for recent flows involving a specific technique or platform.
2. View D3FEND mappings for those techniques.
3. Identify missing detection controls or artifacts.
4. Update detection backlog or deploy new rules.

**Outcome:** Prioritized detection engineering tasks mapped directly to observed adversary patterns.

---

### 5.3 Threat Hunter

1. Input partial observed sequence from telemetry.
2. System retrieves similar historical flows via vector search.
3. Predicts probable next steps based on past patterns.
4. Hunter pivots to search for indicators from predicted steps.

**Outcome:** Faster, intelligence-driven hypothesis generation during hunts.

---

## 6. Non-Functional Requirements

* **Performance:** Initial graph load of ATT\&CK+D3FEND ≤ 5 min on target infra.
* **Scalability:** Support ≥ 5M nodes and 20M edges.
* **Interoperability:** Strict STIX 2.1 compliance for import/export.
* **Security:** Enforce TLP and other markings per STIX marking definitions.
* **Extensibility:** Support additional ontologies (e.g., D3FEND updates, CAPEC).

---

## 7. Success Metrics

* ≥ 90% analyst acceptance rate on system-generated entity mappings after 3 months.
* ≥ 80% accuracy in automated technique assignment (vs. gold-standard set).
* Reduction of average report-to-graph time from days to hours.
* Increase in detection coverage for high-risk techniques over 6 months.

---

## 8. Open Questions

* Will we integrate **CAPEC** for attack patterns not in ATT\&CK?
* Should we incorporate industry-specific ATT\&CK extensions?
* Which embedding model family will we standardize on for v1?

---

If you’d like, I can follow up with an **architecture diagram + data flow** so the PRD has a visual showing how ATT\&CK, D3FEND, the vector store, and the feedback loop connect. That would make onboarding new engineers much faster.
