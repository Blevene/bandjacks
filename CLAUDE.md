# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Bandjacks is a Cyber Threat Defense World Modeling system designed to:
- Ingest and process cyber threat intelligence from multiple sources
- Build a comprehensive knowledge graph of threat actors, techniques, and defenses
- Model attack flows and sequences based on MITRE ATT&CK framework
- Integrate with D3FEND ontology for defensive recommendations
- Provide simulation and prediction capabilities for threat behaviors

## Current Status

The project is in the **planning/architecture phase**. The repository contains:
- Comprehensive technical architecture documentation in `/product_management_stuff/architecture.md`
- Detailed functional specification with sprint-based implementation plan in `/product_management_stuff/functional_spec.md`
- Basic git configuration and Python-oriented `.gitignore`
- No implementation code yet

## Architecture Overview

The system consists of these main components:

1. **Ingestion & Mapping**: Parser, vector retriever, IE & linker, STIX mapper with ADM validation
2. **Knowledge Layer**: Neo4j property graph, RDF/OWL store via n10s, OpenSearch KNN vector store
3. **World Model**: Attack flow builder, D3FEND overlay, simulation/prediction, coverage analytics
4. **Feedback & Operations**: Review API/UI, active learning queue, model refresh, RBAC

Key technologies and standards:
- **FastAPI** with **uv** for Python package management
- **Neo4j** with neosemantics (n10s) for RDF bridge
- **OpenSearch KNN** for vector embeddings
- **STIX 2.1** with strict **ATT&CK Data Model (ADM)** validation
- **ATT&CK release pinning** via official `index.json` catalog
- **D3FEND** ontology integration for defensive mappings
- Optional Node.js sidecar for ADM validation or JSON-Schema export

## Development Commands

Based on the architecture using FastAPI and uv:

```bash
# Project setup (when implemented)
uv sync                    # Install dependencies
uv run pytest             # Run tests
uv run python -m bandjacks.api  # Start FastAPI server

# Development tasks
uv run ruff check .       # Lint code
uv run mypy .            # Type checking
uv run pytest tests/unit  # Run unit tests only
uv run pytest -k "test_name"  # Run specific test

# Database setup
# Neo4j constraints/indexes will be in migrations
# OpenSearch index templates to be created on startup
```

## Implementation Roadmap

The functional spec defines feature-based sprints:

**Sprint 1 (2 weeks)** - Foundations: Catalog, Loader, ADM Validation, TTP Search
- ATT&CK catalog API with release pinning
- STIX bundle ingestion with ADM validation
- Vector embeddings and TTP search endpoint

**Sprint 2 (2 weeks)** - Mapper MVP & Review Hooks
- Report-derived bundle processing
- Analyst review decisions API

**Sprint 3 (3 weeks)** - Attack Flow Builder v1 + Flow Search
- Episode assembly and sequencing
- STIX Attack Flow generation
- Similar flow search

**Sprint 4 (2 weeks)** - D3FEND Overlay & Defense Recommendations
- D3FEND ontology integration
- COUNTERS edges and artifact hints
- Minimal-cut defensive recommendations

**Sprint 5 (3 weeks)** - Feedback → Active Learning & Coverage Analytics
- Uncertainty queues and retraining
- Coverage gap analysis by tactic/platform

## Key Design Decisions

- **ATT&CK release pinning**: Use official `index.json` catalog for version control
- **ADM-gated validation**: All STIX content must pass ATT&CK Data Model validation
- **Dual representation**: RDF/OWL for semantics, Neo4j property graph for analytics
- **TTP-centric**: Focus on behaviors, IOCs out of scope except for context
- **Hybrid retrieval**: Vector KNN to seed candidates, graph for precise linking
- **Attack Flow first-class**: Materialized as STIX extension and graph structure
- **Provenance tracking**: Every node/edge stamped with source metadata
- **No downgrades**: Prevent accidental version rollbacks unless forced

## Graph Schema

Primary node types:
- AttackPattern (techniques & sub-techniques with `x_mitre_is_subtechnique`)
- Tactic, IntrusionSet, Software, Mitigation
- DataSource, DataComponent
- AttackEpisode, AttackAction (operational)
- D3fendTechnique, DigitalArtifact (defense overlay)

Primary edge types:
- USES (Group→Technique, Software→Technique)
- HAS_TACTIC (Technique→Tactic via kill_chain_phases)
- MITIGATES (Mitigation→Technique)
- NEXT {p} (AttackAction→AttackAction with probability)
- COUNTERS (D3fendTechnique→Technique/AttackAction)

Core properties (all nodes):
- `stix_id`, `type`, `name`, `description`, `created`, `modified`, `revoked`
- `source`: `{collection, version, modified, url, adm_spec, adm_sha}`

## API Endpoints (v1)

All endpoints under `/v1` with OpenAPI spec:

**Catalog & Loading**
- `GET /v1/catalog/attack/releases` - List ATT&CK collections/versions
- `POST /v1/stix/load/attack?collection=&version=&adm_strict=true` - Load ATT&CK release
- `POST /v1/stix/bundles?strict=true` - Import validated STIX bundles

**Search**
- `POST /v1/search/ttx` - Text→ATT&CK technique candidates (KNN)
- `POST /v1/search/flows` - Find similar attack flows

**Flows**
- `POST /v1/flows/build?source_id=` - Build attack flow from observations
- `GET /v1/flows/{flow_id}` - Get flow steps and NEXT edges

**Defense**
- `GET /v1/defense/overlay/{flow_id}` - D3FEND techniques per step
- `POST /v1/defense/mincut` - Compute minimal defensive set

**Review & Feedback**
- `POST /v1/review/mapping` - Accept/edit/reject object mappings
- `POST /v1/review/flowedge` - Review flow edge decisions
- `GET /v1/analytics/coverage` - Coverage gap analysis

## Environment Configuration

Key environment variables:
```bash
ATTACK_INDEX_URL=.../attack-stix-data/master/index.json
ATTACK_COLLECTION=enterprise-attack
ATTACK_VERSION=latest

ADM_MODE=sidecar|schema
ADM_BASE_URL=http://adm-validate:8080
ADM_SPEC_MIN=3.3.0

NEO4J_URI=bolt://neo4j:7687
OPENSEARCH_URL=http://opensearch:9200
BLOB_BASE=s3://world-model/
```

## Performance Targets (Dev)

- `/search/ttx` P95 ≤ 300ms (top_k ≤ 10)
- Initial ATT&CK load ≤ 5 min
- Flow build for small episode (≤ 10 actions) ≤ 2s

## Important Notes

- **Defensive security focus**: Designed for threat analysis and defense only
- **TTP-centric**: No IOC lifecycle management (out of scope)
- **Strict validation**: All STIX content must pass ADM validation
- **Version control**: ATT&CK releases are pinned, no accidental downgrades
- **Analyst-in-the-loop**: Designed for review and feedback integration