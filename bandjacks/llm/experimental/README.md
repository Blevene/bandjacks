# Experimental LLM Modules

This folder contains experimental and research modules that are **NOT** part of the core extraction and review pipeline.

## Important Note

These modules are used by experimental API endpoints but are **NOT** used by:
- The main extraction pipeline (`/v1/reports/ingest`)
- The unified review system (`/v1/reports/{id}/unified-review`)
- The frontend UI

## Modules

### Judge System
- `judge_client.py` - LLM-based judging client for sequence validation
- `judge_cache.py` - Caching layer for judge verdicts
- `judge_integration.py` - PTG and judge system integration
- `evidence_pack.py` - Evidence packaging for judge decisions
- `triage.py` - Pair-wise triage logic for sequences

**Used by**: `/v1/sequence/*` endpoints

### PTG System (Probabilistic Temporal Graph)
- `ptg_builder.py` - Builds probabilistic graphs from attack sequences
- `ptg_config.py` - Configuration for PTG building

**Used by**: `/v1/sequence/*` endpoints

### Attack Flow Simulation
- `attack_flow_simulator.py` - Simulates attack flows and paths

**Used by**: `/v1/attackflow/*` endpoints

### Sequence Analysis
- `sequence_extractor.py` - Extracts and analyzes technique sequences

**Used by**: `/v1/sequence/*` endpoints

### Other Experimental
- `opportunities.py` - Opportunity analysis (currently unused)

## Status

These modules represent experimental features that may be:
- Under development
- Used for research purposes
- Candidates for future integration into the core system
- Eventually deprecated if not proven useful

## Migration Note

These modules were moved from `bandjacks/llm/` to `bandjacks/llm/experimental/` as part of the codebase cleanup effort to clearly separate production code from experimental features.