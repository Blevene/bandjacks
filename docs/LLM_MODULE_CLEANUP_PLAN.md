# LLM Module Cleanup Plan

## ⚠️ IMPORTANT FINDINGS (Updated with Complete Flow Analysis)

### Production PDF Upload Flow
**Frontend → Backend → Extraction Modules**

1. **ACTIVE PATHS** (Used by frontend at `/reports/new`):
   - Small files (<5KB): `/v1/reports/ingest/upload` → `run_extraction_pipeline()`
   - Large files (>5KB): `/v1/reports/ingest_file_async` → JobProcessor →
     - Small docs (<10KB): `run_extraction_pipeline()`
     - Large docs (>10KB): `OptimizedChunkedExtractor` or `ChunkedExtractor`

2. **DEAD CODE** (Not used by frontend):
   - `/extract` endpoint (routes/extract.py) - Not even registered in main.py
   - `/extract/runs` endpoint (routes/extract_runs.py) - Registered but NEVER called by frontend
   - `agentic_v2_async.py` - Only used by dead `/extract/runs` endpoint
   - `agentic_v2_optimized.py` - Never imported anywhere in production

3. **ESSENTIAL MODULES** (Must keep):
   - **Detection validators** (`detection_validator.py`, `sigma_validator.py`) - Used by API endpoints
   - **Batch Neo4j** (`batch_neo4j.py`) - Critical for flow_builder.py performance
   - **Extraction pipeline** (`extraction_pipeline.py`) - Core of all extraction
   - **Chunked extractors** - Used for large document processing

## Overview
The `bandjacks/llm/` folder currently contains 56 modules, but only 23 are actively used in the production extraction pipeline. This document tracks the cleanup effort to remove redundant code and organize the remaining modules.

## Current State Analysis

### Active Production Modules (23 files)
These modules are actively used in the extraction pipeline and must be preserved:

#### Core Pipeline
- `extraction_pipeline.py` - Main pipeline coordinator
- `chunked_extractor.py` - Standard chunked processing
- `optimized_chunked_extractor.py` - Advanced chunked processing

#### Agent Chain
- `agents_v2.py` - All core extraction agents
- `mapper_optimized.py` - BatchMapperAgent
- `batch_retriever.py` - BatchRetrieverAgent
- `entity_extractor.py` - EntityExtractionAgent
- `entity_consolidator.py` - EntityConsolidatorAgent
- `entity_batch_extractor.py` - BatchEntityExtractor

#### Infrastructure
- `memory.py` - WorkingMemory class
- `tools.py` - Vector search and ATT&CK lookup
- `client.py` - LLM client and tool execution
- `flow_builder.py` - Attack flow generation
- `tracker.py` - ExtractionTracker

#### Utilities
- `entity_utils.py` - Entity consolidation
- `evidence_utils.py` - Evidence extraction
- `json_utils.py` - JSON parsing
- `consolidator_base.py` - Base consolidation class
- `accumulator.py` - ThreadSafeAccumulator
- `token_utils.py` - Token estimation
- `semantic_dedup.py` - Deduplication
- `vector_cache.py` - Search caching
- `entity_ignorelist.py` - Entity filtering

## Cleanup Phases

### Phase 1: Remove Clearly Redundant Modules (REVISED)
**Goal**: Remove unused and legacy modules that have no production dependencies.

#### ✅ Task 1.1: Remove Legacy Extractors and Dead Endpoints
**STATUS**: READY TO EXECUTE - These are dead code paths
- **Safe to delete immediately**:
  - [ ] Delete `routes/extract.py` - Not registered in main.py, completely unused
  - [ ] Delete `agentic_v2_optimized.py` - Never imported in production

- **Safe to delete after cleanup**:
  - [ ] Remove `extract_runs` import from main.py
  - [ ] Delete `routes/extract_runs.py` - Registered but NEVER called by frontend
  - [ ] Delete `agentic_v2_async.py` - Only used by dead extract_runs endpoint

- **Test cleanup**:
  - [ ] Fix or delete tests importing non-existent `agentic_v2.py`
  - [ ] Update tests to use `extraction_pipeline` instead

- **Commits** (in order):
  1. "Remove unused /extract endpoint and route file"
  2. "Remove unused /extract/runs endpoint and agentic_v2_async"
  3. "Clean up broken test imports"

#### ❌ Task 1.2: Detection Validators - MUST KEEP
**STATUS**: CANCELLED - These are essential production components
- **`detection_validator.py`**: ✅ KEEP - Used by `detection_loader.py` → `/detections` API
- **`sigma_validator.py`**: ✅ KEEP - Used by `sigma_loader.py` → `/sigma` API
- **Reason**: Critical for detection rule validation functionality
- **No action needed**

#### ✅ Task 1.3: Remove Unused Active Learning System
**STATUS**: READY TO EXECUTE
- [ ] Archive or delete `active_learning.py`
- [ ] Archive or delete `al_sampler.py`
- [ ] Archive or delete `embedding_refresher.py`
- [ ] Update test imports if keeping tests
- **Note**: Only used in tests, safe to remove
- **Commit**: "Remove unused active learning components"

#### ✅ Task 1.4: Other Modules Status
- **`batch_neo4j.py`**: ✅ KEEP - Essential for `flow_builder.py` optimizations
- **No modules to remove in this task**

### Phase 2: Archive Experimental Systems
**Goal**: Move experimental/research code to a dedicated folder to reduce clutter.

#### Task 2.1: Create Experimental Folder Structure
- [ ] Create `bandjacks/llm/experimental/` folder
- [ ] Create `bandjacks/llm/experimental/__init__.py`
- [ ] Create `bandjacks/llm/experimental/README.md` explaining the folder
- **Commit**: "Create experimental folder structure"

#### Task 2.2: Move Judge System
- [ ] Move `judge_client.py` → `experimental/judge_client.py`
- [ ] Move `judge_cache.py` → `experimental/judge_cache.py`
- [ ] Move `judge_integration.py` → `experimental/judge_integration.py`
- [ ] Move `evidence_pack.py` → `experimental/evidence_pack.py`
- [ ] Move `triage.py` → `experimental/triage.py`
- [ ] Update imports in test files
- **Commit**: "Archive judge/triage system to experimental"

#### Task 2.3: Move PTG System
- [ ] Move `ptg_builder.py` → `experimental/ptg_builder.py`
- [ ] Move `ptg_config.py` → `experimental/ptg_config.py`
- [ ] Update any test imports
- **Commit**: "Archive PTG system to experimental"

#### Task 2.4: Move Other Experimental Modules
- [ ] Move `attack_flow_simulator.py` → `experimental/attack_flow_simulator.py`
- [ ] Move `sequence_extractor.py` → `experimental/sequence_extractor.py`
- [ ] Move `opportunities.py` → `experimental/opportunities.py`
- [ ] Update imports in tests and examples
- **Commit**: "Archive remaining experimental modules"

### Phase 3: Consolidate Core Modules
**Goal**: Merge related functionality to reduce module count.

#### Task 3.1: Consolidate Entity Processing
- [ ] Merge `entity_utils.py` functions into `entity_consolidator.py`
- [ ] Update all imports from entity_utils to entity_consolidator
- [ ] Delete `entity_utils.py`
- [ ] Run tests to verify
- **Commit**: "Consolidate entity processing modules"

#### Task 3.2: Consolidate Evidence Processing
- [ ] Merge `evidence_utils.py` functions into `consolidator_base.py`
- [ ] Update all imports
- [ ] Delete `evidence_utils.py`
- [ ] Verify with tests
- **Commit**: "Consolidate evidence processing modules"

#### Task 3.3: Consolidate Token Management
- [ ] Merge `budget.py` into `token_utils.py`
- [ ] Update any imports
- [ ] Delete `budget.py`
- [ ] Test token management functionality
- **Commit**: "Consolidate token management modules"

### Phase 4: Documentation and Organization
**Goal**: Document the cleaned-up structure for future maintenance.

#### Task 4.1: Create Module Documentation
- [ ] Create `bandjacks/llm/README.md` with:
  - Module organization overview
  - Extraction pipeline flow diagram
  - Module dependency graph
  - Purpose of each production module
- **Commit**: "Add LLM module documentation"

#### Task 4.2: Add Deprecation Notices
- [ ] Add deprecation warnings to any modules scheduled for future removal
- [ ] Update docstrings to indicate module status (production/experimental/deprecated)
- **Commit**: "Add module status indicators"

#### Task 4.3: Update Import Organization
- [ ] Update `__init__.py` to expose only production modules
- [ ] Create clear import paths for common functionality
- [ ] Add type hints where missing
- **Commit**: "Organize module imports and exports"

## Validation Checklist

After each phase, verify:
- [ ] All tests pass (`uv run pytest`)
- [ ] Extraction pipeline works (`python -m bandjacks.cli.batch_extract`)
- [ ] API endpoints function (`/v1/reports/ingest`)
- [ ] No broken imports (`uv run python -m py_compile bandjacks/llm/*.py`)

## Expected Outcomes (Final)

### Before Cleanup
- 56 modules in `bandjacks/llm/`
- 2 dead API route files (`extract.py`, `extract_runs.py`)
- Mixed production and experimental code
- Unclear module dependencies
- Redundant implementations

### After Cleanup
- **~46 modules remaining in llm/** (10 removed/archived)
  - ~36 production modules in `bandjacks/llm/`
  - ~10 modules in `bandjacks/llm/experimental/` (judge, PTG, simulation)
  - 5 LLM modules deleted (2 legacy extractors, 3 active learning)
  - 2 route files deleted (dead endpoints)
- Clear separation of concerns
- Single extraction pipeline path (`extraction_pipeline.py`)
- No dead code paths
- Well-documented module purposes

## Module Status Reference

### Production (Keep in main folder)
✅ extraction_pipeline.py
✅ optimized_chunked_extractor.py
✅ chunked_extractor.py
✅ agents_v2.py
✅ mapper_optimized.py
✅ batch_retriever.py
✅ entity_extractor.py
✅ entity_consolidator.py
✅ entity_batch_extractor.py
✅ memory.py
✅ tools.py
✅ client.py
✅ flow_builder.py
✅ tracker.py
✅ consolidator_base.py
✅ accumulator.py
✅ semantic_dedup.py
✅ vector_cache.py
✅ entity_ignorelist.py
✅ json_utils.py
✅ prompts.py
✅ schemas.py
✅ cache.py
✅ rate_limiter.py
✅ tactic_priors.py
✅ stix_builder.py
✅ stix_converter.py
✅ bundle_validator.py
✅ provenance_tracker.py
✅ flow_exporter.py
✅ attack_flow_validator.py
✅ sequence_proposal.py
✅ entity_resolver.py

### To Be Consolidated
🔀 entity_utils.py → entity_consolidator.py
🔀 evidence_utils.py → consolidator_base.py
🔀 token_utils.py + budget.py → token_utils.py

### To Archive (Experimental)
📦 judge_client.py
📦 judge_cache.py
📦 judge_integration.py
📦 evidence_pack.py
📦 triage.py
📦 ptg_builder.py
📦 ptg_config.py
📦 attack_flow_simulator.py
📦 sequence_extractor.py
📦 opportunities.py

### To Delete (Safe to Remove)
✅ **Dead Endpoints & Routes**:
- routes/extract.py - Not registered, completely dead
- routes/extract_runs.py - Registered but never used by frontend

✅ **Legacy Extractors**:
- agentic_v2_async.py - Only used by dead /extract/runs endpoint
- agentic_v2_optimized.py - Never imported in production

✅ **Active Learning** (test-only):
- active_learning.py
- al_sampler.py
- embedding_refresher.py

### Must Keep (Previously Marked for Deletion)
✅ detection_validator.py - Essential for /detections API
✅ sigma_validator.py - Essential for /sigma API
✅ batch_neo4j.py - Essential for flow_builder.py optimizations

## Recommended Execution Order

Based on the complete flow analysis, here's the safest order:

1. **Phase 1.1**: Remove dead endpoints and legacy extractors
   - These are completely unused by the frontend
   - No risk to production functionality

2. **Phase 1.3**: Remove active learning modules
   - Only used in tests
   - No production impact

3. **Phase 2**: Archive experimental systems
   - Move to experimental/ folder
   - Preserves code for future use

4. **Phase 3**: Consolidate core modules
   - More risky, requires careful testing
   - Do this last after verifying everything still works

## Notes
- Each task should be a separate commit for easy rollback
- Run tests after each phase
- Keep commit messages descriptive
- Update this document as tasks are completed
- **Test the frontend PDF upload after Phase 1.1 to verify nothing broke**