# Codebase Redundancy Analysis Report

## Executive Summary
This report identifies redundant, unused, or replaced functions and files in the `llm`, `services`, and `loaders` folders of the Bandjacks codebase.

---

## 1. LLM Folder Analysis

### Files Marked as Deleted (Git Status)
These files have been removed from the working directory but not yet committed:
- **`attack_flow_generator.py`** - Replaced by `flow_builder.py`
- **`flows.py`** - Functionality merged into `flow_builder.py` and `attack_flow_validator.py`

### Potentially Unused/Redundant Files

#### Low/No Usage Files:
1. **`al_sampler.py`** - Active Learning sampler
   - Status: **UNUSED** - No imports found in codebase
   - Purpose: Was for active learning sampling, but not integrated

2. **`embedding_refresher.py`** 
   - Status: **MINIMALLY USED** - Only referenced in `active_learning.py` and tests
   - Purpose: Embedding cache management after reviews
   - Recommendation: Remove if active learning is not being pursued

3. **`entity_resolver.py`**
   - Status: **UNUSED** - No imports found
   - Purpose: Entity resolution logic
   - Recommendation: Remove or integrate if needed

4. **`flow_exporter.py`**
   - Status: **UNUSED** - No direct imports found
   - Purpose: Export flows to various formats
   - Recommendation: Check if functionality moved elsewhere

5. **`stix_converter.py`**
   - Status: **UNUSED** - No imports found
   - Purpose: STIX format conversion
   - Note: `stix_builder.py` is actively used instead

6. **`tactic_priors.py`**
   - Status: **USED** only in `ptg_builder.py` and `evidence_pack.py`
   - Purpose: Tactic probability priors
   - Recommendation: Consider if still needed

### Replaced/Superseded Files

#### Agent Evolution:
- **Original**: `agents.py` (not present)
- **Current Active**: `agents_v2.py` - Primary agent implementation
- **Optimizations**:
  - `agentic_v2_optimized.py` - Performance optimized version
  - `agentic_v2_async.py` - Async parallel processing version
- **Recommendation**: Consolidate to one primary implementation

#### Extraction Pipeline Evolution:
- **Current Primary**: `extraction_pipeline.py` - Main extraction orchestrator
- **Alternative**: `chunked_extractor.py` - For large documents
- Both are actively used and serve different purposes

---

## 2. Services Folder Analysis

### Deleted Files (Git Status)
- **`services/api/routes/reports_async.py`** - Async report handling
  - Status: **DELETED** - No imports found
  - Replaced by: Synchronous `reports.py` with job processing

### Potentially Unused Service Files

#### Core Services:
1. **`cache_manager.py`**
   - Status: **MINIMALLY USED** - Only in `notification_service.py` and tests
   - Purpose: Cache management service
   - Recommendation: Review if caching strategy has changed

2. **`notification_service.py`**
   - Status: **MINIMALLY USED** - Only self-referential imports
   - Purpose: Notification handling
   - Recommendation: Remove if notifications not implemented

### Potentially Unused API Routes

These routes are imported in `main.py` but may have limited usage:

1. **Low Usage Routes** (check if still needed):
   - `candidates.py` - Candidate management
   - `drift.py` - Drift detection
   - `feedback.py` - Feedback collection
   - `review_queue.py` - Review queue management
   - `review.py` - Review workflows
   - `simulate.py` vs `simulation.py` - Duplicate simulation endpoints?

2. **Specialized Routes** (verify if actively used):
   - `compliance.py` - Compliance checking
   - `coverage.py` - Coverage analysis
   - `ml_metrics.py` - ML metrics tracking
   - `notifications.py` - Notification endpoints

---

## 3. Loaders Folder Analysis

### Potentially Unused Loader Files

1. **`attack_catalog.py`**
   - Status: **UNUSED** - No imports found
   - Purpose: Attack catalog loading
   - Recommendation: Remove or verify if needed

2. **`chunker.py`**
   - Status: **UNUSED** - No imports found
   - Purpose: Text chunking
   - Note: Chunking logic may have moved to LLM folder

3. **`d3fend_verifier.py`**
   - Status: **MINIMALLY USED** - Only in specific routes
   - Purpose: D3FEND verification
   - Keep if D3FEND integration is planned

4. **`parse_text.py`**
   - Status: **UNUSED** - No direct imports
   - Purpose: Text parsing utilities
   - Recommendation: Check if functionality moved elsewhere

5. **`search_nodes.py`**
   - Status: **MINIMALLY USED**
   - Purpose: Node search functionality
   - May be replaced by `enhanced_search.py` or `hybrid_search.py`

---

## 4. Key Findings and Recommendations

### High Priority Removals (Unused/Deleted):
1. **LLM Folder**:
   - Remove: `al_sampler.py`, `entity_resolver.py`, `flow_exporter.py`, `stix_converter.py`
   - Already deleted: `attack_flow_generator.py`, `flows.py`

2. **Services Folder**:
   - Consider removing: `notification_service.py` (if not implementing notifications)
   - Already deleted: `reports_async.py`

3. **Loaders Folder**:
   - Remove: `attack_catalog.py`, `chunker.py`, `parse_text.py`

### Medium Priority (Consolidation Opportunities):
1. **Agent Implementations**: 
   - Consolidate `agents_v2.py`, `agentic_v2_optimized.py`, `agentic_v2_async.py`
   - Keep one primary implementation with configuration options

2. **Search Implementations**:
   - Review overlap between `enhanced_search.py`, `hybrid_search.py`, `search_nodes.py`
   - Consider consolidating into single search module

3. **Simulation Routes**:
   - Clarify difference between `simulate.py` and `simulation.py`
   - Merge if they serve similar purposes

### Low Priority (Verify Usage):
1. Review specialized routes that may not be in active use
2. Check if active learning components (`active_learning.py`, `embedding_refresher.py`) are still planned
3. Verify if all mapper variations are needed (`mapper.py` vs `mapper_optimized.py`)

### Code Health Improvements:
1. **Documentation**: Add deprecation notices to files being phased out
2. **Testing**: Ensure tests don't reference deleted/unused files
3. **Imports**: Clean up unused imports across the codebase
4. **Configuration**: Use feature flags to enable/disable optional components

---

## 5. Migration Path

### Immediate Actions:
1. Remove clearly unused files listed in "High Priority Removals"
2. Add deprecation warnings to files being phased out
3. Update imports to use consolidated modules

### Short-term (1-2 weeks):
1. Consolidate agent implementations
2. Merge duplicate functionality
3. Clean up test files

### Long-term:
1. Refactor to clear module boundaries
2. Implement proper plugin architecture for optional features
3. Document the canonical implementation for each feature

---

## Appendix: File Usage Statistics

### Most Imported LLM Modules:
1. `client.py` - Core LLM client
2. `memory.py` - Working memory
3. `agents_v2.py` - Main agents
4. `flow_builder.py` - Flow construction
5. `tools.py` - LLM tools

### Most Imported Service Modules:
1. `main.py` - FastAPI app
2. `deps.py` - Dependencies
3. `settings.py` - Configuration
4. `schemas.py` - Data schemas

### Most Imported Loader Modules:
1. `embedder.py` - Embedding generation
2. `opensearch_index.py` - OpenSearch operations
3. `neo4j_ddl.py` - Neo4j schema
4. `edge_embeddings.py` - Edge embedding management

---

## 6. Frontend Analysis

### Navigation Links to Non-Existent Pages
The navigation component (`ui/components/navigation.tsx`) includes links to pages that don't exist:

1. **Missing Pages** (linked in navigation but files don't exist):
   - `/feedback` - No `ui/app/feedback/page.tsx` found
   - `/settings` - No `ui/app/settings/page.tsx` found
   - `/analytics/active-learning` - No `ui/app/analytics/active-learning/page.tsx` found

### Frontend Pages Using Deprecated/Unused Backend Services

#### Review-Related Pages
- **`/review/queue`** (`ui/app/review/queue/page.tsx`)
  - Uses: `typedApi.activeLearning.getQueue()` and `typedApi.activeLearning.getStatistics()`
  - Backend: These likely use the unused active learning components
  - **Recommendation**: Remove if active learning is not being pursued

- **`/review`** and **`/review/[id]`** 
  - Uses review candidate endpoints
  - Backend routes still exist but may have limited usage
  - **Recommendation**: Verify if review workflow is still active

#### Simulation Page
- **`/simulation`** (`ui/app/simulation/page.tsx`)
  - Contains 4 sub-components: PathSimulator, PredictionPanel, WhatIfAnalyzer, ScenarioBuilder
  - Backend: Check if `simulate.py` vs `simulation.py` confusion affects this
  - **Recommendation**: Verify which simulation endpoints are actually implemented

#### Campaigns Page
- **`/campaigns`** (`ui/app/campaigns/page.tsx`)
  - Uses: `typedApi` for campaign operations
  - Backend: `candidates.py` route may be related
  - **Recommendation**: Verify if campaign management is actively used

### Frontend Components Referencing Unused Functionality

1. **Feedback Components**:
   - `ui/components/features/feedback/feedback-form.tsx` - Exists but no page uses it
   - `ui/components/navigation.tsx` - Links to non-existent feedback page

2. **Simulation Components** (may be over-engineered):
   - `ui/components/features/simulation/` - Contains 4 different simulation components
   - `ui/components/simulation/` - Duplicate simulation components folder
   - **Recommendation**: Consolidate duplicate folders

3. **Review Components**:
   - `ui/components/review/queue-stats.tsx`
   - `ui/components/review/review-item.tsx`
   - Used by review queue page which depends on unused active learning

### API Client References to Deprecated Endpoints

The `ui/lib/api-client.ts` file includes typed API methods for:
- Active learning operations
- Review operations  
- Feedback operations
- Simulation operations (multiple variants)

Many of these correspond to the unused backend services identified earlier.

### Duplicate/Redundant Frontend Components

1. **Simulation Components** - Two folders with same components:
   - `ui/components/features/simulation/`
   - `ui/components/simulation/`
   Both contain: path-simulator.tsx, prediction-panel.tsx, scenario-builder.tsx, whatif-analyzer.tsx

### Frontend Cleanup Recommendations

#### High Priority (Remove):
1. Remove navigation links to non-existent pages:
   - Feedback link
   - Settings link (unless implementing)
   - AL Analytics link

2. Remove unused pages if features are deprecated:
   - `/review/queue` - if active learning is not pursued
   - Simulation page - if not implementing all 4 simulation modes

3. Remove duplicate component folders:
   - Consolidate simulation components into one folder

#### Medium Priority (Verify & Clean):
1. Review workflow pages - verify if still needed
2. Campaign pages - check usage metrics
3. API client methods for unused endpoints

#### Low Priority (Polish):
1. Clean up unused component imports
2. Remove test files for deprecated features
3. Update TypeScript types to remove unused API schemas

### Impact Analysis

Removing these frontend elements would:
- **Reduce bundle size** by removing unused components
- **Improve UX** by removing non-functional navigation items  
- **Reduce confusion** by eliminating duplicate component folders
- **Simplify maintenance** by reducing surface area

### Migration Steps for Frontend

1. **Immediate**:
   - Remove broken navigation links
   - Add "Coming Soon" badges to features under development
   - Consolidate duplicate component folders

2. **Short-term**:
   - Remove pages for deprecated features
   - Clean up API client to remove unused methods
   - Update tests to remove deprecated feature tests

3. **Long-term**:
   - Implement proper feature flags for experimental features
   - Create a plugin system for optional features
   - Document which features are core vs optional

---

*Generated: [Current Date]*
*Analysis based on import patterns, git status, and code references*
