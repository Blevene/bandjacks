# CLI Tooling Modernization Plan

## Project Overview
**Goal**: Upgrade the Bandjacks CLI to match the sophistication of the API's extraction pipeline, ensuring consistent, high-quality results across all interfaces.

**Current State**: CLI uses basic `extract_chunked()` while API uses advanced `run_extraction_pipeline()` with intelligent routing, flow generation, and entity extraction.

**Target State**: Feature-complete CLI with intelligent document processing, flow generation, and full alignment with API capabilities.

## Timeline
- **Start Date**: TBD
- **Target Completion**: 6 weeks from start
- **Review Checkpoints**: End of each phase

## Phase 1: Foundation & Alignment (Week 1-2)
**Objective**: Establish configuration management and align extraction strategies with API

### 1.1 Configuration Management
- [ ] Create `bandjacks/cli/config.py` with shared configuration classes
- [ ] Import settings from `bandjacks/services/api/settings.py`
- [ ] Add CLI-specific overrides via environment variables
- [ ] Create `.bandjacks.yaml` config file support for user preferences
- [ ] Add validation for all configuration parameters
- [ ] Document all configuration options

**Acceptance Criteria**: CLI can read and validate configuration from multiple sources with proper precedence

### 1.2 Extraction Strategy Alignment
- [ ] Port intelligent document size detection from JobProcessor
- [ ] Implement 10KB threshold logic for pipeline selection
- [ ] Add dynamic chunk/span calculation algorithm
- [ ] Create `calculate_chunks_and_spans()` utility function
- [ ] Add document complexity scoring
- [ ] Unit tests for size-based routing

**Acceptance Criteria**: CLI correctly routes documents to appropriate extraction pipeline based on size

### 1.3 Progress & Monitoring Infrastructure
- [ ] Create `bandjacks/cli/progress.py` with rich progress bars
- [ ] Implement callback system for extraction progress
- [ ] Add real-time metrics display (chunks, techniques, confidence)
- [ ] Create summary statistics formatter
- [ ] Add verbose/quiet mode support
- [ ] Add logging configuration

**Acceptance Criteria**: Users can see detailed progress during extraction with configurable verbosity

## Phase 2: Core Extraction Enhancement (Week 2-3)
**Objective**: Integrate advanced extraction pipelines and enhance chunked processing

### 2.1 Pipeline Integration
- [ ] Import `run_extraction_pipeline` from extraction_pipeline.py
- [ ] Create wrapper for small document processing (<10KB)
- [ ] Add flow generation support to CLI output
- [ ] Implement entity extraction in CLI results
- [ ] Add claims processing and consolidation
- [ ] Integration tests with extraction pipeline

**Acceptance Criteria**: CLI can process small documents using the same pipeline as API

### 2.2 Chunked Extraction Upgrade
- [ ] Port OptimizedChunkedExtractor selection logic
- [ ] Add progressive accumulation support
- [ ] Implement early termination logic
- [ ] Add confidence boosting algorithm
- [ ] Create context hint management
- [ ] Performance benchmarks for large documents

**Acceptance Criteria**: Large document processing matches API performance and quality

### 2.3 Output Formatting
- [ ] Create unified result formatter matching API response
- [ ] Add JSON, YAML, and table output formats
- [ ] Implement STIX bundle generation
- [ ] Add technique details with evidence
- [ ] Create flow visualization (ASCII or export)
- [ ] Add export to file options

**Acceptance Criteria**: CLI output format is consistent with API responses

## Phase 3: Advanced Features (Week 3-4)
**Objective**: Add batch processing, API mode optimization, and performance features

### 3.1 Batch Processing Enhancement
- [ ] Add intelligent parallelization based on document sizes
- [ ] Implement job queue with priority handling
- [ ] Add checkpoint/resume capability for large batches
- [ ] Create batch summary reports
- [ ] Add CSV/Excel export for batch results
- [ ] Error handling and retry logic

**Acceptance Criteria**: Can process 100+ documents efficiently with proper error handling

### 3.2 API Mode Optimization
- [ ] Make API mode the default with fallback to direct
- [ ] Add connection testing and auto-discovery
- [ ] Implement retry logic with exponential backoff
- [ ] Add async job monitoring with live updates
- [ ] Create job management commands (list, cancel, retry)
- [ ] Add timeout configuration

**Acceptance Criteria**: Seamless API integration with robust error handling

### 3.3 Caching & Performance
- [ ] Port TechniqueCache integration
- [ ] Add local result caching
- [ ] Implement incremental processing for duplicates
- [ ] Add performance profiling mode
- [ ] Create cache management commands
- [ ] Memory usage optimization

**Acceptance Criteria**: 50% performance improvement for repeated operations

## Phase 4: Interactive Features (Week 4-5)
**Objective**: Build interactive capabilities and command structure

### 4.1 Interactive Mode
- [ ] Create interactive CLI shell with command completion
- [ ] Add technique search and exploration
- [ ] Implement flow editing capabilities
- [ ] Add review workflow in terminal
- [ ] Create technique suggestion system
- [ ] Add help system integration

**Acceptance Criteria**: Full interactive shell with intuitive commands

### 4.2 Integration Commands
- [ ] Add `bandjacks extract` main command
- [ ] Create `bandjacks review` for result validation
- [ ] Implement `bandjacks flow` for flow operations
- [ ] Add `bandjacks search` for technique discovery
- [ ] Create `bandjacks stats` for analytics
- [ ] Add `bandjacks config` for configuration management

**Acceptance Criteria**: Complete command suite with consistent interface

### 4.3 Database Operations
- [ ] Add direct Neo4j result storage
- [ ] Implement OpenSearch indexing
- [ ] Create campaign management commands
- [ ] Add report linking capabilities
- [ ] Implement provenance tracking
- [ ] Add database health checks

**Acceptance Criteria**: Direct database integration without API dependency

## Phase 5: Quality & Testing (Week 5-6)
**Objective**: Ensure quality, documentation, and reliability

### 5.1 Testing Infrastructure
- [ ] Create comprehensive test suite for CLI
- [ ] Add integration tests with API
- [ ] Implement performance benchmarks
- [ ] Create test data generators
- [ ] Add regression test suite
- [ ] Set up CI/CD pipeline

**Acceptance Criteria**: >95% code coverage with automated testing

### 5.2 Documentation
- [ ] Write CLI user guide
- [ ] Create command reference
- [ ] Add example workflows
- [ ] Document configuration options
- [ ] Create troubleshooting guide
- [ ] Add API migration guide

**Acceptance Criteria**: Complete documentation for all features

### 5.3 Validation & Quality
- [ ] Add input validation for all file types
- [ ] Implement error recovery mechanisms
- [ ] Create detailed error messages
- [ ] Add logging with rotation
- [ ] Implement telemetry (optional)
- [ ] Security audit

**Acceptance Criteria**: Robust error handling with clear user feedback

## Phase 6: Deployment & Migration (Week 6)
**Objective**: Deploy new CLI and migrate existing users

### 6.1 Migration Tools
- [ ] Create migration script from old CLI format
- [ ] Add backward compatibility mode
- [ ] Implement config migration utility
- [ ] Create comparison tool (old vs new)
- [ ] Add rollback capability
- [ ] User notification system

**Acceptance Criteria**: Zero-downtime migration for existing users

### 6.2 Packaging & Distribution
- [ ] Update setup.py/pyproject.toml
- [ ] Create standalone executable
- [ ] Add shell completion scripts
- [ ] Create Docker image
- [ ] Implement auto-update mechanism
- [ ] Package for different platforms

**Acceptance Criteria**: Easy installation across all platforms

### 6.3 User Communication
- [ ] Create changelog with breaking changes
- [ ] Add deprecation warnings
- [ ] Implement feature flags
- [ ] Create migration guide
- [ ] Add feedback collection
- [ ] Schedule training sessions

**Acceptance Criteria**: Clear communication of changes to all users

## Success Metrics

### Functional Metrics
- ✅ Feature parity with API extraction pipeline
- ✅ Support for all document sizes and types
- ✅ Consistent results between CLI and API
- ✅ Performance within 10% of API

### Quality Metrics
- ✅ 95% test coverage
- ✅ Zero critical bugs
- ✅ <2s startup time
- ✅ <5% memory overhead vs direct API

### User Metrics
- ✅ Improved extraction quality (>90% technique capture)
- ✅ Reduced processing time for batches
- ✅ Simplified command structure
- ✅ Enhanced error messages

## Risk Register

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Dependency conflicts | High | Medium | Use virtual environments, pin versions |
| Performance degradation | High | Low | Implement profiling from day 1 |
| API compatibility | High | Medium | Version lock API and CLI together |
| Breaking changes | Medium | High | Provide compatibility mode |
| Learning curve | Low | High | Extensive documentation and examples |
| Feature gaps | Medium | Medium | Phased rollout with feedback loops |

## Resource Requirements

### Development Team
- **Lead Developer**: 1 person full-time
- **Support Developer**: 1 person part-time
- **QA/Testing**: Shared resource
- **Documentation**: Shared resource

### Infrastructure
- **Development Environment**:
  - Neo4j test instance
  - OpenSearch test instance
  - Redis test instance
  - API staging server

- **CI/CD**:
  - GitHub Actions or similar
  - Test runners
  - Coverage reporting
  - Performance benchmarking

- **Distribution**:
  - PyPI account
  - Docker Hub account
  - Documentation hosting (ReadTheDocs or similar)

## Communication Plan

### Stakeholder Updates
- Weekly progress reports
- Phase completion reviews
- Blocker escalation within 24 hours

### User Communication
- Beta testing invitation (Week 4)
- Release candidate announcement (Week 5)
- Launch announcement (Week 6)
- Training webinar (Post-launch)

## Dependencies

### Internal Dependencies
- `bandjacks.llm.extraction_pipeline`
- `bandjacks.llm.flow_builder`
- `bandjacks.services.api.settings`
- `bandjacks.services.api.job_processor`

### External Dependencies
- Neo4j Python driver
- OpenSearch Python client
- Redis Python client
- Rich (for terminal UI)
- Click (for CLI framework)
- Pydantic (for configuration)

## Notes and Decisions

### Design Decisions
1. **Default to API mode**: Better consistency and maintenance
2. **Use Rich for UI**: Modern terminal experience
3. **Pydantic for config**: Type safety and validation
4. **Async where possible**: Better performance for I/O operations

### Open Questions
1. Should we support Windows natively or via WSL only?
2. What level of backward compatibility is required?
3. Should we implement a GUI wrapper in the future?
4. How to handle authentication for direct database access?

## Progress Tracking

### Phase Completion
- [ ] Phase 1: Foundation & Alignment
- [ ] Phase 2: Core Extraction Enhancement
- [ ] Phase 3: Advanced Features
- [ ] Phase 4: Interactive Features
- [ ] Phase 5: Quality & Testing
- [ ] Phase 6: Deployment & Migration

### Milestone Dates
| Milestone | Target Date | Actual Date | Status |
|-----------|-------------|-------------|---------|
| Phase 1 Complete | TBD | - | Not Started |
| Phase 2 Complete | TBD | - | Not Started |
| Phase 3 Complete | TBD | - | Not Started |
| Phase 4 Complete | TBD | - | Not Started |
| Phase 5 Complete | TBD | - | Not Started |
| Phase 6 Complete | TBD | - | Not Started |
| Production Release | TBD | - | Not Started |

## Change Log

### [Date] - Initial Plan Created
- Comprehensive 6-phase plan developed
- 138 individual tasks identified
- Success metrics defined
- Risk mitigation strategies documented

---

**Document Status**: DRAFT
**Last Updated**: [Current Date]
**Next Review**: [End of Phase 1]
**Owner**: [Development Team Lead]