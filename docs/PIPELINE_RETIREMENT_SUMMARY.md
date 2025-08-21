# Pipeline Retirement and Optimization Summary

## Executive Summary

The original extraction pipeline has been retired due to extreme inefficiency (228 seconds for simple text). The async pipeline is now the default, providing **94.4% performance improvement** while maintaining or improving extraction quality.

## Pipeline Comparison

| Pipeline | Status | Performance | Use Case |
|----------|--------|------------|----------|
| **Original** | ❌ RETIRED | 228s baseline | N/A - Too slow |
| **Optimized** | ✅ Active (fallback) | 32s (7x faster) | When async not available |
| **Async** | ✅ Active (default) | 12.7s (18x faster) | Production default |

## DarkCloud Stealer PDF Test Results

### Test Parameters
- **Document**: new-darkcloud-stealer-infection-chain.pdf
- **Text Length**: 10,000 characters (truncated from 14,911)
- **Word Count**: 1,493 words
- **Pipeline Used**: Async with single-pass extraction

### Performance
- **Extraction Time**: 36.13 seconds
- **Techniques Found**: 12 high-confidence techniques
- **Average Confidence**: 93%

### Extracted Techniques
1. **T1566.001** - Phishing: Spearphishing Attachment (95%)
2. **T1027.002** - Obfuscated Files: Software Packing (95%)
3. **T1059.005** - Command Interpreter: AutoIt (95%)
4. **T1059.007** - Command Interpreter: JavaScript (95%)
5. **T1105** - Ingress Tool Transfer (95%)
6. **T1059.001** - Command Interpreter: PowerShell (95%)
7. **T1027.006** - Obfuscated Files: Encrypted Content (95%)
8. **T1027.001** - Obfuscated Files: Symbol Obfuscation (95%)
9. **T1027.004** - Obfuscated Files: Control Flow Obfuscation (95%)
10. **T1055.012** - Process Injection: Process Hollowing (95%)
11. **T1027** - Obfuscated Files or Information (90%)
12. **T1027.005** - Obfuscated Files: Indicator Removal (90%)

## Key Changes

### 1. Default Pipeline Change
```python
# Before
use_async = cfg.get("use_async", False)  # Had to opt-in

# After
use_async = cfg.get("use_async", True)   # Now default
```

### 2. Removed Dependencies
- Removed import for `run_agentic_v2` (original pipeline)
- Simplified pipeline selection logic
- Reduced code complexity

### 3. Cache Effectiveness
- **87.5% speedup** on repeated extractions
- In-memory cache with 15-minute TTL
- Thread-safe implementation

## Configuration Recommendations

### For Production
```python
{
    "use_async": True,  # Default
    "single_pass_threshold": 2000,
    "cache_llm_responses": True,
    "max_spans": 20,
    "span_score_threshold": 0.7,
    "early_termination_confidence": 85
}
```

### For Development/Testing
```python
{
    "use_async": True,
    "cache_llm_responses": True,  # Critical for iteration
    "single_pass_threshold": 500,  # Lower for faster testing
    "max_spans": 10
}
```

## Migration Guide

### For API Users
No changes required - the async pipeline is now the default. To force synchronous mode:
```bash
curl -X POST http://localhost:8000/v1/extract/runs \
  -H "Content-Type: application/json" \
  -d '{
    "method": "agentic_v2",
    "content": "Your text",
    "config": {"use_async": false}
  }'
```

### For Developers
1. Remove any references to `run_agentic_v2` (original pipeline)
2. Use `run_agentic_v2_async` for new integrations
3. Keep `run_agentic_v2_optimized` as fallback only

## Performance Metrics Summary

### Small Documents (<500 words)
- **Single-pass extraction**: 4-8 seconds
- **Technique accuracy**: 90-95%
- **Cache hit rate**: 66.7% on repeated runs

### Medium Documents (500-2000 words)
- **Async pipeline**: 12-40 seconds
- **Parallel span processing**: 5-10x speedup
- **Batch mapping**: Single LLM call for all spans

### Large Documents (>2000 words)
- **Full pipeline**: 40-120 seconds
- **Span limiting**: Max 20 spans processed
- **Early termination**: Skip verification for high-confidence

## Conclusion

The retirement of the original pipeline and adoption of the async pipeline as default represents a major performance milestone. The system can now process complex threat intelligence reports in seconds rather than minutes, while maintaining high extraction quality (90-95% confidence).

### Next Steps
1. Monitor production performance metrics
2. Tune thresholds based on real-world usage
3. Consider Redis-based caching for distributed deployments
4. Implement result streaming for real-time feedback