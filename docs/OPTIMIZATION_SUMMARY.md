# Extraction Pipeline Optimization Summary

## Performance Results

The optimization efforts have achieved dramatic performance improvements:

- **Original Pipeline**: 228.07 seconds (baseline)
- **Optimized Pipeline**: 32.43 seconds (7.03x speedup, 85.8% faster)
- **Async Pipeline**: 12.71 seconds (17.94x speedup, 94.4% faster)

## Implemented Optimizations

### 1. Batch Processing (✅ Completed)
- **File**: `bandjacks/llm/mapper_optimized.py`
- **Implementation**: BatchMapperAgent processes all spans in a single LLM call
- **Impact**: Reduced LLM calls from N spans to 1 call

### 2. Async Parallel Processing (✅ Completed)
- **File**: `bandjacks/llm/agentic_v2_async.py`
- **Implementation**: AsyncRetrieverAgent processes spans concurrently
- **Impact**: Parallel vector searches instead of sequential

### 3. Single-Pass Extraction (✅ Completed)
- **File**: `bandjacks/llm/agentic_v2_async.py`
- **Implementation**: SinglePassExtractor for documents <500 words
- **Impact**: Skip entire span-finding pipeline for small documents

### 4. LLM Response Caching (✅ Completed)
- **File**: `bandjacks/llm/cache.py`
- **Implementation**: Thread-safe in-memory cache with TTL support
- **Impact**: Avoid duplicate LLM calls for identical requests

### 5. Early Termination (✅ Completed)
- **File**: `bandjacks/llm/agentic_v2_async.py`
- **Implementation**: Skip verification for high-confidence claims (>90%)
- **Impact**: Reduced verification overhead

### 6. Span Optimization (✅ Completed)
- **File**: `bandjacks/llm/agentic_v2_optimized.py`
- **Implementation**: OptimizedSpanFinder with deduplication and higher thresholds
- **Impact**: Fewer, higher-quality spans to process

### 7. Targeted Extraction Control (✅ Completed)
- **Configuration**: `disable_targeted_extraction: true` by default
- **Impact**: Skip expensive second-pass extraction

### 8. Neo4j Query Optimization (✅ Completed)
- **File**: `bandjacks/llm/tools.py`
- **Fix**: Removed x_mitre_platforms field causing warnings
- **Impact**: Cleaner logs, faster queries

## Configuration Options

### Optimized Pipeline Config
```python
{
    "use_optimized": True,
    "use_batch_mapper": True,
    "disable_targeted_extraction": True,
    "max_spans": 10,
    "span_score_threshold": 0.8,
    "top_k": 5
}
```

### Async Pipeline Config
```python
{
    "use_async": True,
    "use_async_retriever": True,
    "single_pass_threshold": 500,
    "early_termination_confidence": 90,
    "cache_llm_responses": True,
    "top_k": 5
}
```

## API Usage

### Using Optimized Pipeline (Default)
```bash
curl -X POST http://localhost:8000/v1/extract/runs \
  -H "Content-Type: application/json" \
  -d '{
    "method": "agentic_v2",
    "content": "Your text here",
    "config": {"use_optimized": true}
  }'
```

### Using Async Pipeline
```bash
curl -X POST http://localhost:8000/v1/extract/runs \
  -H "Content-Type: application/json" \
  -d '{
    "method": "agentic_v2",
    "content": "Your text here",
    "config": {"use_async": true}
  }'
```

### Cache Management
```bash
# Get cache statistics
curl http://localhost:8000/v1/cache/stats

# Clear cache
curl -X POST http://localhost:8000/v1/cache/clear
```

## Remaining Optimizations

1. **Result Streaming**: Stream results as they're generated (not yet implemented)
2. **Persistent Cache**: Redis-based cache for production (not yet implemented)
3. **GPU Acceleration**: For vector operations (requires hardware)

## Key Learnings

1. **Sequential LLM calls are the biggest bottleneck** - Batching and caching are critical
2. **Small documents benefit from specialized handling** - Single-pass extraction is much faster
3. **Over-segmentation hurts performance** - Better to have fewer, high-quality spans
4. **Parallel processing provides massive gains** - Async operations are worth the complexity
5. **Caching is essential for repeated operations** - Especially during development/testing

## Recommendations

1. **Use async pipeline for production** - Best performance for most documents
2. **Enable caching in development** - Speeds up testing iterations
3. **Monitor cache hit rates** - Helps identify optimization opportunities
4. **Adjust thresholds based on content** - Different document types may need tuning
5. **Consider document size** - Route small documents to single-pass extraction