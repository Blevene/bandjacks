# Sprint 2 Optimizations Summary

## Implemented Enhancements

### 1. KB-Type Filtering for `/v1/search/ttx`
- **New Function**: `ttx_search_kb()` in `search_nodes.py`
  - Supports optional `kb_types` parameter to filter results
  - Fetches extra results (2x) when filtering to ensure adequate matches
  - Returns `name` field for better entity identification
- **Updated API**: `/v1/search/ttx` now accepts `kb_types` list
  - Example: `["AttackPattern"]` for techniques only
  - Example: `["IntrusionSet", "Software"]` for groups and tools
- **Schema Update**: `TtxQuery` model includes optional `kb_types` field

### 2. Tactic Inference Boost
- **TACTIC_HINTS Mapping**: 16 tactic keywords mapped to shortnames
  - Includes common abbreviations (C2, C&C)
  - Covers all ATT&CK tactics
- **Inference Function**: `infer_tactic_shortnames()`
  - Detects tactic mentions in text
  - Returns set of matching tactic shortnames
- **Scoring Enhancement**: +6 point boost when tactic context aligns
  - Applied conservatively to maintain accuracy
  - Only for technique candidates (not groups/software)

### 3. Improved Proposal Engine
- **Unified Search**: All entity searches now use `ttx_search_kb()`
  - Cleaner code, consistent behavior
  - Automatic kb_type filtering
- **Enhanced Scoring**: Four-factor confidence calculation
  - 70% similarity score (normalized)
  - 20% keyword matching
  - 10% explicit ID mentions
  - +6 tactic inference boost (when applicable)
- **Better Details**: `scoring_details` now includes `tactic_boost`

## Key Benefits

1. **More Precise Searches**: Filter by entity type reduces false positives
2. **Context-Aware Scoring**: Tactic hints improve technique relevance
3. **Flexible API**: Backward compatible with optional parameters
4. **Better Names**: Including `name` field improves entity identification
5. **Performance**: Fetching extra results ensures quality after filtering

## Code Quality

- **Absolute Imports**: All imports use `bandjacks.*` style
- **Type Hints**: Proper typing with `Optional[List[str]]`
- **Documentation**: Clear docstrings for all new functions
- **Testing**: Comprehensive test suite validates all features

## Usage Examples

### Search with KB-Type Filtering
```python
# Search only for techniques
results = ttx_search_kb(os_url, index, "ransomware encryption", 10, ["AttackPattern"])

# Search only for threat groups
results = ttx_search_kb(os_url, index, "russian hackers", 5, ["IntrusionSet"])

# Search for groups and software
results = ttx_search_kb(os_url, index, "cobalt strike beacon", 10, ["IntrusionSet", "Software"])
```

### Tactic Inference
```python
text = "The attacker establishes persistence through registry modifications"
tactics = infer_tactic_shortnames(text)
# Returns: {"persistence"}
```

### API Request
```json
POST /v1/search/ttx
{
  "text": "APT29 persistence techniques",
  "top_k": 10,
  "kb_types": ["AttackPattern"]
}
```

## Test Results

All tests pass successfully:
- ✓ Tactic inference working correctly
- ✓ Tactic boost scoring working correctly  
- ✓ KB types filtering structure correct
- ✓ Comprehensive scoring with all factors

## Files Modified

1. `bandjacks/services/api/schemas.py` - Added TtxQuery model
2. `bandjacks/loaders/search_nodes.py` - Added ttx_search_kb function
3. `bandjacks/services/api/routes/search.py` - Updated to use new schema and function
4. `bandjacks/loaders/propose.py` - Added tactic inference and enhanced scoring
5. `tests/test_optimizations.py` - New comprehensive test suite