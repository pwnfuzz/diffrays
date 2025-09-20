# DiffRays 1.2 Implementation Summary

## Overview
This implementation adds a wide table optimized for diff viewing with precomputed scores, while maintaining backward compatibility with the existing tall schema.

## Key Changes

### 1. Database Layer (`diffrays/database.py`)
- **Added new wide table schema**: `function_diffs` table with columns for both old and new function data
- **Added indices**: `idx_function_diffs_name` and `idx_function_diffs_ratio` for performance
- **Added bulk upsert function**: `bulk_upsert_function_diffs()` for efficient batch operations
- **Maintained compatibility**: Existing `functions` table (tall schema) is preserved
- **Migration support**: Automatically creates new table and indices if missing

### 2. Analyzer (`diffrays/analyzer.py`)
- **Replaced per-function generator**: New `analyze_binary_collect()` returns complete function data in one pass
- **One-pass collection**: Collects all function data for both binaries before processing
- **Similarity computation**: Uses `difflib.SequenceMatcher` to compute `ratio` and `s_ratio`
- **Bulk operations**: Backfills tall schema and bulk-upserts to wide table
- **Removed debug prints**: Cleaned up stray debug output

### 3. Server (`diffrays/server.py`)
- **Schema detection**: `detect_schema()` checks for wide vs tall schema presence
- **Preference system**: Server prefers wide table, falls back to tall schema
- **New functions**:
  - `ensure_indices()`: Creates indices for both schemas
  - `build_function_meta()`: Builds metadata preferring wide table
  - `compute_all_categories_once()`: Uses precomputed ratios for fast categorization
- **Updated routes**: All routes now use `compute_all_categories_once()`
- **Function fetching**: `fetch_function_pair()` prefers wide table

### 4. Explorer (`diffrays/explorer.py`)
- **Added safety import**: `import traceback` for robust error logging

## Schema Details

### Wide Table (`function_diffs`)
```sql
CREATE TABLE function_diffs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_name TEXT NOT NULL,
    old_pseudocode BLOB,
    new_pseudocode BLOB,
    old_address INTEGER,
    new_address INTEGER,
    old_blocks INTEGER,
    new_blocks INTEGER,
    old_signature TEXT,
    new_signature TEXT,
    ratio REAL,
    s_ratio REAL,
    UNIQUE(function_name)
);
```

### Indices
- `idx_function_diffs_name`: For function name lookups
- `idx_function_diffs_ratio`: For ratio-based sorting/filtering

## Performance Improvements

1. **One-pass analysis**: Functions are collected once per binary instead of processed individually
2. **Precomputed scores**: Similarity ratios are calculated once during analysis, not on every request
3. **Bulk operations**: Database operations use transactions and bulk upserts
4. **Optimized queries**: Server uses precomputed data when available

## Backward Compatibility

- **Tall schema preserved**: Existing `functions` table remains unchanged
- **Fallback support**: Server automatically falls back to tall schema if wide table not present
- **Migration safe**: New installations get both schemas, existing databases can be migrated

## Verification

The implementation can be verified using:

```sql
-- Check schema presence
SELECT name FROM sqlite_master WHERE name='function_diffs';

-- Check counts
SELECT COUNT(*) FROM function_diffs;

-- Sample data
SELECT function_name, LENGTH(old_pseudocode), LENGTH(new_pseudocode), ratio, s_ratio 
FROM function_diffs LIMIT 5;
```

## Usage

The workflow remains the same:
1. `diffrays diff <old_binary> <new_binary>` - Creates database with both schemas
2. `diffrays server --db-path <result_db.sqlite>` - Serves web interface

The server automatically detects and uses the optimal schema for each request.
