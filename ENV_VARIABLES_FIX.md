# Environment Variables Fix - Password Validation

## Summary

After removing hardcoded default passwords, we've added proper validation and error handling to ensure the application fails gracefully with clear error messages when required environment variables are missing.

## Changes Made

### 1. Added Password Validation in API Dependencies ✅

**File:** `bandjacks/services/api/deps.py`

- Added validation in `get_neo4j_session()` to check if `NEO4J_PASSWORD` is set
- Updated `get_opensearch_client()` to handle empty passwords gracefully (OpenSearch may work without password if security is disabled)

### 2. Added Validation in Route Handlers ✅

**Files:**
- `bandjacks/services/api/routes/provenance.py`
- `bandjacks/services/api/routes/analytics.py`

- Added validation in `get_neo4j_driver()` functions to ensure password is set before creating connections

### 3. Added Startup Warning ✅

**File:** `bandjacks/services/api/main.py`

- Added warning message at startup if `NEO4J_PASSWORD` is not set
- This helps catch configuration issues early

### 4. Updated Environment Sample File ✅

**File:** `infra/env.sample`

- Updated to show clear placeholders: `your-neo4j-password-here` and `your-opensearch-password-here`
- Added comments indicating these must be set
- Added `OPENSEARCH_USER` and `OPENSEARCH_PASSWORD` fields

## How Environment Variables Work

### Settings Loading

The `Settings` class in `bandjacks/services/api/settings.py` uses `pydantic_settings.BaseSettings` which automatically:

1. Loads from `.env` file (if present) via `SettingsConfigDict(env_file=".env")`
2. Loads from environment variables
3. Uses default values if neither is set

### Required Environment Variables

For the application to work, you **must** set:

```bash
NEO4J_PASSWORD=your-actual-password
```

Optional but recommended:
```bash
OPENSEARCH_PASSWORD=your-opensearch-password  # Only if OpenSearch security is enabled
```

### Setting Up Environment Variables

#### Option 1: Using .env file (Recommended for Development)

1. Copy the sample file:
   ```bash
   cp infra/env.sample .env
   ```

2. Edit `.env` and set your passwords:
   ```bash
   NEO4J_PASSWORD=your-actual-neo4j-password
   OPENSEARCH_PASSWORD=your-actual-opensearch-password
   ```

3. The `.env` file is automatically loaded by `pydantic_settings`

#### Option 2: Using Environment Variables (Recommended for Production)

```bash
export NEO4J_PASSWORD=your-actual-password
export OPENSEARCH_PASSWORD=your-actual-opensearch-password
```

#### Option 3: Docker Compose

The `infra/docker-compose.yml` file uses environment variable substitution:

```yaml
environment:
  - NEO4J_AUTH=neo4j/${NEO4J_PASSWORD:-}
```

Set `NEO4J_PASSWORD` in your shell or `.env` file before running `docker-compose up`.

## Error Handling

### What Happens If Password Is Missing?

1. **At Startup:** A warning message is printed:
   ```
   [startup] WARNING: NEO4J_PASSWORD not set. Neo4j operations will fail.
   [startup] Please set NEO4J_PASSWORD in your .env file or environment variables.
   ```

2. **When Creating Connections:** A clear `ValueError` is raised:
   ```
   ValueError: NEO4J_PASSWORD environment variable is required. 
   Please set it in your .env file or environment variables.
   ```

3. **OpenSearch:** Empty password is allowed (only uses auth if password is provided)

## Testing the Fix

To verify the fix works:

1. **Without password set:**
   ```bash
   # Unset the password
   unset NEO4J_PASSWORD
   
   # Try to start the API
   python -m bandjacks.services.api.main
   # Should see warning message
   ```

2. **With password set:**
   ```bash
   export NEO4J_PASSWORD=test-password
   python -m bandjacks.services.api.main
   # Should start normally (will fail to connect if password is wrong, but won't fail on validation)
   ```

## Migration Guide

If you were using the old hardcoded defaults:

1. **Before:** Code worked with default `"neo4j"` password
2. **After:** You must explicitly set `NEO4J_PASSWORD` in environment

**Action Required:**
- Create a `.env` file or set environment variables
- Update any deployment scripts to set `NEO4J_PASSWORD`
- Update Docker Compose configurations if needed

## Files Modified

1. `bandjacks/services/api/deps.py` - Added validation
2. `bandjacks/services/api/routes/provenance.py` - Added validation
3. `bandjacks/services/api/routes/analytics.py` - Added validation
4. `bandjacks/services/api/main.py` - Added startup warning
5. `infra/env.sample` - Updated with clear placeholders

## Notes

- **OpenSearch:** Empty password is allowed because OpenSearch may run with security disabled (as in the docker-compose setup)
- **Neo4j:** Password is required - Neo4j always requires authentication
- **CLI Tools:** CLI tools will also fail if password is not set, but they read from environment variables directly
- **Test Files:** Test files may still use hardcoded `"password"` for local testing - this is acceptable

