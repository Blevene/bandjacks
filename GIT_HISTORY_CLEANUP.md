# Git History Cleanup Plan for Open Sourcing

## Security Scan Results

### ✅ Good News
- **No actual API keys found** in git history
- **No real secrets or tokens** found
- **No .env files committed** to repository
- **No database connection strings with real credentials**

### ⚠️ Issues Found
- **Hardcoded default passwords** in git history (e.g., `"password"`, `"neo4j"`)
- These are defaults, not real secrets, but should be cleaned for open source

## What Needs Cleaning

### 1. Hardcoded Default Passwords in History
The following patterns appear in git history:
- `NEO4J_PASSWORD=password` (default values)
- `neo4j_password = "password"` (test code)
- `neo4j/password` (docker-compose examples)

**Status:** These are defaults, not real secrets, but should be removed from history.

### 2. Files That May Contain Sensitive Patterns
- Test files with hardcoded `"password"` values
- Documentation examples (acceptable to keep)
- Docker compose examples (acceptable to keep if using env vars)

## Cleanup Strategy

### Option 1: Rewrite History (Recommended for Clean Slate)
Use `git filter-branch` or BFG Repo-Cleaner to remove sensitive patterns from entire history.

**Pros:**
- Complete cleanup
- No sensitive patterns in any commit
- Clean history for open source

**Cons:**
- Rewrites all commit hashes
- Requires force push (if remote exists)
- Team members need to re-clone

### Option 2: Squash History (Simpler)
Create a new initial commit with current clean state.

**Pros:**
- Simple and fast
- No complex history rewriting
- Clean starting point

**Cons:**
- Loses all commit history
- No attribution of past work

### Option 3: Keep History, Document (Minimal)
Keep history as-is but document that defaults were used.

**Pros:**
- No disruption
- Preserves history

**Cons:**
- Default passwords visible in history
- Not ideal for open source

## Recommended Approach: Option 1 (BFG Repo-Cleaner)

BFG Repo-Cleaner is faster and safer than git filter-branch.

### Step 1: Install BFG Repo-Cleaner

```bash
# macOS
brew install bfg

# Or download from https://rtyley.github.io/bfg-repo-cleaner/
```

### Step 2: Create Password Replacement File

Create `passwords.txt`:
```
neo4j/password==>neo4j/CHANGEME
NEO4J_PASSWORD=password==>NEO4J_PASSWORD=CHANGEME
neo4j_password = "password"==>neo4j_password = "CHANGEME"
default=os.getenv("NEO4J_PASSWORD", "password")==>default=os.getenv("NEO4J_PASSWORD", "")
```

### Step 3: Clean Repository

```bash
# Clone a fresh copy (BFG works on clones)
cd /tmp
git clone --mirror /Volumes/tank/bandjacks bandjacks-clean.git

# Run BFG to replace passwords
cd bandjacks-clean.git
bfg --replace-text /path/to/passwords.txt

# Clean up
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Verify cleanup
git log --all -p | grep -i password | head -20

# If clean, push to new remote or replace original
```

### Step 4: Alternative - Manual git filter-branch

```bash
# Create script to replace passwords
cat > /tmp/fix-passwords.sh << 'EOF'
#!/bin/bash
git filter-branch --force --index-filter \
  'git ls-files -s | sed "s/\t\"&/\"neo4j\/password\"/g" | \
   GIT_INDEX_FILE=$GIT_INDEX_FILE.new git update-index --index-info && \
   mv "$GIT_INDEX_FILE.new" "$GIT_INDEX_FILE"' \
  --prune-empty --tag-name-filter cat -- --all
EOF

chmod +x /tmp/fix-passwords.sh
```

**Note:** This is complex. BFG is recommended.

## What to Replace

### Patterns to Clean:
1. `neo4j/password` → `neo4j/CHANGEME` or use env var
2. `NEO4J_PASSWORD=password` → `NEO4J_PASSWORD=CHANGEME`
3. `"password"` in connection strings → `""` or env var
4. Hardcoded defaults in code → empty strings

### Patterns to Keep:
- Documentation examples (clearly marked as examples)
- Test files (acceptable for local testing)
- Comments explaining defaults

## Verification Steps

After cleanup, verify:

```bash
# Check for any remaining passwords
git log --all -p | grep -iE "password.*=.*['\"][^'\"]{4,}['\"]" | grep -v "CHANGEME" | grep -v "your-"

# Check for API keys
git log --all -p | grep -iE "(sk-[a-zA-Z0-9]{32,}|AIza[0-9A-Za-z_-]{35})"

# Check for committed .env files
git log --all --name-only | grep "\.env$"

# Check for connection strings
git log --all -p | grep -iE "(mongodb|postgres|mysql|redis).*://.*:.*@"
```

## Current Status

✅ **Current codebase is clean** - all hardcoded passwords removed
⚠️ **Git history contains defaults** - needs cleanup before open source
✅ **No real secrets found** - only default values

## Recommendation

**Before open sourcing:**
1. Use BFG Repo-Cleaner to replace default passwords in history
2. Replace with placeholders like `CHANGEME` or empty strings
3. Verify cleanup with scans
4. Create fresh repository or force-push cleaned history
5. Document the cleanup in release notes

## Alternative: Start Fresh

If history cleanup is too complex, consider:
1. Create new repository with current clean state
2. Add LICENSE and README
3. Start fresh commit history
4. Document this in release notes

This is simpler but loses attribution of past work.

