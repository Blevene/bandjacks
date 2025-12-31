#!/bin/bash
# Git History Cleanup Script for Open Sourcing
# This script removes hardcoded default passwords from git history
#
# WARNING: This rewrites git history. All commit hashes will change.
# Make sure you have a backup before running this!

set -e

echo "=========================================="
echo "Git History Cleanup for Open Sourcing"
echo "=========================================="
echo ""
echo "This script will:"
echo "  1. Remove hardcoded default passwords from git history"
echo "  2. Replace them with placeholders"
echo "  3. Clean up git references"
echo ""
echo "WARNING: This rewrites ALL commit hashes!"
echo "You will need to force-push to update the remote."
echo ""
read -p "Continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 1
fi

# Check if BFG is installed
if ! command -v bfg &> /dev/null; then
    echo "BFG Repo-Cleaner not found. Installing..."
    echo "Please install BFG:"
    echo "  macOS: brew install bfg"
    echo "  Or download from: https://rtyley.github.io/bfg-repo-cleaner/"
    exit 1
fi

# Create temporary directory for cleanup
TEMP_DIR=$(mktemp -d)
echo "Working in temporary directory: $TEMP_DIR"

# Create password replacement file
cat > "$TEMP_DIR/passwords.txt" << 'EOF'
neo4j/CHANGEME==>neo4j/CHANGEME
NEO4J_AUTH=neo4j/CHANGEME==>NEO4J_AUTH=neo4j/${NEO4J_PASSWORD:-}
NEO4J_PASSWORD=CHANGEME==>NEO4J_PASSWORD=CHANGEME
NEO4J_PASSWORD=CHANGEME==>NEO4J_PASSWORD=CHANGEME
neo4j_password = ""==>neo4j_password = ""
neo4j_password=""==>neo4j_password=""
default=os.getenv("NEO4J_PASSWORD", "")==>default=os.getenv("NEO4J_PASSWORD", "")
default=os.getenv('NEO4J_PASSWORD', '')==>default=os.getenv('NEO4J_PASSWORD', '')
ctx.obj['neo4j_password'] = os.getenv('NEO4J_PASSWORD', '')==>ctx.obj['neo4j_password'] = os.getenv('NEO4J_PASSWORD', '')
opensearch_password: str = ""==>opensearch_password: str = ""
neo4j_password: str = ""==>neo4j_password: str = ""
EOF

echo "Created password replacement file"

# Clone repository as bare for BFG
REPO_NAME=$(basename "$(pwd)")
BARE_REPO="$TEMP_DIR/${REPO_NAME}.git"

echo "Cloning repository as bare mirror..."
git clone --mirror . "$BARE_REPO"

# Run BFG to replace passwords
echo "Running BFG to clean history..."
cd "$BARE_REPO"
bfg --replace-text "$TEMP_DIR/passwords.txt"

# Clean up
echo "Cleaning up git references..."
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# Verify cleanup
echo ""
echo "Verifying cleanup..."
REMAINING=$(git log --all -p | grep -iE "password.*=.*['\"]password['\"]" | wc -l || echo "0")
if [ "$REMAINING" -gt 0 ]; then
    echo "WARNING: Some password patterns may still remain"
    git log --all -p | grep -iE "password.*=.*['\"]password['\"]" | head -10
else
    echo "✓ No hardcoded 'password' defaults found"
fi

echo ""
echo "=========================================="
echo "Cleanup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Review the cleaned repository in: $BARE_REPO"
echo "  2. If satisfied, replace your current .git with the cleaned one:"
echo "     cd /path/to/bandjacks"
echo "     mv .git .git.backup"
echo "     cp -r $BARE_REPO .git"
echo "  3. Force push to remote (if needed):"
echo "     git push --force --all"
echo "     git push --force --tags"
echo ""
echo "WARNING: Force pushing will rewrite remote history!"
echo "Make sure all team members are aware and can re-clone."

