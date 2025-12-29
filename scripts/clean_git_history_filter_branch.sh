#!/bin/bash
# Git History Cleanup Script (using git filter-branch)
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

# Create temporary directory for cleanup
TEMP_DIR=$(mktemp -d)
echo "Working in temporary directory: $TEMP_DIR"

# Create password replacement script
cat > "$TEMP_DIR/replace-passwords.sh" << 'REPLACE_EOF'
#!/bin/bash
# This script replaces default passwords in git history

sed -i.bak \
  -e 's|neo4j/CHANGEME|neo4j/CHANGEME|g' \
  -e 's|NEO4J_AUTH=neo4j/CHANGEME|NEO4J_AUTH=neo4j/${NEO4J_PASSWORD:-}|g' \
  -e 's|NEO4J_PASSWORD=CHANGEME|NEO4J_PASSWORD=CHANGEME|g' \
  -e 's|NEO4J_PASSWORD=CHANGEME|NEO4J_PASSWORD=CHANGEME|g' \
  -e 's|neo4j_password = ""|neo4j_password = ""|g' \
  -e 's|neo4j_password=""|neo4j_password=""|g' \
  -e 's|os.getenv("NEO4J_PASSWORD", "")|os.getenv("NEO4J_PASSWORD", "")|g' \
  -e "s|os.getenv('NEO4J_PASSWORD', '')|os.getenv('NEO4J_PASSWORD', '')|g" \
  -e "s|ctx.obj\['neo4j_password'\] = os.getenv('NEO4J_PASSWORD', '')|ctx.obj['neo4j_password'] = os.getenv('NEO4J_PASSWORD', '')|g" \
  -e 's|opensearch_password: str = ""|opensearch_password: str = ""|g' \
  -e 's|neo4j_password: str = ""|neo4j_password: str = ""|g' \
  "$1"
rm -f "$1.bak"
REPLACE_EOF

chmod +x "$TEMP_DIR/replace-passwords.sh"

echo "Created password replacement script"

# Run git filter-branch
echo "Running git filter-branch to clean history..."
echo "This may take a few minutes..."

git filter-branch --force --tree-filter \
  "find . -type f -name '*.py' -o -name '*.yml' -o -name '*.yaml' -o -name '*.sh' | \
   xargs -I {} $TEMP_DIR/replace-passwords.sh {}" \
  --prune-empty --tag-name-filter cat -- --all

# Clean up
echo "Cleaning up git references..."
git for-each-ref --format="%(refname)" refs/original/ | xargs -n 1 git update-ref -d
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
echo "  1. Review the cleaned history:"
echo "     git log --all -p | grep -i password | head -20"
echo ""
echo "  2. If satisfied, force push to remote (if needed):"
echo "     git push --force --all"
echo "     git push --force --tags"
echo ""
echo "WARNING: Force pushing will rewrite remote history!"
echo "Make sure all team members are aware and can re-clone."
echo ""
echo "Backup location: /tmp/bandjacks-backup-*.bundle"

