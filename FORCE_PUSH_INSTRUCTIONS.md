# Force Push Instructions

## ⚠️ CRITICAL: Read Before Proceeding

Force-pushing will **rewrite the remote repository history**. This is **irreversible** and will affect all team members.

## ✅ Pre-Flight Checklist

- [x] Git history cleaned
- [x] Backup created (see `bandjacks-backup-*.bundle` file)
- [x] Documentation committed
- [ ] **Team notified** about history rewrite
- [ ] **All team members** have committed/pushed their work
- [ ] **All team members** understand they need to re-clone or reset

## 📋 Step-by-Step Instructions

### Step 1: Verify Backup

```bash
# List backup files
ls -lh bandjacks-backup-*.bundle

# Verify backup contains all branches
git bundle verify bandjacks-backup-*.bundle
```

### Step 2: Final Verification

```bash
# Check current status
git status

# Verify you're on the correct branch
git branch --show-current

# Should be on 'main' or your primary branch
```

### Step 3: Force Push All Branches

```bash
# Push all branches (this rewrites remote history)
git push --force --all origin

# Push all tags
git push --force --tags origin
```

### Step 4: Verify Push

```bash
# Check remote branches
git ls-remote --heads origin

# Check remote tags
git ls-remote --tags origin
```

### Step 5: Create Initial Release Tag

```bash
# Create annotated tag
git tag -a v0.1.0 -m "Initial open source release - Security cleanup complete"

# Push tag to remote
git push origin v0.1.0
```

## 🔄 Team Member Instructions

**Send this to your team:**

```
⚠️ IMPORTANT: Repository History Rewritten

The git history has been cleaned to remove sensitive data before open sourcing.
All commit hashes have changed.

ACTION REQUIRED:

Option 1: Re-clone (Recommended)
  rm -rf bandjacks
  git clone https://github.com/Blevene/bandjacks.git
  cd bandjacks

Option 2: Reset local branches
  git fetch origin
  git reset --hard origin/main
  # Repeat for each branch you have checked out
```

## 🚨 Rollback Instructions (If Needed)

If something goes wrong, you can restore from backup:

```bash
# Create a new repository from backup
git clone bandjacks-backup-*.bundle bandjacks-restored

# Or restore to current repository
git fetch bandjacks-backup-*.bundle '*:*'
git reset --hard origin/main
```

## 📝 Post-Push Checklist

After force-pushing:

- [ ] Verify all branches pushed successfully
- [ ] Verify tags pushed successfully
- [ ] Test cloning the repository fresh
- [ ] Create GitHub release (if using GitHub)
- [ ] Update repository description/topics
- [ ] Make repository public (if ready)
- [ ] Monitor for any issues

## 🎯 Ready to Proceed?

If you've completed the pre-flight checklist, you can run:

```bash
# This will force-push everything
git push --force --all origin && git push --force --tags origin
```

**Remember:** This is a one-way operation. Make sure you're ready!

