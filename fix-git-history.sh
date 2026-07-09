#!/bin/bash
# fix-git-history.sh
# ──────────────────
# Removes node_modules from git tracking without deleting the files on disk.
# Run this ONCE from the root of your repository.
#
# After running:
#   1. Verify with:  git status  (node_modules should not appear)
#   2. Push:         git push origin main --force
#      (force-push is required because you're rewriting history)
#
# WARNING: If others have cloned the repo, they need to re-clone after this.

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AD Web Console — Remove node_modules from git history"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Step 1: Make sure we're in a git repo
if [ ! -d ".git" ]; then
  echo "❌ Error: run this script from the root of your git repository."
  exit 1
fi

# Step 2: Stage .gitignore changes first
if ! grep -q "^node_modules/" .gitignore 2>/dev/null; then
  echo "node_modules/" >> .gitignore
  echo "✅ Added node_modules/ to .gitignore"
fi

if ! grep -q "^\.env$" .gitignore 2>/dev/null; then
  echo ".env" >> .gitignore
  echo "✅ Added .env to .gitignore"
fi

# Step 3: Remove node_modules from git index (not from disk)
echo ""
echo "Removing node_modules from git tracking (files stay on disk)..."
git rm -r --cached node_modules/ --quiet 2>/dev/null && echo "✅ node_modules removed from git index" || echo "ℹ️  node_modules was not tracked — nothing to remove"

# Step 4: Also untrack .env if it was committed
git rm --cached .env --quiet 2>/dev/null && echo "✅ .env removed from git index" || echo "ℹ️  .env was not tracked"

# Step 5: Commit the cleanup
git add .gitignore
git commit -m "chore: remove node_modules and .env from git tracking

- Add node_modules/ and .env to .gitignore
- Untrack previously committed node_modules directory
- These files should never be in version control

Resolves security and repo bloat issues flagged in code review."

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ Done! Next steps:"
echo ""
echo "  1. Review the commit:  git log --oneline -3"
echo "  2. Push to GitHub:     git push origin main --force"
echo "     (--force needed because this rewrites the tip commit)"
echo ""
echo "  ⚠️  If teammates have cloned this repo, they should:"
echo "     git fetch origin && git reset --hard origin/main"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
