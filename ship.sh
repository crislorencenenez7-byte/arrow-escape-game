#!/data/data/com.termux/files/usr/bin/bash
set -e

cd "$(dirname "$0")"

branch="$(git branch --show-current)"

if [ -z "$branch" ]; then
  echo "Error: not on a branch."
  exit 1
fi

echo "Branch: $branch"
git add -A

if git diff --cached --quiet; then
  echo "No changes to commit."
  exit 0
fi

if [ -n "$1" ]; then
  message="$*"
else
  message="Update: $(date '+%Y-%m-%d %H:%M:%S')"
fi

git commit -m "$message"
git push -u origin "$branch"

echo "Done! Changes committed and pushed to $branch."
