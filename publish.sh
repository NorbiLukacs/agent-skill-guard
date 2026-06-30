#!/usr/bin/env bash
# One-shot publisher for agent-skill-guard. Run from the repo root.
# Usage:  GH_USER=your-handle bash publish.sh
set -euo pipefail

: "${GH_USER:?Set GH_USER to your GitHub username, e.g. GH_USER=norbert-lukacs bash publish.sh}"
REPO="agent-skill-guard"
DESC="Security auditor for AI agent skills — catches hidden-Unicode prompt injection, reviewer-subversion, data exfiltration & post-install drift that markdown-only vetters miss."

# Up to 20 topics — the single biggest lever for GitHub discoverability.
TOPICS=(claude claude-code agent-skills ai-agents skills security security-tools \
        security-scanner prompt-injection supply-chain-security mcp mcp-server \
        llm-security static-analysis ai-safety skill-security anthropic devsecops \
        python skill-vetting)

if command -v gh >/dev/null 2>&1; then
  echo "==> Creating public repo via gh and pushing…"
  gh repo create "$GH_USER/$REPO" --public --source=. --remote=origin \
     --description "$DESC" --push
  echo "==> Setting topics…"
  gh repo edit "$GH_USER/$REPO" $(printf -- "--add-topic %s " "${TOPICS[@]}")
  echo "==> Done: https://github.com/$GH_USER/$REPO"
else
  echo "gh CLI not found. Manual path:"
  echo "  1) Create an EMPTY public repo named '$REPO' at https://github.com/new"
  echo "     (no README/license/gitignore — this repo already has them)"
  echo "  2) Then run:"
  echo "       git remote add origin https://github.com/$GH_USER/$REPO.git"
  echo "       git branch -M main"
  echo "       git push -u origin main"
  echo "  3) On the repo page, click the ⚙ next to 'About' and paste:"
  echo "     Description: $DESC"
  echo "     Topics: ${TOPICS[*]}"
fi

echo
echo "After publishing, list it on the skills ecosystem so others can install:"
echo "  npx skills add $GH_USER/$REPO@skill-guard   # verify it installs"
echo "  (submit/visit https://skills.sh to get it indexed on the leaderboard)"
