#!/usr/bin/env bash
set -euo pipefail

# Publish this lab to GitHub using gh (GitHub CLI) over SSH.
# - Creates repo (if missing), sets remote, pushes main
# - Adds SSH key (~/.ssh/id_ed25519_github_portfolio.pub) if available
# - Sets description and topics (best-effort)
#
# Usage:
#   bash scripts/publish_github.sh [repo-name]
#

REPO_NAME="${1:-portscan-detection-lab}"
DESC="Detect TCP SYN port scanning with Suricata → Filebeat → Elasticsearch → Kibana. Includes local rules, Kibana dashboard (NDJSON export), and backup scripts."

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Checking gh CLI"
command -v gh >/dev/null 2>&1 || { echo "gh not found. Install GitHub CLI first."; exit 1; }

echo "==> Unsetting GH_TOKEN for SSH auth"
unset GH_TOKEN || true

echo "==> gh auth status"
if ! env -u GH_TOKEN gh auth status -h github.com >/dev/null 2>&1; then
  echo "Not authenticated. Launching web-based SSH login..."
  echo "A browser/device flow will prompt you to authorize."
  env -u GH_TOKEN gh auth login -h github.com -p ssh --web || true
fi

echo "==> Adding SSH key to GitHub (if present)"
KEY_PUB="$HOME/.ssh/id_ed25519_github_portfolio.pub"
if [ -f "$KEY_PUB" ]; then
  env -u GH_TOKEN gh ssh-key add "$KEY_PUB" -t "Portfolio Key" || true
else
  echo "No key found at $KEY_PUB (skipping)."
fi

echo "==> Creating repo (or linking existing)"
env -u GH_TOKEN gh repo create "$REPO_NAME" --public --source=. --remote=origin -y --description "$DESC" || true

echo "==> Pushing main to origin"
git push -u origin main || true

echo "==> Setting description and topics (best-effort)"
NAME_WITH_OWNER=$(env -u GH_TOKEN gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo "")
if [ -n "$NAME_WITH_OWNER" ]; then
  env -u GH_TOKEN gh repo edit "$NAME_WITH_OWNER" \
    --description "$DESC" \
    --add-topic suricata \
    --add-topic filebeat \
    --add-topic elasticsearch \
    --add-topic kibana \
    --add-topic docker \
    --add-topic siem \
    --add-topic soc \
    --add-topic detection-engineering \
    --add-topic nmap \
    --add-topic portscan \
    --add-topic security-lab \
    --add-topic elk-stack || true
fi

echo "==> Done. If any step failed due to auth, run: gh auth login -h github.com -p ssh --web, then rerun this script."
