#!/usr/bin/env bash
# Bloque tout commit accidentel de fichiers secrets (.env, etc.)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BLOCKED='\.env$|\.env\.|secrets/|\.pem$|\.key$'
STAGED=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)

if [[ -z "$STAGED" ]]; then
  exit 0
fi

BAD=$(echo "$STAGED" | grep -E "$BLOCKED" | grep -vE '^\.env\.example$' || true)
if [[ -n "$BAD" ]]; then
  echo "❌ Commit refusé — fichiers sensibles détectés :" >&2
  echo "$BAD" >&2
  echo "Retirez-les : git reset HEAD -- <fichier>" >&2
  exit 1
fi

if git ls-files --error-unmatch .env &>/dev/null; then
  echo "❌ .env est encore suivi par git. Exécutez : git rm --cached .env" >&2
  exit 1
fi

exit 0
