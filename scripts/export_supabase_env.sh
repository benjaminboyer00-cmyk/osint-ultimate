#!/usr/bin/env bash
# Configure DATABASE_URL pour Supabase — à sourcer, ne pas commiter.
# Usage :
#   export SUPABASE_DB_PASSWORD='votre_mot_de_passe'
#   source scripts/export_supabase_env.sh pooler    # Hugging Face / IPv4 (recommandé)
#   source scripts/export_supabase_env.sh direct    # IPv6 ou add-on IPv4 Supabase
set -euo pipefail

MODE="${1:-pooler}"
PROJECT_REF="${SUPABASE_PROJECT_REF:-mkciozumxpxllsjmcsyz}"

if [[ -z "${SUPABASE_DB_PASSWORD:-}" ]]; then
  echo "❌ Définissez d'abord : export SUPABASE_DB_PASSWORD='...'" >&2
  echo "   (mot de passe : Supabase → Project Settings → Database → Reset)" >&2
  return 1 2>/dev/null || exit 1
fi

case "$MODE" in
  direct)
    export DATABASE_URL="postgresql://postgres:${SUPABASE_DB_PASSWORD}@db.${PROJECT_REF}.supabase.co:5432/postgres?sslmode=require"
    echo "✓ DATABASE_URL = connexion DIRECTE (db.${PROJECT_REF}.supabase.co)"
  ;;
  pooler|session)
    export DATABASE_URL="postgresql://postgres.${PROJECT_REF}:${SUPABASE_DB_PASSWORD}@aws-0-eu-west-1.pooler.supabase.com:5432/postgres?sslmode=require"
    echo "✓ DATABASE_URL = Session POOLER (IPv4 — Hugging Face / VPS)"
  ;;
  *)
    echo "Usage: source scripts/export_supabase_env.sh [direct|pooler]" >&2
    return 1 2>/dev/null || exit 1
    ;;
esac

export FLASK_APP="${FLASK_APP:-app:app}"
