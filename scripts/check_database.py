#!/usr/bin/env python3
"""Teste DATABASE_URL (Supabase) sans lancer toute l'app."""
from __future__ import annotations

import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

PROJECT_REF = os.environ.get('SUPABASE_PROJECT_REF', 'mkciozumxpxllsjmcsyz')


def _normalize_database_url(url: str) -> str:
    if url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    if url.startswith('postgresql://') and '+psycopg2' not in url and '+psycopg' not in url:
        url = url.replace('postgresql://', 'postgresql+psycopg2://', 1)
    if 'supabase' in url and 'sslmode=' not in url:
        sep = '&' if '?' in url else '?'
        url = f'{url}{sep}sslmode=require'
    return url


def _build_url(mode: str, password: str) -> str:
    if mode == 'direct':
        return (
            f'postgresql://postgres:{password}'
            f'@db.{PROJECT_REF}.supabase.co:5432/postgres?sslmode=require'
        )
    return (
        f'postgresql://postgres.{PROJECT_REF}:{password}'
        f'@aws-0-eu-west-1.pooler.supabase.com:5432/postgres?sslmode=require'
    )


def _resolve_url() -> str:
    url = os.environ.get('DATABASE_URL', '').strip()
    if url:
        return url
    pwd = os.environ.get('SUPABASE_DB_PASSWORD', '').strip()
    if not pwd:
        return ''
    mode = os.environ.get('SUPABASE_MODE', 'pooler').strip().lower()
    return _build_url(mode, pwd)


def _describe_url(url: str) -> str:
    if 'pooler.supabase.com' in url:
        return 'Session pooler (IPv4)'
    if f'db.{PROJECT_REF}.supabase.co' in url:
        return 'Directe (IPv6 — peut échouer en IPv4)'
    return 'PostgreSQL'


def _check_one(url: str) -> bool:
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine.url import make_url

    norm = _normalize_database_url(url)
    print(f'  Mode     : {_describe_url(url)}')
    try:
        u = make_url(norm)
        if u.username:
            print(f'  User     : {u.username}')
        if u.host:
            print(f'  Host     : {u.host}')
    except Exception:
        pass

    engine = create_engine(norm, pool_pre_ping=True, connect_args={'connect_timeout': 10})
    with engine.connect() as conn:
        row = conn.execute(text('SELECT version()')).scalar()
        rev = conn.execute(text('SELECT version_num FROM alembic_version LIMIT 1')).scalar()
    print('✓ Connexion PostgreSQL OK')
    print(f'  Serveur : {str(row)[:60]}...')
    print(f'  Alembic  : {rev or "(vide — flask db upgrade)"}')
    return True


def main() -> int:
    url = _resolve_url()
    if not url:
        print('❌ DATABASE_URL ou SUPABASE_DB_PASSWORD manquant.', file=sys.stderr)
        print('', file=sys.stderr)
        print('  export SUPABASE_DB_PASSWORD="..."', file=sys.stderr)
        print('  source scripts/export_supabase_env.sh pooler', file=sys.stderr)
        print('  python scripts/check_database.py', file=sys.stderr)
        return 1

    # Avertissement pooler : user doit être postgres.<ref>
    if 'pooler.supabase.com' in url:
        try:
            user = url.split('://', 1)[1].split('@', 1)[0].split(':', 1)[0]
            if user == 'postgres':
                print('❌ Sur le pooler, user = postgres.<project_ref> obligatoire.', file=sys.stderr)
                print(f'   Ex. postgres.{PROJECT_REF}', file=sys.stderr)
                print('   source scripts/export_supabase_env.sh pooler', file=sys.stderr)
                return 1
        except Exception:
            pass

    try:
        return 0 if _check_one(url) else 1
    except Exception as e:
        err = str(e).lower()
        print(f'❌ Échec : {e}', file=sys.stderr)

        pwd = os.environ.get('SUPABASE_DB_PASSWORD', '').strip()
        if pwd and 'network is unreachable' in err and 'db.' in url:
            print('', file=sys.stderr)
            print('→ Directe indisponible en IPv4 sur ce réseau.', file=sys.stderr)
            print('→ Test automatique du pooler (recommandé HF)…', file=sys.stderr)
            try:
                if _check_one(_build_url('pooler', pwd)):
                    print('', file=sys.stderr)
                    print('→ Mettez cette URL dans HF : source scripts/export_supabase_env.sh pooler', file=sys.stderr)
                    return 0
            except Exception as e2:
                print(f'❌ Pooler aussi en échec : {e2}', file=sys.stderr)

        if 'password authentication failed' in err:
            print('', file=sys.stderr)
            print('→ Mot de passe incorrect ou pas encore propagé après reset Supabase.', file=sys.stderr)
            print('→ Copiez l’URI depuis le dashboard (bouton Copy), sans espace.', file=sys.stderr)
            print('→ Pooler : postgres.' + PROJECT_REF, file=sys.stderr)
            print('→ Direct : postgres@db.' + PROJECT_REF + '.supabase.co', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
