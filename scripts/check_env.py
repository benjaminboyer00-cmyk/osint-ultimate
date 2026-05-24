#!/usr/bin/env python3
"""Vérifie .env : présence, format, et appels API (sans afficher les secrets)."""
from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Charge .env comme l'app
from config import _load_dotenv_file  # noqa: E402

_load_dotenv_file()

import requests  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402

PLACEHOLDERS = (
    '',
    'changeme',
    'change-me',
    'xxx',
    'xxxxxxxx',
    'generer',
    'your_',
    'gsk_xxxxxxxx',
)


def _val(name: str) -> str:
    return (os.environ.get(name) or '').strip()


def _placeholder(v: str) -> bool:
    low = v.lower().strip()
    if not low:
        return True
    return any(p and p in low for p in PLACEHOLDERS if len(p) > 2)


def _line(name: str, status: str, detail: str = '') -> dict:
    return {'name': name, 'status': status, 'detail': detail}


def check_secret_key() -> dict:
    v = _val('SECRET_KEY')
    if _placeholder(v) or len(v) < 32:
        return _line('SECRET_KEY', 'fail', 'manquant ou < 32 caractères')
    return _line('SECRET_KEY', 'ok', f'{len(v)} caractères')


def check_fernet() -> dict:
    v = _val('FERNET_KEY')
    if _placeholder(v):
        return _line('FERNET_KEY', 'fail', 'manquant')
    try:
        Fernet(v.encode() if isinstance(v, str) else v)
        return _line('FERNET_KEY', 'ok', 'clé Fernet valide')
    except Exception as e:
        return _line('FERNET_KEY', 'fail', str(e)[:80])


def check_database() -> dict:
    url = _val('DATABASE_URL')
    if _placeholder(url):
        return _line('DATABASE_URL', 'fail', 'manquant')
    try:
        from sqlalchemy import create_engine, text
        from config import normalize_database_url

        eng = create_engine(normalize_database_url(url), pool_pre_ping=True)
        with eng.connect() as conn:
            conn.execute(text('SELECT 1'))
        return _line('DATABASE_URL', 'ok', 'PostgreSQL OK')
    except Exception as e:
        msg = str(e).split('\n')[0][:120]
        hint = ''
        if 'db.' in url and 'pooler' not in url:
            if 'unreachable' in str(e).lower() or '2a05:' in str(e):
                hint = ' — utilisez le pooler : source scripts/export_supabase_env.sh pooler'
            elif 'password authentication' in str(e).lower():
                hint = ' — vérifiez le MDP Supabase ou passez au pooler (postgres.PROJECT_REF)'
        return _line('DATABASE_URL', 'fail', msg + hint)


def check_groq() -> dict:
    key = _val('GROQ_API_KEY')
    if _placeholder(key):
        return _line('GROQ_API_KEY', 'fail', 'manquant')
    if key.startswith('xai-'):
        return _line(
            'GROQ_API_KEY',
            'fail',
            'clé xAI détectée — mettez une clé Groq (gsk_…) depuis console.groq.com',
        )
    if not key.startswith('gsk_'):
        return _line('GROQ_API_KEY', 'fail', 'format invalide (attendu gsk_…)')
    try:
        r = requests.get(
            'https://api.groq.com/openai/v1/models',
            headers={'Authorization': f'Bearer {key}'},
            timeout=15,
        )
        if r.status_code == 200:
            return _line('GROQ_API_KEY', 'ok', 'API Groq accessible')
        return _line('GROQ_API_KEY', 'fail', f'HTTP {r.status_code}')
    except Exception as e:
        return _line('GROQ_API_KEY', 'fail', str(e)[:80])


def check_github() -> dict:
    key = _val('GITHUB_TOKEN')
    if _placeholder(key):
        return _line('GITHUB_TOKEN', 'skip', 'non configuré')
    try:
        r = requests.get(
            'https://api.github.com/user',
            headers={'Authorization': f'Bearer {key}', 'Accept': 'application/vnd.github+json'},
            timeout=15,
        )
        if r.status_code == 200:
            login = (r.json() or {}).get('login', '?')
            return _line('GITHUB_TOKEN', 'ok', f'compte {login}')
        return _line('GITHUB_TOKEN', 'fail', f'HTTP {r.status_code}')
    except Exception as e:
        return _line('GITHUB_TOKEN', 'fail', str(e)[:80])


def check_shodan() -> dict:
    key = _val('SHODAN_API_KEY')
    if _placeholder(key):
        return _line('SHODAN_API_KEY', 'skip', 'non configuré')
    try:
        r = requests.get(f'https://api.shodan.io/api-info?key={key}', timeout=15)
        if r.status_code == 200:
            return _line('SHODAN_API_KEY', 'ok', 'API Shodan OK')
        return _line('SHODAN_API_KEY', 'fail', f'HTTP {r.status_code}')
    except Exception as e:
        return _line('SHODAN_API_KEY', 'fail', str(e)[:80])


def check_hunter() -> dict:
    from services.quota_monitor import check_hunter

    key = _val('HUNTER_API_KEY')
    if _placeholder(key):
        return _line('HUNTER_API_KEY', 'skip', 'non configuré')
    c = check_hunter(key)
    if c.get('status') == 'ok':
        return _line('HUNTER_API_KEY', 'ok', f"quota {c.get('used', '?')}/{c.get('available', '?')}")
    return _line('HUNTER_API_KEY', 'fail', f"status={c.get('status')} http={c.get('http', '')}")


def check_numverify() -> dict:
    key = _val('NUMVERIFY_KEY')
    if _placeholder(key):
        return _line('NUMVERIFY_KEY', 'skip', 'non configuré')
    try:
        r = requests.get(
            f'http://apilayer.net/api/validate?access_key={key}&number=+33123456789',
            timeout=15,
        )
        data = r.json() if r.content else {}
        if data.get('success') is True or data.get('valid') is not None:
            return _line('NUMVERIFY_KEY', 'ok', 'API Numverify OK')
        err = data.get('error', {})
        info = err.get('info') or err.get('type') or f'HTTP {r.status_code}'
        return _line('NUMVERIFY_KEY', 'fail', str(info)[:80])
    except Exception as e:
        return _line('NUMVERIFY_KEY', 'fail', str(e)[:80])


def check_dehashed() -> dict:
    key = _val('DEHASHED_API_KEY')
    email = _val('DEHASHED_EMAIL')
    if _placeholder(key):
        return _line('DEHASHED_API_KEY', 'skip', 'non configuré')
    headers = {'Accept': 'application/json'}
    if email:
        token = base64.b64encode(f'{email}:{key}'.encode()).decode()
        headers['Authorization'] = f'Basic {token}'
    else:
        headers['Authorization'] = f'Bearer {key}'
    try:
        r = requests.get(
            'https://api.dehashed.com/v2/search?query=test&size=1',
            headers=headers,
            timeout=20,
        )
        if r.status_code in (200, 402):
            return _line('DEHASHED_API_KEY', 'ok', 'auth OK (quota peut limiter)')
        if r.status_code == 401:
            return _line('DEHASHED_API_KEY', 'fail', 'email + clé invalides')
        return _line('DEHASHED_API_KEY', 'fail', f'HTTP {r.status_code}')
    except Exception as e:
        return _line('DEHASHED_API_KEY', 'fail', str(e)[:80])


def check_redis() -> dict:
    url = _val('REDIS_URL')
    if _placeholder(url):
        return _line('REDIS_URL', 'skip', 'non configuré (mode thread OK)')
    try:
        import redis

        r = redis.from_url(url, socket_connect_timeout=3)
        r.ping()
        return _line('REDIS_URL', 'ok', 'Redis ping OK')
    except Exception as e:
        return _line('REDIS_URL', 'warn', f'indisponible localement : {str(e)[:60]}')


def check_sentry() -> dict:
    dsn = _val('SENTRY_DSN')
    if _placeholder(dsn):
        return _line('SENTRY_DSN', 'skip', 'non configuré')
    if dsn.startswith('https://') and '@' in dsn:
        return _line('SENTRY_DSN', 'ok', 'format DSN valide')
    return _line(
        'SENTRY_DSN',
        'fail',
        'doit ressembler à https://xxx@o123.ingest.sentry.io/456 (Settings → Client Keys)',
    )


def check_openrouter() -> dict:
    if _val('OPENROUTER_KEY'):
        return _line('OPENROUTER_KEY', 'warn', 'présent mais non utilisé par le code actuel')
    return _line('OPENROUTER_KEY', 'skip', 'absent')


def main() -> int:
    env_file = ROOT / '.env'
    print(f'Fichier .env : {"présent" if env_file.is_file() else "ABSENT"}')
    if not env_file.is_file():
        print('Créez .env depuis .env.example')
        return 1

    checks = [
        check_secret_key(),
        check_fernet(),
        check_database(),
        check_groq(),
        check_github(),
        check_shodan(),
        check_hunter(),
        check_numverify(),
        check_dehashed(),
        check_redis(),
        check_sentry(),
        check_openrouter(),
    ]

    icons = {'ok': '✓', 'fail': '✗', 'skip': '○', 'warn': '⚠'}
    fails = 0
    for c in checks:
        icon = icons.get(c['status'], '?')
        detail = f" — {c['detail']}" if c.get('detail') else ''
        print(f"  {icon} {c['name']}: {c['status']}{detail}")
        if c['status'] == 'fail':
            fails += 1

    print()
    if fails:
        print(f'❌ {fails} clé(s) obligatoire(s) en échec.')
        return 1
    print('✓ Configuration utilisable (vérifiez les avertissements optionnels).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
