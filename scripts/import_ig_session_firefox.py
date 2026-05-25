#!/usr/bin/env python3
"""
Importe la session Instagram depuis Firefox (deb, Snap, Flatpak).

1. Firefox → https://www.instagram.com → connexion → naviguer un peu
2. Fermer Firefox
3. python scripts/import_ig_session_firefox.py

Liste les profils : python scripts/import_ig_session_firefox.py --list
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SESSION = ROOT / 'session-ig'

sys.path.insert(0, str(ROOT / 'scripts'))
from ig_session_paths import (  # noqa: E402
    best_firefox_cookie_db,
    firefox_cookie_candidates,
    instagram_cookie_stats,
    load_rows_from_sqlite,
)


def _is_rate_limited(err: str) -> bool:
    low = err.lower()
    return 'please wait' in low or '429' in low or 'too many' in low or 'few minutes' in low


def import_session(cookiefile: Path, sessionfile: Path, *, force: bool = False) -> str:
    try:
        from instaloader import Instaloader
    except ImportError:
        raise SystemExit('pip install instaloader') from None

    if sessionfile.is_dir():
        raise SystemExit(f'{sessionfile} est un dossier — supprimez-le (rm -rf session-ig)')

    rows = load_rows_from_sqlite(cookiefile)
    if not rows:
        raise SystemExit(f'Aucun cookie IG dans {cookiefile}')

    cookies = {name: value for name, value, _host in rows}
    if not cookies.get('sessionid'):
        raise SystemExit(f'Pas de sessionid dans {cookiefile} — reconnectez-vous dans Firefox.')

    print(f'Cookies : {len(rows)} entrées depuis {cookiefile}')

    L = Instaloader(max_connection_attempts=1)
    for name, value, host in rows:
        L.context._session.cookies.set(name, value, domain=host.lstrip('.'))

    username = None
    test_err = ''
    try:
        username = L.test_login()
    except Exception as e:
        test_err = str(e)

    if not username:
        for key in ('ds_user', 'ds_user_name', 'username'):
            if cookies.get(key):
                username = cookies[key].strip()
                break
    if not username:
        username = (os.environ.get('IG_DUMMY_USER') or '').strip()

    if not username and not force:
        raise SystemExit(
            'Pseudo inconnu (rate-limit ?). export IG_DUMMY_USER=bzk7534 '
            'puis --force\n'
            f'Détail : {test_err[:300]}',
        )

    if test_err and _is_rate_limited(test_err):
        print('⚠ Rate-limit Instagram — session sauvegardée quand même.')
        print('  Attendez 15–30 min avant les scans si besoin.')

    L.context.username = username
    L.save_session_to_file(str(sessionfile))
    try:
        sessionfile.chmod(0o600)
    except OSError:
        pass
    return username


def cmd_list() -> int:
    print('Profils Firefox (cookies instagram.com) :\n')
    found = False
    for path in firefox_cookie_candidates():
        st = instagram_cookie_stats(path)
        mark = '✓' if st.get('sessionid') else ('·' if st.get('count') else ' ')
        err = st.get('error', '')
        print(f"  [{mark}] {st['count']:3} cookies  sessionid={st.get('sessionid')}  {path}")
        if err:
            print(f'       erreur: {err}')
        if st.get('count'):
            found = True
    if not found:
        print('\n→ Connectez-vous à Instagram dans Firefox (souvent la version Snap sous Ubuntu).')
    else:
        try:
            best = best_firefox_cookie_db()
            print(f'\n→ Profil recommandé : {best}')
        except FileNotFoundError as e:
            print(f'\n{e}')
    return 0


def main() -> int:
    import argparse

    p = argparse.ArgumentParser(description='Session IG depuis cookies Firefox')
    p.add_argument('-c', '--cookiefile', type=Path, help='cookies.sqlite (auto si omis)')
    p.add_argument('-o', '--output', default=os.environ.get('IG_SESSION_FILE', str(DEFAULT_SESSION)))
    p.add_argument('--force', action='store_true', help='sauver même si test_login échoue')
    p.add_argument('--wait', type=int, default=0, metavar='SEC', help='pause avant import')
    p.add_argument('--list', action='store_true', help='lister les profils Firefox')
    args = p.parse_args()

    if args.list:
        return cmd_list()

    if args.wait > 0:
        print(f'Attente {args.wait}s…')
        time.sleep(args.wait)

    out = Path(args.output).resolve()
    try:
        cookiefile = args.cookiefile or best_firefox_cookie_db()
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        print('\nPlan B : python scripts/import_ig_session_cookies_txt.py ~/Downloads/cookies.txt',
              file=sys.stderr)
        return 1

    print(f'Profil sélectionné : {cookiefile}')
    try:
        user = import_session(Path(cookiefile), out, force=args.force)
    except SystemExit as e:
        print(e, file=sys.stderr)
        return 1
    except Exception as e:
        print(f'Échec : {e}', file=sys.stderr)
        return 1

    print(f'✓ Session @{user} → {out}')
    print('  Docker : IG_SESSION_FILE=/code/session-ig')
    return 0


if __name__ == '__main__':
    sys.exit(main())
