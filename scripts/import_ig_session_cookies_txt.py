#!/usr/bin/env python3
"""
Plan B — session Instagram depuis cookies.txt (extension « Get cookies.txt LOCALLY »).

1. Extension → export cookies instagram.com → cookies.txt
2. python scripts/import_ig_session_cookies_txt.py ~/Downloads/cookies.txt
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SESSION = ROOT / 'session-ig'

sys.path.insert(0, str(ROOT / 'scripts'))
from ig_session_paths import load_cookies_from_netscape  # noqa: E402


def main() -> int:
    import argparse

    p = argparse.ArgumentParser(description='Session IG depuis cookies.txt Netscape')
    p.add_argument('cookies_txt', type=Path, help='fichier exporté par l’extension navigateur')
    p.add_argument('-o', '--output', default=os.environ.get('IG_SESSION_FILE', str(DEFAULT_SESSION)))
    p.add_argument('--force', action='store_true')
    args = p.parse_args()

    try:
        from instaloader import Instaloader
    except ImportError:
        print('pip install instaloader', file=sys.stderr)
        return 1

    src = args.cookies_txt.expanduser().resolve()
    out = Path(args.output).resolve()
    if not src.is_file():
        print(f'Fichier introuvable : {src}', file=sys.stderr)
        return 1
    if out.is_dir():
        print(f'{out} est un dossier — rm -rf session-ig', file=sys.stderr)
        return 1

    rows = load_cookies_from_netscape(src)
    if not rows:
        print('Aucune ligne instagram.com dans le fichier.', file=sys.stderr)
        return 1

    cookies = {n: v for n, v, _h in rows}
    if not cookies.get('sessionid'):
        print('Cookie sessionid manquant — exportez depuis instagram.com connecté.',
              file=sys.stderr)
        return 1

    L = Instaloader(max_connection_attempts=1)
    for name, value, host in rows:
        L.context._session.cookies.set(name, value, domain=host.lstrip('.'))

    username = (os.environ.get('IG_DUMMY_USER') or '').strip()
    for key in ('ds_user', 'ds_user_name', 'username'):
        if cookies.get(key):
            username = cookies[key].strip()
            break
    if not username:
        try:
            username = L.test_login() or ''
        except Exception:
            pass
    if not username and not args.force:
        print('export IG_DUMMY_USER=… ou --force', file=sys.stderr)
        return 1

    L.context.username = username
    L.save_session_to_file(str(out))
    try:
        out.chmod(0o600)
    except OSError:
        pass

    print(f'✓ Session @{username} → {out}')
    print('  Docker : IG_SESSION_FILE=/code/session-ig')
    return 0


if __name__ == '__main__':
    sys.exit(main())
