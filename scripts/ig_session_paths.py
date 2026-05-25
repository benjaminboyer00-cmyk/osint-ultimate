"""Découverte des bases cookies Firefox (deb + Snap + Flatpak) et import Netscape."""
from __future__ import annotations

import os
from glob import glob
from os.path import expanduser
from pathlib import Path
from platform import system
from sqlite3 import connect

INSTAGRAM_COOKIE_QUERY = (
    "SELECT name, value, host FROM moz_cookies "
    "WHERE host LIKE '%instagram.com%'"
)


def firefox_cookie_candidates() -> list[Path]:
    """Tous les cookies.sqlite Firefox connus sur Linux/macOS/Windows."""
    patterns = [
        '~/.mozilla/firefox/*/cookies.sqlite',
        '~/snap/firefox/common/.mozilla/firefox/*/cookies.sqlite',
        '~/snap/firefox/current/.mozilla/firefox/*/cookies.sqlite',
        '~/.var/app/org.mozilla.firefox/.mozilla/firefox/*/cookies.sqlite',
        '~/Library/Application Support/Firefox/Profiles/*/cookies.sqlite',
        '~/AppData/Roaming/Mozilla/Firefox/Profiles/*/cookies.sqlite',
    ]
    if system() == 'Darwin':
        patterns = patterns[3:4] + patterns[:3]
    elif system() == 'Windows':
        patterns = patterns[5:6] + patterns[:3]

    seen: set[str] = set()
    out: list[Path] = []
    for pat in patterns:
        for p in sorted(glob(expanduser(pat))):
            rp = str(Path(p).resolve())
            if rp not in seen and Path(p).is_file():
                seen.add(rp)
                out.append(Path(p))
    return out


def instagram_cookie_stats(cookiefile: Path | str) -> dict:
    """Compte les cookies IG et présence de sessionid."""
    cf = str(cookiefile)
    try:
        conn = connect(f'file:{cf}?immutable=1', uri=True)
        rows = list(conn.execute(INSTAGRAM_COOKIE_QUERY))
    except Exception as e:
        return {'path': cf, 'count': 0, 'sessionid': False, 'error': str(e)}
    names = {r[0] for r in rows}
    return {
        'path': cf,
        'count': len(rows),
        'sessionid': 'sessionid' in names,
        'rows': rows,
    }


def best_firefox_cookie_db() -> Path:
    """
    Choisit le profil avec le plus de cookies Instagram (priorité sessionid).
    Résout le piège Snap : ~/.mozilla vs ~/snap/firefox/common/.mozilla
    """
    candidates = firefox_cookie_candidates()
    if not candidates:
        raise FileNotFoundError(
            'Aucun cookies.sqlite Firefox. Installez Firefox ou utilisez '
            'scripts/import_ig_session_cookies_txt.py avec cookies.txt',
        )

    best: Path | None = None
    best_score = (-1, False)
    for path in candidates:
        st = instagram_cookie_stats(path)
        if st.get('error'):
            continue
        score = (st['count'], st['sessionid'])
        if score > best_score:
            best_score = score
            best = path

    if not best or best_score[0] == 0:
        paths = '\n  '.join(str(p) for p in candidates)
        raise FileNotFoundError(
            'Aucun cookie instagram.com dans Firefox.\n'
            f'Profils inspectés :\n  {paths}\n'
            'Connectez-vous sur instagram.com dans Firefox (Snap si Ubuntu), '
            'fermez Firefox, relancez.',
        )
    if not best_score[1]:
        raise FileNotFoundError(
            f'Cookies IG trouvés ({best_score[0]}) mais pas de sessionid dans {best}.\n'
            'Reconnectez-vous à Instagram dans Firefox.',
        )
    return best


def load_rows_from_sqlite(cookiefile: Path | str) -> list[tuple]:
    conn = connect(f'file:{cookiefile}?immutable=1', uri=True)
    return list(conn.execute(INSTAGRAM_COOKIE_QUERY))


def load_cookies_from_netscape(path: Path | str) -> list[tuple]:
    """
    Lit un cookies.txt (extension « Get cookies.txt LOCALLY »).
    Retourne [(name, value, host), ...] pour instagram.com.
    """
    text = Path(path).read_text(encoding='utf-8', errors='replace')
    rows: list[tuple] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) < 7:
            continue
        domain, _flag, _path, _secure, _expiry, name, value = parts[:7]
        if 'instagram.com' not in domain:
            continue
        host = domain if domain.startswith('.') else f'.{domain}'
        rows.append((name, value, host))
    return rows
