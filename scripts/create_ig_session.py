#!/usr/bin/env python3
"""
Crée le fichier de session Instagram pour instaloader (à monter dans Docker).

Usage (sur la machine hôte, une seule fois) :
  export IG_DUMMY_USER=votre_compte
  export IG_DUMMY_PASS='...'
  python scripts/create_ig_session.py

Produit ./session-ig à la racine du projet → monté en /code/session-ig dans les conteneurs.
"""
from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SESSION = ROOT / 'session-ig'


def _print_login_help() -> None:
    print(
        '\nCauses fréquentes de "fail" (message vide) :\n'
        '  • Mot de passe incorrect (vérifiez avec export IG_DUMMY_PASS=…)\n'
        '  • Compte avec 2FA — le script demande le code après le mot de passe\n'
        '  • Instagram bloque la connexion "automatisée" — ouvrez l’app IG, validez\n'
        '    la notification "nouvelle connexion", puis réessayez\n'
        '  • Checkpoint / "activité suspecte" — connectez-vous une fois dans Firefox,\n'
        '    puis importez les cookies (méthode recommandée par instaloader) :\n'
        '    https://instaloader.github.io/troubleshooting.html\n'
        '  • Caractères spéciaux dans le mot de passe : utilisez export IG_DUMMY_PASS\n'
        '    plutôt que la saisie masquée du terminal\n',
        file=sys.stderr,
    )


def main() -> int:
    try:
        import instaloader
    except ImportError:
        print('Installez instaloader : pip install instaloader', file=sys.stderr)
        return 1

    user = (os.environ.get('IG_DUMMY_USER') or '').strip()
    if not user:
        user = input('Compte Instagram (IG_DUMMY_USER) : ').strip()
    passwd = (os.environ.get('IG_DUMMY_PASS') or '').strip()
    pass_file = (os.environ.get('IG_DUMMY_PASS_FILE') or '').strip()
    if not passwd and pass_file and Path(pass_file).is_file():
        passwd = Path(pass_file).read_text(encoding='utf-8').strip()
    if not passwd and user and os.environ.get('IG_DUMMY_USER'):
        print(
            'IG_DUMMY_USER est défini mais pas IG_DUMMY_PASS (export shell cassé ?).\n'
            '  Mot de passe avec apostrophe : utilisez des guillemets doubles :\n'
            '    export IG_DUMMY_PASS="votre\'mot\'de\'passe"\n'
            '  Ou fichier : echo -n \'…\' > .ig-pass && export IG_DUMMY_PASS_FILE=.ig-pass',
            file=sys.stderr,
        )
    if not passwd:
        passwd = getpass.getpass('Mot de passe Instagram : ')

    out = Path(os.environ.get('IG_SESSION_FILE', str(DEFAULT_SESSION))).resolve()
    if out.is_dir():
        print(f'Erreur : {out} est un dossier (supprimez-le et relancez)', file=sys.stderr)
        return 1

    from instaloader.exceptions import (
        BadCredentialsException,
        ConnectionException,
        TwoFactorAuthRequiredException,
    )

    L = instaloader.Instaloader()
    print(f'Connexion {user}…')
    try:
        L.login(user, passwd)
    except TwoFactorAuthRequiredException:
        print('2FA requis — ouvrez votre app Authenticator (pas un ancien code SMS).')
        code = input('Code 2FA à 6 chiffres : ').strip()
        try:
            L.two_factor_login(code)
        except Exception as e2:
            print(f'Échec 2FA : {e2}', file=sys.stderr)
            _print_login_help()
            return 1
    except BadCredentialsException as e:
        print(f'Échec login : {e}', file=sys.stderr)
        _print_login_help()
        return 1
    except ConnectionException as e:
        print(f'Échec login : {e}', file=sys.stderr)
        print(
            '\n→ Si le mot de passe est correct dans le navigateur, utilisez Firefox :\n'
            '    python scripts/import_ig_session_firefox.py\n',
            file=sys.stderr,
        )
        _print_login_help()
        return 1
    except Exception as e:
        print(f'Échec login : {e}', file=sys.stderr)
        _print_login_help()
        return 1

    L.save_session_to_file(str(out))
    try:
        out.chmod(0o600)
    except OSError:
        pass

    print(f'✓ Session enregistrée : {out}')
    print('  Docker : IG_SESSION_FILE=/code/session-ig')
    print('  Ne commitez jamais ce fichier (déjà dans .gitignore).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
