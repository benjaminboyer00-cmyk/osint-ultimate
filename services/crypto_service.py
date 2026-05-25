"""Chiffrement Fernet — point d'accès unique (évite le couplage à app.py)."""
from __future__ import annotations

import logging
import os

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)
_fernet: Fernet | None = None


def get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet
    raw = os.environ.get('FERNET_KEY', '').strip()
    if raw:
        key = raw.encode() if isinstance(raw, str) else raw
    else:
        key = Fernet.generate_key()
        logger.warning(
            'FERNET_KEY absent — clé éphémère générée (clés API utilisateur perdues au redémarrage)',
        )
    _fernet = Fernet(key)
    return _fernet


def reset_fernet_for_tests():
    """Réinitialise le singleton (tests uniquement)."""
    global _fernet
    _fernet = None
