"""Jeton de polling scan — lecture résultat sans session (Spaces HF frontend/backend séparés)."""
from __future__ import annotations

import json
import secrets
from typing import Any


def new_poll_token() -> str:
    return secrets.token_urlsafe(24)


def ensure_poll_token(options: dict | None) -> str:
    """Garantit un jeton de polling pour GET /scan/<id> (HF, sessions fragiles)."""
    opts = options if isinstance(options, dict) else {}
    tok = opts.get('_poll_token')
    if not tok:
        tok = new_poll_token()
        opts['_poll_token'] = tok
    return str(tok)


def _extract_poll_token(scan) -> str | None:
    if not scan or not scan.result_json:
        return None
    try:
        data = json.loads(scan.result_json)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    tok = data.get('_poll_token')
    if tok:
        return str(tok)
    pending = data.get('_pending_options')
    if isinstance(pending, dict) and pending.get('_poll_token'):
        return str(pending['_poll_token'])
    meta = data.get('_meta')
    if isinstance(meta, dict) and meta.get('_poll_token'):
        return str(meta['_poll_token'])
    return None


def poll_token_valid(scan, token: str | None) -> bool:
    if not token or not scan:
        return False
    stored = _extract_poll_token(scan)
    if not stored:
        return False
    try:
        return secrets.compare_digest(stored, token.strip())
    except Exception:
        return False


def attach_poll_token_to_result(result: dict, token: str | None) -> dict:
    if not token or not isinstance(result, dict):
        return result
    meta = result.setdefault('_meta', {})
    if isinstance(meta, dict):
        meta['_poll_token'] = token
    return result


# Clés d'options qui portent des objets non-sérialisables (jamais à persister ;
# le worker les reconstruit lui-même). Ex: _app (objet Flask) causait un
# TypeError 'Flask is not JSON serializable' -> 500 sur /graph/scan-node.
_NON_SERIALIZABLE_OPT_KEYS = {'_app', '_socketio', '_fernet'}


def _json_safe(value):
    """True si la valeur est sérialisable en JSON (types de base uniquement)."""
    return isinstance(value, (str, int, float, bool, list, dict, type(None)))


def pending_payload(options: dict) -> dict[str, Any]:
    """JSON stocké avant exécution du scan (pending).

    Ne conserve que les options sérialisables (retire _app/_socketio/_fernet
    et tout objet non-JSON), sinon json.dumps lève et le scan renvoie 500.
    """
    opts = {
        k: v for k, v in (options or {}).items()
        if k not in _NON_SERIALIZABLE_OPT_KEYS and _json_safe(v)
    }
    return {
        '_pending_options': opts,
        '_poll_token': opts.get('_poll_token'),
    }
