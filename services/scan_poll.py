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


def pending_payload(options: dict) -> dict[str, Any]:
    """JSON stocké avant exécution du scan (pending)."""
    opts = dict(options or {})
    tok = opts.get('_poll_token')
    return {
        '_pending_options': opts,
        '_poll_token': tok,
    }
