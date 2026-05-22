"""Notifications webhook à la fin d'un scan."""
import json
import requests
from models import Webhook


def notify_scan_complete(scan, result: dict, user_id: int | None):
    if not user_id:
        return
    hooks = Webhook.query.filter_by(user_id=user_id, enabled=True).all()
    if not hooks:
        return
    payload = {
        'event': 'scan.completed',
        'scan_id': scan.id,
        'module': scan.module,
        'target': scan.target,
        'status': scan.status,
        'has_error': bool(result.get('error') or result.get('Erreur')),
    }
    body = json.dumps(payload).encode()
    for hook in hooks:
        try:
            requests.post(
                hook.url,
                data=body,
                headers={'Content-Type': 'application/json', 'X-OSINT-Event': 'scan.completed'},
                timeout=8,
            )
        except Exception:
            pass
