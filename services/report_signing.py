"""Signature d'intégrité des rapports PDF (HMAC-SHA256, secret serveur).

Auparavant : simple SHA-256 stocké à côté de la donnée -> falsifiable par
quiconque a un accès en écriture DB. Désormais : HMAC-SHA256 avec un secret
serveur (REPORT_SIGNING_KEY ou SECRET_KEY) -> impossible à forger sans le
secret, même avec accès DB.
"""
import hashlib
import hmac
import json
import os


def _signing_key() -> bytes:
    key = os.environ.get('REPORT_SIGNING_KEY') or os.environ.get('SECRET_KEY')
    if not key:
        try:
            from flask import current_app
            key = current_app.config.get('SECRET_KEY')
        except Exception:
            key = None
    return (key or 'osint-ultimate-dev-only').encode('utf-8')


def sign_bytes(data: bytes) -> str:
    """Signature HMAC-SHA256 (hex) de `data` avec le secret serveur."""
    return hmac.new(_signing_key(), bytes(data), hashlib.sha256).hexdigest()


def verify_signature(data: bytes, signature: str) -> bool:
    """Comparaison en temps constant d'une signature attendue."""
    if not signature:
        return False
    return hmac.compare_digest(sign_bytes(data).lower(), signature.strip().lower())


def build_report_hashes(scan, data: dict, generated_at: str) -> dict:
    """Empreinte du contenu (SHA-256) + SIGNATURE HMAC du document d'intégrité."""
    payload = json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
    content_hash = hashlib.sha256(payload.encode()).hexdigest()

    integrity_doc = {
        'scan_id': scan.id,
        'module': scan.module,
        'target': scan.target,
        'user_id': scan.user_id,
        'generated_at': generated_at,
        'content_sha256': content_hash,
    }
    integrity_json = json.dumps(integrity_doc, sort_keys=True, ensure_ascii=False)
    # Vraie signature (HMAC) plutôt qu'un simple hash.
    signature_hash = hmac.new(
        _signing_key(), integrity_json.encode('utf-8'), hashlib.sha256,
    ).hexdigest()

    return {
        'content_hash': content_hash,
        'content_hash_short': content_hash[:32],
        'signature_hash': signature_hash,
        'integrity_json': integrity_json,
    }
