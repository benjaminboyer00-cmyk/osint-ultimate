"""Empreinte et signature d'intégrité des rapports PDF."""
import hashlib
import json
from datetime import datetime


def build_report_hashes(scan, data: dict, generated_at: str) -> dict:
    """Calcule empreintes SHA-256 pour le rapport professionnel."""
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
    signature_hash = hashlib.sha256(integrity_json.encode()).hexdigest()

    return {
        'content_hash': content_hash,
        'content_hash_short': content_hash[:32],
        'signature_hash': signature_hash,
        'integrity_json': integrity_json,
    }
