"""Livrable blindé — QR code, empreinte PDF, vérification upload (Phase 4 V7)."""
import base64
import hashlib
import io
import os
from datetime import datetime


def public_base_url(fallback: str | None = None) -> str:
    """URL publique de l'app (HF Space, domaine custom)."""
    base = (os.environ.get('PUBLIC_BASE_URL') or '').strip().rstrip('/')
    if base:
        return base
    try:
        from flask import request
        if request and request.host_url:
            return request.host_url.rstrip('/')
    except RuntimeError:
        pass
    return (fallback or 'http://localhost:7860').rstrip('/')


def verify_page_url(scan_id: int, base_url: str | None = None) -> str:
    base = (base_url or public_base_url()).rstrip('/')
    return f'{base}/verify/{scan_id}'


def qr_code_data_uri(url: str, *, box_size: int = 4) -> str:
    """PNG QR en data URI pour WeasyPrint."""
    import qrcode
    qr = qrcode.QRCode(version=1, box_size=box_size, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color='#006644', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    b64 = base64.b64encode(buf.getvalue()).decode('ascii')
    return f'data:image/png;base64,{b64}'


def build_seal_assets(scan_id: int, base_url: str | None = None) -> dict:
    """URL de vérification + image QR pour le template PDF."""
    url = verify_page_url(scan_id, base_url)
    return {
        'verify_url': url,
        'qr_data_uri': qr_code_data_uri(url),
    }


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seal_scan_report(scan, pdf_hash: str, *, generated_at: str | None = None) -> None:
    """Enregistre l'empreinte du PDF final en base."""
    from extensions import db
    scan.report_pdf_hash = pdf_hash
    scan.report_sealed_at = datetime.utcnow()
    db.session.add(scan)


def verify_uploaded_pdf(file_bytes: bytes, scan) -> dict:
    """
    Compare le hash du fichier uploadé à l'empreinte enregistrée.
    Retourne {valid, uploaded_hash, stored_hash, message, sealed_at}.
    """
    uploaded = sha256_bytes(file_bytes)
    stored = (scan.report_pdf_hash or '').strip().lower() if scan else ''
    if not stored:
        return {
            'valid': False,
            'uploaded_hash': uploaded,
            'stored_hash': None,
            'message': 'Aucun PDF officiel enregistré pour ce scan — générez le rapport depuis la plateforme.',
            'sealed_at': None,
        }
    valid = uploaded.lower() == stored.lower()
    sealed = scan.report_sealed_at.isoformat() if getattr(scan, 'report_sealed_at', None) else None
    return {
        'valid': valid,
        'uploaded_hash': uploaded,
        'stored_hash': stored,
        'message': '✅ Document authentique — empreinte PDF conforme.' if valid else
        '❌ Document modifié ou non reconnu — l\'empreinte ne correspond pas.',
        'sealed_at': sealed,
    }
