"""Vérification PDF et rapports publics."""
from flask import render_template, request, jsonify
from extensions import db

from routes.views_bp import views_bp

@views_bp.route('/verify/<int:scan_id>', methods=['GET'])
def verify_page(scan_id):
    """Page publique de vérification PDF (livrable blindé)."""
    from models import Scan
    scan = db.session.get(Scan, scan_id)
    sealed_at = None
    has_seal = False
    if scan and scan.report_sealed_at:
        sealed_at = scan.report_sealed_at.strftime('%d/%m/%Y %H:%M UTC')
        has_seal = bool(scan.report_pdf_hash)
    return render_template(
        'verify.html',
        scan_id=scan_id,
        sealed_at=sealed_at,
        has_seal=has_seal,
        scan_exists=scan is not None,
    )


@views_bp.route('/verify/<int:scan_id>', methods=['POST'])
def verify_upload(scan_id):
    """Compare l'empreinte SHA-256 du PDF uploadé."""
    from models import Scan
    from services.report_seal import verify_uploaded_pdf
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({'error': 'Référence scan inconnue'}), 404
    f = request.files.get('pdf') or request.files.get('file')
    if not f or not f.filename:
        return jsonify({'error': 'Fichier PDF requis'}), 400
    data = f.read()
    if len(data) > 25 * 1024 * 1024:
        return jsonify({'error': 'Fichier trop volumineux (max 25 Mo)'}), 400
    if not data.startswith(b'%PDF'):
        return jsonify({'error': 'Le fichier ne semble pas être un PDF valide'}), 400
    out = verify_uploaded_pdf(data, scan)
    return jsonify(out)
