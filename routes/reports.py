"""Vérification PDF et rapports publics."""
from flask import render_template, request, jsonify
from extensions import db

from routes.views_bp import views_bp

@views_bp.route('/verify/<int:scan_id>', methods=['GET'])
def verify_page(scan_id):
    """Page publique de vérification PDF (livrable blindé).

    Requiert le token opaque (?t=…) présent dans le QR/lien du rapport : sans
    lui, on ne révèle rien (empêche l'énumération des ID séquentiels).
    """
    from models import Scan
    from services.report_seal import verify_token, verify_token_ok
    token = request.args.get('t', '')
    scan = db.session.get(Scan, scan_id)
    if not scan or not verify_token_ok(scan_id, token):
        # ne divulgue pas l'existence si le token est absent/invalide
        return render_template('verify.html', scan_id=scan_id, sealed_at=None,
                               has_seal=False, scan_exists=False, token=token)
    sealed_at = scan.report_sealed_at.strftime('%d/%m/%Y %H:%M UTC') if scan.report_sealed_at else None
    return render_template(
        'verify.html',
        scan_id=scan_id,
        sealed_at=sealed_at,
        has_seal=bool(scan.report_pdf_hash),
        scan_exists=True,
        token=verify_token(scan_id),
    )


@views_bp.route('/verify/<int:scan_id>', methods=['POST'])
def verify_upload(scan_id):
    """Compare la signature HMAC du PDF uploadé (token requis)."""
    from models import Scan
    from services.report_seal import verify_uploaded_pdf, verify_token_ok
    token = request.args.get('t') or request.form.get('t') or ''
    scan = db.session.get(Scan, scan_id)
    if not scan or not verify_token_ok(scan_id, token):
        return jsonify({'error': 'Référence ou jeton de vérification invalide'}), 404
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
