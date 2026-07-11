"""Export PDF professionnel avec en-têtes d'intégrité."""
import hashlib
from io import BytesIO

from flask import send_file, jsonify


def generate_pdf_response(scan, raw_data: dict, **kwargs):
    """
    Génère le PDF et retourne une réponse Flask avec en-têtes X-Document-*.
    kwargs: investigator, classification, graph_image, narrative_html, base_url, …
    """
    try:
        from weasyprint import HTML as WeasyHTML
        from services.report_builder import build_report_context, render_report_html
    except (ImportError, OSError) as e:
        msg = (
            'WeasyPrint indisponible (dépendances système manquantes, ex. libgobject). '
            'Reconstruisez l’image Docker avec les paquets GTK/Pango/Cairo.'
        )
        if 'libgobject' in str(e).lower() or 'cannot load library' in str(e).lower():
            msg = (
                'PDF impossible : bibliothèques GTK manquantes (libgobject). '
                'Ajoutez les paquets WeasyPrint au Dockerfile et redéployez.'
            )
        return None, None, jsonify({'error': msg, 'detail': str(e)[:200]}), 503

    try:
        from services.report_seal import public_base_url
        if not kwargs.get('base_url'):
            kwargs['base_url'] = public_base_url()
        html_str = render_report_html(scan, raw_data, **kwargs)
        pdf_bytes = WeasyHTML(string=html_str).write_pdf()
        from services.report_seal import seal_scan_report
        from extensions import db
        seal_scan_report(scan, pdf_bytes)   # signe les OCTETS du PDF (HMAC)
        db.session.commit()
        # 2e passe : empreinte PDF visible sur la page de garde
        html_str = render_report_html(scan, raw_data, **kwargs)
        ctx = build_report_context(scan, raw_data, **kwargs)
        pdf_bytes = WeasyHTML(string=html_str).write_pdf()
        seal_scan_report(scan, pdf_bytes)   # signe le PDF FINAL (HMAC)
        db.session.commit()
        pdf_hash = hashlib.sha256(pdf_bytes).hexdigest()   # empreinte affichée (cosmétique)
    except Exception as e:
        return None, None, jsonify({'error': str(e)}), 500

    response = send_file(
        BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'osint_report_{scan.id}.pdf',
    )
    response.headers['X-Document-Hash'] = pdf_hash
    response.headers['X-Content-Hash'] = ctx['content_hash']
    response.headers['X-Signature-Hash'] = ctx['signature_hash']
    response.headers['X-Scan-Id'] = str(scan.id)
    response.headers['X-Verify-Url'] = ctx.get('verify_url', '')
    return pdf_hash, response, None
