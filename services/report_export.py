"""Export PDF professionnel avec en-têtes d'intégrité."""
import hashlib
import json
from io import BytesIO

from flask import send_file, jsonify


def generate_pdf_response(scan, raw_data: dict, **kwargs):
    """kwargs: investigator, classification, graph_image, narrative_html, narrative_markdown, …"""
    """
    Génère le PDF et retourne une réponse Flask avec en-têtes X-Document-*.
    kwargs: investigator, classification, graph_image, generated_at
    """
    try:
        from weasyprint import HTML as WeasyHTML
        from services.report_builder import build_report_context, render_report_html
    except ImportError:
        return None, None, jsonify({'error': 'WeasyPrint non disponible'}), 500

    try:
        html_str = render_report_html(scan, raw_data, **kwargs)
        ctx = build_report_context(scan, raw_data, **kwargs)
        pdf_bytes = WeasyHTML(string=html_str).write_pdf()
    except Exception as e:
        return None, None, jsonify({'error': str(e)}), 500
    pdf_hash = hashlib.sha256(pdf_bytes).hexdigest()

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
    return pdf_hash, response, None
