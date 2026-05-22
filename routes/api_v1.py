"""API REST v1 — documentation OpenAPI."""
import json
from functools import wraps
from flask import Blueprint, request, jsonify, send_file, abort
from flask_login import current_user
from io import BytesIO

from extensions import db
from models import User, Scan
from services.target_detector import detect_target_type

api_bp = Blueprint('api_v1', __name__)


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not key:
            return jsonify({'error': 'Header X-API-Key requis'}), 401
        user = User.query.filter_by(api_token=key).first()
        if not user:
            return jsonify({'error': 'Clé API invalide'}), 403
        request.api_user = user
        return f(*args, **kwargs)
    return decorated


@api_bp.route('/docs')
def openapi_docs():
    spec = {
        'openapi': '3.0.0',
        'info': {
            'title': 'OSINT Ultimate API',
            'version': '1.0.0',
            'description': 'API REST pour lancer des investigations OSINT.',
        },
        'servers': [{'url': '/api/v1'}],
        'paths': {
            '/search': {
                'post': {
                    'summary': 'Lancer une recherche',
                    'parameters': [{'name': 'X-API-Key', 'in': 'header', 'required': True}],
                    'requestBody': {
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'target': {'type': 'string'},
                                        'module': {'type': 'string'},
                                        'mode': {'type': 'string', 'enum': ['express', 'expert']},
                                    },
                                },
                            },
                        },
                    },
                },
            },
            '/results/{scan_id}': {'get': {'summary': 'Récupérer un résultat'}},
            '/entity/{entity_id}/graph': {'get': {'summary': 'Graphe de corrélation'}},
            '/export/{scan_id}/pdf': {'get': {'summary': 'Exporter en PDF'}},
        },
    }
    return jsonify(spec)


@api_bp.route('/search', methods=['POST'])
@require_api_key
def api_search():
    from app import run_scan_async, SCAN_FUNCTIONS
    data = request.json or {}
    target = (data.get('target') or '').strip()
    module = data.get('module') or detect_target_type(target)
    mode = data.get('mode', 'expert')
    if not target:
        return jsonify({'error': 'target requis'}), 400
    if module not in SCAN_FUNCTIONS:
        return jsonify({'error': f'module inconnu: {module}'}), 400
    scan_id = run_scan_async(module, target, data.get('options', []), request.api_user.id, mode=mode)
    if not scan_id:
        return jsonify({'error': 'échec lancement'}), 500
    return jsonify({'scan_id': scan_id, 'status': 'started', 'module': module}), 202


@api_bp.route('/results/<int:scan_id>')
@require_api_key
def api_results(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != request.api_user.id:
        return jsonify({'error': 'non trouvé'}), 404
    if scan.status != 'completed':
        return jsonify({'scan_id': scan_id, 'status': scan.status})
    out = json.loads(scan.result_json or '{}')
    if scan.ai_summary:
        out['_ai_summary'] = scan.ai_summary
    return jsonify({'scan_id': scan_id, 'status': 'completed', 'module': scan.module, 'target': scan.target, 'result': out})


@api_bp.route('/entity/<int:entity_id>/graph')
@require_api_key
def api_graph(entity_id):
    from services.correlation import build_graph_json
    g = build_graph_json(entity_id, request.api_user.id)
    if not g.get('nodes'):
        return jsonify({'error': 'entité non trouvée'}), 404
    return jsonify(g)


@api_bp.route('/export/<int:scan_id>/pdf')
@require_api_key
def api_export_pdf(scan_id):
    from flask import render_template
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != request.api_user.id:
        abort(404)
    try:
        from weasyprint import HTML as WeasyHTML
        data = json.loads(scan.result_json or '{}')
        html_str = render_template('report.html', scan=scan, data=data, ai_summary=scan.ai_summary)
        pdf_bytes = WeasyHTML(string=html_str).write_pdf()
        return send_file(
            BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'osint_report_{scan_id}.pdf',
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500
