"""API REST v1 — auth token, corrélation, scans programmés."""
import json
from flask import Blueprint, request, jsonify, send_file, abort
from io import BytesIO
from datetime import datetime, timedelta

from extensions import db
from models import User, Scan, ScheduledScan
from services.target_detector import detect_target_type
from services.api_auth import require_api_key, resolve_api_user
from services.correlation import build_graph_json, build_entity_links_json

api_bp = Blueprint('api_v1', __name__)


@api_bp.route('/docs')
def openapi_docs():
    spec = {
        'openapi': '3.0.0',
        'info': {
            'title': 'OSINT Ultimate API',
            'version': '1.1.0',
            'description': 'API REST — authentification par X-API-Key ou Bearer token.',
        },
        'servers': [{'url': '/api/v1'}],
        'components': {
            'securitySchemes': {
                'ApiKeyAuth': {'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key'},
                'BearerAuth': {'type': 'http', 'scheme': 'bearer'},
            },
        },
        'security': [{'ApiKeyAuth': []}, {'BearerAuth': []}],
        'paths': {
            '/search': {'post': {'summary': 'Lancer une recherche', 'security': [{'ApiKeyAuth': []}]}},
            '/results/{scan_id}': {'get': {'summary': 'Récupérer un résultat'}},
            '/entity/{entity_id}/links': {'get': {'summary': 'Relations déduites (corrélation)'}},
            '/entity/{entity_id}/graph': {'get': {'summary': 'Graphe de corrélation'}},
            '/export/{scan_id}/pdf': {'get': {'summary': 'Exporter en PDF'}},
            '/scheduled': {'get': {'summary': 'Lister surveillances'}, 'post': {'summary': 'Créer surveillance'}},
            '/scheduled/{job_id}': {'delete': {'summary': 'Supprimer surveillance'}},
            '/me': {'get': {'summary': 'Profil API (vérifie le token)'}},
        },
    }
    return jsonify(spec)


@api_bp.route('/me')
@require_api_key
def api_me():
    u = request.api_user
    return jsonify({
        'user_id': u.id,
        'username': u.username,
        'email': u.email,
        'api_authenticated': True,
    })


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
    scan_id = run_scan_async(
        module, target, data.get('options', []),
        request.api_user.id, mode=mode,
    )
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
    return jsonify({
        'scan_id': scan_id, 'status': 'completed',
        'module': scan.module, 'target': scan.target, 'result': out,
    })


@api_bp.route('/entity/<int:entity_id>/links')
@require_api_key
def api_entity_links(entity_id):
    data = build_entity_links_json(entity_id, request.api_user.id)
    if not data:
        return jsonify({'error': 'entité non trouvée'}), 404
    return jsonify(data)


@api_bp.route('/entity/<int:entity_id>/graph')
@require_api_key
def api_graph(entity_id):
    g = build_graph_json(entity_id, request.api_user.id)
    if not g.get('nodes'):
        return jsonify({'error': 'entité non trouvée'}), 404
    links = build_entity_links_json(entity_id, request.api_user.id)
    g['links_detail'] = links.get('links', []) if links else []
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
            BytesIO(pdf_bytes), mimetype='application/pdf',
            as_attachment=True, download_name=f'osint_report_{scan_id}.pdf',
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/scheduled', methods=['GET', 'POST'])
@require_api_key
def api_scheduled():
    if request.method == 'GET':
        jobs = ScheduledScan.query.filter_by(user_id=request.api_user.id)\
            .order_by(ScheduledScan.next_run_at.asc()).all()
        return jsonify({'scheduled': [_job_json(j) for j in jobs]})

    data = request.json or {}
    target = (data.get('target') or '').strip()
    module = data.get('module') or detect_target_type(target)
    hours = int(data.get('interval_hours', 24))
    if not target:
        return jsonify({'error': 'target requis'}), 400
    if hours < 1 or hours > 168:
        return jsonify({'error': 'interval_hours entre 1 et 168'}), 400

    job = ScheduledScan(
        user_id=request.api_user.id,
        module=module,
        target=target,
        interval_hours=hours,
        enabled=True,
        next_run_at=datetime.utcnow(),
        notify_on_change=bool(data.get('notify_on_change', False)),
    )
    db.session.add(job)
    db.session.commit()
    return jsonify(_job_json(job)), 201


@api_bp.route('/scheduled/<int:job_id>', methods=['DELETE', 'PATCH'])
@require_api_key
def api_scheduled_one(job_id):
    job = db.session.get(ScheduledScan, job_id)
    if not job or job.user_id != request.api_user.id:
        return jsonify({'error': 'non trouvé'}), 404
    if request.method == 'DELETE':
        db.session.delete(job)
        db.session.commit()
        return jsonify({'deleted': job_id})
    data = request.json or {}
    if 'enabled' in data:
        job.enabled = bool(data['enabled'])
    if 'interval_hours' in data:
        job.interval_hours = max(1, min(168, int(data['interval_hours'])))
    db.session.commit()
    return jsonify(_job_json(job))


def _job_json(job: ScheduledScan) -> dict:
    return {
        'id': job.id,
        'module': job.module,
        'target': job.target,
        'interval_hours': job.interval_hours,
        'enabled': job.enabled,
        'last_run_at': job.last_run_at.isoformat() if job.last_run_at else None,
        'next_run_at': job.next_run_at.isoformat() if job.next_run_at else None,
        'last_scan_id': job.last_scan_id,
    }
