"""API REST v1 — auth token, corrélation, scans programmés."""
import json
from flask import Blueprint, request, jsonify, send_file, abort
from io import BytesIO
from datetime import datetime, timedelta

from extensions import db, limiter
from models import User, Scan, ScheduledScan, Investigation
from services.target_detector import detect_target_type
from services.api_auth import require_api_key
from services.correlation import get_rebound_suggestions
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
            '/entity/{entity_id}/links': {'get': {'summary': 'Relations déduites'}},
            '/entity/{entity_id}/rebound': {'get': {'summary': 'Scans suggérés'}},
            '/entity/{entity_id}/graph': {'get': {'summary': 'Graphe de corrélation'}},
            '/export/{scan_id}/csv': {'get': {'summary': 'Export CSV'}},
            '/webhooks': {'get': {'summary': 'Webhooks'}, 'post': {'summary': 'Ajouter webhook'}},
            '/examples': {'get': {'summary': 'Exemples curl'}},
            '/export/{scan_id}/pdf': {'get': {'summary': 'Exporter en PDF'}},
            '/scheduled': {'get': {'summary': 'Lister surveillances'}, 'post': {'summary': 'Créer surveillance'}},
            '/scheduled/{job_id}': {'delete': {'summary': 'Supprimer surveillance'}},
            '/me': {'get': {'summary': 'Profil API (vérifie le token)'}},
            '/investigate': {'post': {'summary': 'Lancer enquête guidée IA'}},
            '/investigate/{inv_id}': {'get': {'summary': 'Statut enquête'}},
            '/entity/{entity_id}/suggestions': {'get': {'summary': 'Prochain nœud (mode enquête)'}},
        },
    }
    return jsonify(spec)


@api_bp.route('/investigate', methods=['POST'])
@require_api_key
@limiter.limit('10/minute')
def api_investigate_start():
    from app import app, socketio, fernet
    from services.investigation_agent import start_investigation
    data = request.json or {}
    query = (data.get('query') or data.get('objective') or '').strip()
    if not query:
        return jsonify({'error': 'query requis'}), 400
    inv_id = start_investigation(request.api_user.id, query, app, socketio, fernet)
    return jsonify({'investigation_id': inv_id, 'status': 'started'})


@api_bp.route('/investigate/<int:inv_id>')
@require_api_key
def api_investigate_status(inv_id):
    inv = Investigation.query.filter_by(id=inv_id, user_id=request.api_user.id).first()
    if not inv:
        return jsonify({'error': 'not found'}), 404
    steps = json.loads(inv.steps_json or '[]') if inv.steps_json else []
    return jsonify({
        'id': inv.id,
        'status': inv.status,
        'objective': inv.objective,
        'summary': inv.result_summary,
        'steps': steps,
        'root_entity_id': inv.root_entity_id,
    })


@api_bp.route('/entity/<int:entity_id>/suggestions')
@require_api_key
def api_entity_suggestions(entity_id):
    from services.graph_enquiry import suggest_next_node
    s = suggest_next_node(entity_id, request.api_user.id)
    if not s:
        return jsonify({'error': 'no suggestion'}), 404
    return jsonify(s)


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
@limiter.limit('30/minute')
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


@api_bp.route('/entity/<int:entity_id>/timeline')
@require_api_key
def api_entity_timeline(entity_id):
    from services.timeline import build_timeline
    data = build_timeline(entity_id, request.api_user.id)
    if not data:
        return jsonify({'error': 'entité non trouvée'}), 404
    return jsonify(data)


@api_bp.route('/entity/<int:entity_id>/map')
@require_api_key
def api_entity_map(entity_id):
    from services.geo import build_map_markers
    from extensions import db
    data = build_map_markers(entity_id, request.api_user.id)
    if data.get('root_entity_id') is None:
        return jsonify({'error': 'entité non trouvée'}), 404
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
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


@api_bp.route('/graph/pivot', methods=['POST'])
@require_api_key
@limiter.limit('15/minute')
def api_graph_pivot():
    """Pivot OSINT multi-modules depuis une entité du graphe."""
    from services.graph_pivot import launch_pivot
    data = request.json or {}
    entity_id = data.get('entity_id')
    if not entity_id:
        return jsonify({'error': 'entity_id requis'}), 400
    try:
        out = launch_pivot(
            request.api_user.id,
            int(entity_id),
            root_entity_id=data.get('root_entity_id'),
            deep_dorking=bool(data.get('deep_dorking')),
            stealth=bool(data.get('stealth')),
        )
        return jsonify(out), 202
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@api_bp.route('/export/<int:scan_id>/pdf')
@require_api_key
@limiter.limit('10/minute')
def api_export_pdf(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != request.api_user.id:
        abort(404)
    raw_data = json.loads(scan.result_json or '{}')
    from services.report_export import generate_pdf_response
    from services.narrative_report import narrative_pdf_context

    nar_html = ''
    nar_md = ''
    try:
        if scan.root_entity_id:
            _, _, nar_html, nar_md = narrative_pdf_context(
                scan.root_entity_id, request.api_user.id,
            )
    except Exception:
        pass

    _, response, err = generate_pdf_response(
        scan, raw_data,
        narrative_html=nar_html,
        narrative_markdown=nar_md,
        investigator=request.api_user.username,
        classification=request.args.get('classification', 'CONFIDENTIEL'),
    )
    if err:
        return err
    return response


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

    from services.monitor_rules import parse_alert_rules, serialize_rules, DEFAULT_RULES
    notify = bool(data.get('notify_on_change', False))
    job = ScheduledScan(
        user_id=request.api_user.id,
        module=module,
        target=target,
        interval_hours=hours,
        enabled=True,
        next_run_at=datetime.utcnow(),
        notify_on_change=notify,
        alert_rules_json=serialize_rules(parse_alert_rules(data.get('alert_rules'))) if notify else None,
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


@api_bp.route('/entity/<int:entity_id>/rebound')
@require_api_key
def api_rebound(entity_id):
    suggestions = get_rebound_suggestions(entity_id, request.api_user.id)
    return jsonify({'entity_id': entity_id, 'suggestions': suggestions})


@api_bp.route('/export/<int:scan_id>/csv')
@require_api_key
def api_export_csv(scan_id):
    import csv
    scan = db.session.get(Scan, scan_id)
    if not scan or scan.user_id != request.api_user.id:
        return jsonify({'error': 'non trouvé'}), 404
    data = json.loads(scan.result_json or '{}')
    buf = BytesIO()
    w = csv.writer(buf)
    w.writerow(['section', 'key', 'value'])
    for section, content in data.items():
        if isinstance(content, dict):
            for k, v in content.items():
                w.writerow([section, k, str(v)[:500]])
        else:
            w.writerow([section, '', str(content)[:500]])
    buf.seek(0)
    return send_file(buf, mimetype='text/csv', as_attachment=True,
                     download_name=f'osint_{scan_id}.csv')


@api_bp.route('/webhooks', methods=['GET', 'POST'])
@require_api_key
def api_webhooks():
    from models import Webhook
    if request.method == 'GET':
        hooks = Webhook.query.filter_by(user_id=request.api_user.id).all()
        return jsonify({'webhooks': [{'id': h.id, 'url': h.url, 'enabled': h.enabled} for h in hooks]})
    url = (request.json or {}).get('url', '').strip()
    if not url.startswith('http'):
        return jsonify({'error': 'url HTTP(S) requise'}), 400
    h = Webhook(user_id=request.api_user.id, url=url)
    db.session.add(h)
    db.session.commit()
    return jsonify({'id': h.id, 'url': h.url}), 201


@api_bp.route('/recipes', methods=['GET', 'POST'])
@require_api_key
def api_recipes():
    from services.recipes import list_recipes, create_recipe, _recipe_to_dict
    if request.method == 'GET':
        return jsonify({'recipes': list_recipes(request.api_user.id)})
    data = request.json or {}
    try:
        r = create_recipe(request.api_user.id, data)
        return jsonify(_recipe_to_dict(r, request.api_user.username)), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@api_bp.route('/recipes/<recipe_ref>', methods=['GET', 'DELETE'])
@require_api_key
def api_recipe_detail(recipe_ref):
    from services.recipes import get_recipe, delete_recipe, _recipe_to_dict
    if request.method == 'DELETE':
        if str(recipe_ref).startswith('builtin-'):
            return jsonify({'error': 'Recette système non supprimable'}), 400
        if delete_recipe(int(recipe_ref), request.api_user.id):
            return jsonify({'ok': True})
        return jsonify({'error': 'Non trouvé'}), 404
    r = get_recipe(recipe_ref, request.api_user.id)
    if not r:
        return jsonify({'error': 'Non trouvé'}), 404
    return jsonify(r)


@api_bp.route('/recipes/<recipe_ref>/run', methods=['POST'])
@require_api_key
def api_recipe_run(recipe_ref):
    from services.recipes import launch_recipe
    data = request.json or {}
    target = (data.get('target') or '').strip()
    try:
        scan_id, recipe = launch_recipe(
            recipe_ref, target, request.api_user.id, mode=data.get('mode', 'expert'),
        )
        return jsonify({'scan_id': scan_id, 'status': 'started', 'recipe': recipe.get('name')})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@api_bp.route('/connectors')
def api_connectors():
    from services.connector_catalog import get_catalog
    return jsonify({'connectors': get_catalog(installed_only=False)})


@api_bp.route('/examples')
def api_examples():
    base = request.host_url.rstrip('/') + '/api/v1'
    return jsonify({
        'examples': [
            {'desc': 'Vérifier token', 'curl': f'curl -H "X-API-Key: TOKEN" {base}/me'},
            {'desc': 'Lancer scan', 'curl': f'curl -X POST -H "X-API-Key: TOKEN" -H "Content-Type: application/json" -d \'{{"target":"example.com","module":"whois"}}\' {base}/search'},
            {'desc': 'Résultat', 'curl': f'curl -H "X-API-Key: TOKEN" {base}/results/1'},
            {'desc': 'Liens entité', 'curl': f'curl -H "X-API-Key: TOKEN" {base}/entity/1/links'},
            {'desc': 'PDF', 'curl': f'curl -H "X-API-Key: TOKEN" -o report.pdf {base}/export/1/pdf'},
        ],
    })


@api_bp.route('/notifications')
@require_api_key
def api_notifications():
    from services.notifications import list_alerts, unread_count
    return jsonify({
        'unread': unread_count(request.api_user.id),
        'alerts': list_alerts(request.api_user.id, limit=50),
    })


def _job_json(job: ScheduledScan) -> dict:
    import json as _json
    rules = []
    if job.alert_rules_json:
        try:
            rules = _json.loads(job.alert_rules_json)
        except Exception:
            pass
    return {
        'id': job.id,
        'module': job.module,
        'target': job.target,
        'interval_hours': job.interval_hours,
        'enabled': job.enabled,
        'notify_on_change': job.notify_on_change,
        'alert_rules': rules,
        'last_run_at': job.last_run_at.isoformat() if job.last_run_at else None,
        'next_run_at': job.next_run_at.isoformat() if job.next_run_at else None,
        'last_scan_id': job.last_scan_id,
    }
