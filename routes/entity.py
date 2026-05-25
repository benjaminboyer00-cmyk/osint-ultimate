"""Dossiers, graphe, carte, timeline, enquête."""
import json as _json
from flask import render_template, request, jsonify, redirect, url_for, flash, current_app, abort
from flask_login import login_required, current_user

from routes.views_bp import views_bp, entities_paginated as _entities_paginated
from extensions import db, limiter
from models import Entity, Investigation
from services.target_detector import detect_target_type

@views_bp.route('/expert/dossier/<int:entity_id>')
@login_required
def dossier(entity_id):
    from services.dossier import build_dossier
    d = build_dossier(entity_id, current_user.id)
    if not d:
        abort(404)
    return render_template('dossier.html', dossier=d, username=current_user.username)


@views_bp.route('/expert/dossier/<int:entity_id>/scan', methods=['POST'])
@login_required
@limiter.limit('25/minute')
def dossier_launch_scan(entity_id):
    """Lance un scan rattaché au dossier (suggestions, rebonds)."""
    from app import run_scan_async, SCAN_FUNCTIONS
    from services.dossier_access import get_dossier_context

    ctx = get_dossier_context(entity_id, current_user.id, min_role='editor')
    if not ctx:
        return jsonify({'error': 'Droits insuffisants (éditeur requis)'}), 403
    data = request.json or {}
    module = (data.get('module') or '').strip()
    target = (data.get('target') or '').strip()
    if not target:
        return jsonify({'error': 'Cible manquante'}), 400
    if not module:
        module = detect_target_type(target)
    if module not in SCAN_FUNCTIONS:
        return jsonify({'error': f'Module inconnu: {module}'}), 400
    opts = {
        '_root_entity_id': entity_id,
        '_app': current_app._get_current_object(),
    }
    if data.get('stealth'):
        opts['_stealth_mode'] = True
    from services.scan_poll import ensure_poll_token
    poll_token = ensure_poll_token(opts)
    scan_id = run_scan_async(module, target, opts, user_id=current_user.id, mode='expert')
    if not scan_id:
        return jsonify({'error': 'Échec du lancement'}), 500
    return jsonify({
        'scan_id': scan_id,
        'poll_token': poll_token,
        'status': 'started',
        'module': module,
        'target': target,
        'poll_url': f'/scan/{scan_id}',
    })


@views_bp.route('/expert/dossier/<int:entity_id>/narrative', methods=['POST'])
@login_required
@limiter.limit('15/minute')
def dossier_narrative(entity_id):
    """Génère le rapport narratif IA (JSON) — ne renvoie jamais de page HTML 500."""
    from services.dossier_access import get_dossier_context
    from services.dossier_scans import link_scans_to_dossier
    from services.narrative_api import flask_narrative_response

    ctx = get_dossier_context(entity_id, current_user.id, min_role='reader')
    if not ctx:
        return jsonify({'error': 'Dossier non accessible', 'entity_id': entity_id}), 403
    try:
        link_scans_to_dossier(entity_id, ctx['owner_user_id'])
    except Exception as e:
        current_app.logger.warning('link_scans narrative entity=%s: %s', entity_id, e)

    body = request.get_json(silent=True) or {}
    style = body.get('style') or 'executive'
    length = body.get('length') or 'medium'
    use_cache = body.get('use_cache', True) is not False
    if body.get('async') is True or request.args.get('async') == '1':
        from app import socketio
        from services.async_tasks import enqueue_narrative
        task_id = enqueue_narrative(
            entity_id, current_user.id,
            current_app._get_current_object(), socketio=socketio,
            style=style, length=length, use_cache=use_cache,
        )
        return jsonify({
            'task_id': task_id,
            'status': 'pending',
            'entity_id': entity_id,
            'poll_url': f'/expert/dossier/{entity_id}/narrative/status/{task_id}',
        }), 202
    try:
        return flask_narrative_response(
            entity_id,
            current_user.id,
            style=style,
            length=length,
            use_cache=use_cache,
        )
    except Exception as e:
        current_app.logger.exception('narrative route entity=%s', entity_id)
        from services.narrative_report import FALLBACK_NARRATIVE_MD, markdown_to_html
        return jsonify({
            'error': str(e),
            'entity_id': entity_id,
            'markdown': FALLBACK_NARRATIVE_MD,
            'html': markdown_to_html(FALLBACK_NARRATIVE_MD),
            'partial': True,
        }), 200


@views_bp.route('/expert/dossier/<int:entity_id>/narrative/status/<task_id>')
@login_required
def dossier_narrative_status(entity_id, task_id):
    """Statut tâche narratif asynchrone."""
    from services.async_tasks import get_job

    job = get_job(task_id)
    if not job:
        return jsonify({'error': 'Tâche introuvable', 'task_id': task_id}), 404
    if job.get('entity_id') and int(job.get('entity_id')) != entity_id:
        return jsonify({'error': 'Tâche non associée à ce dossier'}), 403
    status = job.get('status', 'unknown')
    if status in ('pending', 'running'):
        return jsonify({'task_id': task_id, 'status': status, 'entity_id': entity_id}), 202
    if status == 'failed':
        return jsonify({
            'task_id': task_id, 'status': 'failed',
            'error': job.get('error', 'Échec'),
            'entity_id': entity_id,
        }), 200
    result = job.get('result') or {}
    return jsonify({
        'task_id': task_id,
        'status': 'completed',
        'entity_id': entity_id,
        'markdown': result.get('markdown'),
        'html': result.get('html'),
        'cached': result.get('cached', job.get('cached')),
        'partial': result.get('partial'),
        'groq_error': result.get('groq_error'),
        'dossier_title': result.get('dossier_title'),
    }), 200


@views_bp.route('/expert/dossier/<int:entity_id>/suggestions')
@login_required
def dossier_suggestions(entity_id):
    """Modules OSINT suggérés pour enrichir le dossier."""
    from services.dossier_access import get_dossier_context
    from services.osint_suggestions import suggest_investigation_steps

    ctx = get_dossier_context(entity_id, current_user.id, min_role='reader')
    if not ctx:
        return jsonify({'error': 'Accès refusé'}), 403
    steps = suggest_investigation_steps(entity_id, current_user.id)
    return jsonify({'entity_id': entity_id, 'suggestions': steps})


@views_bp.route('/expert/dossier/<int:entity_id>/narrative/pdf', methods=['GET'])
@login_required
@limiter.limit('10/minute')
def dossier_narrative_pdf(entity_id):
    """PDF professionnel avec section rapport narratif IA."""
    from services.narrative_report import narrative_pdf_context
    from services.report_export import generate_pdf_response
    style = request.args.get('style', 'executive')
    length = request.args.get('length', 'medium')
    try:
        scan, raw, nar_html, nar_md = narrative_pdf_context(
            entity_id, current_user.id,
            style=style, length=length,
        )
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        current_app.logger.exception('narrative PDF entity=%s', entity_id)
        return jsonify({'error': f'Échec génération PDF : {e}'}), 500
    graph_image = request.args.get('graph', '')
    try:
        _, response, err = generate_pdf_response(
            scan, raw,
            investigator=current_user.username,
            classification=request.args.get('classification', 'CONFIDENTIEL'),
            graph_image=graph_image or None,
            narrative_html=nar_html,
            narrative_markdown=nar_md,
        )
    except Exception as e:
        current_app.logger.exception('WeasyPrint narrative PDF')
        return jsonify({'error': f'Export PDF : {e}'}), 500
    if err:
        return err
    return response


@views_bp.route('/expert/dossier/<int:entity_id>/add-entity', methods=['POST'])
@login_required
def dossier_add_entity(entity_id):
    from app import run_scan_async
    from services.dossier_access import get_dossier_context
    ctx = get_dossier_context(entity_id, current_user.id, min_role='editor')
    if not ctx:
        abort(403)
    target = request.form.get('target', '').strip()
    module = request.form.get('module') or detect_target_type(target)
    if target:
        run_scan_async(
            module, target,
            options={'_root_entity_id': entity_id, '_app': current_app._get_current_object()},
            user_id=current_user.id,
        )
        flash(f'Scan {module} lancé pour {target}', 'success')
    return redirect(url_for('views.dossier', entity_id=entity_id))


@views_bp.route('/investigate')
@login_required
def investigate_page():
    """Enquête guidée — agent IA chef d'orchestre."""
    from models import Investigation
    recent = Investigation.query.filter_by(user_id=current_user.id)\
        .order_by(Investigation.created_at.desc()).limit(10).all()
    return render_template(
        'investigate.html',
        username=current_user.username,
        recent_investigations=recent,
    )


@views_bp.route('/investigate/start', methods=['POST'])
@login_required
def investigate_start():
    from app import app, socketio, fernet
    from services.investigation_agent import start_investigation
    data = request.json or {}
    query = (data.get('query') or data.get('objective') or '').strip()
    if not query:
        return jsonify({'error': 'Objectif manquant'}), 400
    inv_id = start_investigation(current_user.id, query, app, socketio, fernet)
    return jsonify({
        'investigation_id': inv_id,
        'status': 'started',
        'message': 'Enquête lancée — suivez la progression en direct.',
    })


@views_bp.route('/investigate/<int:inv_id>/status')
@login_required
def investigate_status(inv_id):
    from models import Investigation
    import json as _json
    inv = Investigation.query.filter_by(id=inv_id, user_id=current_user.id).first()
    if not inv:
        return jsonify({'error': 'Enquête introuvable'}), 404
    steps = []
    if inv.steps_json:
        try:
            steps = _json.loads(inv.steps_json)
        except Exception:
            pass
    return jsonify({
        'id': inv.id,
        'status': inv.status,
        'objective': inv.objective,
        'summary': inv.result_summary,
        'steps': steps,
        'root_entity_id': inv.root_entity_id,
        'graph_url': url_for('views.graph_view', entity_id=inv.root_entity_id) if inv.root_entity_id else None,
    })


@views_bp.route('/graph/suggestions/<int:entity_id>')
@login_required
def graph_suggestions(entity_id):
    from services.graph_enquiry import suggest_next_node
    from services.dossier_access import get_dossier_context
    ctx = get_dossier_context(entity_id, current_user.id, min_role='reader')
    if not ctx:
        return jsonify({'error': 'Accès refusé'}), 403
    s = suggest_next_node(entity_id, ctx['owner_user_id'])
    if not s:
        return jsonify({'error': 'Aucune suggestion'}), 404
    return jsonify(s)




@views_bp.route('/timeline')
@login_required
def timeline_view():
    from services.entity_resolve import find_entity_for_target
    entity_id = request.args.get('entity_id', type=int)
    target_q = (request.args.get('target') or '').strip()
    if not entity_id and target_q:
        ent = find_entity_for_target(current_user.id, target_q)
        if ent:
            entity_id = ent.id
    page = request.args.get('page', 1, type=int)
    ent_page = _entities_paginated(current_user.id, page=page)
    return render_template(
        'timeline.html',
        entity_id=entity_id,
        entities=ent_page['items'],
        entities_page=ent_page,
        username=current_user.username,
    )


@views_bp.route('/timeline/data/<int:entity_id>')
@login_required
def timeline_data(entity_id):
    from services.timeline import build_timeline
    from services.dossier_access import get_dossier_context
    ctx = get_dossier_context(entity_id, current_user.id, min_role='reader')
    if not ctx:
        return jsonify({'error': 'Accès refusé'}), 403
    data = build_timeline(entity_id, ctx['owner_user_id'])
    if not data:
        return jsonify({'error': 'Entité non trouvée'}), 404
    return jsonify(data)


@views_bp.route('/map')
@login_required
def map_view():
    from services.entity_resolve import find_entity_for_target
    entity_id = request.args.get('entity_id', type=int)
    target_q = (request.args.get('target') or '').strip()
    if not entity_id and target_q:
        ent = find_entity_for_target(current_user.id, target_q)
        if ent:
            entity_id = ent.id
    page = request.args.get('page', 1, type=int)
    ent_page = _entities_paginated(current_user.id, page=page)
    return render_template(
        'map.html',
        entity_id=entity_id,
        entities=ent_page['items'],
        entities_page=ent_page,
        username=current_user.username,
    )


@views_bp.route('/map/data/<int:entity_id>')
@login_required
def map_data(entity_id):
    from services.geo import build_map_markers
    from services.dossier_access import get_dossier_context
    ctx = get_dossier_context(entity_id, current_user.id, min_role='reader')
    if not ctx:
        return jsonify({'error': 'Accès refusé'}), 403
    geocode_off = request.args.get('geocode', '').lower() in ('0', 'false', 'no')
    data = build_map_markers(
        entity_id, ctx['owner_user_id'],
        geocode_missing=not geocode_off,
        max_geocode_calls=15,
        hydrate_from_scans=True,
    )
    if data.get('root_entity_id') is None:
        return jsonify({'error': 'Entité non trouvée'}), 404
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error('Erreur commit map_data entity=%s: %s', entity_id, e)
    return jsonify(data)


@views_bp.route('/graph')
@login_required
def graph_view():
    from services.entity_resolve import find_entity_for_target
    entity_id = request.args.get('entity_id', type=int)
    target_q = (request.args.get('target') or '').strip()
    if not entity_id and target_q:
        ent = find_entity_for_target(current_user.id, target_q)
        if ent:
            entity_id = ent.id
    page = request.args.get('page', 1, type=int)
    ent_page = _entities_paginated(current_user.id, page=page)
    return render_template(
        'graph.html',
        entity_id=entity_id,
        entities=ent_page['items'],
        entities_page=ent_page,
        username=current_user.username,
        graph_hint='historique surveillance' if target_q and entity_id else None,
        target_query=target_q,
    )


@views_bp.route('/graph/data/<int:entity_id>')
@login_required
def graph_data(entity_id):
    from services.correlation import build_graph_json, build_entity_links_json
    from services.dossier_access import get_dossier_context
    ctx = get_dossier_context(entity_id, current_user.id, min_role='reader')
    if not ctx:
        return jsonify({'error': 'Accès refusé'}), 403
    g = build_graph_json(entity_id, ctx['owner_user_id'])
    if not g.get('nodes'):
        return jsonify({'error': 'Entité non trouvée'}), 404
    links = build_entity_links_json(entity_id, ctx['owner_user_id'])
    if links:
        g['links_detail'] = links.get('links', [])
        g['entity'] = links.get('entity')
    return jsonify(g)


@views_bp.route('/graph/pivot', methods=['POST'])
@login_required
def graph_pivot():
    """Pivot : scan multi-modules depuis un nœud du graphe."""
    from services.graph_pivot import launch_pivot
    data = request.json or {}
    entity_id = data.get('entity_id')
    if not entity_id:
        return jsonify({'error': 'entity_id requis'}), 400
    try:
        out = launch_pivot(
            current_user.id,
            int(entity_id),
            root_entity_id=data.get('root_entity_id'),
            deep_dorking=bool(data.get('deep_dorking')),
            stealth=bool(data.get('stealth')),
        )
        return jsonify(out)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@views_bp.route('/graph/scan-node', methods=['POST'])
@login_required
def graph_scan_node():
    """Lance un scan depuis un nœud du graphe."""
    from app import run_scan_async, SCAN_FUNCTIONS
    from services.target_detector import detect_target_type
    data = request.json or {}
    entity_id = data.get('entity_id')
    value = (data.get('value') or '').strip()
    etype = data.get('entity_type', '')
    if entity_id:
        from services.dossier_access import get_dossier_context
        from services.collaboration import resolve_dossier_root_for_entity
        ent = db.session.get(Entity, entity_id)
        if not ent:
            return jsonify({'error': 'Entité non trouvée'}), 404
        root_id = data.get('root_entity_id') or resolve_dossier_root_for_entity(entity_id, current_user.id)
        if root_id and not get_dossier_context(int(root_id), current_user.id, min_role='editor'):
            return jsonify({'error': 'Accès refusé'}), 403
        value = ent.value
        etype = ent.entity_type
    if not value:
        return jsonify({'error': 'Valeur manquante'}), 400
    module_map = {
        'email': 'email', 'phone': 'phone', 'username': 'sherlock',
        'domain': 'site', 'platform': 'sherlock', 'ip': 'ip', 'unknown': 'site',
    }
    module = module_map.get(etype) or detect_target_type(value)
    if module not in SCAN_FUNCTIONS:
        module = detect_target_type(value)
    if module not in SCAN_FUNCTIONS:
        return jsonify({'error': f'Aucun module pour le type {etype}'}), 400

    root_entity_id = data.get('root_entity_id')
    opts = {'_graph_pivot_notify': str(current_user.id)}
    if etype == 'domain' and module == 'site':
        module = 'whois'
    opts['_app'] = current_app._get_current_object()
    if root_entity_id:
        from services.dossier_access import get_dossier_context
        if not get_dossier_context(int(root_entity_id), current_user.id, min_role='editor'):
            return jsonify({'error': 'Droits insuffisants pour scanner ce dossier'}), 403
        opts['_root_entity_id'] = int(root_entity_id)

    from services.scan_poll import ensure_poll_token
    poll_token = ensure_poll_token(opts)
    scan_id = run_scan_async(module, value, options=opts, user_id=current_user.id)
    if not scan_id:
        return jsonify({'error': 'Échec du lancement du scan'}), 500
    return jsonify({
        'scan_id': scan_id,
        'poll_token': poll_token,
        'module': module,
        'target': value,
        'status': 'started',
        'poll_url': f'/scan/{scan_id}',
    })


@views_bp.route('/graph/entity/<int:entity_id>/intel')
@login_required
def graph_entity_intel(entity_id):
    from services.graph_entity_intel import build_entity_intel
    ent = Entity.query.filter_by(id=entity_id, user_id=current_user.id).first()
    if not ent:
        return jsonify({'error': 'Entité non trouvée'}), 404
    return jsonify(build_entity_intel(ent.id, current_user.id, ent.value, ent.entity_type))


@views_bp.route('/graph/links/<int:entity_id>')
@login_required
def graph_links(entity_id):
    from services.correlation import build_entity_links_json
    data = build_entity_links_json(entity_id, current_user.id)
    if not data:
        return jsonify({'error': 'Entité non trouvée'}), 404
    return jsonify(data)

