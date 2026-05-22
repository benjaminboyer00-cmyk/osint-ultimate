"""Routes vues : Express, Expert, paramètres."""
import json
import os
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, current_app, abort
from flask_login import login_required, current_user

from extensions import db
from models import User, Scan, Entity, ScheduledScan
from services.target_detector import detect_target_type
from services.express_card import build_express_card

views_bp = Blueprint('views', __name__)


@views_bp.route('/')
def home():
    return redirect(url_for('views.express'))


@views_bp.route('/express')
def express():
    return render_template(
        'express.html',
        authenticated=current_user.is_authenticated,
        username=current_user.username if current_user.is_authenticated else None,
        version='5.0',
    )


@views_bp.route('/expert')
def expert():
    return render_template(
        'index.html',
        authenticated=current_user.is_authenticated,
        username=current_user.username if current_user.is_authenticated else None,
        version='5.0',
        expert_mode=True,
    )


@views_bp.route('/express/detect', methods=['POST'])
def express_detect():
    data = request.json or {}
    target = (data.get('target') or '').strip()
    if not target:
        return jsonify({'error': 'Cible manquante'}), 400
    from services.target_detector import target_category
    module = detect_target_type(target)
    return jsonify({
        'module': module,
        'target': target,
        'category': target_category(target),
    })


@views_bp.route('/express/card', methods=['POST'])
def express_card():
    data = request.json or {}
    module = data.get('module', 'pseudo')
    target = data.get('target', '')
    result = data.get('result', {})
    return jsonify(build_express_card(module, target, result))


@views_bp.route('/express/assist', methods=['POST'])
def express_assist():
    """Assistant IA pédagogique pour le mode Express."""
    from services.groq import chat_completion, fallback_explain
    from services.action_links import build_action_links

    data = request.json or {}
    card = data.get('card', {})
    result = data.get('result', {})
    module = data.get('module', '') or card.get('module', '')
    target = data.get('target', '') or card.get('target', '')
    prompt_ctx = json.dumps({'carte': card, 'donnees': result}, ensure_ascii=False)[:3500]
    system = (
        'Tu es un assistant OSINT pédagogique. Réponds en français simple, sans jargon. '
        'Structure : 1) Ce que signifient les résultats 2) Risques éventuels 3) Prochaines étapes. '
        'Termine par "ACTIONS:" puis une ligne par action avec → (ex: → Rechercher ce pseudo sur Sherlock).'
    )
    try:
        summary = chat_completion(
            f'Explique ces résultats de recherche OSINT:\n\n{prompt_ctx}',
            system=system,
        )
        from services.investigation_ai import parse_suggested_actions
        parts = summary.split('ACTIONS:')
        raw_actions = parse_suggested_actions(parts[1] if len(parts) > 1 else summary)
        action_links = build_action_links(raw_actions, module, target, card, result)
        return jsonify({
            'assistant': parts[0].strip(),
            'actions': [a['label'] for a in action_links],
            'action_links': action_links,
            'source': 'groq',
        })
    except Exception as e:
        current_app.logger.warning('Express assist Groq: %s', e)
        fallback = fallback_explain(card, result)
        raw = card.get('next_steps') or []
        action_links = build_action_links(raw, module, target, card, result)
        return jsonify({
            'assistant': fallback,
            'actions': [a['label'] for a in action_links],
            'action_links': action_links,
            'source': 'fallback',
            'warning': str(e),
        })


@views_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        keys = {
            'shodan': request.form.get('shodan', '').strip(),
            'hibp': request.form.get('hibp', '').strip(),
            'hunter': request.form.get('hunter', '').strip(),
            'dehashed': request.form.get('dehashed', '').strip(),
            'dehashed_email': request.form.get('dehashed_email', '').strip(),
            'epieos': request.form.get('epieos', '').strip(),
            'otx': request.form.get('otx', '').strip(),
            'numverify': request.form.get('numverify', '').strip(),
            'github': request.form.get('github', '').strip(),
        }
        keys = {k: v for k, v in keys.items() if v}
        from app import fernet
        current_user.set_api_keys(keys, fernet)
        current_user.proxy_list = request.form.get('proxy_list', '').strip() or None
        current_user.stealth_mode = request.form.get('stealth_mode') == 'on'
        current_user.scrape_fallback_enabled = request.form.get('scrape_fallback_enabled') == 'on'
        wh = request.form.get('webhook_url', '').strip()
        if wh:
            from models import Webhook
            existing = Webhook.query.filter_by(user_id=current_user.id).first()
            if existing:
                existing.url = wh
            else:
                db.session.add(Webhook(user_id=current_user.id, url=wh))
        db.session.commit()
        flash('Paramètres enregistrés (chiffrés).', 'success')
        return redirect(url_for('views.settings'))

    from app import fernet
    user_keys = current_user.get_api_keys(fernet)
    token = current_user.ensure_api_token()
    db.session.commit()
    from models import Webhook
    wh = Webhook.query.filter_by(user_id=current_user.id).first()
    from services.quota_monitor import check_all_for_user
    quotas = check_all_for_user(current_user, fernet)
    return render_template(
        'settings.html',
        user_keys=user_keys,
        api_token=token,
        username=current_user.username,
        proxy_list=current_user.proxy_list or '',
        stealth_mode=current_user.stealth_mode,
        scrape_fallback_enabled=getattr(current_user, 'scrape_fallback_enabled', True),
        webhook_url=wh.url if wh else '',
        quotas=quotas,
    )


@views_bp.route('/privacy')
def privacy():
    return render_template('privacy.html')


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


@views_bp.route('/expert/dossier/<int:entity_id>')
@login_required
def dossier(entity_id):
    from services.dossier import build_dossier
    d = build_dossier(entity_id, current_user.id)
    if not d:
        abort(404)
    return render_template('dossier.html', dossier=d, username=current_user.username)


@views_bp.route('/expert/dossier/<int:entity_id>/narrative', methods=['POST'])
@login_required
def dossier_narrative(entity_id):
    """Génère le rapport narratif IA (JSON)."""
    from services.narrative_report import build_narrative_for_entity
    body = request.json or {}
    style = body.get('style', 'executive')
    length = body.get('length', 'medium')
    use_cache = body.get('use_cache', True)
    try:
        out = build_narrative_for_entity(
            entity_id, current_user.id,
            style=style, length=length, cache_on_scan=use_cache,
        )
        return jsonify(out)
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@views_bp.route('/expert/dossier/<int:entity_id>/narrative/pdf', methods=['GET'])
@login_required
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
    entities = Entity.query.filter_by(user_id=current_user.id).order_by(Entity.created_at.desc()).limit(50).all()
    return render_template(
        'timeline.html',
        entity_id=entity_id,
        entities=entities,
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
    entities = Entity.query.filter_by(user_id=current_user.id).order_by(Entity.created_at.desc()).limit(50).all()
    return render_template(
        'map.html',
        entity_id=entity_id,
        entities=entities,
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
    except Exception:
        db.session.rollback()
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
    entities = Entity.query.filter_by(user_id=current_user.id).order_by(Entity.created_at.desc()).limit(50).all()
    return render_template(
        'graph.html',
        entity_id=entity_id,
        entities=entities,
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
        from services.dossier_access import get_dossier_context, resolve_dossier_root_for_entity
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

    scan_id = run_scan_async(module, value, options=opts, user_id=current_user.id)
    if not scan_id:
        return jsonify({'error': 'Échec du lancement du scan'}), 500
    return jsonify({
        'scan_id': scan_id,
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


@views_bp.route('/settings/token/regenerate', methods=['POST'])
@login_required
def regenerate_token():
    import secrets
    current_user.api_token = secrets.token_hex(32)
    db.session.commit()
    flash('Nouvelle clé API générée.', 'success')
    return redirect(url_for('views.settings'))


def _jobs_for_user(user_id: int):
    from services.monitoring import frequency_label
    from services.entity_resolve import find_entity_for_target
    jobs = ScheduledScan.query.filter_by(user_id=user_id)\
        .order_by(ScheduledScan.next_run_at.asc()).all()
    for j in jobs:
        j.frequency_label = frequency_label(j.interval_hours or 24)
        ent = find_entity_for_target(user_id, j.target, j.module)
        j.entity_id = ent.id if ent else None
    return jobs


@views_bp.route('/monitoring', methods=['GET', 'POST'])
@login_required
def monitoring_page():
    from services.monitoring import create_monitoring_job
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        module = request.form.get('module') or None
        frequency = request.form.get('frequency', 'daily')
        notify = request.form.get('notify_on_change') == 'on'
        from services.monitor_rules import rules_from_form
        alert_rules = rules_from_form(request.form)
        try:
            if target:
                create_monitoring_job(
                    current_user.id, target, module=module, frequency=frequency,
                    notify_on_change=notify,
                    alert_rules=alert_rules if notify else None,
                )
                flash('Surveillance activée.', 'success')
        except ValueError as e:
            flash(str(e), 'error')
        return redirect(url_for('views.monitoring_page'))

    from services.monitor_rules import RULE_LABELS, DEFAULT_RULES
    from services.notifications import list_alerts
    return render_template(
        'monitoring.html',
        jobs=_jobs_for_user(current_user.id),
        username=current_user.username,
        rule_labels=RULE_LABELS,
        default_rules=DEFAULT_RULES,
        recent_alerts=list_alerts(current_user.id, limit=30),
    )


@views_bp.route('/monitoring/quick', methods=['POST'])
@login_required
def monitoring_quick():
    """Création rapide depuis le mode Expert (après un scan)."""
    from services.monitoring import create_monitoring_job
    data = request.json or {}
    target = (data.get('target') or '').strip()
    module = data.get('module') or ''
    frequency = data.get('frequency', 'daily')
    if not target:
        return jsonify({'error': 'Cible manquante'}), 400
    try:
        from services.monitor_rules import parse_alert_rules
        job = create_monitoring_job(
            current_user.id, target, module=module or None, frequency=frequency,
            notify_on_change=bool(data.get('notify_on_change')),
            alert_rules=parse_alert_rules(data.get('alert_rules')),
        )
        return jsonify({
            'ok': True,
            'job_id': job.id,
            'message': f'Surveillance {job.target} programmée',
            'monitoring_url': url_for('views.monitoring_page'),
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@views_bp.route('/monitoring/<int:job_id>/toggle', methods=['POST'])
@login_required
def monitoring_toggle(job_id):
    job = db.session.get(ScheduledScan, job_id)
    if job and job.user_id == current_user.id:
        job.enabled = not job.enabled
        db.session.commit()
    return redirect(url_for('views.monitoring_page'))


@views_bp.route('/notifications')
@login_required
def notifications_list():
    from services.notifications import list_alerts, unread_count
    return jsonify({
        'unread': unread_count(current_user.id),
        'alerts': list_alerts(current_user.id, limit=80),
    })


@views_bp.route('/notifications/count')
@login_required
def notifications_count():
    from services.notifications import unread_count
    return jsonify({'unread': unread_count(current_user.id)})


@views_bp.route('/notifications/<int:alert_id>/read', methods=['POST'])
@login_required
def notifications_mark_read(alert_id):
    from services.notifications import mark_read, unread_count
    if not mark_read(current_user.id, alert_id):
        return jsonify({'error': 'Alerte non trouvée'}), 404
    return jsonify({'ok': True, 'unread': unread_count(current_user.id)})


@views_bp.route('/notifications/read-all', methods=['POST'])
@login_required
def notifications_mark_all_read():
    from services.notifications import mark_all_read
    n = mark_all_read(current_user.id)
    return jsonify({'ok': True, 'marked': n, 'unread': 0})


@views_bp.route('/monitoring/<int:job_id>/delete', methods=['POST'])
@login_required
def monitoring_delete(job_id):
    job = db.session.get(ScheduledScan, job_id)
    if job and job.user_id == current_user.id:
        db.session.delete(job)
        db.session.commit()
    return redirect(url_for('views.monitoring_page'))


@views_bp.route('/scheduled', methods=['GET', 'POST'])
@views_bp.route('/scheduled/', methods=['GET', 'POST'])
@login_required
def scheduled_page():
    """Ancienne URL — délègue à /monitoring."""
    return monitoring_page()


@views_bp.route('/scheduled/<int:job_id>/toggle', methods=['POST'])
@login_required
def scheduled_toggle(job_id):
    return monitoring_toggle(job_id)


@views_bp.route('/scheduled/<int:job_id>/delete', methods=['POST'])
@login_required
def scheduled_delete(job_id):
    return monitoring_delete(job_id)


@views_bp.route('/recipes')
def recipes_page():
    from services.recipes import list_recipes
    recipes = list_recipes(
        current_user.id if current_user.is_authenticated else None,
    )
    return render_template(
        'recipes.html',
        recipes=recipes,
        authenticated=current_user.is_authenticated,
        username=current_user.username if current_user.is_authenticated else None,
    )


@views_bp.route('/recipes/new', methods=['POST'])
@login_required
def recipes_create():
    from services.recipes import create_recipe
    data = request.json or request.form
    modules = data.get('modules')
    if isinstance(modules, str):
        import json as _json
        modules = _json.loads(modules)
    target_types = data.get('target_types')
    if isinstance(target_types, str):
        import json as _json
        target_types = _json.loads(target_types)
    try:
        create_recipe(current_user.id, {
            'name': data.get('name'),
            'description': data.get('description'),
            'modules': modules,
            'target_types': target_types,
            'is_public': data.get('is_public') in (True, 'true', 'on', '1'),
        })
        if request.is_json:
            return jsonify({'ok': True})
        flash('Recette créée.', 'success')
    except ValueError as e:
        if request.is_json:
            return jsonify({'error': str(e)}), 400
        flash(str(e), 'error')
    return redirect(url_for('views.recipes_page'))


@views_bp.route('/recipes/<recipe_ref>/run', methods=['POST'])
def recipes_run(recipe_ref):
    from services.recipes import launch_recipe
    data = request.json or {}
    target = (data.get('target') or request.form.get('target') or '').strip()
    mode = data.get('mode', 'expert')
    user_id = current_user.id if current_user.is_authenticated else None
    try:
        scan_id, recipe = launch_recipe(recipe_ref, target, user_id, mode=mode)
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'recipe': recipe.get('name'),
            'poll_url': f'/scan/{scan_id}',
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@views_bp.route('/recipes/<int:recipe_id>/delete', methods=['POST'])
@login_required
def recipes_delete(recipe_id):
    from services.recipes import delete_recipe
    delete_recipe(recipe_id, current_user.id)
    return redirect(url_for('views.recipes_page'))


@views_bp.route('/recipes/<recipe_ref>/fork', methods=['POST'])
@login_required
def recipes_fork(recipe_ref):
    from services.recipes import fork_recipe
    r = fork_recipe(recipe_ref, current_user.id)
    if not r:
        return jsonify({'error': 'Recette introuvable'}), 404
    if request.is_json:
        return jsonify({'ok': True, 'recipe_id': r.id})
    flash('Recette copiée dans votre bibliothèque.', 'success')
    return redirect(url_for('views.recipes_page'))


@views_bp.route('/marketplace')
def marketplace_page():
    from services.connector_catalog import get_catalog
    connectors = get_catalog(installed_only=False)
    return render_template(
        'marketplace.html',
        connectors=connectors,
        authenticated=current_user.is_authenticated,
        username=current_user.username if current_user.is_authenticated else None,
    )
