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
    module = detect_target_type(target)
    return jsonify({'module': module, 'target': target})


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
            'numverify': request.form.get('numverify', '').strip(),
            'github': request.form.get('github', '').strip(),
        }
        keys = {k: v for k, v in keys.items() if v}
        from app import fernet
        current_user.set_api_keys(keys, fernet)
        current_user.proxy_list = request.form.get('proxy_list', '').strip() or None
        current_user.stealth_mode = request.form.get('stealth_mode') == 'on'
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
        webhook_url=wh.url if wh else '',
        quotas=quotas,
    )


@views_bp.route('/privacy')
def privacy():
    return render_template('privacy.html')


@views_bp.route('/expert/dossier/<int:entity_id>')
@login_required
def dossier(entity_id):
    from services.dossier import build_dossier
    from services.correlation import get_rebound_suggestions
    d = build_dossier(entity_id, current_user.id)
    if not d:
        abort(404)
    d['rebound_suggestions'] = get_rebound_suggestions(entity_id, current_user.id)
    return render_template('dossier.html', dossier=d, username=current_user.username)


@views_bp.route('/expert/dossier/<int:entity_id>/add-entity', methods=['POST'])
@login_required
def dossier_add_entity(entity_id):
    from app import run_scan_async
    target = request.form.get('target', '').strip()
    module = request.form.get('module') or detect_target_type(target)
    if target:
        run_scan_async(module, target, user_id=current_user.id)
        flash(f'Scan {module} lancé pour {target}', 'success')
    return redirect(url_for('views.dossier', entity_id=entity_id))


@views_bp.route('/investigate', methods=['GET', 'POST'])
@login_required
def investigate_chat():
    from models import InvestigationMessage
    from services.investigation_ai import investigate_step
    if request.method == 'POST':
        data = request.json or {}
        msg = (data.get('message') or '').strip()
        if not msg:
            return jsonify({'error': 'message vide'}), 400
        out = investigate_step(msg, data.get('context', {}))
        db.session.add(InvestigationMessage(user_id=current_user.id, role='user', content=msg))
        db.session.add(InvestigationMessage(
            user_id=current_user.id, role='assistant', content=out['reply'],
            suggested_actions=json.dumps(out.get('actions', [])),
        ))
        db.session.commit()
        return jsonify(out)
    history = InvestigationMessage.query.filter_by(user_id=current_user.id)\
        .order_by(InvestigationMessage.created_at.desc()).limit(30).all()
    return render_template('investigate.html', history=history, username=current_user.username)




@views_bp.route('/graph')
@login_required
def graph_view():
    entity_id = request.args.get('entity_id', type=int)
    entities = Entity.query.filter_by(user_id=current_user.id).order_by(Entity.created_at.desc()).limit(50).all()
    return render_template(
        'graph.html',
        entity_id=entity_id,
        entities=entities,
        username=current_user.username,
    )


@views_bp.route('/graph/data/<int:entity_id>')
@login_required
def graph_data(entity_id):
    from services.correlation import build_graph_json, build_entity_links_json
    g = build_graph_json(entity_id, current_user.id)
    if not g.get('nodes'):
        return jsonify({'error': 'Entité non trouvée'}), 404
    links = build_entity_links_json(entity_id, current_user.id)
    if links:
        g['links_detail'] = links.get('links', [])
        g['entity'] = links.get('entity')
    return jsonify(g)


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
        ent = Entity.query.filter_by(id=entity_id, user_id=current_user.id).first()
        if not ent:
            return jsonify({'error': 'Entité non trouvée'}), 404
        value = ent.value
        etype = ent.entity_type
    if not value:
        return jsonify({'error': 'Valeur manquante'}), 400
    module_map = {
        'email': 'email', 'phone': 'phone', 'username': 'sherlock',
        'domain': 'whois', 'platform': 'sherlock', 'ip': 'ip',
    }
    module = module_map.get(etype) or detect_target_type(value)
    if module not in SCAN_FUNCTIONS:
        module = detect_target_type(value)
    scan_id = run_scan_async(module, value, user_id=current_user.id)
    return jsonify({'scan_id': scan_id, 'module': module, 'target': value})


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


@views_bp.route('/scheduled', methods=['GET', 'POST'])
@login_required
def scheduled_page():
    if request.method == 'POST':
        target = request.form.get('target', '').strip()
        module = request.form.get('module') or detect_target_type(target)
        hours = int(request.form.get('interval_hours', 24) or 24)
        if target and 1 <= hours <= 168:
            job = ScheduledScan(
                user_id=current_user.id,
                module=module,
                target=target,
                interval_hours=hours,
                enabled=True,
                next_run_at=datetime.utcnow(),
            )
            db.session.add(job)
            db.session.commit()
            flash('Surveillance programmée créée.', 'success')
        return redirect(url_for('views.scheduled_page'))

    jobs = ScheduledScan.query.filter_by(user_id=current_user.id)\
        .order_by(ScheduledScan.next_run_at.asc()).all()
    return render_template('scheduled.html', jobs=jobs, username=current_user.username)


@views_bp.route('/scheduled/<int:job_id>/toggle', methods=['POST'])
@login_required
def scheduled_toggle(job_id):
    job = db.session.get(ScheduledScan, job_id)
    if job and job.user_id == current_user.id:
        job.enabled = not job.enabled
        db.session.commit()
    return redirect(url_for('views.scheduled_page'))


@views_bp.route('/scheduled/<int:job_id>/delete', methods=['POST'])
@login_required
def scheduled_delete(job_id):
    job = db.session.get(ScheduledScan, job_id)
    if job and job.user_id == current_user.id:
        db.session.delete(job)
        db.session.commit()
    return redirect(url_for('views.scheduled_page'))
