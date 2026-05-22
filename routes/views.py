"""Routes vues : Express, Expert, paramètres."""
import json
import os
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash, current_app
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
        version='4.2',
    )


@views_bp.route('/expert')
def expert():
    return render_template(
        'index.html',
        authenticated=current_user.is_authenticated,
        username=current_user.username if current_user.is_authenticated else None,
        version='4.2',
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
    from services.openrouter import chat_completion, fallback_explain
    data = request.json or {}
    card = data.get('card', {})
    result = data.get('result', {})
    prompt_ctx = json.dumps({'carte': card, 'donnees': result}, ensure_ascii=False)[:3500]
    system = (
        'Tu es un assistant OSINT pédagogique. Réponds en français simple, sans jargon. '
        'Structure : 1) Ce que signifient les résultats 2) Risques éventuels 3) 2-3 prochaines étapes concrètes.'
    )
    try:
        summary = chat_completion(
            f'Explique ces résultats de recherche OSINT:\n\n{prompt_ctx}',
            system=system,
        )
        return jsonify({'assistant': summary, 'source': 'openrouter'})
    except Exception as e:
        current_app.logger.warning('Express assist OpenRouter: %s', e)
        fallback = fallback_explain(card, result)
        return jsonify({
            'assistant': fallback,
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
            'numverify': request.form.get('numverify', '').strip(),
            'github': request.form.get('github', '').strip(),
        }
        keys = {k: v for k, v in keys.items() if v}
        from app import fernet
        current_user.set_api_keys(keys, fernet)
        db.session.commit()
        flash('Clés API enregistrées (chiffrées).', 'success')
        return redirect(url_for('views.settings'))

    from app import fernet
    user_keys = current_user.get_api_keys(fernet)
    token = current_user.ensure_api_token()
    db.session.commit()
    return render_template(
        'settings.html',
        user_keys=user_keys,
        api_token=token,
        username=current_user.username,
    )


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
