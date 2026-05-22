"""Routes vues : Express, Expert, paramètres."""
import json
import os
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user

from extensions import db
from models import User, Scan, Entity
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
    from app import summarize_osint_with_openrouter
    data = request.json or {}
    card = data.get('card', {})
    result = data.get('result', {})
    try:
        prompt_ctx = json.dumps({'carte': card, 'donnees': result}, ensure_ascii=False)[:3500]
        summary = summarize_osint_with_openrouter(
            f"Tu es un assistant OSINT pédagogique pour le grand public. "
            f"Explique en français simple ce que signifient ces résultats, les risques, "
            f"et propose 2-3 prochaines étapes concrètes (sans jargon technique):\n\n{prompt_ctx}"
        )
        return jsonify({'assistant': summary})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


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
    from services.correlation import build_graph_json
    g = build_graph_json(entity_id, current_user.id)
    if not g.get('nodes'):
        return jsonify({'error': 'Entité non trouvée'}), 404
    return jsonify(g)
