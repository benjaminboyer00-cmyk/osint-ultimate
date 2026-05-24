"""Routes mode Express (lookup rapide)."""
import json

from flask import render_template, request, jsonify, redirect, url_for, current_app
from flask_login import current_user

from routes.views_bp import views_bp
from extensions import limiter
from services.target_detector import detect_target_type
from services.express_card import build_express_card


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
@limiter.limit('30/minute')
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
@limiter.limit('40/minute')
def express_card():
    data = request.json or {}
    module = data.get('module', 'pseudo')
    target = data.get('target', '')
    result = data.get('result', {})
    return jsonify(build_express_card(module, target, result))


@views_bp.route('/express/assist', methods=['POST'])
@limiter.limit('20/minute')
def express_assist():
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
