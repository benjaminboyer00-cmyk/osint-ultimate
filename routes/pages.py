"""Pages statiques et paramètres utilisateur."""
import secrets
from flask import render_template, request, jsonify, redirect, url_for, flash, current_app, session
from flask_login import login_required, current_user

from routes.views_bp import views_bp
from extensions import db

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
        totp_enabled=getattr(current_user, 'totp_enabled', False),
    )


@views_bp.route('/settings/security', methods=['GET', 'POST'])
@login_required
def settings_security():
    from app import fernet
    from services.totp_auth import (
        generate_secret, provisioning_uri, qr_code_base64,
        enable_totp, disable_totp, get_decrypted_secret, verify_code,
    )
    setup_secret = session.get('totp_setup_secret')
    if request.method == 'POST':
        action = request.form.get('action', '')
        if action == 'disable':
            code = request.form.get('code', '')
            secret = get_decrypted_secret(current_user, fernet)
            if secret and verify_code(secret, code):
                disable_totp(current_user)
                flash('2FA désactivée.', 'success')
            else:
                flash('Code invalide.', 'error')
            return redirect(url_for('views.settings_security'))
        if action == 'enable':
            secret = session.get('totp_setup_secret') or generate_secret()
            code = request.form.get('code', '')
            if enable_totp(current_user, secret, code, fernet):
                session.pop('totp_setup_secret', None)
                flash('2FA activée.', 'success')
                return redirect(url_for('views.settings_security'))
            flash('Code incorrect — réessayez avec l\'application d\'authentification.', 'error')
        if action == 'start_setup':
            secret = generate_secret()
            session['totp_setup_secret'] = secret
            setup_secret = secret
    uri = provisioning_uri(current_user, setup_secret) if setup_secret else None
    qr_b64 = qr_code_base64(uri) if uri else None
    return render_template(
        'settings_security.html',
        username=current_user.username,
        totp_enabled=getattr(current_user, 'totp_enabled', False),
        setup_secret=setup_secret,
        provisioning_uri=uri,
        qr_base64=qr_b64,
    )


@views_bp.route('/privacy')
def privacy():
    return render_template('privacy.html')
@views_bp.route('/settings/token/regenerate', methods=['POST'])
@login_required
def regenerate_token():
    import secrets
    current_user.api_token = secrets.token_hex(32)
    db.session.commit()
    flash('Nouvelle clé API générée.', 'success')
    return redirect(url_for('views.settings'))

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
