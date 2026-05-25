"""Authentification : inscription, connexion, 2FA TOTP."""
from datetime import datetime

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, session, jsonify,
)
from flask_login import login_user, logout_user, login_required, current_user

from extensions import db, limiter
from flask_limiter.util import get_remote_address
from models import User
from services.password_policy import password_strength
from services.totp_auth import (
    generate_secret, provisioning_uri, verify_code, qr_code_base64,
    enable_totp, disable_totp, get_decrypted_secret,
)

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit('8/minute', key_func=get_remote_address)
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        if not all([username, email, password]):
            flash('Tous les champs sont requis.', 'error')
            return redirect(url_for('auth.register'))
        strength = password_strength(password)
        if not strength['acceptable']:
            flash(
                'Mot de passe trop faible : ' + '; '.join(strength.get('feedback') or [strength['label']]),
                'error',
            )
            return redirect(url_for('auth.register'))
        if User.query.filter_by(username=username).first():
            flash("Nom d'utilisateur déjà pris.", 'error')
            return redirect(url_for('auth.register'))
        if User.query.filter_by(email=email).first():
            flash('Email déjà enregistré.', 'error')
            return redirect(url_for('auth.register'))
        user = User(username=username, email=email)
        user.set_password(password)
        user.ensure_api_token()
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('views.expert'))
    return render_template('auth.html', mode='register')


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit('5/minute', key_func=get_remote_address)
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if getattr(user, 'totp_enabled', False):
                session['pending_2fa_user_id'] = user.id
                return redirect(url_for('auth.login_totp'))
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=True)
            return redirect(url_for('views.expert'))
        flash(
            'Identifiants invalides. Sur Hugging Face, recréez un compte après chaque redéploiement '
            'si la base n\'est pas persistante.',
            'error',
        )
    return render_template('auth.html', mode='login')


@auth_bp.route('/login/totp', methods=['GET', 'POST'])
@limiter.limit('15/minute', key_func=get_remote_address)
def login_totp():
    uid = session.get('pending_2fa_user_id')
    if not uid:
        return redirect(url_for('auth.login'))
    user = db.session.get(User, int(uid))
    if not user or not getattr(user, 'totp_enabled', False):
        session.pop('pending_2fa_user_id', None)
        return redirect(url_for('auth.login'))
    if request.method == 'POST':
        from app import fernet
        secret = get_decrypted_secret(user, fernet)
        code = request.form.get('code', '')
        if secret and verify_code(secret, code):
            session.pop('pending_2fa_user_id', None)
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=True)
            return redirect(url_for('views.expert'))
        flash('Code 2FA invalide.', 'error')
    return render_template('auth_totp.html', username=user.username)


@auth_bp.route('/logout')
@login_required
def logout():
    session.pop('pending_2fa_user_id', None)
    logout_user()
    return redirect(url_for('views.expert'))


@auth_bp.route('/api/password-strength', methods=['POST'])
@limiter.limit('60/minute')
def api_password_strength():
    data = request.get_json(silent=True) or {}
    pwd = data.get('password', '')
    return jsonify(password_strength(pwd))
