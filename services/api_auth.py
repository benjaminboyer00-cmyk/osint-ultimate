"""Authentification API REST — X-API-Key ou Bearer."""
from functools import wraps
from flask import request, jsonify
from models import User


def extract_api_token() -> str | None:
    key = request.headers.get('X-API-Key', '').strip()
    if key:
        return key
    auth = request.headers.get('Authorization', '')
    if auth.lower().startswith('bearer '):
        return auth[7:].strip()
    return request.args.get('api_key', '').strip() or None


def resolve_api_user():
    token = extract_api_token()
    if not token:
        return None
    return User.query.filter_by(api_token=token).first()


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = resolve_api_user()
        if not user:
            return jsonify({
                'error': 'Authentification requise',
                'hint': 'Header X-API-Key ou Authorization: Bearer <token>',
            }), 401
        request.api_user = user
        return f(*args, **kwargs)
    return decorated
