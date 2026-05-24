"""Gestionnaires d'erreurs Flask — réponses JSON/HTML cohérentes."""
from __future__ import annotations

from flask import jsonify, request

from services.errors import (
    OSINTError,
    ConnectorError,
    APIQuotaExceeded,
    AccessDeniedError,
    ValidationError,
)


def _wants_json() -> bool:
    if request.path.startswith('/api/'):
        return True
    accept = request.accept_mimetypes.best_match(['application/json', 'text/html'])
    return accept == 'application/json' or request.is_json


def _json_error(message: str, *, status: int, code: str = 'error', extra: dict | None = None):
    body = {'error': message, 'code': code}
    if extra:
        body.update(extra)
    return jsonify(body), status


def register_error_handlers(app):
    """Enregistre les handlers pour les exceptions métier."""

    @app.errorhandler(APIQuotaExceeded)
    def handle_quota(exc: APIQuotaExceeded):
        app.logger.warning('Quota %s: %s', exc.provider, exc)
        if _wants_json():
            return _json_error(
                str(exc), status=429, code='quota_exceeded',
                extra={'provider': exc.provider},
            )
        from flask import flash, redirect, url_for
        flash(f'Quota API atteint ({exc.provider or "service"}).', 'error')
        return redirect(request.referrer or url_for('views.express'))

    @app.errorhandler(ConnectorError)
    def handle_connector(exc: ConnectorError):
        app.logger.warning('Connector %s: %s', exc.provider, exc)
        if _wants_json():
            return _json_error(
                str(exc), status=502, code='connector_error',
                extra={'provider': exc.provider, 'status_code': exc.status_code},
            )
        from flask import flash, redirect, url_for
        flash('Service externe indisponible. Réessayez plus tard.', 'error')
        return redirect(request.referrer or url_for('views.express'))

    @app.errorhandler(AccessDeniedError)
    def handle_access(exc: AccessDeniedError):
        if _wants_json():
            return _json_error(str(exc) or 'Accès refusé', status=403, code='access_denied')
        from flask import abort
        abort(403)

    @app.errorhandler(ValidationError)
    def handle_validation(exc: ValidationError):
        if _wants_json():
            return _json_error(str(exc) or 'Données invalides', status=400, code='validation_error')
        from flask import flash, redirect, url_for
        flash(str(exc), 'error')
        return redirect(request.referrer or url_for('views.express'))

    @app.errorhandler(OSINTError)
    def handle_osint(exc: OSINTError):
        app.logger.error('OSINTError: %s', exc)
        if _wants_json():
            return _json_error(str(exc), status=500, code='osint_error')
        raise exc
