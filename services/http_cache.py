"""En-têtes Cache-Control pour fichiers statiques et endpoints publics."""
from flask import request


def init_http_cache(app):
    @app.after_request
    def _cache_headers(response):
        path = request.path or ''
        if path.startswith('/static/'):
            response.cache_control.public = True
            response.cache_control.max_age = 604800
            if path.endswith(('.css', '.js', '.woff2', '.woff', '.ico')):
                response.cache_control.immutable = True
        elif path == '/manifest.json':
            response.cache_control.public = True
            response.cache_control.max_age = 86400
        return response
