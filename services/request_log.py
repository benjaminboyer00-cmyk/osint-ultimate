"""Request ID et logging structuré."""
import logging
import uuid

from flask import g, request

logger = logging.getLogger(__name__)


def init_request_logging(app):
    @app.before_request
    def _assign_request_id():
        g.request_id = request.headers.get('X-Request-ID') or str(uuid.uuid4())[:12]

    @app.after_request
    def _log_request(response):
        rid = getattr(g, 'request_id', '-')
        logger.info(
            '%s %s %s → %s',
            rid, request.method, request.path, response.status_code,
        )
        response.headers['X-Request-ID'] = rid
        return response
