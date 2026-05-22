"""Exécution fiable des scans (thread dédié, compatible Gunicorn/gevent)."""
import json
import logging
from datetime import datetime

from extensions import db
from models import Scan, User

logger = logging.getLogger(__name__)


def process_scan_by_id(scan_id: int, app, socketio=None, fernet=None):
    """Exécute un scan déjà créé en base (statut pending → running → completed)."""
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan or scan.status not in ('pending', 'running'):
            return

        from app import SCAN_FUNCTIONS

        func = SCAN_FUNCTIONS.get(scan.module)
        if not func:
            scan.status = 'failed'
            scan.result_json = json.dumps(
                {'error': f'Module inconnu: {scan.module}'}, ensure_ascii=False,
            )
            scan.completed_at = datetime.utcnow()
            db.session.commit()
            _emit(socketio, 'scan_error', {'scan_id': scan_id, 'error': scan.result_json})
            return

        scan.status = 'running'
        db.session.commit()
        _emit(socketio, 'scan_progress', {
            'scan_id': scan_id, 'status': 'running', 'module': scan.module, 'target': scan.target,
        })

        try:
            opts = _build_options(scan, fernet)
            opts['_app'] = app
            if scan.result_json:
                try:
                    pending = json.loads(scan.result_json)
                    if isinstance(pending, dict) and pending.get('_pending_options'):
                        opts.update(pending['_pending_options'])
                except Exception:
                    pass
            result = func(scan.target, opts)
            if isinstance(result, dict):
                from services.result_hints import annotate_result, annotate_multi_results
                if scan.module == 'multi' or result.get('_meta', {}).get('multi'):
                    result = annotate_multi_results(result)
                else:
                    result = annotate_result(scan.module, result, opts)
            scan.result_json = json.dumps(result, ensure_ascii=False, default=str)
            scan.status = 'completed'
            scan.completed_at = datetime.utcnow()
            db.session.commit()

            _run_correlation(scan, result, opts)
            _emit(socketio, 'scan_done', {'scan_id': scan_id, 'result': result})
            logger.info('Scan #%s terminé (%s)', scan_id, scan.module)

        except Exception as e:
            logger.exception('Scan #%s échoué', scan_id)
            db.session.rollback()
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.result_json = json.dumps({'error': str(e)}, ensure_ascii=False)
                scan.status = 'completed'
                scan.completed_at = datetime.utcnow()
                db.session.commit()
                _emit(socketio, 'scan_error', {'scan_id': scan_id, 'error': str(e)})


def _build_options(scan: Scan, fernet) -> dict:
    opts = {}
    if not scan.user_id or not fernet:
        return opts
    import os
    from services.user_keys import get_key
    u = db.session.get(User, scan.user_id)
    if not u:
        return opts
    for opt_k, ukey, env in [
        ('_shodan_key', 'shodan', 'SHODAN_API_KEY'),
        ('_hibp_key', 'hibp', 'HIBP_API_KEY'),
        ('_hunter_key', 'hunter', 'HUNTER_API_KEY'),
        ('_dehashed_key', 'dehashed', 'DEHASHED_API_KEY'),
        ('_dehashed_email', 'dehashed_email', 'DEHASHED_EMAIL'),
        ('_epieos_key', 'epieos', 'EPIEOS_API_KEY'),
        ('_otx_key', 'otx', 'OTX_API_KEY'),
        ('_github_key', 'github', 'GITHUB_TOKEN'),
    ]:
        opts[opt_k] = get_key(u, ukey, env, fernet) or os.environ.get(env, '')
    if u.proxy_list:
        opts['_proxy_list'] = u.proxy_list
    if u.stealth_mode:
        opts['_stealth_mode'] = True
    # Fallback scraping (Hunter/Dehashed quota) — désactivable OPSEC
    opts['_scrape_fallback'] = bool(getattr(u, 'scrape_fallback_enabled', True))
    return opts


def _run_correlation(scan: Scan, result: dict, opts: dict):
    try:
        from services.correlation import process_scan_correlations, process_multi_correlations
        root_ent = opts.get('_root_entity_id')
        if scan.module == 'multi' or (isinstance(result, dict) and result.get('_meta', {}).get('multi')):
            process_multi_correlations(
                scan.id, scan.target, result, scan.user_id, root_entity_id=root_ent,
            )
        else:
            process_scan_correlations(
                scan.id, scan.module, scan.target, result, scan.user_id,
                root_entity_id=root_ent,
            )
    except Exception as e:
        logger.warning('Corrélation scan #%s: %s', scan.id, e)
    try:
        from services.webhooks import notify_scan_complete
        notify_scan_complete(scan, result, scan.user_id)
    except Exception:
        pass
    if scan.scheduled_scan_id:
        try:
            from services.monitoring_alerts import check_scheduled_scan_alerts
            check_scheduled_scan_alerts(scan, result)
        except Exception as e:
            logger.warning('Alertes monitoring #%s: %s', scan.id, e)


def _emit(socketio, event: str, payload: dict):
    if socketio:
        try:
            socketio.emit(event, payload)
        except Exception as e:
            logger.warning('Socket emit %s: %s', event, e)


def dispatch_scan(scan_id: int, app, socketio=None, fernet=None):
    """Lance le scan via Celery (si REDIS_URL) ou thread OS (fiable sous gevent)."""
    from services.task_queue import enqueue_scan
    return enqueue_scan(scan_id, app, socketio, fernet)
