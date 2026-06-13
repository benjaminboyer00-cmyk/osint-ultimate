"""Exécution fiable des scans (thread dédié, compatible Gunicorn/gevent)."""
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutureTimeout
from datetime import datetime

from extensions import db
from models import Scan, User

logger = logging.getLogger(__name__)

_SCAN_HARD_TIMEOUT = int(os.environ.get('SCAN_HARD_TIMEOUT', '180'))
_scan_pool = ThreadPoolExecutor(
    max_workers=int(os.environ.get('SCAN_POOL_SIZE', '4')),
    thread_name_prefix='scan-exec',
)


def _run_scan_func(func, target, opts, timeout):
    """Exécute la fonction de scan avec un timeout mur (wall-clock).

    Le scan tourne dans un thread du pool, distinct du thread qui détient
    le `app.app_context()` de process_scan_by_id : on ouvre donc ici un
    contexte applicatif dédié pour ce thread afin que `current_app`,
    `db.session`, etc. restent disponibles (ex: connectors/base.py ApiCache).
    """
    app = opts.get('_app')

    def _wrapped():
        if app is not None:
            with app.app_context():
                return func(target, opts)
        return func(target, opts)

    fut = _scan_pool.submit(_wrapped)
    try:
        return fut.result(timeout=timeout)
    except _FutureTimeout:
        fut.cancel()  # libère le slot si encore en file
        raise TimeoutError(
            f'Scan interrompu : dépassement de {timeout}s.'
        )


def process_scan_by_id(scan_id: int, app, socketio=None, fernet=None):
    """Exécute un scan déjà créé en base (statut pending → running → completed)."""
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan or scan.status not in ('pending', 'running'):
            return

        from scans.registry import SCAN_FUNCTIONS

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
            if scan.module == 'instagram':
                from connectors.instagram import inject_rotating_proxy

                inject_rotating_proxy(opts)
            poll_token = None
            if scan.result_json:
                try:
                    pending = json.loads(scan.result_json)
                    if isinstance(pending, dict):
                        poll_token = pending.get('_poll_token')
                        if pending.get('_pending_options'):
                            opts.update(pending['_pending_options'])
                            poll_token = poll_token or opts.get('_poll_token')
                except Exception:
                    pass
            result = _run_scan_func(func, scan.target, opts, _SCAN_HARD_TIMEOUT)
            if isinstance(result, dict):
                from services.result_hints import annotate_result, annotate_multi_results
                from services.scan_poll import attach_poll_token_to_result
                if scan.module == 'multi' or result.get('_meta', {}).get('multi'):
                    result = annotate_multi_results(result)
                else:
                    result = annotate_result(scan.module, result, opts)
                result = attach_poll_token_to_result(result, poll_token or opts.get('_poll_token'))
            scan.result_json = json.dumps(result, ensure_ascii=False, default=str)
            scan.status = 'completed'
            scan.completed_at = datetime.utcnow()
            db.session.commit()

            _run_correlation(scan, result, opts)
            root_ent = opts.get('_root_entity_id') or scan.root_entity_id
            if root_ent and scan.user_id:
                try:
                    from services.collaboration import log_activity, emit_dossier_event
                    from models import User
                    actor = db.session.get(User, scan.user_id) if scan.user_id else None
                    log_activity(int(root_ent), scan.user_id, 'scan_completed', {
                        'scan_id': scan.id,
                        'module': scan.module,
                        'target': scan.target,
                        'username': actor.username if actor else 'Système',
                    })
                    db.session.commit()
                    emit_dossier_event(socketio, int(root_ent), 'scan_completed', {
                        'scan_id': scan.id,
                        'module': scan.module,
                        'target': scan.target,
                        'user_id': scan.user_id,
                        'username': actor.username if actor else 'Système',
                        'status': scan.status,
                    })
                except Exception as e:
                    db.session.rollback()
                    logger.error(
                        'Erreur commit activité scan_completed #%s: %s',
                        scan.id, e,
                    )
            if opts.get('_graph_pivot'):
                try:
                    from services.graph_pivot import emit_graph_update_after_scan
                    emit_graph_update_after_scan(scan, socketio, opts)
                except Exception as e:
                    logger.warning('Pivot graph_update #%s: %s', scan_id, e)
            root_ent = opts.get('_root_entity_id')
            if root_ent:
                try:
                    from services.geo import emit_map_update_after_scan
                    emit_map_update_after_scan(scan, socketio, opts)
                except Exception as e:
                    logger.warning('map_update #%s: %s', scan_id, e)
                try:
                    from services.timeline import emit_timeline_update_after_scan
                    emit_timeline_update_after_scan(scan, socketio, opts)
                except Exception as e:
                    logger.warning('timeline_update #%s: %s', scan_id, e)
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
                try:
                    opts_err = _build_options(scan, fernet)
                except Exception:
                    opts_err = {}
                _emit_graph_pivot_error(socketio, opts_err, scan_id, str(e))


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
    env_proxies = (os.environ.get('PROXY_LIST') or '').strip()
    if env_proxies:
        if opts.get('_proxy_list'):
            opts['_proxy_list'] = f"{opts['_proxy_list']},{env_proxies}"
        else:
            opts['_proxy_list'] = env_proxies
    if u.stealth_mode:
        opts['_stealth_mode'] = True
    # Fallback scraping (Hunter/Dehashed quota) — désactivable OPSEC
    opts['_scrape_fallback'] = bool(getattr(u, 'scrape_fallback_enabled', True))
    return opts


def _run_correlation(scan: Scan, result: dict, opts: dict):
    try:
        from services.correlation import process_scan_correlations, process_multi_correlations
        from services.dossier_access import correlation_user_id
        root_ent = opts.get('_root_entity_id') or scan.root_entity_id
        corr_uid = correlation_user_id(scan.user_id, root_ent)
        if scan.module == 'multi' or (isinstance(result, dict) and result.get('_meta', {}).get('multi')):
            process_multi_correlations(
                scan.id, scan.target, result, corr_uid, root_entity_id=root_ent,
            )
        else:
            process_scan_correlations(
                scan.id, scan.module, scan.target, result, corr_uid,
                root_entity_id=root_ent,
            )
    except Exception as e:
        logger.warning('Corrélation scan #%s: %s', scan.id, e)
    try:
        if scan.user_id and not scan.root_entity_id:
            from services.entity_resolve import find_entity_for_target
            ent = find_entity_for_target(scan.user_id, scan.target, scan.module)
            if ent:
                scan.root_entity_id = ent.id
        root_ent = opts.get('_root_entity_id') or scan.root_entity_id
        if root_ent and scan.user_id:
            from services.dossier_scans import link_scans_to_dossier
            from services.dossier_access import correlation_user_id
            owner = correlation_user_id(scan.user_id, int(root_ent))
            if owner:
                link_scans_to_dossier(int(root_ent), owner)
    except Exception as e:
        logger.warning('Lien dossier scan #%s: %s', scan.id, e)
    try:
        from services.geo import enrich_geo_from_scan
        enrich_geo_from_scan(scan, result, scan.user_id)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error('Erreur commit géo scan #%s: %s', scan.id, e)
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


def _emit_graph_pivot_error(socketio, opts: dict | None, scan_id: int, message: str):
    """Notifie l'UI graphe si un pivot multi-modules a échoué."""
    opts = opts or {}
    if not socketio or not opts.get('_graph_pivot'):
        return
    room = str(opts.get('_graph_pivot_notify') or '')
    if not room:
        return
    try:
        socketio.emit('graph_error', {
            'scan_id': scan_id,
            'message': message,
            'root_entity_id': opts.get('_root_entity_id'),
        }, room=room)
    except Exception as e:
        logger.warning('graph_error emit scan #%s: %s', scan_id, e)


def dispatch_scan(scan_id: int, app, socketio=None, fernet=None):
    """Lance le scan via Celery (si REDIS_URL) ou thread OS (fiable sous gevent)."""
    from services.task_queue import enqueue_scan
    return enqueue_scan(scan_id, app, socketio, fernet)
