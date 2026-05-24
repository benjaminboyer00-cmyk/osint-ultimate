"""
Tâches asynchrones (narratif IA, etc.) — Celery si Redis, sinon thread + store Redis/mémoire.
"""
import hashlib
import json
import logging
import threading
import uuid
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Repli mémoire (non partagé entre workers Gunicorn)
_memory_jobs: dict[str, dict] = {}
_memory_lock = threading.Lock()
_JOB_TTL_SEC = 3600


def _job_redis_key(task_id: str) -> str:
    return f'job:{task_id}'


def _save_job(task_id: str, data: dict) -> None:
    payload = json.dumps({**data, 'updated_at': datetime.utcnow().isoformat()}, default=str)
    try:
        from services.cache_manager import get_redis
        r = get_redis()
        if r:
            r.setex(_job_redis_key(task_id), _JOB_TTL_SEC, payload)
            return
    except Exception as e:
        logger.debug('job redis save: %s', e)
    with _memory_lock:
        _memory_jobs[task_id] = data


def get_job(task_id: str) -> dict | None:
    try:
        from services.cache_manager import get_redis
        r = get_redis()
        if r:
            raw = r.get(_job_redis_key(task_id))
            if raw:
                return json.loads(raw)
    except Exception:
        pass
    with _memory_lock:
        return _memory_jobs.get(task_id)


def _run_narrative_task(
    task_id: str,
    entity_id: int,
    user_id: int,
    *,
    style: str,
    length: str,
    use_cache: bool,
    app,
    socketio=None,
) -> None:
    _save_job(task_id, {
        'task_id': task_id,
        'type': 'narrative',
        'status': 'running',
        'entity_id': entity_id,
    })
    try:
        with app.app_context():
            from services.dossier_scans import link_scans_to_dossier
            from services.dossier_access import get_dossier_context
            from services.report_data import build_report_data
            from services.narrative_report import build_narrative_for_entity

            ctx = get_dossier_context(entity_id, user_id, min_role='reader')
            if not ctx:
                _save_job(task_id, {
                    'task_id': task_id, 'status': 'failed',
                    'error': 'Dossier non accessible', 'entity_id': entity_id,
                })
                return
            link_scans_to_dossier(entity_id, ctx['owner_user_id'])

            data_hash = ''
            if use_cache:
                data = build_report_data(entity_id, user_id)
                if data:
                    blob = json.dumps(data, sort_keys=True, default=str)
                    data_hash = hashlib.sha256(blob.encode()).hexdigest()[:16]
                    from services.cache_manager import get_narrative_cached
                    cached = get_narrative_cached(
                        entity_id, ctx['owner_user_id'], data_hash,
                    )
                    if cached:
                        _save_job(task_id, {
                            'task_id': task_id, 'status': 'completed',
                            'entity_id': entity_id, 'result': cached, 'cached': True,
                        })
                        _emit_narrative_done(socketio, user_id, entity_id, task_id)
                        return

            out = build_narrative_for_entity(
                entity_id, user_id,
                style=style, length=length, cache_on_scan=use_cache,
            )
            if use_cache and data_hash and not out.get('partial'):
                from services.cache_manager import set_narrative_cached
                set_narrative_cached(
                    entity_id, ctx['owner_user_id'], data_hash, out,
                )
            _save_job(task_id, {
                'task_id': task_id, 'status': 'completed',
                'entity_id': entity_id, 'result': out,
            })
            _emit_narrative_done(socketio, user_id, entity_id, task_id)
    except Exception as e:
        logger.exception('narrative task %s', task_id)
        _save_job(task_id, {
            'task_id': task_id, 'status': 'failed',
            'error': str(e), 'entity_id': entity_id,
        })


def _emit_narrative_done(socketio, user_id: int, entity_id: int, task_id: str) -> None:
    if not socketio or not user_id:
        return
    try:
        socketio.emit(
            'narrative_ready',
            {'task_id': task_id, 'entity_id': entity_id},
            room=str(user_id),
        )
    except Exception as e:
        logger.warning('narrative_ready emit: %s', e)


def enqueue_narrative(
    entity_id: int,
    user_id: int,
    app,
    socketio=None,
    *,
    style: str = 'executive',
    length: str = 'medium',
    use_cache: bool = True,
) -> str:
    """Enfile la génération narratif ; retourne task_id."""
    task_id = str(uuid.uuid4())
    _save_job(task_id, {
        'task_id': task_id,
        'type': 'narrative',
        'status': 'pending',
        'entity_id': entity_id,
    })

    from services.task_queue import use_celery
    if use_celery():
        try:
            from tasks import run_narrative_task
            run_narrative_task.delay(
                task_id, entity_id, user_id, style, length, use_cache,
            )
            return task_id
        except Exception as e:
            logger.warning('Celery narrative repli thread: %s', e)

    t = threading.Thread(
        target=_run_narrative_task,
        args=(task_id, entity_id, user_id),
        kwargs={
            'style': style, 'length': length, 'use_cache': use_cache,
            'app': app, 'socketio': socketio,
        },
        daemon=True,
        name=f'narrative-{task_id[:8]}',
    )
    t.start()
    return task_id
