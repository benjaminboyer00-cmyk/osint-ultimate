"""Notifications temps réel et journal d'activité pour scans dossier partagé."""
import logging

from extensions import db
from services.collaboration import log_activity, emit_dossier_event

logger = logging.getLogger(__name__)


def _username(user_id: int | None) -> str:
    if not user_id:
        return 'Système'
    from models import User
    u = db.session.get(User, user_id)
    return u.username if u else f'user#{user_id}'


def notify_dossier_scan_started(
    socketio,
    root_entity_id: int,
    user_id: int | None,
    scan_id: int,
    module: str,
    target: str,
) -> None:
    if not root_entity_id:
        return
    log_activity(root_entity_id, user_id, 'scan_started', {
        'scan_id': scan_id,
        'module': module,
        'target': target,
        'username': _username(user_id),
    })
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return
    payload = {
        'scan_id': scan_id,
        'module': module,
        'target': target,
        'user_id': user_id,
        'username': _username(user_id),
        'status': 'started',
        'root_entity_id': root_entity_id,
    }
    emit_dossier_event(socketio, root_entity_id, 'scan_started', payload)
    if socketio and user_id:
        try:
            socketio.emit('scan_progress', payload, room=str(user_id))
        except Exception as e:
            logger.warning('scan_progress emit: %s', e)
