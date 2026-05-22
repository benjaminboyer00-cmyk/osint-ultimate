"""Centre de notifications — alertes surveillance."""
from extensions import db
from models import MonitoringAlert


def unread_count(user_id: int) -> int:
    return MonitoringAlert.query.filter_by(user_id=user_id, read=False).count()


def list_alerts(user_id: int, *, limit: int = 50, unread_only: bool = False) -> list[dict]:
    q = MonitoringAlert.query.filter_by(user_id=user_id)
    if unread_only:
        q = q.filter_by(read=False)
    rows = q.order_by(MonitoringAlert.created_at.desc()).limit(limit).all()
    return [_alert_json(a) for a in rows]


def mark_read(user_id: int, alert_id: int) -> bool:
    row = MonitoringAlert.query.filter_by(id=alert_id, user_id=user_id).first()
    if not row:
        return False
    row.read = True
    db.session.commit()
    return True


def mark_all_read(user_id: int) -> int:
    rows = MonitoringAlert.query.filter_by(user_id=user_id, read=False).all()
    for r in rows:
        r.read = True
    db.session.commit()
    return len(rows)


def _alert_json(a: MonitoringAlert) -> dict:
    return {
        'id': a.id,
        'level': a.level,
        'type': a.alert_type,
        'message': a.message,
        'job_id': a.job_id,
        'scan_id': a.scan_id,
        'read': a.read,
        'created_at': a.created_at.isoformat() if a.created_at else None,
    }
