"""Surveillance continue — fréquences et création de jobs."""
from datetime import datetime

from extensions import db
from models import ScheduledScan
from services.target_detector import detect_target_type

FREQUENCY_HOURS = {
    'daily': 24,
    'quotidien': 24,
    'weekly': 168,
    'hebdomadaire': 168,
}


def frequency_to_hours(freq: str, default: int = 24) -> int:
    if isinstance(freq, (int, float)):
        h = int(freq)
        return h if 1 <= h <= 168 else default
    if isinstance(freq, str) and freq.isdigit():
        h = int(freq)
        return h if 1 <= h <= 168 else default
    return FREQUENCY_HOURS.get((freq or '').lower().strip(), default)


def frequency_label(hours: int) -> str:
    if hours == 24:
        return 'Quotidien'
    if hours == 168:
        return 'Hebdomadaire'
    return f'Toutes les {hours}h'


def create_monitoring_job(
    user_id: int,
    target: str,
    module: str | None = None,
    frequency: str = 'daily',
    webhook_url: str | None = None,
    notify_on_change: bool = False,
    alert_rules: list[str] | None = None,
) -> ScheduledScan:
    target = (target or '').strip()
    if not target:
        raise ValueError('Cible manquante')
    module = (module or '').strip() or detect_target_type(target)
    hours = frequency_to_hours(frequency)
    from services.monitor_rules import serialize_rules, DEFAULT_RULES
    rules_json = None
    if notify_on_change:
        rules_json = serialize_rules(alert_rules or DEFAULT_RULES)
    job = ScheduledScan(
        user_id=user_id,
        module=module,
        target=target,
        interval_hours=hours,
        enabled=True,
        next_run_at=datetime.utcnow(),
        webhook_url=webhook_url,
        notify_on_change=notify_on_change,
        alert_rules_json=rules_json,
    )
    db.session.add(job)
    db.session.commit()
    return job
