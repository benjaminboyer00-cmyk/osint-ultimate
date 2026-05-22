"""Alertes surveillance — règles, snapshots, webhooks, notifications (Phase 7 V7)."""
import json
import logging
import os

from extensions import db
from models import Scan, ScheduledScan, Webhook, MonitoringAlert, User
from services.monitor_rules import parse_alert_rules, DEFAULT_RULES
from services.monitor_snapshot import (
    build_monitor_snapshot,
    snapshot_to_json,
    snapshot_from_json,
    extract_signals,
)

logger = logging.getLogger(__name__)


def compare_signals(prev: dict, new: dict) -> list[dict]:
    """Rétrocompat — compare signaux menace."""
    alerts = []
    if new.get('has_error') and not prev.get('has_error'):
        alerts.append({
            'level': 'warning', 'type': 'scan_error',
            'message': 'Le dernier scan a échoué ou retourné une erreur.',
        })
    prev_score = prev.get('threat_score', 0)
    new_score = new.get('threat_score', 0)
    if new_score > prev_score and new_score > 0:
        alerts.append({
            'level': 'high', 'type': 'threat_increase',
            'message': f'Niveau de menace en hausse ({prev_score} → {new_score}).',
        })
    for mod, new_val in (new.get('sections') or {}).items():
        old_val = (prev.get('sections') or {}).get(mod, 0)
        if new_val > old_val and new_val > 0:
            alerts.append({
                'level': 'high', 'type': f'{mod}_change',
                'message': f'Nouveau signal {mod} (score {old_val} → {new_val}).',
            })
    if new_score == 0 and prev_score > 0:
        alerts.append({
            'level': 'info', 'type': 'threat_cleared',
            'message': 'Plus de signal de menace détecté sur cette cible.',
        })
    return alerts


def evaluate_snapshot_rules(prev: dict | None, new: dict, rules: list[str]) -> list[dict]:
    """Applique les règles configurées entre deux snapshots."""
    if not prev:
        return []
    alerts = []
    active = set(rules or DEFAULT_RULES)

    if 'scan_error' in active and new.get('has_error') and not prev.get('has_error'):
        alerts.append({
            'level': 'warning', 'type': 'scan_error',
            'message': 'Le scan programmé a échoué ou retourné une erreur.',
        })

    if 'threat_change' in active:
        for a in compare_signals(
            {'threat_score': prev.get('threat_score', 0), 'sections': prev.get('threat_sections', {}),
             'has_error': prev.get('has_error')},
            {'threat_score': new.get('threat_score', 0), 'sections': new.get('threat_sections', {}),
             'has_error': new.get('has_error')},
        ):
            if a['type'] in ('threat_increase', 'threat_cleared') or a['type'].endswith('_change'):
                a['type'] = 'threat_change' if a['type'] == 'threat_increase' else a['type']
                alerts.append(a)

    if 'whois_change' in active:
        if prev.get('whois_hash') and new.get('whois_hash') and prev['whois_hash'] != new['whois_hash']:
            alerts.append({
                'level': 'high', 'type': 'whois_change',
                'message': 'Modification WHOIS détectée (registre / dates / statut).',
                'details': {'before': prev.get('whois'), 'after': new.get('whois')},
            })

    if 'new_subdomain' in active:
        old_s = set(prev.get('subdomains') or [])
        new_s = set(new.get('subdomains') or [])
        added = sorted(new_s - old_s)
        if added:
            alerts.append({
                'level': 'high', 'type': 'new_subdomain',
                'message': f'Nouveau(x) enregistrement(s) DNS : {", ".join(added[:5])}'
                + ('…' if len(added) > 5 else ''),
                'details': {'added': added[:20]},
            })

    if 'data_breach' in active:
        old_b = set(prev.get('breaches') or [])
        new_b = set(new.get('breaches') or [])
        added = sorted(new_b - old_b)
        if added:
            alerts.append({
                'level': 'high', 'type': 'data_breach',
                'message': f'Nouvelle(s) fuite(s) : {", ".join(added[:4])}'
                + ('…' if len(added) > 4 else ''),
                'details': {'added': added[:20]},
            })

    if 'new_section' in active:
        old_sec = set(prev.get('sections') or [])
        new_sec = set(new.get('sections') or [])
        added = sorted(new_sec - old_sec)
        if added:
            alerts.append({
                'level': 'info', 'type': 'new_section',
                'message': f'Nouvelles sections de données : {", ".join(added[:4])}',
                'details': {'added': added},
            })

    return alerts


def _persist_alerts(scan: Scan, job: ScheduledScan, alerts: list[dict]) -> list[MonitoringAlert]:
    rows = []
    for a in alerts:
        row = MonitoringAlert(
            user_id=scan.user_id,
            job_id=job.id,
            scan_id=scan.id,
            level=a.get('level', 'info'),
            alert_type=a.get('type', 'change'),
            message=a.get('message', 'Changement détecté'),
            details_json=json.dumps(a.get('details'), ensure_ascii=False) if a.get('details') else None,
            read=False,
        )
        db.session.add(row)
        rows.append(row)
    db.session.commit()
    return rows


def _emit_notification_socket(user_id: int, rows: list[MonitoringAlert], job: ScheduledScan, scan: Scan):
    try:
        from app import socketio
        if not socketio:
            return
        for row in rows:
            socketio.emit('alert_notification', {
                'id': row.id,
                'level': row.level,
                'type': row.alert_type,
                'message': row.message,
                'job_id': job.id,
                'scan_id': scan.id,
                'target': scan.target,
                'created_at': row.created_at.isoformat() if row.created_at else None,
                'monitoring_url': '/monitoring',
            }, room=str(user_id))
    except Exception as e:
        logger.debug('Socket alerte: %s', e)


def _send_email_alert(user: User, job: ScheduledScan, scan: Scan, alerts: list[dict]) -> bool:
    host = os.environ.get('SMTP_HOST', '').strip()
    if not host or not user.email:
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        port = int(os.environ.get('SMTP_PORT', '587'))
        user_smtp = os.environ.get('SMTP_USER', '')
        pass_smtp = os.environ.get('SMTP_PASSWORD', '')
        from_addr = os.environ.get('SMTP_FROM', user_smtp or 'osint@localhost')
        lines = [f'Cible : {scan.target}', f'Module : {scan.module}', f'Job #{job.id}', '']
        for a in alerts:
            lines.append(f"[{a.get('level', 'info').upper()}] {a.get('message', '')}")
        lines.append('\n— OSINT Ultimate')
        msg = MIMEText('\n'.join(lines), 'plain', 'utf-8')
        msg['Subject'] = f'[OSINT] Alerte surveillance — {scan.target[:60]}'
        msg['From'] = from_addr
        msg['To'] = user.email
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            if os.environ.get('SMTP_TLS', 'true').lower() in ('1', 'true', 'yes'):
                smtp.starttls()
            if user_smtp and pass_smtp:
                smtp.login(user_smtp, pass_smtp)
            smtp.send_message(msg)
        return True
    except Exception as e:
        logger.warning('Email alerte: %s', e)
        return False


def _notify_alerts(scan: Scan, job: ScheduledScan, alerts: list[dict], rows: list[MonitoringAlert]):
    payload = {
        'event': 'monitoring.alert',
        'scan_id': scan.id,
        'job_id': job.id,
        'target': scan.target,
        'module': scan.module,
        'alerts': alerts,
        'notification_ids': [r.id for r in rows],
        'dossier_hint': f'/expert?scan_id={scan.id}',
    }
    logger.info('Alerte monitoring job #%s: %d alerte(s)', job.id, len(alerts))

    hooks = []
    if job.webhook_url:
        hooks.append(job.webhook_url)
    for wh in Webhook.query.filter_by(user_id=job.user_id, enabled=True).all():
        if wh.url not in hooks:
            hooks.append(wh.url)

    if hooks:
        import requests
        discord_body = {
            **payload,
            'content': '🔔 **OSINT Ultimate — Alerte surveillance**\n'
            + '\n'.join(f"• {a.get('message', '')}" for a in alerts[:6]),
        }
        body = json.dumps(discord_body, ensure_ascii=False).encode()
        for hook_url in hooks:
            try:
                requests.post(
                    hook_url, data=body,
                    headers={'Content-Type': 'application/json', 'X-OSINT-Event': 'monitoring.alert'},
                    timeout=8,
                )
            except Exception as e:
                logger.warning('Webhook alerte: %s', e)

    user = db.session.get(User, scan.user_id)
    if user and os.environ.get('ALERT_EMAIL_ENABLED', '').lower() in ('1', 'true', 'yes'):
        _send_email_alert(user, job, scan, alerts)


def check_scheduled_scan_alerts(scan: Scan, result: dict):
    """Après un scan programmé : compare snapshot, enregistre et notifie."""
    job_id = scan.scheduled_scan_id
    if not job_id or not scan.user_id:
        return

    job = db.session.get(ScheduledScan, job_id)
    if not job:
        return

    prev_snap = snapshot_from_json(job.last_snapshot_json)
    if not prev_snap:
        prev_scan = (
            Scan.query.filter(
                Scan.scheduled_scan_id == job_id,
                Scan.id != scan.id,
                Scan.status == 'completed',
            )
            .order_by(Scan.completed_at.desc())
            .first()
        )
        if prev_scan and prev_scan.result_json:
            try:
                prev_snap = build_monitor_snapshot(
                    json.loads(prev_scan.result_json), prev_scan.module,
                )
            except Exception:
                prev_snap = None

    new_snap = build_monitor_snapshot(result, scan.module)
    job.last_snapshot_json = snapshot_to_json(new_snap)
    db.session.add(job)

    if not job.notify_on_change:
        db.session.commit()
        return

    rules = parse_alert_rules(job.alert_rules_json)
    alerts = evaluate_snapshot_rules(prev_snap, new_snap, rules)
    if not alerts:
        db.session.commit()
        return

    rows = _persist_alerts(scan, job, alerts)
    db.session.commit()
    _notify_alerts(scan, job, alerts, rows)
    _emit_notification_socket(scan.user_id, rows, job, scan)