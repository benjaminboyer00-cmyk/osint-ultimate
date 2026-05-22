"""Alertes intelligentes surveillance — détection changements menace & résultats."""
import json
import logging

from extensions import db
from models import Scan, ScheduledScan, Webhook

logger = logging.getLogger(__name__)

THREAT_MODULES = ('otx', 'urlhaus', 'dehashed')


def _threat_score(data: dict) -> int:
    if not isinstance(data, dict):
        return 0
    score = 0
    if data.get('listed'):
        score += 3
    if data.get('pulse_count', 0) > 0:
        score += min(5, int(data.get('pulse_count', 0)))
    if data.get('risk') == 'élevé':
        score += 2
    if data.get('url_count', 0) > 0:
        score += 2
    entries = data.get('entries') or data.get('Entrées') or []
    if isinstance(entries, list) and len(entries) > 0:
        score += min(3, len(entries))
    return score


def extract_signals(result: dict, module: str) -> dict:
    """Extrait signaux comparables depuis un résultat de scan."""
    signals = {'threat_score': 0, 'sections': {}}
    if not isinstance(result, dict):
        return signals

    if module == 'multi' or result.get('_meta', {}).get('multi'):
        for key, val in result.items():
            if key.startswith('_') or key.startswith('Module:'):
                continue
            mod = key.replace('Module:', '').strip() if key.startswith('Module:') else key
            if mod in THREAT_MODULES or mod in ('dehashed',):
                signals['sections'][mod] = _threat_score(val)
                signals['threat_score'] += signals['sections'][mod]
    else:
        signals['sections'][module] = _threat_score(result)
        signals['threat_score'] = signals['sections'][module]

    signals['has_error'] = bool(result.get('error') or result.get('Erreur'))
    return signals


def compare_signals(prev: dict, new: dict) -> list[dict]:
    """Compare deux jeux de signaux ; retourne liste d'alertes."""
    alerts = []
    if new.get('has_error') and not prev.get('has_error'):
        alerts.append({
            'level': 'warning',
            'type': 'scan_error',
            'message': 'Le dernier scan a échoué ou retourné une erreur.',
        })

    prev_score = prev.get('threat_score', 0)
    new_score = new.get('threat_score', 0)
    if new_score > prev_score and new_score > 0:
        alerts.append({
            'level': 'high',
            'type': 'threat_increase',
            'message': f'Niveau de menace en hausse ({prev_score} → {new_score}).',
        })

    for mod, new_val in (new.get('sections') or {}).items():
        old_val = (prev.get('sections') or {}).get(mod, 0)
        if new_val > old_val and new_val > 0:
            alerts.append({
                'level': 'high',
                'type': f'{mod}_change',
                'message': f'Nouveau signal {mod} (score {old_val} → {new_val}).',
            })

    if not alerts and new_score == 0 and prev_score == 0:
        return alerts

    if new_score == 0 and prev_score > 0:
        alerts.append({
            'level': 'info',
            'type': 'threat_cleared',
            'message': 'Plus de signal de menace détecté sur cette cible.',
        })

    return alerts


def check_scheduled_scan_alerts(scan: Scan, result: dict):
    """Après un scan programmé : compare au précédent et notifie si changement."""
    job_id = scan.scheduled_scan_id
    if not job_id or not scan.user_id:
        return

    job = db.session.get(ScheduledScan, job_id)
    if not job or not job.notify_on_change:
        return

    prev_scan = (
        Scan.query.filter(
            Scan.scheduled_scan_id == job_id,
            Scan.id != scan.id,
            Scan.status == 'completed',
        )
        .order_by(Scan.completed_at.desc())
        .first()
    )
    if not prev_scan or not prev_scan.result_json:
        return

    try:
        prev_data = json.loads(prev_scan.result_json)
    except Exception:
        return

    prev_sig = extract_signals(prev_data, prev_scan.module)
    new_sig = extract_signals(result, scan.module)
    alerts = compare_signals(prev_sig, new_sig)
    if not alerts:
        return

    _notify_alerts(scan, job, alerts)


def _notify_alerts(scan: Scan, job: ScheduledScan, alerts: list[dict]):
    payload = {
        'event': 'monitoring.alert',
        'scan_id': scan.id,
        'job_id': job.id,
        'target': scan.target,
        'module': scan.module,
        'alerts': alerts,
    }
    logger.info('Alerte monitoring job #%s: %s', job.id, alerts)

    url = job.webhook_url
    hooks = []
    if url:
        hooks.append(url)
    for wh in Webhook.query.filter_by(user_id=job.user_id, enabled=True).all():
        if wh.url not in hooks:
            hooks.append(wh.url)

    if not hooks:
        return

    import requests
    body = json.dumps(payload, ensure_ascii=False).encode()
    for hook_url in hooks:
        try:
            requests.post(
                hook_url,
                data=body,
                headers={
                    'Content-Type': 'application/json',
                    'X-OSINT-Event': 'monitoring.alert',
                },
                timeout=8,
            )
        except Exception as e:
            logger.warning('Webhook alerte: %s', e)
