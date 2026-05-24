"""Suggestions de modules OSINT non encore exécutés pour un dossier."""
from services.correlation import get_rebound_suggestions
from services.report_data import build_report_data


def suggest_investigation_steps(entity_id: int, user_id: int) -> list[dict]:
    """
    Propose des actions concrètes pour enrichir le dossier.
    [{module, target, reason, priority}, ...]
    """
    suggestions = []
    seen = set()

    for row in get_rebound_suggestions(entity_id, user_id) or []:
        key = (row.get('module'), row.get('target'))
        if key in seen:
            continue
        seen.add(key)
        suggestions.append({
            'module': row.get('module'),
            'target': row.get('target'),
            'reason': row.get('reason', 'Rebond corrélation'),
            'priority': 'high',
            'source': 'correlation',
        })

    data = build_report_data(entity_id, user_id)
    if not data:
        return suggestions[:12]

    executed_modules = set()
    for scan in data.get('scans') or []:
        executed_modules.add(scan.get('module'))

    root = (data.get('dossier') or {}).get('root_entity') or {}
    root_type = root.get('type') or 'unknown'
    root_value = root.get('value') or ''

    candidates = []
    if root_type == 'email' and '@' in root_value:
        local = root_value.split('@')[0]
        candidates.extend([
            ('dehashed', root_value, 'Fuites associées à l\'email'),
            ('epieos', root_value, 'Enrichissement Epieos'),
            ('sherlock', local, 'Pseudos dérivés de l\'email'),
        ])
    elif root_type in ('username', 'platform'):
        candidates.extend([
            ('instagram', root_value, 'Profil Instagram'),
            ('github', root_value, 'Compte GitHub'),
            ('dorking', root_value, 'Mentions web (dorking)'),
        ])
    elif root_type in ('domain', 'site', 'unknown'):
        candidates.extend([
            ('whois', root_value, 'WHOIS du domaine'),
            ('wayback', root_value, 'Historique Wayback'),
            ('hunter', root_value, 'Emails professionnels (Hunter)'),
        ])
    elif root_type == 'phone':
        candidates.append(('messaging', root_value, 'Présence messageries'))

    for mod, target, reason in candidates:
        if mod in executed_modules:
            continue
        key = (mod, target)
        if key in seen:
            continue
        seen.add(key)
        suggestions.append({
            'module': mod,
            'target': target,
            'reason': reason,
            'priority': 'medium',
            'source': 'gap_analysis',
        })

    return suggestions[:15]
