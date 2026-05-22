"""Règles d'alerte surveillance — Phase 7 V7."""
import json

# Règles activables par job
RULE_IDS = (
    'threat_change',
    'data_breach',
    'whois_change',
    'new_subdomain',
    'new_section',
    'scan_error',
)

RULE_LABELS = {
    'threat_change': 'Hausse menace (OTX, URLhaus, Dehashed…)',
    'data_breach': 'Nouvelle fuite de données (HIBP / Dehashed)',
    'whois_change': 'Changement WHOIS (domaine)',
    'new_subdomain': 'Nouveau sous-domaine / enregistrement DNS',
    'new_section': 'Nouvelle source de données dans le scan',
    'scan_error': 'Échec ou erreur de scan',
}

DEFAULT_RULES = ['threat_change', 'data_breach', 'whois_change', 'new_subdomain', 'scan_error']


def parse_alert_rules(raw) -> list[str]:
    """Parse JSON, liste ou checkboxes formulaire."""
    if raw is None:
        return list(DEFAULT_RULES)
    if isinstance(raw, list):
        return [r for r in raw if r in RULE_IDS]
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return list(DEFAULT_RULES)
        try:
            data = json.loads(s)
            if isinstance(data, list):
                return [r for r in data if r in RULE_IDS]
        except json.JSONDecodeError:
            pass
        if s in RULE_IDS:
            return [s]
    return list(DEFAULT_RULES)


def rules_from_form(form) -> list[str]:
    """Extrait les règles cochées dans le formulaire monitoring."""
    selected = form.getlist('alert_rules') if hasattr(form, 'getlist') else []
    if not selected and form.get('notify_on_change') == 'on':
        return list(DEFAULT_RULES)
    return parse_alert_rules(selected)


def serialize_rules(rules: list[str]) -> str:
    return json.dumps(parse_alert_rules(rules), ensure_ascii=False)
