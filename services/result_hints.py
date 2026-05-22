"""Annotations résultats — clés API manquantes, liens manuels."""
import re

SETTINGS_URL = '/settings'

# (regex sur message d'erreur, clé settings, libellé)
KEY_ERROR_RULES = [
    (r'hibp|have i been', 'hibp', 'HIBP'),
    (r'hunter', 'hunter', 'Hunter.io'),
    (r'dehashed', 'dehashed', 'Dehashed'),
    (r'epieos', 'epieos', 'Epieos'),
    (r'shodan', 'shodan', 'Shodan'),
    (r'otx|alienvault', 'otx', 'OTX'),
    (r'numverify', 'numverify', 'Numverify'),
    (r'github.*token|github', 'github', 'GitHub'),
]


def _msg(result: dict) -> str:
    return ' '.join(
        str(result.get(k, ''))
        for k in ('Erreur', 'error', 'Message', 'message', 'Fuites (HIBP)', 'SMTP')
    ).lower()


def is_missing_key_error(result: dict) -> bool:
    if not isinstance(result, dict):
        return False
    msg = _msg(result)
    return bool(
        'non configurée' in msg
        or 'non configuré' in msg
        or 'api_key' in msg
        or 'clé ' in msg and 'invalide' not in msg
        or 'clé hunter' in msg
    )


def annotate_result(module: str, result: dict, options: dict | None = None) -> dict:
    """Ajoute _key_required et _manual_link pour l'UI."""
    if not isinstance(result, dict):
        return result
    out = dict(result)
    if is_missing_key_error(out):
        out['_key_required'] = True
        out['_settings_url'] = SETTINGS_URL
        for pattern, key, label in KEY_ERROR_RULES:
            if re.search(pattern, _msg(out), re.I):
                out['_key_label'] = label
                break
        else:
            out['_key_label'] = module
    if out.get('Lien manuel') or out.get('Lien'):
        out['_manual_link'] = out.get('Lien manuel') or out.get('Lien')
    if out.get('_degraded'):
        out['_badge'] = 'scraping'
    return out


def annotate_multi_results(data: dict) -> dict:
    """Parcourt les sections Module: * d'un scan multi."""
    if not isinstance(data, dict):
        return data
    out = dict(data)
    for key, val in list(out.items()):
        if key.startswith('Module:') and isinstance(val, dict):
            mod = key.replace('Module:', '').strip()
            out[key] = annotate_result(mod, val)
    return out
