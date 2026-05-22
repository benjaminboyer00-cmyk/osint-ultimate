"""Scans multi-modules parallèles avec gestion des timeouts."""
import json
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout

from services.target_detector import detect_target_type, target_category

# Stratégies Expert (analyse complète)
SCAN_STRATEGIES = {
    'email': ['email', 'dehashed', 'hunter', 'epieos'],
    'phone': ['phone', 'dehashed', 'messaging'],
    'pseudo': ['sherlock', 'dehashed', 'github'],
    'username': ['sherlock', 'dehashed', 'github'],
    'domain': ['site', 'whois', 'wayback', 'hunter'],
    'site': ['site', 'whois', 'wayback', 'hunter'],
    'ip': ['ip', 'whois'],
}

# Express : 3–4 modules essentiels, rapides
EXPRESS_STRATEGIES = {
    'email': ['email', 'dehashed'],
    'phone': ['phone'],
    'pseudo': ['sherlock'],
    'username': ['sherlock'],
    'domain': ['site', 'whois'],
    'site': ['site', 'whois'],
    'ip': ['ip'],
}

MODULE_TIMEOUT_SEC = 14
GLOBAL_TIMEOUT_SEC = 50
RETRY_TIMEOUT_SEC = 20


def _resolve_target_for_module(module: str, target: str, category: str) -> str:
    t = (target or '').strip()
    if module == 'hunter' and '@' in t:
        return t.split('@', 1)[1]
    if module == 'sherlock' and category == 'email' and '@' in t:
        local = t.split('@')[0]
        if len(local) >= 2:
            return local
    return t


def _run_one_module(module: str, target: str, options: dict, category: str) -> tuple:
    """Exécute un module ; retourne (module, payload, status). status: ok|timeout|error"""
    from app import SCAN_FUNCTIONS

    func = SCAN_FUNCTIONS.get(module)
    if not func:
        return module, {'Erreur': f'Module inconnu: {module}'}, 'error'

    mod_target = _resolve_target_for_module(module, target, category)
    opts = dict(options or {})
    opts['_module_timeout'] = MODULE_TIMEOUT_SEC

    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(func, mod_target, opts)
            result = fut.result(timeout=MODULE_TIMEOUT_SEC)
    except FuturesTimeout:
        return module, {'Message': 'Délai dépassé — service lent ou indisponible', '_timeout': True}, 'timeout'
    except Exception as e:
        return module, {'Erreur': str(e)}, 'error'

    if not result:
        return module, {'Message': 'Aucune réponse', '_timeout': True}, 'timeout'
    if isinstance(result, dict):
        if result.get('_timeout') or result.get('Erreur') == 'timeout':
            return module, result, 'timeout'
        err = result.get('error') or result.get('Erreur')
        if err and 'timeout' in str(err).lower():
            return module, result, 'timeout'
    return module, result, 'ok'


def launch_multi_scan(
    target: str,
    options=None,
    mode: str = 'expert',
    modules: list | None = None,
    category: str | None = None,
) -> dict:
    """
    Lance plusieurs modules en parallèle.
    Retourne un dict avec sections par module + clé _meta (timeouts, errors).
    """
    options = options or {}
    category = category or target_category(target)
    strategies = EXPRESS_STRATEGIES if mode == 'express' else SCAN_STRATEGIES
    module_list = modules or strategies.get(category) or [detect_target_type(target)]

    # Filtrer modules disponibles
    from app import SCAN_FUNCTIONS
    module_list = [m for m in module_list if m in SCAN_FUNCTIONS]

    if not module_list:
        module_list = [detect_target_type(target)]

    results = {}
    timeouts = []
    errors = {}
    sources = {}

    max_workers = min(6, len(module_list))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_run_one_module, mod, target, options, category): mod
            for mod in module_list
        }
        try:
            for fut in as_completed(futures, timeout=GLOBAL_TIMEOUT_SEC):
                mod = futures[fut]
                try:
                    m, payload, status = fut.result(timeout=2)
                    section = f'Module: {m}'
                    if status == 'timeout':
                        timeouts.append(m)
                        payload = payload or {}
                        payload['_status'] = 'timeout'
                        results[section] = payload
                        sources[m] = 'timeout'
                    elif status == 'error':
                        err_msg = payload.get('Erreur') or payload.get('error') or 'Erreur'
                        errors[m] = str(err_msg)[:200]
                        results[section] = payload
                        sources[m] = 'error'
                    else:
                        results[section] = payload
                        sources[m] = payload.get('_cached') and 'cache' or 'live'
                except Exception as e:
                    timeouts.append(mod)
                    errors[mod] = str(e)[:200]
        except FuturesTimeout:
            for mod in module_list:
                if f'Module: {mod}' not in results and mod not in timeouts:
                    timeouts.append(mod)
                    results[f'Module: {mod}'] = {
                        'Message': 'Scan global interrompu (timeout)',
                        '_timeout': True,
                    }

    # Wayback → section dossier « Historique Web »
    for key, val in list(results.items()):
        if 'wayback' in key.lower() and isinstance(val, dict):
            snaps = val.get('Snapshots')
            if isinstance(snaps, list):
                results['Historique Web (Wayback)'] = {
                    'Snapshots': snaps,
                    'Total': val.get('Total archivé', len(snaps)),
                    'Domaine': val.get('Domaine'),
                }

    merged = {
        '_meta': {
            'multi': True,
            'category': category,
            'target': target,
            'mode': mode,
            'modules': module_list,
            'timeouts': timeouts,
            'errors': errors,
            'sources': sources,
        },
        **results,
    }
    return merged


def merge_retry_results(existing: dict, retry_payload: dict) -> dict:
    """Fusionne les résultats d'un retry dans le scan existant."""
    out = dict(existing)
    meta = dict(out.get('_meta') or {})
    timeouts = list(meta.get('timeouts') or [])
    errors = dict(meta.get('errors') or {})

    for section, data in retry_payload.items():
        if section == '_meta':
            continue
        out[section] = data
        mod = section.replace('Module: ', '').strip()
        if mod in timeouts:
            timeouts.remove(mod)
        errors.pop(mod, None)

    meta['timeouts'] = timeouts
    meta['errors'] = errors
    out['_meta'] = meta
    return out


def retry_timeout_modules(scan, options=None) -> dict:
    """Relance uniquement les modules en timeout d'un scan multi."""
    data = json.loads(scan.result_json or '{}')
    meta = data.get('_meta') or {}
    timeout_mods = list(meta.get('timeouts') or [])
    if not timeout_mods:
        return data

    opts = dict(options or {})
    opts['_retry'] = True
    category = meta.get('category') or target_category(scan.target)

    retry_results = {}
    new_timeouts = []
    new_errors = {}

    for mod in timeout_mods:
        m, payload, status = _run_one_module(mod, scan.target, opts, category)
        section = f'Module: {m}'
        retry_results[section] = payload
        if status == 'timeout':
            new_timeouts.append(m)
        elif status == 'error':
            new_errors[m] = str(payload.get('Erreur', 'Erreur'))[:200]

    merged = merge_retry_results(data, retry_results)
    merged['_meta']['timeouts'] = new_timeouts
    merged['_meta']['errors'] = {**merged['_meta'].get('errors', {}), **new_errors}
    return merged
