"""Snapshots comparables pour détection de changements surveillance."""
import json
import hashlib

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
    """Extrait signaux menace depuis un résultat de scan."""
    signals = {'threat_score': 0, 'sections': {}, 'has_error': False}
    if not isinstance(result, dict):
        return signals
    if module == 'multi' or result.get('_meta', {}).get('multi'):
        for key, val in result.items():
            if key.startswith('_'):
                continue
            mod = key.replace('Module:', '').strip() if key.startswith('Module:') else key
            if mod in THREAT_MODULES or mod == 'dehashed':
                if isinstance(val, dict):
                    signals['sections'][mod] = _threat_score(val)
                    signals['threat_score'] += signals['sections'][mod]
    else:
        signals['sections'][module] = _threat_score(result)
        signals['threat_score'] = signals['sections'][module]
    signals['has_error'] = bool(result.get('error') or result.get('Erreur'))
    return signals


def _walk_sections(result: dict):
    """Parcourt sections simples et multi-modules."""
    if not isinstance(result, dict):
        return
    yield '', result
    for key, val in result.items():
        if key.startswith('_'):
            continue
        if key.startswith('Module:'):
            yield key, val if isinstance(val, dict) else {}
        elif isinstance(val, dict) and not key.startswith('Module:'):
            yield key, val


def _whois_from_block(block: dict) -> dict:
    if not isinstance(block, dict):
        return {}
    return {
        'creation': str(block.get('Création') or block.get('creation') or ''),
        'expiration': str(block.get('Expiration') or block.get('expiration') or ''),
        'registrar': str(block.get('Registrar') or block.get('registrar') or ''),
        'status': str(block.get('Statut') or block.get('status') or ''),
    }


def _extract_whois(result: dict) -> dict:
    for _k, block in _walk_sections(result):
        if not isinstance(block, dict):
            continue
        if 'WHOIS' in block or 'Création' in block or 'Registrar' in block:
            w = _whois_from_block(block.get('WHOIS') if isinstance(block.get('WHOIS'), dict) else block)
            if any(w.values()):
                return w
        if 'Domaine WHOIS' in block:
            w = _whois_from_block(block['Domaine WHOIS'])
            if any(w.values()):
                return w
    return {}


def _extract_subdomains(result: dict) -> list[str]:
    found = set()
    for _k, block in _walk_sections(result):
        if not isinstance(block, dict):
            continue
        for key in ('Sous-domaines', 'Subdomains', 'subdomains', 'Sous domaines'):
            val = block.get(key)
            if isinstance(val, list):
                found.update(str(x).lower() for x in val if x)
            elif isinstance(val, str) and val:
                found.add(val.lower())
        dns = block.get('DNS') or block.get('dns')
        if isinstance(dns, dict):
            for rtype in ('A', 'AAAA', 'CNAME', 'MX', 'NS'):
                recs = dns.get(rtype) or []
                if isinstance(recs, list):
                    found.update(str(r).lower()[:200] for r in recs)
    return sorted(found)


def _extract_breaches(result: dict) -> list[str]:
    names = set()
    for _k, block in _walk_sections(result):
        if not isinstance(block, dict):
            continue
        hibp = block.get('Fuites (HIBP)') or result.get('Fuites (HIBP)')
        if isinstance(hibp, list):
            names.update(str(x) for x in hibp)
        entries = block.get('Entrées') or block.get('entries') or []
        if isinstance(entries, list):
            for row in entries:
                if isinstance(row, dict):
                    base = row.get('Base') or row.get('database_name') or row.get('name')
                    if base:
                        names.add(str(base))
        if block.get('Fuites trouvées') and int(block.get('Fuites trouvées') or 0) > 0:
            names.add(f"dehashed:{block.get('Requête', '')[:40]}")
    return sorted(names)


def _section_fingerprint(result: dict) -> list[str]:
    keys = []
    if not isinstance(result, dict):
        return keys
    for k in sorted(result.keys()):
        if k.startswith('_'):
            continue
        keys.append(k)
    return keys


def build_monitor_snapshot(result: dict, module: str) -> dict:
    """État sérialisable pour comparaison entre deux scans programmés."""
    signals = extract_signals(result, module)
    return {
        'threat_score': signals.get('threat_score', 0),
        'threat_sections': signals.get('sections', {}),
        'has_error': signals.get('has_error', False),
        'whois': _extract_whois(result),
        'whois_hash': hashlib.sha256(
            json.dumps(_extract_whois(result), sort_keys=True).encode()
        ).hexdigest()[:16],
        'subdomains': _extract_subdomains(result),
        'breaches': _extract_breaches(result),
        'sections': _section_fingerprint(result),
    }


def snapshot_to_json(snap: dict) -> str:
    return json.dumps(snap, ensure_ascii=False, sort_keys=True, default=str)


def snapshot_from_json(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None
