"""Consolidation des scans pour rapport PDF — déduplication et faits techniques."""
import json
import re
from datetime import datetime

from extensions import db
from models import Scan
from services.result_hints import is_missing_key_error

# Sections canoniques (une seule fois dans le PDF)
SECTION_ALIASES: dict[str, list[str]] = {
    'WHOIS': ['WHOIS', 'Domaine WHOIS', 'Module: whois'],
    'DNS': ['DNS'],
    'HTTP': ['HTTP', 'Headers HTTP'],
    'IP': ['IP'],
    'Géolocalisation': ['Géolocalisation', 'Géolocalisation IP'],
    'SSL/TLS': ['SSL/TLS'],
    'MX': ['MX'],
    'SPF': ['SPF'],
    'DMARC': ['DMARC'],
    'Hunter': ['Hunter', 'Module: hunter'],
    'Dehashed': ['Dehashed', 'Module: dehashed'],
    'Shodan': ['Shodan', 'Module: ip'],
    'Wayback': ['Historique Web (Wayback)', 'Module: wayback'],
    'Fuites (HIBP)': ['Fuites (HIBP)', 'Module: email'],
    'Téléphone': ['Module: phone'],
    'Sherlock': ['Module: sherlock', 'Module: pseudo'],
    'Epieos': ['Module: epieos'],
    'OTX': ['OTX', 'Module: otx'],
    'Dorking': ['Module: dorking'],
}

# Modules optionnels (clé API) — affichage si jamais exécutés
OPTIONAL_API_MODULES = {
    'hunter': ('Hunter', 'Clé API Hunter manquante — module non exécuté'),
    'dehashed': ('Dehashed', 'Clé API Dehashed manquante — module non exécuté'),
    'hibp': ('Fuites (HIBP)', 'Clé API HIBP manquante — module non exécuté'),
    'shodan': ('Shodan', 'Clé API Shodan manquante — module non exécuté'),
    'epieos': ('Epieos', 'Clé API Epieos manquante — module non exécuté'),
    'otx': ('OTX', 'Clé API OTX manquante — module non exécuté'),
}


def _normalize_domain(value: str) -> str:
    v = (value or '').strip().lower()
    for prefix in ('http://', 'https://', 'www.'):
        if v.startswith(prefix):
            v = v[len(prefix):]
    return v.split('/')[0].split(':')[0]


def _section_score(content) -> int:
    """Plus le score est élevé, plus la section est complète."""
    if content is None:
        return -10
    if isinstance(content, str):
        if 'non configur' in content.lower() or 'clé ' in content.lower():
            return 1
        return 2 if content else 0
    if isinstance(content, dict):
        if content.get('_timeout'):
            return 0
        if content.get('Erreur') or content.get('error'):
            return 1
        keys = [k for k in content if not str(k).startswith('_')]
        return 10 + len(keys)
    if isinstance(content, list):
        return 5 + min(len(content), 20)
    return 3


def _canonical_key(section_name: str) -> str | None:
    for canon, aliases in SECTION_ALIASES.items():
        if section_name == canon or section_name in aliases:
            return canon
    if section_name.startswith('Module:'):
        mod = section_name.replace('Module:', '').strip()
        for canon, aliases in SECTION_ALIASES.items():
            if f'Module: {mod}' in aliases or mod.lower() in canon.lower():
                return canon
    if re.match(r'^.+\s+\(scan #\d+\)$', section_name):
        base = section_name.rsplit(' (scan #', 1)[0]
        return _canonical_key(base) or base
    return None


def _format_display_value(obj, depth=0):
    """Remplace null / vides ambigus par libellés explicites."""
    if depth > 6:
        return '…'
    if obj is None:
        return '— (non renseigné)'
    if isinstance(obj, dict):
        if obj.get('_not_executed'):
            return obj
        out = {}
        for k, v in obj.items():
            if str(k).startswith('_') and k not in ('_source', '_cached'):
                continue
            out[k] = _format_display_value(v, depth + 1)
        if obj.get('Erreur') and len(out) <= 2:
            return {
                'Statut': 'Échec de collecte',
                'Message': str(obj.get('Erreur'))[:500],
                '_source': obj.get('_source'),
            }
        if obj.get('_timeout'):
            return {
                'Statut': 'Timeout',
                'Message': str(obj.get('Erreur') or 'Service inaccessible')[:300],
            }
        return out
    if isinstance(obj, list):
        return [_format_display_value(x, depth + 1) for x in obj[:80]]
    if isinstance(obj, str) and obj.strip().lower() in ('null', 'none', ''):
        return '— (non renseigné)'
    return obj


def consolidate_scan_payloads(entity_id: int, user_id: int, root_value: str | None = None) -> dict:
    """
    Fusionne les scans du dossier : une section par catégorie (dernier état connu),
    historique des scans en métadonnées, statut des modules optionnels.
    """
    from sqlalchemy import or_
    from services.dossier_access import get_dossier_context

    ctx = get_dossier_context(entity_id, user_id, min_role='reader')
    owner_id = ctx['owner_user_id'] if ctx else user_id
    scans = (
        Scan.query.filter(
            Scan.status == 'completed',
            or_(Scan.user_id == owner_id, Scan.root_entity_id == entity_id),
        )
        .order_by(Scan.timestamp.asc())
        .limit(100)
        .all()
    )
    root_l = (root_value or '').lower()
    related: list[tuple[Scan, dict]] = []

    for s in scans:
        if root_l and s.target.lower() != root_l and root_l not in (s.result_json or '').lower():
            continue
        try:
            payload = json.loads(s.result_json or '{}')
        except json.JSONDecodeError:
            continue
        related.append((s, payload))

    if not related and scans:
        s = scans[-1]
        try:
            related = [(s, json.loads(s.result_json or '{}'))]
        except Exception:
            related = []

    best: dict[str, tuple[int, object, int]] = {}  # canon -> (score, content, scan_id)
    modules_seen = set()
    optional_ran = set()  # hunter, dehashed, …
    scan_history = []
    whois_errors: list[str] = []

    for s, payload in related:
        modules_seen.add(s.module)
        for key in payload:
            if key.startswith('Module:'):
                optional_ran.add(key.replace('Module:', '').strip().lower())
        scan_history.append({
            'scan_id': s.id,
            'module': s.module,
            'target': s.target,
            'completed_at': (s.completed_at or s.timestamp).isoformat() if (s.completed_at or s.timestamp) else None,
            'sections': [k for k in payload if not str(k).startswith('_')][:12],
        })
        for key, content in payload.items():
            if str(key).startswith('_'):
                continue
            canon = _canonical_key(key) or key
            if canon == 'WHOIS' and isinstance(content, dict):
                err = content.get('Erreur') or content.get('error')
                if err:
                    msg = str(err)[:200]
                    if msg not in whois_errors:
                        whois_errors.append(msg)
            score = _section_score(content)
            prev = best.get(canon)
            if prev is None or score >= prev[0]:
                best[canon] = (score, content, s.id)

    modules_status = {}
    for mod, (section, default_reason) in OPTIONAL_API_MODULES.items():
        ran = mod in modules_seen or mod in optional_ran
        entry = {'executed': ran, 'section': section}
        if not ran:
            entry['reason'] = default_reason
        modules_status[mod] = entry

    out: dict = {
        '_meta': {
            'dossier_entity_id': entity_id,
            'consolidated': True,
            'scan_count': len(related),
            'modules_executed': sorted(modules_seen | optional_ran),
            'modules_status': modules_status,
            'scan_history': scan_history[-25:],
        },
    }

    if whois_errors:
        out['_meta']['whois_notice'] = (
            'WHOIS : information partielle ou indisponible. '
            + whois_errors[0]
        )

    for canon, (_score, content, scan_id) in sorted(best.items()):
        display = _format_display_value(content)
        if isinstance(display, dict):
            display = dict(display)
            if display.get('_not_executed'):
                display['executed'] = False
            else:
                display['executed'] = True
                display['_dernier_scan'] = f'#{scan_id}'
                if _section_score(content) <= 1 and (content.get('Erreur') or content.get('_timeout')):
                    display['executed'] = True
                    display['resultat'] = 'Aucun résultat exploitable'
        out[canon] = display

    # Modules API jamais vus sur le dossier
    for mod, (section, msg) in OPTIONAL_API_MODULES.items():
        if mod in modules_seen or mod in optional_ran:
            continue
        if section in out:
            continue
        out[section] = {
            '_not_executed': True,
            'executed': False,
            'Statut': 'Non exécuté',
            'Raison': msg,
        }

    # Marquer clé manquante si scan module a tourné mais échoué pour clé
    for s, payload in related:
        for key, content in payload.items():
            if not isinstance(content, dict):
                continue
            if is_missing_key_error(content):
                canon = _canonical_key(key) or key
                out[canon] = {
                    '_not_executed': True,
                    'executed': False,
                    'Statut': 'Non exécuté',
                    'Raison': content.get('Erreur') or content.get('Message') or 'Clé API manquante',
                }

    return out


def extract_technical_facts(consolidated: dict, root_value: str = '') -> dict:
    """Bloc structuré pour le narratif IA — décrit la cible, pas les scans."""
    facts = {
        'cible': root_value,
        'infrastructure': [],
        'reseau': [],
        'identite': [],
        'securite': [],
        'lacunes': [],
    }
    if not isinstance(consolidated, dict):
        return facts

    whois = consolidated.get('WHOIS')
    if isinstance(whois, dict):
        if whois.get('_not_executed'):
            facts['lacunes'].append(whois.get('Raison', 'WHOIS non disponible'))
        elif whois.get('Erreur') or whois.get('Statut') == 'Échec de collecte':
            facts['lacunes'].append(f"WHOIS : {whois.get('Message') or whois.get('Erreur', 'indisponible')}")
        else:
            line = ', '.join(filter(None, [
                f"Registrar : {whois.get('Registrar')}" if whois.get('Registrar') else None,
                f"Création : {whois.get('Création')}" if whois.get('Création') else None,
                f"Expiration : {whois.get('Expiration')}" if whois.get('Expiration') else None,
                f"Pays registrant : {whois.get('Pays')}" if whois.get('Pays') and whois.get('Pays') != 'N/A' else None,
                f"Organisation : {whois.get('Organisation')}" if whois.get('Organisation') and whois.get('Organisation') != 'N/A' else None,
            ]))
            if line:
                facts['identite'].append(line)

    dns = consolidated.get('DNS')
    if isinstance(dns, dict):
        a = dns.get('A') or []
        mx = dns.get('MX') or []
        ns = dns.get('NS') or []
        if a:
            facts['infrastructure'].append(f"Enregistrements A : {', '.join(str(x) for x in a[:5])}")
        if mx:
            facts['infrastructure'].append(f"MX : {', '.join(str(x) for x in mx[:3])}")
        if ns:
            facts['infrastructure'].append(f"NS : {', '.join(str(x) for x in ns[:3])}")

    ip = consolidated.get('IP')
    geo = consolidated.get('Géolocalisation')
    if ip:
        facts['reseau'].append(f"IP résolue : {ip}")
    if isinstance(geo, dict) and not geo.get('_not_executed'):
        gline = ', '.join(filter(None, [
            geo.get('Ville'), geo.get('Région'), geo.get('Pays'),
            f"FAI {geo.get('FAI')}" if geo.get('FAI') else None,
            f"AS {geo.get('AS')}" if geo.get('AS') else None,
            f"Organisation {geo.get('Organisation')}" if geo.get('Organisation') else None,
        ]))
        if gline:
            facts['reseau'].append(f"Hébergement / géolocalisation : {gline}")
        if geo.get('Hébergement') == 'Oui' or geo.get('hosting'):
            facts['reseau'].append('IP identifiée comme hébergement / datacenter')

    ssl = consolidated.get('SSL/TLS')
    if isinstance(ssl, dict) and ssl.get('Émetteur'):
        facts['securite'].append(
            f"Certificat TLS — émetteur : {ssl.get('Émetteur')}, "
            f"valide jusqu'au : {ssl.get('Valide jusqu\'au', 'N/A')}"
        )

    http = consolidated.get('HTTP')
    if isinstance(http, dict) and http.get('Statut'):
        facts['infrastructure'].append(f"HTTP statut {http.get('Statut')} — URL {http.get('URL finale', '')}")

    for mod in ('Hunter', 'Dehashed', 'Fuites (HIBP)'):
        block = consolidated.get(mod)
        if isinstance(block, dict) and block.get('_not_executed'):
            facts['lacunes'].append(block.get('Raison', f'{mod} non exécuté'))

    meta = consolidated.get('_meta') or {}
    if meta.get('whois_notice') and meta['whois_notice'] not in facts['lacunes']:
        facts['lacunes'].append(meta['whois_notice'])

    return facts
