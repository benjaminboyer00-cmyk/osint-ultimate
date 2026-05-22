"""Formatage des résultats pour la vue Express (langage simple)."""
from services.target_detector import express_label


def build_express_card(module: str, target: str, result: dict) -> dict:
    """Construit une carte de synthèse lisible pour le grand public."""
    if not result or result.get('error') or result.get('Erreur'):
        err = result.get('error') or result.get('Erreur', 'Erreur inconnue')
        return {
            'module': module,
            'type': express_label(module),
            'target': target,
            'status': 'error',
            'title': 'Analyse impossible',
            'highlights': [],
            'risks': [str(err)],
            'next_steps': ['Vérifiez le format de la cible et réessayez.'],
        }

    highlights = []
    risks = []
    next_steps = []

    if module == 'phone':
        for k in ('Pays', 'Opérateur', 'Type', 'Format international', 'Valide'):
            if result.get(k):
                highlights.append({'label': k, 'value': str(result[k])})
        if 'Surtaxé' in str(result.get('Type', '')):
            risks.append('Numéro surtaxé — méfiance aux rappels.')
        next_steps.append('Rechercher ce numéro sur les réseaux sociaux (mode Expert).')

    elif module == 'email':
        for k in ('Format', 'Domaine', 'MX', 'SPF', 'Gravatar'):
            if result.get(k):
                highlights.append({'label': k, 'value': str(result[k])[:120]})
        fuites = result.get('Fuites (HIBP)')
        if fuites and fuites != 'Aucune fuite connue ✓':
            risks.append(f'Fuites de données détectées : {fuites}')
        if result.get('DMARC') == 'Absent':
            risks.append('DMARC absent — domaine potentiellement usurpé.')
        local = target.split('@')[0] if '@' in target else ''
        if local:
            next_steps.append(f'Rechercher le pseudo « {local} » sur les réseaux (Sherlock).')

    elif module == 'ip':
        geo = result.get('Géolocalisation', {})
        if isinstance(geo, dict):
            for k in ('Pays', 'Ville', 'FAI', 'Organisation'):
                if geo.get(k):
                    highlights.append({'label': k, 'value': str(geo[k])})
        sh = result.get('Shodan', {})
        if isinstance(sh, dict):
            ports = sh.get('Ports', [])
            if ports:
                highlights.append({'label': 'Ports Shodan', 'value': ', '.join(map(str, ports[:15]))})
            cves = sh.get('CVE (top 10)', [])
            if cves:
                risks.append(f'Vulnérabilités connues : {", ".join(cves[:5])}')
        if geo.get('Proxy/VPN', '').startswith('⚠️'):
            risks.append('IP identifiée comme proxy/VPN.')

    elif module in ('sherlock', 'pseudo'):
        found = [(k, v) for k, v in result.items() if 'Existe' in str(v) or '✓' in str(v)]
        highlights.append({'label': 'Comptes trouvés', 'value': str(len(found))})
        for name, status in found[:5]:
            highlights.append({'label': name, 'value': status})
        if not found:
            next_steps.append('Essayer des variantes du pseudo (chiffres, underscores).')
        else:
            next_steps.append('Ouvrir les profils trouvés pour vérifier manuellement.')

    elif module == 'site':
        for k in ('WHOIS', 'IP', 'HTTP'):
            v = result.get(k)
            if v:
                highlights.append({'label': k, 'value': str(v)[:150]})
        sec = result.get('En-têtes sécurité', {})
        if isinstance(sec, dict):
            missing = sum(1 for v in sec.values() if 'Absent' in str(v))
            if missing >= 3:
                risks.append(f'{missing} en-têtes de sécurité manquants.')

    else:
        for k, v in list(result.items())[:6]:
            highlights.append({'label': k, 'value': str(v)[:100]})

    if not next_steps:
        next_steps.append('Passez en mode Expert pour une analyse approfondie.')
        next_steps.append('Générez un rapport PDF pour documenter l\'investigation.')

    return {
        'module': module,
        'type': express_label(module),
        'target': target,
        'status': 'ok',
        'title': f'Résultat pour {target}',
        'highlights': highlights[:12],
        'risks': risks[:6],
        'next_steps': next_steps[:5],
        'raw_module': module,
    }
