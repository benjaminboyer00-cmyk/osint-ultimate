"""Résumé OSINT pour un nœud du graphe (panneau latéral)."""
import json

from models import Scan


def build_entity_intel(entity_id: int, user_id: int, entity_value: str, entity_type: str) -> dict:
    """Derniers scans et extraits utiles pour affichage dans le graphe."""
    value_l = (entity_value or '').lower().strip()
    scans = (
        Scan.query.filter_by(user_id=user_id, status='completed')
        .order_by(Scan.completed_at.desc().nullslast(), Scan.timestamp.desc())
        .limit(80)
        .all()
    )
    highlights = []
    related = []
    for s in scans:
        if s.target.lower() != value_l and value_l not in (s.result_json or '').lower():
            continue
        related.append({'scan_id': s.id, 'module': s.module, 'target': s.target})
        try:
            data = json.loads(s.result_json or '{}')
        except Exception:
            continue
        if isinstance(data, dict):
            for key in ('WHOIS', 'Domaine WHOIS', 'Module: whois', 'DNS', 'Géolocalisation',
                        'Fuites (HIBP)', 'Module: dehashed', 'MX', 'Module: ip'):
                block = data.get(key)
                if isinstance(block, dict) and not block.get('_timeout'):
                    if block.get('Erreur') or block.get('error'):
                        highlights.append(f'{key}: {block.get("Erreur") or block.get("error")}')
                    else:
                        parts = []
                        for k, v in list(block.items())[:6]:
                            if str(k).startswith('_'):
                                continue
                            parts.append(f'{k}: {v}')
                        if parts:
                            highlights.append(f'{key} — ' + '; '.join(parts)[:200])
            if s.module == 'multi':
                for sec, content in data.items():
                    if sec.startswith('Module:') and isinstance(content, dict):
                        if content.get('Erreur'):
                            highlights.append(f'{sec}: {content["Erreur"]}')
                        elif not content.get('_timeout'):
                            keys = [k for k in content if not str(k).startswith('_')][:4]
                            if keys:
                                highlights.append(f'{sec} — {", ".join(keys)}')
        if len(related) >= 5:
            break

    return {
        'entity_id': entity_id,
        'entity_type': entity_type,
        'value': entity_value,
        'highlights': highlights[:12],
        'scans': related[:8],
        'hint': 'Lancez « Analyser » ou « Pivoter » pour enrichir ce nœud.' if not highlights else None,
    }
