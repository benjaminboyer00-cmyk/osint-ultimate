"""Collecte structurée des données dossier pour le rapport narratif IA (Phase 3 V7)."""
import json
from datetime import datetime

from extensions import db
from models import Entity, EntityLink, Scan
from services.correlation import build_graph_json, build_entity_links_json
from services.dossier import build_dossier


def _entity_row(ent: Entity) -> dict:
    return {
        'id': ent.id,
        'type': ent.entity_type,
        'value': ent.value,
        'created_at': ent.created_at.isoformat() if ent.created_at else None,
        'source_scan_id': ent.source_scan_id,
    }


def _collect_related_scans(user_id: int, root_value: str, entity_ids: set[int]) -> list[dict]:
    root_l = (root_value or '').lower()
    out = []
    scans = (
        Scan.query.filter_by(user_id=user_id)
        .order_by(Scan.timestamp.desc())
        .limit(150)
        .all()
    )
    for s in scans:
        if s.status != 'completed':
            continue
        hit = s.target.lower() == root_l or str(s.id) in (s.result_json or '')
        if not hit:
            for eid in entity_ids:
                ent = db.session.get(Entity, eid)
                if ent and ent.value.lower() in (s.target.lower(), (s.result_json or '').lower()):
                    hit = True
                    break
        if not hit:
            continue
        sections = []
        try:
            payload = json.loads(s.result_json or '{}')
            sections = [k for k in payload if not str(k).startswith('_')]
        except Exception:
            payload = {}
        out.append({
            'id': s.id,
            'module': s.module,
            'target': s.target,
            'mode': s.mode or 'expert',
            'status': s.status,
            'started_at': s.timestamp.isoformat() if s.timestamp else None,
            'completed_at': s.completed_at.isoformat() if s.completed_at else None,
            'sections': sections,
            'sections_count': len(sections),
        })
    return out[:40]


def build_report_data(entity_id: int, user_id: int) -> dict | None:
    """
    JSON structuré pour Groq : entités, liens, scans, timeline, métadonnées.
    Retourne None si le dossier n'existe pas.
    """
    dossier = build_dossier(entity_id, user_id)
    if not dossier:
        return None

    ent = Entity.query.filter_by(id=entity_id, user_id=user_id).first()
    if not ent:
        return None

    graph = build_graph_json(entity_id, user_id)
    links_detail = build_entity_links_json(entity_id, user_id) or {}
    entity_ids = {int(n['id']) for n in graph.get('nodes', []) if n.get('id')}

    entities = []
    for nid in entity_ids:
        e = db.session.get(Entity, nid)
        if e and e.user_id == user_id:
            entities.append(_entity_row(e))

    links = []
    for row in links_detail.get('links', []):
        src_v = (row.get('source') or {}).get('value', '')
        tgt_v = (row.get('target') or {}).get('value', '')
        if src_v and tgt_v and src_v.lower() == tgt_v.lower():
            continue
        links.append({
            'type': row.get('type'),
            'direction': row.get('direction'),
            'proof': (row.get('proof') or '')[:300],
            'confidence': row.get('confidence'),
            'scan_id': row.get('scan_id'),
            'created_at': row.get('created_at'),
            'from': src_v,
            'to': tgt_v,
        })

    scans = _collect_related_scans(user_id, ent.value, entity_ids)

    sources = []
    seen = set()
    for s in scans:
        for sec in s.get('sections', []):
            if sec in seen:
                continue
            seen.add(sec)
            sources.append({'section': sec, 'scan_id': s['id']})

    return {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'dossier': {
            'entity_id': entity_id,
            'title': dossier.get('title'),
            'root_entity': dossier.get('entity'),
            'scans_count': dossier.get('scans_count'),
            'links_count': dossier.get('links_count'),
        },
        'entities': entities,
        'links': links,
        'graph': {
            'nodes_count': len(graph.get('nodes', [])),
            'edges_count': len(graph.get('edges', [])),
        },
        'scans': scans,
        'timeline': dossier.get('timeline', [])[:30],
        'web_history': dossier.get('web_history', [])[:10],
        'sources': sources,
    }


def pick_anchor_scan(entity_id: int, user_id: int) -> Scan | None:
    """Scan de référence pour signature PDF / traçabilité."""
    ent = Entity.query.filter_by(id=entity_id, user_id=user_id).first()
    if not ent:
        return None
    if ent.source_scan_id:
        s = db.session.get(Scan, ent.source_scan_id)
        if s and s.user_id == user_id and s.status == 'completed':
            return s
    scans = (
        Scan.query.filter_by(user_id=user_id, status='completed')
        .order_by(Scan.completed_at.desc().nullslast(), Scan.timestamp.desc())
        .limit(80)
        .all()
    )
    root_l = ent.value.lower()
    for s in scans:
        if s.target.lower() == root_l or root_l in (s.result_json or '').lower():
            return s
    return scans[0] if scans else None


def merge_scan_payloads(entity_id: int, user_id: int) -> dict:
    """Données consolidées pour PDF (une section par catégorie, sans doublons)."""
    from services.report_consolidate import consolidate_scan_payloads
    data = build_report_data(entity_id, user_id)
    if not data:
        return {}
    root = (data.get('dossier') or {}).get('root_entity') or {}
    root_value = root.get('value') or ''
    return consolidate_scan_payloads(entity_id, user_id, root_value)
