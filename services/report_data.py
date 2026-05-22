"""Collecte structurée des données dossier pour le rapport narratif IA (Phase 3 V7)."""
import json
import logging
from datetime import datetime

from extensions import db
from models import Entity, EntityLink, Scan
from services.correlation import build_graph_json, build_entity_links_json
from services.dossier import build_dossier
from services.dossier_scans import link_scans_to_dossier

logger = logging.getLogger(__name__)


def _entity_row(ent: Entity) -> dict:
    return {
        'id': ent.id,
        'type': ent.entity_type,
        'value': ent.value,
        'created_at': ent.created_at.isoformat() if ent.created_at else None,
        'source_scan_id': ent.source_scan_id,
    }


def _scan_matches_dossier(
    s: Scan,
    root_l: str,
    entity_ids: set[int],
    target_values: set[str],
) -> bool:
    t = (s.target or '').lower().strip()
    t_at = t.lstrip('@')
    if s.root_entity_id and int(s.root_entity_id) in entity_ids:
        return True
    if t == root_l or t_at == root_l.lstrip('@') or f'@{t_at}' == root_l:
        return True
    if t in target_values or t_at in target_values:
        return True
    body = (s.result_json or '').lower()
    if root_l and root_l in body:
        return True
    for eid in entity_ids:
        ent = db.session.get(Entity, eid)
        if not ent:
            continue
        ev = (ent.value or '').lower()
        if ev == t or ev in body or t in ev:
            return True
    return False


def _collect_related_scans(
    owner_id: int,
    root_entity_id: int,
    root_value: str,
    entity_ids: set[int],
) -> list[dict]:
    from sqlalchemy import or_
    from services.dossier_scans import _target_values_for_dossier

    root_l = (root_value or '').lower().strip()
    target_values = _target_values_for_dossier(root_entity_id, owner_id)
    out = []
    scans = (
        Scan.query.filter(
            Scan.status == 'completed',
            or_(Scan.user_id == owner_id, Scan.root_entity_id == root_entity_id),
        )
        .order_by(Scan.timestamp.desc())
        .limit(150)
        .all()
    )
    for s in scans:
        if s.status != 'completed':
            continue
        if not _scan_matches_dossier(s, root_l, entity_ids, target_values):
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
    from services.dossier_access import get_dossier_context
    ctx = get_dossier_context(entity_id, user_id, min_role='reader')
    if not ctx:
        return None
    try:
        dossier = build_dossier(entity_id, user_id)
    except Exception as e:
        logger.error('build_dossier entity=%s: %s', entity_id, e)
        dossier = None
    if not dossier:
        dossier = {
            'entity': {
                'id': ent.id,
                'type': ent.entity_type,
                'value': ent.value,
            },
            'title': f'Dossier — {ent.value}',
            'scans_count': 0,
            'links_count': 0,
            'timeline': [],
            'web_history': [],
        }

    ent = ctx['entity']
    owner_id = ctx['owner_user_id']
    if not ent:
        return None

    try:
        link_scans_to_dossier(entity_id, owner_id)
    except Exception as e:
        logger.warning('link_scans dossier %s: %s', entity_id, e)

    try:
        graph = build_graph_json(entity_id, owner_id)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(
            'build_graph_json entity=%s owner=%s: %s', entity_id, owner_id, e,
        )
        graph = {'nodes': [], 'edges': [], 'root_id': entity_id}
    try:
        links_detail = build_entity_links_json(entity_id, owner_id) or {}
    except Exception:
        links_detail = {}
    entity_ids = {int(n['id']) for n in graph.get('nodes', []) if n.get('id')}

    entities = []
    for nid in entity_ids:
        e = db.session.get(Entity, nid)
        if e and e.user_id == owner_id:
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

    scans = _collect_related_scans(owner_id, entity_id, ent.value, entity_ids)

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
    from services.dossier_access import get_dossier_context
    from sqlalchemy import or_

    ctx = get_dossier_context(entity_id, user_id, min_role='reader')
    if not ctx:
        return None
    owner_id = ctx['owner_user_id']
    ent = ctx['entity']
    try:
        link_scans_to_dossier(entity_id, owner_id)
    except Exception as e:
        logger.warning('pick_anchor link_scans %s: %s', entity_id, e)
    if ent.source_scan_id:
        s = db.session.get(Scan, ent.source_scan_id)
        if s and s.status == 'completed':
            if s.user_id == owner_id or s.root_entity_id == entity_id:
                return s
    scans = (
        Scan.query.filter(
            Scan.status == 'completed',
            or_(Scan.user_id == owner_id, Scan.root_entity_id == entity_id),
        )
        .order_by(Scan.timestamp.desc())
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
