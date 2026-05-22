"""Tableau de bord dossier d'investigation."""
import json
from extensions import db
from models import Entity, EntityLink, Scan, Investigation
from services.dossier_access import get_dossier_context


def build_dossier(entity_id: int, user_id: int) -> dict | None:
    ctx = get_dossier_context(entity_id, user_id, min_role='reader')
    if not ctx:
        return None

    ent = ctx['entity']
    owner_id = ctx['owner_user_id']

    links = db.session.query(EntityLink).filter(
        EntityLink.user_id == owner_id,
        (EntityLink.source_id == entity_id) | (EntityLink.target_id == entity_id),
    ).order_by(EntityLink.created_at.desc()).all()

    related_entities = []
    seen = {entity_id}
    for link in links:
        oid = link.target_id if link.source_id == entity_id else link.source_id
        if oid in seen:
            continue
        seen.add(oid)
        o = db.session.get(Entity, oid)
        if o:
            related_entities.append({
                'id': o.id, 'type': o.entity_type, 'value': o.value,
                'link_type': link.link_type,
            })

    scans_q = db.session.query(Scan).filter(
        (Scan.user_id == owner_id) | (Scan.root_entity_id == entity_id),
    ).order_by(Scan.timestamp.desc()).limit(100)

    timeline = []
    for s in scans_q:
        if (
            s.root_entity_id == entity_id
            or s.target.lower() == ent.value.lower()
            or str(ent.value) in (s.result_json or '').lower()
        ):
            timeline.append({
                'type': 'scan',
                'id': s.id,
                'module': s.module,
                'target': s.target,
                'status': s.status,
                'at': s.timestamp.isoformat() if s.timestamp else None,
                'by_user_id': s.user_id,
            })
    for link in links:
        timeline.append({
            'type': 'link',
            'link_type': link.link_type,
            'proof': link.source_proof,
            'at': link.created_at.isoformat() if link.created_at else None,
        })
    web_history = []
    for s in scans_q:
        try:
            payload = json.loads(s.result_json or '{}')
        except Exception:
            continue
        wb = payload.get('Historique Web (Wayback)') or payload.get('Module: wayback')
        if isinstance(wb, dict):
            for snap in (wb.get('Snapshots') or [])[:15]:
                if isinstance(snap, dict):
                    web_history.append({
                        'date': snap.get('Date'),
                        'url': snap.get('URL'),
                        'archive': snap.get('Lien archive'),
                        'scan_id': s.id,
                    })

    timeline.sort(key=lambda x: x.get('at') or '', reverse=True)

    inv = db.session.query(Investigation).filter_by(
        user_id=owner_id, root_entity_id=entity_id,
    ).first()

    from services.correlation import get_rebound_suggestions
    rebound = get_rebound_suggestions(entity_id, owner_id)

    from services.collaboration import list_collaborators, get_activity_log
    collaborators = []
    activity = []
    try:
        if ctx['can_admin']:
            collaborators = list_collaborators(entity_id, user_id)
        activity = get_activity_log(entity_id, user_id, limit=30)
    except Exception:
        pass

    return {
        'entity': {
            'id': ent.id,
            'type': ent.entity_type,
            'value': ent.value,
            'created_at': ent.created_at.isoformat() if ent.created_at else None,
        },
        'investigation_id': inv.id if inv else None,
        'title': inv.title if inv else f'Dossier — {ent.value}',
        'related_entities': related_entities,
        'timeline': timeline[:50],
        'web_history': web_history[:20],
        'scans_count': len([t for t in timeline if t['type'] == 'scan']),
        'links_count': len(links),
        'rebound_suggestions': rebound,
        'access': {
            'role': ctx['role'],
            'is_owner': ctx['is_owner'],
            'can_edit': ctx['can_edit'],
            'can_admin': ctx['can_admin'],
        },
        'collaborators': collaborators,
        'activity': activity,
    }
