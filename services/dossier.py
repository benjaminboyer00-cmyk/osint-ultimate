"""Tableau de bord dossier d'investigation."""
import json
from extensions import db
from models import Entity, EntityLink, Scan, Investigation


def build_dossier(entity_id: int, user_id: int) -> dict | None:
    ent = Entity.query.filter_by(id=entity_id, user_id=user_id).first()
    if not ent:
        return None

    links = EntityLink.query.filter(
        EntityLink.user_id == user_id,
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

    scans = Scan.query.filter_by(user_id=user_id).order_by(Scan.timestamp.desc()).limit(100).all()
    timeline = []
    for s in scans:
        if s.target.lower() == ent.value.lower() or str(ent.value) in (s.result_json or ''):
            timeline.append({
                'type': 'scan',
                'id': s.id,
                'module': s.module,
                'target': s.target,
                'status': s.status,
                'at': s.timestamp.isoformat() if s.timestamp else None,
            })
    for link in links:
        timeline.append({
            'type': 'link',
            'link_type': link.link_type,
            'proof': link.source_proof,
            'at': link.created_at.isoformat() if link.created_at else None,
        })
    web_history = []
    for s in scans:
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

    inv = Investigation.query.filter_by(user_id=user_id, root_entity_id=entity_id).first()

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
    }
