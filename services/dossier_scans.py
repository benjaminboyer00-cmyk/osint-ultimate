"""Rattachement des scans orphelins au dossier (root_entity_id sur Scan)."""
import logging

from sqlalchemy import or_

from extensions import db
from models import Entity, EntityLink, Scan

logger = logging.getLogger(__name__)


def _target_values_for_dossier(entity_id: int, owner_id: int) -> set[str]:
    ent = db.session.get(Entity, entity_id)
    if not ent or ent.user_id != owner_id:
        return set()
    raw = (ent.value or '').lower().strip()
    values = {raw}
    uname = raw.lstrip('@')
    if uname:
        values.add(uname)
        values.add(f'@{uname}')
    links = db.session.query(EntityLink).filter(
        EntityLink.user_id == owner_id,
        (EntityLink.source_id == entity_id) | (EntityLink.target_id == entity_id),
    ).all()
    for link in links:
        oid = link.target_id if link.source_id == entity_id else link.source_id
        other = db.session.get(Entity, oid)
        if other and other.value:
            v = other.value.lower().strip()
            values.add(v)
            values.add(v.lstrip('@'))
    return {v for v in values if v}


def link_scans_to_dossier(entity_id: int, owner_id: int) -> int:
    """
    Associe les scans terminés sans root_entity_id (ou mal rattachés)
    lorsque la cible correspond à l'entité racine ou au graphe.
    """
    values = _target_values_for_dossier(entity_id, owner_id)
    if not values:
        return 0
    try:
        candidates = (
            db.session.query(Scan)
            .filter(
                Scan.user_id == owner_id,
                Scan.status == 'completed',
                or_(Scan.root_entity_id.is_(None), Scan.root_entity_id != entity_id),
            )
            .order_by(Scan.timestamp.desc())
            .limit(120)
            .all()
        )
        linked = 0
        for s in candidates:
            t = (s.target or '').lower().strip()
            t_at = t.lstrip('@')
            if t in values or t_at in values or f'@{t_at}' in values:
                s.root_entity_id = entity_id
                linked += 1
                continue
            body = (s.result_json or '').lower()
            if any(len(v) >= 3 and v in body for v in values):
                s.root_entity_id = entity_id
                linked += 1
        if linked:
            db.session.commit()
            logger.info('Dossier %s : %s scan(s) rattaché(s)', entity_id, linked)
        return linked
    except Exception as e:
        db.session.rollback()
        logger.error('link_scans_to_dossier entity=%s: %s', entity_id, e)
        return 0
