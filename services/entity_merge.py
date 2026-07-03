"""Fusion d'entités — regroupe plusieurs identifiants d'une même personne.

Mécanisme : un lien ``EntityLink`` de type ``MEME_PERSONNE`` entre deux
entités. Un « cluster / personne » = composante connexe sur ces liens.
Entièrement réversible et sans migration : réutilise la table
``entity_link`` existante. La fusion connecte deux composantes du graphe
qui étaient jusqu'ici séparées (ex. ``benji`` et ``benjamin.boyer00``).
"""
import difflib

from sqlalchemy import and_, or_

from extensions import db
from models import Entity, EntityLink

MERGE_LINK_TYPE = 'MEME_PERSONNE'


def _owned_entity(user_id: int, entity_id) -> Entity | None:
    try:
        eid = int(entity_id)
    except (TypeError, ValueError):
        return None
    return Entity.query.filter_by(id=eid, user_id=user_id).first()


def _existing_merge_link(user_id: int, a_id: int, b_id: int) -> EntityLink | None:
    return EntityLink.query.filter(
        EntityLink.user_id == user_id,
        EntityLink.link_type == MERGE_LINK_TYPE,
        or_(
            and_(EntityLink.source_id == a_id, EntityLink.target_id == b_id),
            and_(EntityLink.source_id == b_id, EntityLink.target_id == a_id),
        ),
    ).first()


def merge_entities(
    user_id: int,
    entity_id_a,
    entity_id_b,
    *,
    confidence: float = 1.0,
    proof: str = 'Fusion manuelle',
    scan_id: int | None = None,
) -> dict:
    """Marque deux entités comme appartenant à la même personne (idempotent)."""
    a = _owned_entity(user_id, entity_id_a)
    b = _owned_entity(user_id, entity_id_b)
    if not a or not b:
        raise ValueError('Entité introuvable')
    if a.id == b.id:
        raise ValueError('Impossible de fusionner une entité avec elle-même')

    link = _existing_merge_link(user_id, a.id, b.id)
    if link:
        if confidence and (link.confidence or 0) < confidence:
            link.confidence = float(confidence)
            db.session.commit()
        return {
            'status': 'exists',
            'link_id': link.id,
            'cluster': get_person_cluster(user_id, a.id),
        }

    link = EntityLink(
        user_id=user_id,
        source_id=a.id,
        target_id=b.id,
        link_type=MERGE_LINK_TYPE,
        source_proof=str(proof)[:500],
        scan_id=scan_id,
        confidence=float(confidence),
    )
    db.session.add(link)
    db.session.commit()
    return {
        'status': 'merged',
        'link_id': link.id,
        'cluster': get_person_cluster(user_id, a.id),
    }


def unmerge_entities(user_id: int, entity_id_a, entity_id_b) -> dict:
    """Supprime le lien « même personne » entre deux entités."""
    a = _owned_entity(user_id, entity_id_a)
    b = _owned_entity(user_id, entity_id_b)
    if not a or not b:
        raise ValueError('Entité introuvable')
    link = _existing_merge_link(user_id, a.id, b.id)
    if not link:
        return {'status': 'noop'}
    db.session.delete(link)
    db.session.commit()
    return {'status': 'unmerged', 'cluster': get_person_cluster(user_id, a.id)}


def get_person_cluster(user_id: int, entity_id) -> dict:
    """Composante connexe de l'entité sur les liens ``MEME_PERSONNE``."""
    root = _owned_entity(user_id, entity_id)
    if not root:
        return {'members': [], 'size': 0}

    links = EntityLink.query.filter(
        EntityLink.user_id == user_id,
        EntityLink.link_type == MERGE_LINK_TYPE,
    ).all()
    adj: dict[int, list[int]] = {}
    for lk in links:
        adj.setdefault(lk.source_id, []).append(lk.target_id)
        adj.setdefault(lk.target_id, []).append(lk.source_id)

    seen = {root.id}
    stack = [root.id]
    while stack:
        cur = stack.pop()
        for nb in adj.get(cur, ()):
            if nb not in seen:
                seen.add(nb)
                stack.append(nb)

    members = Entity.query.filter(
        Entity.id.in_(seen), Entity.user_id == user_id,
    ).all()
    return {
        'members': [
            {'id': m.id, 'entity_type': m.entity_type, 'value': m.value}
            for m in members
        ],
        'size': len(members),
    }


def _base_token(entity: Entity) -> str:
    """Identifiant comparable : partie locale d'un email, pseudo sans « @ »."""
    val = (entity.value or '').lower().strip()
    if entity.entity_type == 'email' and '@' in val:
        return val.split('@')[0]
    return val.lstrip('@')


def suggest_person_merges(user_id: int, entity_id, limit: int = 5) -> list[dict]:
    """Candidats « même personne » (déterministe, sans dépendance ni coût).

    Amorce locale qui sera affinée par l'IA en Phase 2. Compare la partie
    signifiante des identifiants (pseudo, partie locale d'email) via
    ``difflib`` : égalité inter-types, inclusion, ou similarité élevée.
    """
    ent = _owned_entity(user_id, entity_id)
    if not ent:
        return []
    src = _base_token(ent)
    if not src or len(src) < 3:
        return []

    cluster_ids = {m['id'] for m in get_person_cluster(user_id, entity_id)['members']}
    q = Entity.query.filter(Entity.user_id == user_id)
    if cluster_ids:
        q = q.filter(Entity.id.notin_(cluster_ids))
    candidates = q.limit(500).all()

    out = []
    for other in candidates:
        if other.id == ent.id:
            continue
        tok = _base_token(other)
        if not tok or len(tok) < 3:
            continue
        ratio = difflib.SequenceMatcher(None, src, tok).ratio()
        reason = None
        if src == tok and other.entity_type != ent.entity_type:
            ratio, reason = max(ratio, 0.95), 'Identifiant identique sur un autre type'
        elif (src in tok or tok in src) and min(len(src), len(tok)) >= 3:
            ratio, reason = max(ratio, 0.8), 'Un identifiant contient l’autre'
        elif ratio >= 0.72:
            reason = f'Pseudos similaires ({int(ratio * 100)} %)'
        if reason:
            out.append({
                'entity': {
                    'id': other.id,
                    'entity_type': other.entity_type,
                    'value': other.value,
                },
                'score': round(ratio, 2),
                'reason': reason,
            })

    out.sort(key=lambda x: x['score'], reverse=True)
    return out[:limit]
