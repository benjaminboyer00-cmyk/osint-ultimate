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


# Diminutifs FR/EN courants (bidirectionnel) — aide « benji = benjamin ».
_NICKNAMES = {
    'benji': 'benjamin', 'ben': 'benjamin', 'mike': 'michael', 'mick': 'michael',
    'alex': 'alexandre', 'max': 'maxime', 'tom': 'thomas', 'nico': 'nicolas',
    'flo': 'florian', 'manu': 'emmanuel', 'seb': 'sebastien', 'fred': 'frederic',
    'raf': 'raphael', 'val': 'valentin', 'sam': 'samuel', 'dan': 'daniel',
    'chris': 'christophe', 'matt': 'mathieu', 'vince': 'vincent', 'greg': 'gregory',
    'steph': 'stephane', 'will': 'william', 'rob': 'robert', 'toine': 'antoine',
    'guillon': 'guillaume', 'jé': 'jerome', 'dav': 'david', 'gab': 'gabriel',
}


def _canon(tok: str) -> str:
    """Forme canonique : sans séparateurs ni chiffres finaux."""
    import re
    t = re.sub(r'[._\-]', '', (tok or '').lower())
    return re.sub(r'\d+$', '', t)


def _name_forms(tok: str) -> set[str]:
    """Formes équivalentes (canon + diminutif/expansion)."""
    c = _canon(tok)
    forms = {c}
    if c in _NICKNAMES:
        forms.add(_NICKNAMES[c])
    forms |= {nick for nick, full in _NICKNAMES.items() if full == c}
    return {f for f in forms if f}


def _neighbor_map(user_id: int) -> dict[int, set[int]]:
    """Voisins de chaque entité (hors liens MEME_PERSONNE)."""
    adj: dict[int, set[int]] = {}
    links = EntityLink.query.filter(
        EntityLink.user_id == user_id,
        EntityLink.link_type != MERGE_LINK_TYPE,
    ).all()
    for lk in links:
        adj.setdefault(lk.source_id, set()).add(lk.target_id)
        adj.setdefault(lk.target_id, set()).add(lk.source_id)
    return adj


def suggest_person_merges(user_id: int, entity_id, limit: int = 5) -> list[dict]:
    """Candidats « même personne » — moteur local intelligent (aucune donnée
    envoyée à un tiers) : diminutifs, similarité, et surtout **signal
    structurel** (identifiants partageant une connexion commune)."""
    ent = _owned_entity(user_id, entity_id)
    if not ent:
        return []
    src = _base_token(ent)
    if not src or len(src) < 3:
        return []
    src_canon = _canon(src)
    src_forms = _name_forms(src)

    cluster_ids = {m['id'] for m in get_person_cluster(user_id, entity_id)['members']}
    q = Entity.query.filter(Entity.user_id == user_id)
    if cluster_ids:
        q = q.filter(Entity.id.notin_(cluster_ids))
    candidates = q.limit(500).all()

    adj = _neighbor_map(user_id)
    src_neighbors = adj.get(ent.id, set())

    out = []
    for other in candidates:
        if other.id == ent.id:
            continue
        tok = _base_token(other)
        if not tok or len(tok) < 3:
            continue
        tcanon = _canon(tok)
        ratio = difflib.SequenceMatcher(None, src, tok).ratio()
        reason, score = None, ratio

        if src == tok and other.entity_type != ent.entity_type:
            score, reason = 0.96, 'Identifiant identique sur un autre type'
        elif src_forms & _name_forms(tok):
            score, reason = 0.9, 'Diminutif / variante du même prénom'
        elif src_canon and (src_canon in tcanon or tcanon in src_canon) and min(len(src_canon), len(tcanon)) >= 3:
            score, reason = max(ratio, 0.82), 'Un identifiant contient l’autre'
        elif ratio >= 0.72:
            score, reason = ratio, f'Identifiants similaires ({int(ratio * 100)} %)'

        # Signal structurel : connexion commune (privacy-safe, local)
        shared = src_neighbors & adj.get(other.id, set())
        if shared:
            score = min(0.99, max(score, 0.5) + 0.15 * min(len(shared), 3))
            extra = f'{len(shared)} connexion(s) commune(s)'
            reason = f'{reason} + {extra}' if reason else extra

        if reason:
            out.append({
                'entity': {'id': other.id, 'entity_type': other.entity_type, 'value': other.value},
                'score': round(min(score, 0.99), 2),
                'reason': reason,
            })

    out.sort(key=lambda x: x['score'], reverse=True)
    return out[:limit]
