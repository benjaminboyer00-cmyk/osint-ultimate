"""Graphe actif — l'utilisateur crée un graphe, puis ses recherches s'y
rattachent au lieu de créer un graphe isolé par recherche.

Le « graphe » est matérialisé par une entité racine (type ``person``) à
laquelle le moteur de corrélation relie toutes les nouvelles entités
(``_root_entity_id``). L'entité racine active est mémorisée en session.
"""
from flask import session

from extensions import db
from models import Entity, Investigation

SESSION_KEY = 'active_graph_root'


def _unique_name(user_id: int, name: str) -> str:
    """Évite la collision de la contrainte unique (user, type, value)."""
    base = (name or 'Nouveau graphe').strip()[:170] or 'Nouveau graphe'
    candidate = base
    i = 2
    while Entity.query.filter_by(
        user_id=user_id, entity_type='person', value=candidate,
    ).first():
        candidate = f'{base} ({i})'
        i += 1
    return candidate


def create_graph(user_id: int, name: str) -> dict:
    """Crée un graphe (entité racine + investigation) et l'active."""
    value = _unique_name(user_id, name)
    root = Entity(user_id=user_id, entity_type='person', value=value)
    db.session.add(root)
    db.session.flush()
    inv = Investigation(
        user_id=user_id, title=value, objective=value,
        status='active', steps_json='[]', root_entity_id=root.id,
    )
    db.session.add(inv)
    db.session.commit()
    session[SESSION_KEY] = root.id
    return {'root_id': root.id, 'name': value, 'investigation_id': inv.id}


def set_active(user_id: int, root_id) -> dict | None:
    ent = Entity.query.filter_by(id=int(root_id), user_id=user_id).first()
    if not ent:
        return None
    session[SESSION_KEY] = ent.id
    return {'root_id': ent.id, 'name': ent.value}


def clear_active() -> None:
    session.pop(SESSION_KEY, None)


def get_active(user_id: int) -> dict | None:
    rid = session.get(SESSION_KEY)
    if not rid:
        return None
    ent = Entity.query.filter_by(id=int(rid), user_id=user_id).first()
    if not ent:
        session.pop(SESSION_KEY, None)
        return None
    return {'root_id': ent.id, 'name': ent.value}


def list_graphs(user_id: int, limit: int = 30) -> list[dict]:
    """Graphes (investigations) de l'utilisateur, plus récents d'abord."""
    invs = (
        Investigation.query
        .filter_by(user_id=user_id)
        .filter(Investigation.root_entity_id.isnot(None))
        .order_by(Investigation.created_at.desc())
        .limit(limit)
        .all()
    )
    active = session.get(SESSION_KEY)
    return [
        {'root_id': i.root_entity_id, 'name': i.title, 'id': i.id,
         'active': i.root_entity_id == active}
        for i in invs
    ]
