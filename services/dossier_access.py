"""Contrôle d'accès aux dossiers partagés (Phase 8 V8)."""
from extensions import db
from models import Entity, DossierCollaborator

ROLE_LEVEL = {'reader': 1, 'editor': 2, 'admin': 3}


def _role_level(role: str) -> int:
    return ROLE_LEVEL.get((role or '').lower(), 0)


def get_collaboration(root_entity_id: int, user_id: int) -> DossierCollaborator | None:
    if not root_entity_id or not user_id:
        return None
    return db.session.query(DossierCollaborator).filter_by(
        root_entity_id=root_entity_id,
        user_id=user_id,
    ).first()


def get_dossier_context(root_entity_id: int, user_id: int, *, min_role: str = 'reader') -> dict | None:
    """
    Retourne le contexte d'accès ou None.
    {entity, owner_user_id, role, is_owner, can_read, can_edit, can_admin, collaboration}
    """
    ent = db.session.get(Entity, root_entity_id)
    if not ent:
        return None

    is_owner = ent.user_id == user_id
    collab = None
    role = 'admin' if is_owner else None

    if not is_owner:
        collab = get_collaboration(root_entity_id, user_id)
        if not collab or not collab.accepted_at:
            return None
        role = collab.role or 'reader'

    if _role_level(role) < _role_level(min_role):
        return None

    return {
        'entity': ent,
        'owner_user_id': ent.user_id,
        'role': role,
        'is_owner': is_owner,
        'can_read': True,
        'can_edit': is_owner or _role_level(role) >= _role_level('editor'),
        'can_admin': is_owner or role == 'admin',
        'collaboration': collab,
    }


def can_access_dossier(root_entity_id: int, user_id: int, min_role: str = 'reader') -> bool:
    return get_dossier_context(root_entity_id, user_id, min_role=min_role) is not None


def dossier_room_name(root_entity_id: int) -> str:
    return f'dossier_{root_entity_id}'


def correlation_user_id(scan_user_id: int | None, root_entity_id: int | None) -> int | None:
    """Entités du graphe partagé : scope propriétaire du dossier."""
    if root_entity_id:
        ent = db.session.get(Entity, root_entity_id)
        if ent:
            return ent.user_id
    return scan_user_id
