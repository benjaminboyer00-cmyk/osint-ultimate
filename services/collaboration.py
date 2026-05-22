"""Collaboration — invitations, commentaires, journal d'activité (Phase 8 V8)."""
import json
import logging
from datetime import datetime

from extensions import db
from models import (
    User, Entity, DossierCollaborator, EntityComment,
    DossierActivityLog, CollaborationNotification,
)

logger = logging.getLogger(__name__)

VALID_ROLES = ('reader', 'editor', 'admin')


def log_activity(
    root_entity_id: int,
    user_id: int | None,
    action: str,
    details: dict | None = None,
):
    row = DossierActivityLog(
        root_entity_id=root_entity_id,
        user_id=user_id,
        action=action,
        details_json=json.dumps(details or {}, ensure_ascii=False, default=str),
        timestamp=datetime.utcnow(),
    )
    db.session.add(row)


def invite_collaborator(
    root_entity_id: int,
    inviter_id: int,
    email: str,
    role: str = 'reader',
) -> dict:
    from services.dossier_access import get_dossier_context as _get_ctx

    ctx = _get_ctx(root_entity_id, inviter_id, min_role='admin')
    if not ctx:
        raise ValueError('Droits insuffisants pour inviter (admin requis)')

    role = (role or 'reader').lower()
    if role not in VALID_ROLES:
        raise ValueError(f'Rôle invalide : {role}')

    email = (email or '').strip().lower()
    invitee = db.session.query(User).filter_by(email=email).first()
    if not invitee:
        raise ValueError('Utilisateur introuvable — il doit posséder un compte OSINT Ultimate')
    if invitee.id == ctx['owner_user_id']:
        raise ValueError('Le propriétaire du dossier ne peut pas être invité')

    existing = db.session.query(DossierCollaborator).filter_by(
        root_entity_id=root_entity_id, user_id=invitee.id,
    ).first()
    if existing:
        if existing.accepted_at:
            raise ValueError('Cet utilisateur collabore déjà sur ce dossier')
        raise ValueError('Invitation déjà envoyée — en attente d\'acceptation')

    row = DossierCollaborator(
        root_entity_id=root_entity_id,
        user_id=invitee.id,
        invited_by_user_id=inviter_id,
        role=role,
        invited_at=datetime.utcnow(),
        accepted_at=None,
    )
    db.session.add(row)
    db.session.flush()

    inviter = db.session.get(User, inviter_id)
    ent = ctx['entity']
    msg = (
        f'{inviter.username if inviter else "Un utilisateur"} vous invite sur le dossier '
        f'« {ent.value} » ({role})'
    )
    notif = CollaborationNotification(
        user_id=invitee.id,
        message=msg[:500],
        link=f'/invitations',
        notification_type='invite',
        read=False,
    )
    db.session.add(notif)
    log_activity(root_entity_id, inviter_id, 'invite_sent', {
        'invitee_id': invitee.id,
        'invitee_email': email,
        'role': role,
        'collaboration_id': row.id,
    })
    db.session.commit()
    return {
        'id': row.id,
        'user_id': invitee.id,
        'email': invitee.email,
        'username': invitee.username,
        'role': role,
        'status': 'pending',
    }


def list_pending_invitations(user_id: int) -> list[dict]:
    rows = (
        db.session.query(DossierCollaborator)
        .filter_by(user_id=user_id)
        .filter(DossierCollaborator.accepted_at.is_(None))
        .order_by(DossierCollaborator.invited_at.desc())
        .all()
    )
    out = []
    for row in rows:
        ent = db.session.get(Entity, row.root_entity_id)
        inviter = db.session.get(User, row.invited_by_user_id)
        out.append({
            'id': row.id,
            'root_entity_id': row.root_entity_id,
            'role': row.role,
            'invited_at': row.invited_at.isoformat() if row.invited_at else None,
            'dossier_value': ent.value if ent else '',
            'dossier_type': ent.entity_type if ent else '',
            'invited_by': inviter.username if inviter else '',
        })
    return out


def accept_invitation(collaboration_id: int, user_id: int) -> dict:
    row = db.session.get(DossierCollaborator, collaboration_id)
    if not row or row.user_id != user_id:
        raise ValueError('Invitation introuvable')
    if row.accepted_at:
        raise ValueError('Invitation déjà acceptée')
    row.accepted_at = datetime.utcnow()
    log_activity(row.root_entity_id, user_id, 'invite_accepted', {
        'role': row.role,
        'collaboration_id': row.id,
    })
    db.session.commit()
    return {
        'root_entity_id': row.root_entity_id,
        'role': row.role,
        'dossier_url': f'/expert/dossier/{row.root_entity_id}',
    }


def list_collaborators(root_entity_id: int, requester_id: int) -> list[dict]:
    from services.dossier_access import get_dossier_context
    ctx = get_dossier_context(root_entity_id, requester_id, min_role='reader')
    if not ctx:
        raise ValueError('Accès refusé')

    ent = ctx['entity']
    owner = db.session.get(User, ent.user_id)
    out = [{
        'user_id': owner.id,
        'username': owner.username if owner else '',
        'email': owner.email if owner else '',
        'role': 'owner',
        'accepted': True,
        'is_owner': True,
    }]
    rows = db.session.query(DossierCollaborator).filter_by(
        root_entity_id=root_entity_id,
    ).filter(DossierCollaborator.accepted_at.isnot(None)).all()
    for row in rows:
        u = db.session.get(User, row.user_id)
        out.append({
            'user_id': row.user_id,
            'username': u.username if u else '',
            'email': u.email if u else '',
            'role': row.role,
            'accepted': True,
            'is_owner': False,
            'collaboration_id': row.id,
        })
    pending = db.session.query(DossierCollaborator).filter_by(
        root_entity_id=root_entity_id,
    ).filter(DossierCollaborator.accepted_at.is_(None)).all()
    for row in pending:
        u = db.session.get(User, row.user_id)
        out.append({
            'user_id': row.user_id,
            'username': u.username if u else '',
            'email': u.email if u else '',
            'role': row.role,
            'accepted': False,
            'is_owner': False,
            'collaboration_id': row.id,
        })
    return out


def update_collaborator_role(
    root_entity_id: int, admin_id: int, target_user_id: int, role: str,
) -> None:
    from services.dossier_access import get_dossier_context
    ctx = get_dossier_context(root_entity_id, admin_id, min_role='admin')
    if not ctx:
        raise ValueError('Droits admin requis')
    role = (role or '').lower()
    if role not in VALID_ROLES:
        raise ValueError('Rôle invalide')
    row = db.session.query(DossierCollaborator).filter_by(
        root_entity_id=root_entity_id, user_id=target_user_id,
    ).first()
    if not row or not row.accepted_at:
        raise ValueError('Collaborateur introuvable')
    row.role = role
    log_activity(root_entity_id, admin_id, 'role_changed', {
        'target_user_id': target_user_id, 'role': role,
    })
    db.session.commit()


def remove_collaborator(root_entity_id: int, admin_id: int, target_user_id: int) -> None:
    from services.dossier_access import get_dossier_context
    ctx = get_dossier_context(root_entity_id, admin_id, min_role='admin')
    if not ctx:
        raise ValueError('Droits admin requis')
    if target_user_id == ctx['owner_user_id']:
        raise ValueError('Impossible de retirer le propriétaire')
    row = db.session.query(DossierCollaborator).filter_by(
        root_entity_id=root_entity_id, user_id=target_user_id,
    ).first()
    if row:
        db.session.delete(row)
        log_activity(root_entity_id, admin_id, 'collaborator_removed', {
            'target_user_id': target_user_id,
        })
        db.session.commit()


def add_entity_comment(entity_id: int, user_id: int, content: str) -> dict:
    from services.dossier_access import get_dossier_context, dossier_room_name

    ent = db.session.get(Entity, entity_id)
    if not ent:
        raise ValueError('Entité introuvable')
    root_id = resolve_dossier_root_for_entity(entity_id, user_id)
    if not root_id:
        raise ValueError('Dossier parent introuvable ou accès refusé')
    ctx = get_dossier_context(root_id, user_id, min_role='reader')
    if not ctx:
        raise ValueError('Accès refusé')

    content = (content or '').strip()
    if not content or len(content) > 4000:
        raise ValueError('Commentaire invalide')

    comment = EntityComment(
        entity_id=entity_id,
        user_id=user_id,
        content=content,
    )
    db.session.add(comment)
    db.session.flush()
    author = db.session.get(User, user_id)
    log_activity(root_id, user_id, 'comment_added', {
        'entity_id': entity_id,
        'comment_id': comment.id,
    })
    db.session.commit()

    payload = {
        'id': comment.id,
        'entity_id': entity_id,
        'content': content,
        'author': author.username if author else '',
        'user_id': user_id,
        'created_at': comment.created_at.isoformat() if comment.created_at else None,
        'root_entity_id': root_id,
        'room': dossier_room_name(root_id),
    }
    return payload


def list_entity_comments(entity_id: int, user_id: int) -> list[dict]:
    from services.dossier_access import get_dossier_context

    ent = db.session.get(Entity, entity_id)
    if not ent:
        return []
    root_id = resolve_dossier_root_for_entity(entity_id, user_id)
    if not root_id or not get_dossier_context(root_id, user_id, min_role='reader'):
        raise ValueError('Accès refusé')

    rows = (
        db.session.query(EntityComment)
        .filter_by(entity_id=entity_id)
        .order_by(EntityComment.created_at.asc())
        .limit(200)
        .all()
    )
    out = []
    for row in rows:
        u = db.session.get(User, row.user_id)
        out.append({
            'id': row.id,
            'entity_id': row.entity_id,
            'content': row.content,
            'author': u.username if u else '',
            'user_id': row.user_id,
            'created_at': row.created_at.isoformat() if row.created_at else None,
        })
    return out


def resolve_dossier_root_for_entity(entity_id: int, viewer_user_id: int) -> int | None:
    """Entité → dossier racine si le viewer y a accès."""
    from services.dossier_access import get_dossier_context

    if get_dossier_context(entity_id, viewer_user_id, min_role='reader'):
        return entity_id

    ent = db.session.get(Entity, entity_id)
    if not ent:
        return None

    owned = db.session.query(Entity).filter_by(id=entity_id, user_id=viewer_user_id).first()
    if owned and get_dossier_context(entity_id, viewer_user_id, min_role='reader'):
        return entity_id

    collabs = (
        db.session.query(DossierCollaborator)
        .filter_by(user_id=viewer_user_id)
        .filter(DossierCollaborator.accepted_at.isnot(None))
        .all()
    )
    for collab in collabs:
        ctx = get_dossier_context(collab.root_entity_id, viewer_user_id, min_role='reader')
        if not ctx:
            continue
        from services.correlation import build_graph_json
        graph = build_graph_json(collab.root_entity_id, ctx['owner_user_id'])
        node_ids = {int(n['id']) for n in graph.get('nodes', []) if n.get('id')}
        if entity_id in node_ids:
            return collab.root_entity_id
    return None


def get_activity_log(root_entity_id: int, user_id: int, limit: int = 50) -> list[dict]:
    from services.dossier_access import get_dossier_context
    if not get_dossier_context(root_entity_id, user_id, min_role='reader'):
        raise ValueError('Accès refusé')
    rows = (
        db.session.query(DossierActivityLog)
        .filter_by(root_entity_id=root_entity_id)
        .order_by(DossierActivityLog.timestamp.desc())
        .limit(limit)
        .all()
    )
    out = []
    for row in rows:
        u = db.session.get(User, row.user_id) if row.user_id else None
        details = {}
        try:
            details = json.loads(row.details_json or '{}')
        except Exception:
            pass
        out.append({
            'id': row.id,
            'action': row.action,
            'username': u.username if u else 'Système',
            'timestamp': row.timestamp.isoformat() if row.timestamp else None,
            'details': details,
        })
    return out


def emit_dossier_event(socketio, root_entity_id: int, event: str, payload: dict):
    if not socketio or not root_entity_id:
        return
    from services.dossier_access import dossier_room_name
    try:
        socketio.emit(event, payload, room=dossier_room_name(root_entity_id))
    except Exception as e:
        logger.warning('dossier emit %s: %s', event, e)


def unread_collab_notifications_count(user_id: int) -> int:
    return db.session.query(CollaborationNotification).filter_by(
        user_id=user_id, read=False,
    ).count()
