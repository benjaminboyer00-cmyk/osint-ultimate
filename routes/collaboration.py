"""Routes Phase 8 — collaboration sur dossiers."""
from flask import Blueprint, request, jsonify, render_template, current_app
from flask_login import login_required, current_user

from extensions import db
from services.collaboration import (
    invite_collaborator,
    list_pending_invitations,
    accept_invitation,
    list_collaborators,
    update_collaborator_role,
    remove_collaborator,
    add_entity_comment,
    list_entity_comments,
    get_activity_log,
    unread_collab_notifications_count,
)
from services.dossier_access import get_dossier_context, dossier_room_name

collab_bp = Blueprint('collab', __name__)


@collab_bp.route('/invitations')
@login_required
def invitations_page():
    invites = list_pending_invitations(current_user.id)
    return render_template(
        'invitations.html',
        invitations=invites,
        username=current_user.username,
    )


@collab_bp.route('/invitations/list')
@login_required
def invitations_list_api():
    return jsonify({'invitations': list_pending_invitations(current_user.id)})


@collab_bp.route('/invitations/<int:collab_id>/accept', methods=['POST'])
@login_required
def invitations_accept(collab_id):
    try:
        out = accept_invitation(collab_id, current_user.id)
        return jsonify(out)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@collab_bp.route('/dossier/<int:entity_id>/invite', methods=['POST'])
@login_required
def dossier_invite(entity_id):
    data = request.json or request.form or {}
    email = (data.get('email') or '').strip()
    role = (data.get('role') or 'reader').strip()
    try:
        base = request.url_root.rstrip('/')
        out = invite_collaborator(
            entity_id, current_user.id, email, role, external_base=base,
        )
        from app import socketio
        from services.collaboration import emit_dossier_event, log_activity
        emit_dossier_event(socketio, entity_id, 'invite_sent', out)
        return jsonify(out)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@collab_bp.route('/dossier/<int:entity_id>/collaborators')
@login_required
def dossier_collaborators_list(entity_id):
    try:
        return jsonify({'collaborators': list_collaborators(entity_id, current_user.id)})
    except ValueError as e:
        return jsonify({'error': str(e)}), 403


@collab_bp.route('/dossier/<int:entity_id>/collaborators/<int:target_user_id>', methods=['PUT'])
@login_required
def dossier_collaborator_update(entity_id, target_user_id):
    data = request.json or {}
    role = (data.get('role') or '').strip()
    try:
        update_collaborator_role(entity_id, current_user.id, target_user_id, role)
        return jsonify({'ok': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@collab_bp.route('/dossier/<int:entity_id>/collaborators/<int:target_user_id>', methods=['DELETE'])
@login_required
def dossier_collaborator_remove(entity_id, target_user_id):
    try:
        remove_collaborator(entity_id, current_user.id, target_user_id)
        return jsonify({'ok': True})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@collab_bp.route('/dossier/<int:entity_id>/activity')
@login_required
def dossier_activity(entity_id):
    try:
        return jsonify({'activity': get_activity_log(entity_id, current_user.id)})
    except ValueError as e:
        return jsonify({'error': str(e)}), 403


@collab_bp.route('/entity/<int:entity_id>/comments', methods=['GET'])
@login_required
def entity_comments_get(entity_id):
    try:
        return jsonify({'comments': list_entity_comments(entity_id, current_user.id)})
    except ValueError as e:
        return jsonify({'error': str(e)}), 403


@collab_bp.route('/entity/<int:entity_id>/comments', methods=['POST'])
@login_required
def entity_comments_post(entity_id):
    data = request.json or {}
    content = (data.get('content') or '').strip()
    if not content:
        return jsonify({'error': 'Commentaire vide'}), 400
    try:
        from app import socketio
        payload = add_entity_comment(entity_id, current_user.id, content)
        from services.collaboration import emit_dossier_event
        emit_dossier_event(socketio, payload['root_entity_id'], 'comment_added', payload)
        try:
            socketio.emit('comment_added', payload, room=str(current_user.id))
        except Exception:
            pass
        return jsonify(payload)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        current_app.logger.exception('comment entity=%s', entity_id)
        return jsonify({'error': str(e)}), 500


@collab_bp.route('/collab/notifications/count')
@login_required
def collab_notifications_count():
    return jsonify({'count': unread_collab_notifications_count(current_user.id)})
