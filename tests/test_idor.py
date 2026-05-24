"""Tests IDOR — accès dossiers / scans d'autres utilisateurs."""
import uuid
from datetime import datetime

import pytest

from extensions import db
from models import User, Entity, Scan, DossierCollaborator


@pytest.fixture
def two_users(app):
    suffix = uuid.uuid4().hex[:8]
    owner = User(username=f'owner_idor_{suffix}', email=f'o_{suffix}@t.com')
    owner.set_password('OwnerPass2024!xyz')
    intruder = User(username=f'intruder_idor_{suffix}', email=f'i_{suffix}@t.com')
    intruder.set_password('IntruderPass2024!xyz')
    db.session.add_all([owner, intruder])
    db.session.commit()
    dossier = Entity(user_id=owner.id, value=f'cible_{suffix}@test.com', entity_type='email')
    db.session.add(dossier)
    db.session.commit()
    return owner, intruder, dossier, suffix


def test_get_dossier_context_blocks_intruder(two_users):
    from services.dossier_access import get_dossier_context
    owner, intruder, dossier, _ = two_users
    assert get_dossier_context(dossier.id, owner.id, min_role='reader') is not None
    assert get_dossier_context(dossier.id, intruder.id, min_role='reader') is None


def test_collaborator_reader_access(two_users):
    from services.dossier_access import get_dossier_context
    owner, intruder, dossier, _ = two_users
    db.session.add(DossierCollaborator(
        root_entity_id=dossier.id,
        user_id=intruder.id,
        role='reader',
        accepted_at=datetime.utcnow(),
    ))
    db.session.commit()
    ctx = get_dossier_context(dossier.id, intruder.id, min_role='reader')
    assert ctx is not None
    assert ctx['role'] == 'reader'
    assert ctx['can_edit'] is False


def test_dossier_route_403_for_intruder(client, two_users):
    owner, intruder, dossier, suffix = two_users
    client.post('/login', data={
        'username': f'intruder_idor_{suffix}',
        'password': 'IntruderPass2024!xyz',
    })
    r = client.get(f'/expert/dossier/{dossier.id}')
    assert r.status_code in (403, 404)


def test_scan_result_idor_on_private_scan(client, two_users):
    owner, intruder, dossier, suffix = two_users
    scan = Scan(
        user_id=owner.id,
        module='email',
        target='secret@test.com',
        status='completed',
        result_json='{}',
        root_entity_id=None,
    )
    db.session.add(scan)
    db.session.commit()
    client.post('/login', data={
        'username': f'intruder_idor_{suffix}',
        'password': 'IntruderPass2024!xyz',
    })
    r = client.get(f'/scan/{scan.id}')
    assert r.status_code == 403


def test_scan_result_allowed_via_shared_dossier(client, two_users):
    owner, intruder, dossier, suffix = two_users
    scan = Scan(
        user_id=owner.id,
        module='email',
        target='shared@test.com',
        status='completed',
        result_json='{"ok": true}',
        root_entity_id=dossier.id,
    )
    db.session.add(scan)
    db.session.add(DossierCollaborator(
        root_entity_id=dossier.id,
        user_id=intruder.id,
        role='reader',
        accepted_at=datetime.utcnow(),
    ))
    db.session.commit()
    client.post('/login', data={
        'username': f'intruder_idor_{suffix}',
        'password': 'IntruderPass2024!xyz',
    })
    r = client.get(f'/scan/{scan.id}')
    assert r.status_code == 200
